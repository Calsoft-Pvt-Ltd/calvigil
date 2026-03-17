package parser

import (
	"encoding/json"
	"io"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// ComposerLockParser parses PHP composer.lock files.
type ComposerLockParser struct{}

func init() {
	Register("composer.lock", func() Parser { return &ComposerLockParser{} })
}

type composerLock struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (p *ComposerLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var lock composerLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	var packages []models.Package
	seen := make(map[string]bool)

	for _, list := range [][]composerPkg{lock.Packages, lock.PackagesDev} {
		for _, pkg := range list {
			if pkg.Name == "" || pkg.Version == "" {
				continue
			}
			key := pkg.Name + "@" + pkg.Version
			if seen[key] {
				continue
			}
			seen[key] = true

			// Composer versions often have a "v" prefix — normalize
			version := pkg.Version
			if len(version) > 1 && version[0] == 'v' {
				version = version[1:]
			}

			packages = append(packages, models.Package{
				Name:      pkg.Name,
				Version:   version,
				Ecosystem: models.EcosystemPHP,
				FilePath:  filePath,
			})
		}
	}

	return packages, nil
}
