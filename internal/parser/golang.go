package parser

import (
	"io"

	"github.com/chavakula/calvigil/internal/models"
	"golang.org/x/mod/modfile"
)

// GoModParser parses Go module files (go.mod).
type GoModParser struct{}

func (p *GoModParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	f, err := modfile.Parse(filePath, data, nil)
	if err != nil {
		return nil, err
	}

	var packages []models.Package
	for _, req := range f.Require {
		if req.Indirect {
			continue // skip indirect dependencies for now
		}
		packages = append(packages, models.Package{
			Name:      req.Mod.Path,
			Version:   req.Mod.Version,
			Ecosystem: models.EcosystemGo,
			FilePath:  filePath,
		})
	}

	return packages, nil
}
