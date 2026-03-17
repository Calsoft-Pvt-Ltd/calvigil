package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// CargoLockParser parses Rust Cargo.lock files.
type CargoLockParser struct{}

func init() {
	Register("Cargo.lock", func() Parser { return &CargoLockParser{} })
}

var (
	cargoNameRe    = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	cargoVersionRe = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
)

func (p *CargoLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var packages []models.Package
	scanner := bufio.NewScanner(r)

	var name, version string
	inPackage := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			// Save previous package if complete
			if inPackage && name != "" && version != "" {
				packages = append(packages, models.Package{
					Name:      name,
					Version:   version,
					Ecosystem: models.EcosystemCrates,
					FilePath:  filePath,
				})
			}
			name, version = "", ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		if m := cargoNameRe.FindStringSubmatch(line); len(m) == 2 {
			name = m[1]
		} else if m := cargoVersionRe.FindStringSubmatch(line); len(m) == 2 {
			version = m[1]
		}
	}

	// Don't forget the last package
	if inPackage && name != "" && version != "" {
		packages = append(packages, models.Package{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemCrates,
			FilePath:  filePath,
		})
	}

	return packages, scanner.Err()
}
