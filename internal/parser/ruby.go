package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// GemfileLockParser parses Ruby Gemfile.lock files.
type GemfileLockParser struct{}

func init() {
	Register("Gemfile.lock", func() Parser { return &GemfileLockParser{} })
}

// gemLineRe matches lines like "    actionpack (7.0.4)" in the SPECS section.
var gemLineRe = regexp.MustCompile(`^\s{4}([a-zA-Z0-9][a-zA-Z0-9._-]*)\s+\(([^)]+)\)`)

func (p *GemfileLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var packages []models.Package
	scanner := bufio.NewScanner(r)

	inSpecs := false

	for scanner.Scan() {
		line := scanner.Text()

		trimmed := strings.TrimSpace(line)

		// Sections are headers without leading whitespace
		if trimmed != "" && line[0] != ' ' {
			inSpecs = trimmed == "specs:"
			// Also enter specs after "GEM" section header followed by "specs:"
			if trimmed == "GEM" || trimmed == "PATH" {
				// Next "specs:" line will activate
			}
			continue
		}

		if trimmed == "specs:" {
			inSpecs = true
			continue
		}

		if !inSpecs {
			continue
		}

		// Match gem entries (4-space indented = top-level gem, 6+ = sub-dependencies)
		if m := gemLineRe.FindStringSubmatch(line); len(m) == 3 {
			packages = append(packages, models.Package{
				Name:      m[1],
				Version:   m[2],
				Ecosystem: models.EcosystemRubyGem,
				FilePath:  filePath,
			})
		}
	}

	return packages, scanner.Err()
}
