package parser

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
)

// RequirementsTxtParser parses Python requirements.txt files.
type RequirementsTxtParser struct{}

// requirementRegex matches lines like: package==1.2.3 or package>=1.2.3
var requirementRegex = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s,;#]+)`)

func (p *RequirementsTxtParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var packages []models.Package
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and options
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		matches := requirementRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			packages = append(packages, models.Package{
				Name:      strings.ToLower(matches[1]),
				Version:   matches[2],
				Ecosystem: models.EcosystemPyPI,
				FilePath:  filePath,
			})
		}
	}

	return packages, scanner.Err()
}

// PipfileLockParser parses Pipfile.lock JSON files.
type PipfileLockParser struct{}

type pipfileLock struct {
	Default map[string]pipfilePackage `json:"default"`
	Develop map[string]pipfilePackage `json:"develop"`
}

type pipfilePackage struct {
	Version string `json:"version"`
}

func (p *PipfileLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var lock pipfileLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	var packages []models.Package
	for name, pkg := range lock.Default {
		version := strings.TrimPrefix(pkg.Version, "==")
		packages = append(packages, models.Package{
			Name:      strings.ToLower(name),
			Version:   version,
			Ecosystem: models.EcosystemPyPI,
			FilePath:  filePath,
		})
	}

	return packages, nil
}

// PoetryLockParser parses poetry.lock TOML-like files.
type PoetryLockParser struct{}

func (p *PoetryLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var packages []models.Package
	lines := strings.Split(string(data), "\n")

	var currentName, currentVersion string
	inPackage := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[[package]]" {
			// Save previous package
			if inPackage && currentName != "" && currentVersion != "" {
				packages = append(packages, models.Package{
					Name:      strings.ToLower(currentName),
					Version:   currentVersion,
					Ecosystem: models.EcosystemPyPI,
					FilePath:  filePath,
				})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		if inPackage {
			if strings.HasPrefix(line, "name") {
				currentName = extractTOMLString(line)
			} else if strings.HasPrefix(line, "version") {
				currentVersion = extractTOMLString(line)
			}
		}
	}

	// Don't forget the last package
	if inPackage && currentName != "" && currentVersion != "" {
		packages = append(packages, models.Package{
			Name:      strings.ToLower(currentName),
			Version:   currentVersion,
			Ecosystem: models.EcosystemPyPI,
			FilePath:  filePath,
		})
	}

	return packages, nil
}

// extractTOMLString extracts the string value from a TOML line like: name = "value"
func extractTOMLString(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, "\"")
	return val
}
