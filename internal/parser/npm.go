package parser

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
	"gopkg.in/yaml.v3"
)

// NpmLockParser parses package-lock.json files (v2 and v3 format).
type NpmLockParser struct{}

type npmLockfile struct {
	Packages map[string]npmPackage `json:"packages"`
}

type npmPackage struct {
	Version string `json:"version"`
}

func (p *NpmLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var lock npmLockfile
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	var packages []models.Package
	for path, pkg := range lock.Packages {
		// Skip the root package (empty key)
		if path == "" {
			continue
		}
		// Extract package name from path like "node_modules/express"
		name := path
		if idx := strings.LastIndex(path, "node_modules/"); idx != -1 {
			name = path[idx+len("node_modules/"):]
		}
		if pkg.Version == "" {
			continue
		}
		packages = append(packages, models.Package{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: models.EcosystemNpm,
			FilePath:  filePath,
		})
	}

	return packages, nil
}

// YarnLockParser parses yarn.lock files (v1 format).
type YarnLockParser struct{}

// yarnEntryRegex matches entries like: "package@^1.0.0": and "@scope/pkg@^1.0.0":
var yarnEntryRegex = regexp.MustCompile(`^"?((?:@[^@/\s]+/)?[^@\s]+)@[^"]*"?:`)
var yarnVersionRegex = regexp.MustCompile(`^\s+version\s+"?([^"\s]+)"?`)

func (p *YarnLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var packages []models.Package
	scanner := bufio.NewScanner(r)
	// Increase buffer size for large lock files
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var currentName string

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Check for package entry
		if matches := yarnEntryRegex.FindStringSubmatch(line); len(matches) >= 2 {
			currentName = matches[1]
			continue
		}

		// Check for version line
		if currentName != "" {
			if matches := yarnVersionRegex.FindStringSubmatch(line); len(matches) >= 2 {
				packages = append(packages, models.Package{
					Name:      currentName,
					Version:   matches[1],
					Ecosystem: models.EcosystemNpm,
					FilePath:  filePath,
				})
				currentName = ""
			}
		}
	}

	return packages, scanner.Err()
}

// PnpmLockParser parses pnpm-lock.yaml files.
type PnpmLockParser struct{}

type pnpmLockfile struct {
	Packages map[string]interface{} `yaml:"packages"`
}

// pnpmKeyRegex matches keys like: /express@4.18.2 or express@4.18.2
var pnpmKeyRegex = regexp.MustCompile(`/?([^@\s]+)@(.+)`)

func (p *PnpmLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var packages []models.Package
	for key := range lock.Packages {
		matches := pnpmKeyRegex.FindStringSubmatch(key)
		if len(matches) >= 3 {
			packages = append(packages, models.Package{
				Name:      matches[1],
				Version:   matches[2],
				Ecosystem: models.EcosystemNpm,
				FilePath:  filePath,
			})
		}
	}

	return packages, nil
}
