package parser

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"gopkg.in/yaml.v3"
)

// NpmLockParser parses package-lock.json files (v2 and v3 format).
type NpmLockParser struct{}

func init() {
	Register("package-lock.json", func() Parser { return &NpmLockParser{} })
	Register("yarn.lock", func() Parser { return &YarnLockParser{} })
	Register("pnpm-lock.yaml", func() Parser { return &PnpmLockParser{} })
}

type npmLockfile struct {
	Packages     map[string]npmPackage `json:"packages"`
	Dependencies map[string]npmDep     `json:"dependencies"` // v1 format
}

type npmPackage struct {
	Version string      `json:"version"`
	Dev     bool        `json:"dev"`
	License interface{} `json:"license"` // Can be string or {"type":"MIT"}
}

type npmDep struct {
	Version      string            `json:"version"`
	Requires     map[string]string `json:"requires"`
	Dependencies map[string]npmDep `json:"dependencies"` // nested = transitive
}

func (p *NpmLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	var lock npmLockfile
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	// v2/v3: use "packages" (flat map, path nesting depth determines direct vs transitive)
	if len(lock.Packages) > 0 {
		// Collect top-level direct dependency names from root package's deps
		directNames := make(map[string]bool)
		if root, ok := lock.Packages[""]; ok {
			// The root entry doesn't expose a deps list in the flat format,
			// so top-level is identified by path depth: "node_modules/name" (one level).
			_ = root
		}

		var packages []models.Package
		for path, pkg := range lock.Packages {
			if path == "" {
				continue
			}
			name := path
			if idx := strings.LastIndex(path, "node_modules/"); idx != -1 {
				name = path[idx+len("node_modules/"):]
			}
			if pkg.Version == "" {
				continue
			}

			// Direct deps live at "node_modules/<name>" (exactly one level).
			// Transitive deps are nested: "node_modules/a/node_modules/b"
			nmCount := strings.Count(path, "node_modules/")
			indirect := nmCount > 1

			// Track direct names for reference
			if !indirect {
				directNames[name] = true
			}

			packages = append(packages, models.Package{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: models.EcosystemNpm,
				FilePath:  filePath,
				Indirect:  indirect,
				License:   extractNpmLicense(pkg.License),
			})
		}
		return packages, nil
	}

	// v1 fallback: use "dependencies" (nested tree structure)
	var packages []models.Package
	var walkDeps func(deps map[string]npmDep, indirect bool)
	walkDeps = func(deps map[string]npmDep, indirect bool) {
		for name, dep := range deps {
			if dep.Version == "" {
				continue
			}
			packages = append(packages, models.Package{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: models.EcosystemNpm,
				FilePath:  filePath,
				Indirect:  indirect,
			})
			if dep.Dependencies != nil {
				walkDeps(dep.Dependencies, true)
			}
		}
	}
	walkDeps(lock.Dependencies, false)

	return packages, nil
}

// extractNpmLicense extracts a license string from the npm "license" field,
// which can be a string or an object like {"type": "MIT"}.
func extractNpmLicense(v interface{}) string {
	switch lic := v.(type) {
	case string:
		return lic
	case map[string]interface{}:
		if t, ok := lic["type"].(string); ok {
			return t
		}
	}
	return ""
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
