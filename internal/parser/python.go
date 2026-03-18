package parser

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// RequirementsTxtParser parses Python requirements.txt files.
type RequirementsTxtParser struct{}

func init() {
	Register("requirements.txt", func() Parser { return &RequirementsTxtParser{} })
	Register("Pipfile.lock", func() Parser { return &PipfileLockParser{} })
	Register("poetry.lock", func() Parser { return &PoetryLockParser{} })
	Register("uv.lock", func() Parser { return &PoetryLockParser{} })
}

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

// pyprojectDepRe matches dependency lines like: requests = "^2.28" or flask = {version = "..."}
var pyprojectDepRe = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*=`)

// readPyprojectDirectDeps reads pyproject.toml from dir and returns normalized direct dependency names.
func readPyprojectDirectDeps(dir string) map[string]bool {
	names := make(map[string]bool)
	f, err := os.Open(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return names
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inDeps := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Detect relevant sections
		if strings.HasPrefix(trimmed, "[") {
			lower := strings.ToLower(trimmed)
			inDeps = lower == "[tool.poetry.dependencies]" ||
				lower == "[tool.poetry.dev-dependencies]" ||
				lower == "[project.dependencies]" ||
				lower == "[project]"
			// [project] section has "dependencies = [...]" list syntax
			continue
		}

		if !inDeps {
			continue
		}

		// PEP 621 list syntax: dependencies = ["requests>=2.28", ...]
		if strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "[") {
			// Parse inline list items
			for _, item := range extractBracketItems(trimmed) {
				names[normalizePyName(item)] = true
			}
			// Handle multi-line list
			if !strings.Contains(trimmed, "]") {
				for scanner.Scan() {
					inner := strings.TrimSpace(scanner.Text())
					if inner == "]" || strings.HasSuffix(inner, "]") {
						for _, item := range extractBracketItems(inner) {
							names[normalizePyName(item)] = true
						}
						break
					}
					names[normalizePyName(inner)] = true
				}
			}
			continue
		}

		// Poetry TOML key = value style
		if m := pyprojectDepRe.FindStringSubmatch(trimmed); len(m) == 2 {
			name := strings.ToLower(m[1])
			if name != "python" {
				names[name] = true
			}
		}
	}
	return names
}

// extractBracketItems parses items from a TOML/PEP 621 bracket list line.
func extractBracketItems(line string) []string {
	start := strings.Index(line, "[")
	end := strings.Index(line, "]")
	if start < 0 {
		start = 0
	}
	if end < 0 {
		end = len(line)
	}
	inner := line[start+1 : end]
	var items []string
	for _, part := range strings.Split(inner, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"' ")
		if part != "" {
			items = append(items, part)
		}
	}
	return items
}

// normalizePyName extracts the package name from a PEP 508 requirement string and normalizes it.
func normalizePyName(s string) string {
	s = strings.Trim(s, "\"', ")
	// Split on version specifiers
	for _, sep := range []string{">=", "<=", "!=", "~=", "==", ">", "<", ";"} {
		if idx := strings.Index(s, sep); idx > 0 {
			s = s[:idx]
		}
	}
	// Split on extras bracket
	if idx := strings.Index(s, "["); idx > 0 {
		s = s[:idx]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func (p *PoetryLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Read companion pyproject.toml for direct dependency identification.
	directNames := readPyprojectDirectDeps(filepath.Dir(filePath))
	hasDirect := len(directNames) > 0

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
					Indirect:  hasDirect && !directNames[strings.ToLower(currentName)],
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
			Indirect:  hasDirect && !directNames[strings.ToLower(currentName)],
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
