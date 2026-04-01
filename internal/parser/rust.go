package parser

import (
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
	cargoNameRe     = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	cargoVersionRe  = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
	cargoDepsRe     = regexp.MustCompile(`^dependencies\s*=`)
	cargoChecksumRe = regexp.MustCompile(`^checksum\s*=\s*"([^"]+)"`)
)

func (p *CargoLockParser) Parse(r io.Reader, filePath string) ([]models.Package, error) {
	// Two-pass approach:
	// Pass 1 — collect all packages and their dependency lists.
	type cargoPkg struct {
		name     string
		version  string
		checksum string
		deps     []string // dependency names
	}
	var pkgs []cargoPkg
	var name, version, checksum string
	var deps []string
	inPackage := false
	inDeps := false

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)

		if line == "[[package]]" {
			if inPackage && name != "" && version != "" {
				pkgs = append(pkgs, cargoPkg{name: name, version: version, checksum: checksum, deps: deps})
			}
			name, version, checksum = "", "", ""
			deps = nil
			inPackage = true
			inDeps = false
			continue
		}

		if !inPackage {
			continue
		}

		if m := cargoNameRe.FindStringSubmatch(line); len(m) == 2 {
			name = m[1]
			inDeps = false
		} else if m := cargoVersionRe.FindStringSubmatch(line); len(m) == 2 {
			version = m[1]
			inDeps = false
		} else if m := cargoChecksumRe.FindStringSubmatch(line); len(m) == 2 {
			checksum = m[1]
			inDeps = false
		} else if cargoDepsRe.MatchString(line) {
			inDeps = true
		} else if inDeps {
			// Parse dependency entries like: "serde 1.0.0",
			trimmed := strings.Trim(line, " \t\",[]")
			if trimmed != "" && trimmed != "]" {
				parts := strings.Fields(trimmed)
				if len(parts) >= 1 {
					deps = append(deps, parts[0])
				}
			}
			if strings.Contains(line, "]") {
				inDeps = false
			}
		}
	}
	if inPackage && name != "" && version != "" {
		pkgs = append(pkgs, cargoPkg{name: name, version: version, checksum: checksum, deps: deps})
	}

	// Pass 2 — figure out which packages are direct (depended on by the first/root package)
	// and which are transitive.
	directNames := make(map[string]bool)
	if len(pkgs) > 0 {
		// The root package is typically the first [[package]] entry.
		for _, d := range pkgs[0].deps {
			directNames[d] = true
		}
	}

	var packages []models.Package
	for i, p := range pkgs {
		if i == 0 {
			continue // skip the root package itself
		}
		integ := ""
		if p.checksum != "" {
			integ = "sha256-" + p.checksum
		}
		packages = append(packages, models.Package{
			Name:      p.name,
			Version:   p.version,
			Ecosystem: models.EcosystemCrates,
			FilePath:  filePath,
			Indirect:  !directNames[p.name],
			Integrity: integ,
		})
	}

	return packages, nil
}
