package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// CheckConsistency compares parsed lockfile packages against their
// corresponding manifest files to detect phantom dependencies —
// packages present in a lockfile but not declared (directly or
// transitively) in the manifest.
//
// Currently supports:
//   - npm: package-lock.json direct deps vs package.json dependencies/devDependencies
func CheckConsistency(projectPath string, packages []models.Package) []models.ConsistencyIssue {
	var issues []models.ConsistencyIssue

	// Group direct (non-transitive) packages by lockfile
	lockDeps := make(map[string][]models.Package) // filePath -> direct packages
	for _, pkg := range packages {
		if pkg.Indirect {
			continue
		}
		lockDeps[pkg.FilePath] = append(lockDeps[pkg.FilePath], pkg)
	}

	for lockFile, directPkgs := range lockDeps {
		manifest := manifestForLockfile(lockFile)
		if manifest == "" {
			continue
		}

		declared := readManifestDeps(manifest)
		if declared == nil {
			continue // can't read manifest — skip
		}

		for _, pkg := range directPkgs {
			if !declared[pkg.Name] {
				issues = append(issues, models.ConsistencyIssue{
					Package:  pkg,
					LockFile: lockFile,
					Manifest: manifest,
					Reason:   "package in lockfile but not declared in manifest",
				})
			}
		}
	}

	return issues
}

// manifestForLockfile returns the path to the manifest file
// corresponding to a given lockfile, or "" if unknown.
func manifestForLockfile(lockFile string) string {
	dir := filepath.Dir(lockFile)
	base := filepath.Base(lockFile)

	switch base {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		return filepath.Join(dir, "package.json")
	default:
		return ""
	}
}

// readManifestDeps reads the declared dependency names from a manifest file.
// Returns nil if the file can't be read or parsed.
func readManifestDeps(manifestPath string) map[string]bool {
	base := filepath.Base(manifestPath)
	switch base {
	case "package.json":
		return readPackageJSONDeps(manifestPath)
	default:
		return nil
	}
}

// packageJSON is a minimal representation for dependency extraction.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func readPackageJSONDeps(path string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	names := make(map[string]bool)
	for name := range pkg.Dependencies {
		names[strings.TrimSpace(name)] = true
	}
	for name := range pkg.DevDependencies {
		names[strings.TrimSpace(name)] = true
	}
	for name := range pkg.PeerDependencies {
		names[strings.TrimSpace(name)] = true
	}
	for name := range pkg.OptionalDependencies {
		names[strings.TrimSpace(name)] = true
	}

	return names
}
