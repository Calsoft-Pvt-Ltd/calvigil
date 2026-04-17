// Package fsutil provides filesystem helpers shared across scanners.
package fsutil

// SkippedSubDirs is the canonical list of directory names that scanners
// skip when encountered as a subdirectory of the scan root. Scanners MUST
// NOT apply these rules to the root of the scan itself — users who
// explicitly point calvigil at one of these directories (for example, an
// integration test pointing at its own ./testdata) should still have it
// scanned.
//
// The list combines conventions from Go (testdata), package managers
// (node_modules, vendor, target, __pycache__), VCS (.git), and common
// build/IDE output.
var SkippedSubDirs = map[string]struct{}{
	// Go convention: `go test` ignores directories named "testdata". We
	// follow the same rule so `calvigil scan .` from a repo root does not
	// flag vulnerabilities in deliberately-vulnerable test fixtures.
	"testdata":      {},
	"test-fixtures": {},

	// Package managers / language ecosystems.
	"node_modules":      {},
	"vendor":            {},
	"target":            {},
	"__pycache__":       {},
	"site-packages":     {},
	".venv":             {},
	"venv":              {},
	".env":              {},
	"env":               {},
	".bundle":           {},
	".cargo":            {},
	".terraform":        {},
	".terragrunt-cache": {},
	".serverless":       {},

	// VCS / IDE.
	".git":    {},
	".idea":   {},
	".vscode": {},

	// Build / cache / output directories.
	"build":         {},
	"dist":          {},
	"out":           {},
	"bin":           {},
	"obj":           {},
	".next":         {},
	".nuxt":         {},
	".cache":        {},
	".tox":          {},
	".nox":          {},
	".mypy_cache":   {},
	".pytest_cache": {},
}

// ShouldSkipSubDir reports whether a directory with the given basename
// should be skipped by a scanner walking beneath the scan root.
//
// Callers are responsible for ensuring they do not apply this check to
// the root path itself. The typical usage is:
//
//	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
//	    if err != nil { return nil }
//	    if info.IsDir() && path != root && fsutil.ShouldSkipSubDir(info.Name()) {
//	        return filepath.SkipDir
//	    }
//	    ...
//	})
func ShouldSkipSubDir(name string) bool {
	_, ok := SkippedSubDirs[name]
	return ok
}
