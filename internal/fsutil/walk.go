// Package fsutil provides filesystem helpers shared across scanners.
package fsutil

import (
	"path/filepath"
	"strings"
)

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

// IsTestFile reports whether the given file path looks like a test file based
// on common naming conventions across ecosystems.
//
//   - Go: *_test.go
//   - Python: test_*.py, *_test.py, conftest.py
//   - JavaScript/TypeScript: *.test.{js,ts,jsx,tsx}, *.spec.{js,ts,jsx,tsx}
//   - Java: *Test.java, *Tests.java, *IT.java
//   - Rust: tests in a mod tests block are in the same file (can't skip), but
//     files under a tests/ dir are caught by IsTestDir.
func IsTestFile(path string) bool {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	nameNoExt := base[:len(base)-len(ext)]

	switch ext {
	case ".go":
		return strings.HasSuffix(nameNoExt, "_test")
	case ".py":
		return strings.HasPrefix(nameNoExt, "test_") ||
			strings.HasSuffix(nameNoExt, "_test") ||
			nameNoExt == "conftest"
	case ".js", ".ts", ".jsx", ".tsx", ".mjs":
		return strings.HasSuffix(nameNoExt, ".test") ||
			strings.HasSuffix(nameNoExt, ".spec") ||
			strings.HasSuffix(nameNoExt, "_test") ||
			strings.HasSuffix(nameNoExt, "_spec")
	case ".java":
		return strings.HasSuffix(nameNoExt, "Test") ||
			strings.HasSuffix(nameNoExt, "Tests") ||
			strings.HasSuffix(nameNoExt, "IT")
	case ".rs":
		return nameNoExt == "tests" || strings.HasSuffix(nameNoExt, "_test")
	case ".rb":
		return strings.HasSuffix(nameNoExt, "_test") ||
			strings.HasSuffix(nameNoExt, "_spec")
	case ".php":
		return strings.HasSuffix(nameNoExt, "Test")
	}
	return false
}

// IsTestDir reports whether the given directory name is a common test directory.
func IsTestDir(name string) bool {
	switch strings.ToLower(name) {
	case "test", "tests", "__tests__", "__test__",
		"spec", "specs", "test_data", "testing",
		"fixtures", "mocks", "__mocks__":
		return true
	}
	return false
}
