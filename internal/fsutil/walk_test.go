package fsutil

import "testing"

func TestShouldSkipSubDir(t *testing.T) {
	skip := []string{
		"testdata", "test-fixtures", "node_modules", "vendor", "target",
		"__pycache__", "site-packages", ".venv", "venv", ".env", "env",
		".bundle", ".cargo", ".terraform", ".terragrunt-cache", ".serverless",
		".git", ".idea", ".vscode",
		"build", "dist", "out", "bin", "obj",
		".next", ".nuxt", ".cache",
		".tox", ".nox", ".mypy_cache", ".pytest_cache",
	}
	for _, name := range skip {
		if !ShouldSkipSubDir(name) {
			t.Errorf("ShouldSkipSubDir(%q) = false, want true", name)
		}
	}

	keep := []string{"src", "internal", "cmd", "pkg", "tests", "lib", "", "Testdata", "TESTDATA"}
	for _, name := range keep {
		if ShouldSkipSubDir(name) {
			t.Errorf("ShouldSkipSubDir(%q) = true, want false", name)
		}
	}
}
