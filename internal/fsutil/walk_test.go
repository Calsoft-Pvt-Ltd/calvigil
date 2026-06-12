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

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Go
		{"foo_test.go", true},
		{"handler_test.go", true},
		{"main.go", false},
		{"testutils.go", false},
		// Python
		{"test_handler.py", true},
		{"handler_test.py", true},
		{"conftest.py", true},
		{"handler.py", false},
		{"testing.py", false},
		// JavaScript / TypeScript
		{"app.test.js", true},
		{"app.spec.js", true},
		{"app_test.js", true},
		{"app_spec.ts", true},
		{"component.test.tsx", true},
		{"component.spec.tsx", true},
		{"app.js", false},
		{"testHelper.js", false},
		// Java
		{"UserTest.java", true},
		{"UserTests.java", true},
		{"UserIT.java", true},
		{"User.java", false},
		{"Testing.java", false},
		// Rust
		{"tests.rs", true},
		{"handler_test.rs", true},
		{"handler.rs", false},
		// Ruby
		{"handler_test.rb", true},
		{"handler_spec.rb", true},
		{"handler.rb", false},
		// PHP
		{"UserTest.php", true},
		{"User.php", false},
	}
	for _, tt := range tests {
		if got := IsTestFile(tt.path); got != tt.want {
			t.Errorf("IsTestFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsTestDir(t *testing.T) {
	dirs := []struct {
		name string
		want bool
	}{
		{"test", true},
		{"tests", true},
		{"Test", true},
		{"Tests", true},
		{"__tests__", true},
		{"__test__", true},
		{"spec", true},
		{"specs", true},
		{"test_data", true},
		{"testing", true},
		{"fixtures", true},
		{"mocks", true},
		{"__mocks__", true},
		// Should NOT match
		{"src", false},
		{"internal", false},
		{"cmd", false},
		{"testdata", false}, // handled by ShouldSkipSubDir
		{"test-fixtures", false},
	}
	for _, tt := range dirs {
		if got := IsTestDir(tt.name); got != tt.want {
			t.Errorf("IsTestDir(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
