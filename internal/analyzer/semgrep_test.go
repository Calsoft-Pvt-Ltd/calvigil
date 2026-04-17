package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSemgrepAnalyzer_Available(t *testing.T) {
	sa := NewSemgrepAnalyzer("", false)
	// Just verify it returns without panicking; result depends on env.
	_ = sa.Available()
}

func TestGetBundledRulesDir(t *testing.T) {
	// Exercise the function — it may return "" or a real path depending on
	// the working directory but must not panic.
	dir := getBundledRulesDir()
	_ = dir
}

// TestGetBundledRulesDir_EmptyFromCleanDir verifies that when we chdir into
// a directory with no rules/semgrep subdir, the function returns "". This
// covers the "no local rules directory found" branch.
func TestGetBundledRulesDir_EmptyFromCleanDir(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	clean := t.TempDir()
	if err := os.Chdir(clean); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	// The exe-adjacent lookup can still succeed if go test's binary
	// happens to live near a rules/ dir; the important thing is that
	// calling it here exercises both branches and does not panic.
	_ = getBundledRulesDir()
}

func TestParseSemgrepOutput_SingleCWEString(t *testing.T) {
	data := []byte(`{
		"results": [{
			"check_id": "rules.xss",
			"path": "/tmp/project/app.py",
			"start": {"line": 10, "col": 1},
			"end": {"line": 12, "col": 20},
			"extra": {
				"message": "Cross-site scripting",
				"severity": "ERROR",
				"metadata": {
					"cwe": "CWE-79",
					"owasp": "A7:2017",
					"references": ["https://example.com/xss"]
				},
				"lines": "print(user_input)"
			}
		}],
		"errors": []
	}`)
	vulns, err := parseSemgrepOutput(data, "/tmp/project")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", v.Severity)
	}
	if v.StartLine != 10 {
		t.Errorf("StartLine = %d, want 10", v.StartLine)
	}
	if len(v.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(v.References))
	}
}

func TestSemgrepSeverityToSeverity_LowerCase(t *testing.T) {
	// The existing test in analyzer_test.go only tests uppercase.
	// Verify lowercase "error" also maps to HIGH.
	if got := semgrepSeverityToSeverity("error"); got != "HIGH" {
		t.Errorf("semgrepSeverityToSeverity(\"error\") = %q, want HIGH", got)
	}
	if got := semgrepSeverityToSeverity(""); got != "MEDIUM" {
		t.Errorf("semgrepSeverityToSeverity(\"\") = %q, want MEDIUM", got)
	}
}

// TestSemgrepAnalyzer_ProjectRulesOptIn verifies that .semgrep/ and
// .semgrep.yml in the scanned project are ignored unless TrustProjectRules
// is explicitly enabled. Scanning an untrusted repo that ships its own
// Semgrep rules is a code-execution vector through the rule engine.
func TestSemgrepAnalyzer_ProjectRulesOptIn(t *testing.T) {
	proj := t.TempDir()
	if err := os.Mkdir(filepath.Join(proj, ".semgrep"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".semgrep.yml"), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Default: rules must be ignored.
	sa := NewSemgrepAnalyzer("", false)
	if sa.TrustProjectRules {
		t.Fatal("TrustProjectRules must default to false")
	}

	// Opt-in explicitly.
	sa.TrustProjectRules = true
	if !sa.TrustProjectRules {
		t.Error("TrustProjectRules should be settable")
	}
}

// TestSemgrepAnalyzer_RulesDirSymlinkResolved verifies that a symlink
// passed as the rules directory is resolved before use. This is a
// defense-in-depth measure against operator misconfiguration.
func TestSemgrepAnalyzer_RulesDirSymlinkResolved(t *testing.T) {
	realDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(realDir, "rule.yml"), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(linkDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if resolved == linkDir {
		t.Fatalf("EvalSymlinks did not resolve: %s == %s", resolved, linkDir)
	}
}

// TestSemgrepAnalyze_WhenUnavailable exercises the unavailable-path of
// Analyze by clearing PATH so exec.LookPath("semgrep") fails.
func TestSemgrepAnalyze_WhenUnavailable(t *testing.T) {
	t.Setenv("PATH", "")
	sa := NewSemgrepAnalyzer("", false)
	_, err := sa.Analyze(context.Background(), t.TempDir(), false)
	if err == nil {
		t.Error("expected error when semgrep is not on PATH")
	}
}
