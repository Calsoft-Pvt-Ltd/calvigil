package analyzer

import (
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
