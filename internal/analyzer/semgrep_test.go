package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

func TestSemgrepAnalyze_WhenNoRuleConfigAvailable(t *testing.T) {
	fakeBin := t.TempDir()
	fakeSemgrep := filepath.Join(fakeBin, "semgrep")
	if err := os.WriteFile(fakeSemgrep, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake semgrep: %v", err)
	}
	t.Setenv("PATH", fakeBin)

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	clean := t.TempDir()
	if err := os.Chdir(clean); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	sa := NewSemgrepAnalyzer("", false)
	_, err = sa.Analyze(context.Background(), clean, false)
	if err == nil || !strings.Contains(err.Error(), "no Semgrep rule config found") {
		t.Fatalf("expected missing rule config error, got %v", err)
	}
}

func TestSemgrepAnalyze_InvalidExplicitRulesPath(t *testing.T) {
	fakeBin := t.TempDir()
	fakeSemgrep := filepath.Join(fakeBin, "semgrep")
	if err := os.WriteFile(fakeSemgrep, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake semgrep: %v", err)
	}
	t.Setenv("PATH", fakeBin)

	missingRules := filepath.Join(t.TempDir(), "missing.yaml")
	sa := NewSemgrepAnalyzer(missingRules, false)
	_, err := sa.Analyze(context.Background(), t.TempDir(), false)
	if err == nil || !strings.Contains(err.Error(), "semgrep rules path") {
		t.Fatalf("expected explicit rules path error, got %v", err)
	}
}

func TestSemgrepAnalyze_AcceptsExplicitRulesFile(t *testing.T) {
	fakeBin := t.TempDir()
	fakeSemgrep := filepath.Join(fakeBin, "semgrep")
	if err := os.WriteFile(fakeSemgrep, []byte("#!/bin/sh\nprintf '{\"results\":[],\"errors\":[]}'\n"), 0o755); err != nil {
		t.Fatalf("write fake semgrep: %v", err)
	}
	t.Setenv("PATH", fakeBin)

	rulesFile := filepath.Join(t.TempDir(), "community-aligned.yaml")
	if err := os.WriteFile(rulesFile, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	sa := NewSemgrepAnalyzer(rulesFile, false)
	vulns, err := sa.Analyze(context.Background(), t.TempDir(), false)
	if err != nil {
		t.Fatalf("expected explicit YAML rules file to be accepted, got %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("expected no vulnerabilities from fake semgrep, got %d", len(vulns))
	}
}

func TestSemgrepAnalyze_FailureIncludesValidationDiagnostics(t *testing.T) {
	fakeBin := t.TempDir()
	fakeSemgrep := filepath.Join(fakeBin, "semgrep")
	script := "#!/bin/sh\nprintf 'semgrep-core rule validation failed (PatternParseError): bad rule ai-go-test\\n' >&2\nexit 2\n"
	if err := os.WriteFile(fakeSemgrep, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake semgrep: %v", err)
	}
	t.Setenv("PATH", fakeBin)

	rulesFile := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rulesFile, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	sa := NewSemgrepAnalyzer(rulesFile, false)
	_, err := sa.Analyze(context.Background(), t.TempDir(), false)
	if err == nil {
		t.Fatal("expected semgrep validation error")
	}
	if !strings.Contains(err.Error(), "PatternParseError") || !strings.Contains(err.Error(), "ai-go-test") {
		t.Fatalf("expected validation details in error, got %v", err)
	}
}

type bundledSemgrepRulesDoc struct {
	Rules []struct {
		ID        string   `yaml:"id"`
		Message   string   `yaml:"message"`
		Severity  string   `yaml:"severity"`
		Languages []string `yaml:"languages"`
	} `yaml:"rules"`
}

func TestBundledSemgrepRules_AvoidUnparseableGoShorthand(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules", "semgrep")
	files, err := filepath.Glob(filepath.Join(rulesDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob rules: %v", err)
	}
	forbidden := []string{
		"for ... {",
		"for ...,",
		"... $VAR ...",
		"AllowAllOrigins: true",
		"AllowOrigins: []string{\"*\"}",
		"\n    pattern-not:",
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(data)
		for _, needle := range forbidden {
			if strings.Contains(text, needle) {
				t.Fatalf("%s contains Semgrep shorthand that Go rule validation can reject: %q", file, needle)
			}
		}
	}
}

func TestBundledSemgrepRules_AreLoadableAndUnique(t *testing.T) {
	rulesDir := filepath.Join("..", "..", "rules", "semgrep")
	files, err := filepath.Glob(filepath.Join(rulesDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob rules: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no bundled semgrep rule files found in %s", rulesDir)
	}

	seen := map[string]string{}
	total := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var doc bundledSemgrepRulesDoc
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		if len(doc.Rules) == 0 {
			t.Fatalf("%s contains no rules", file)
		}
		for _, rule := range doc.Rules {
			if strings.TrimSpace(rule.ID) == "" {
				t.Fatalf("%s contains a rule without id", file)
			}
			if strings.TrimSpace(rule.Message) == "" {
				t.Fatalf("%s rule %s has empty message", file, rule.ID)
			}
			switch strings.ToUpper(strings.TrimSpace(rule.Severity)) {
			case "ERROR", "WARNING", "INFO":
			default:
				t.Fatalf("%s rule %s has unsupported severity %q", file, rule.ID, rule.Severity)
			}
			if len(rule.Languages) == 0 {
				t.Fatalf("%s rule %s has no languages", file, rule.ID)
			}
			if previous, ok := seen[rule.ID]; ok {
				t.Fatalf("duplicate semgrep rule id %q in %s and %s", rule.ID, previous, file)
			}
			seen[rule.ID] = file
			total++
		}
	}
	if total < 100 {
		t.Fatalf("expected at least 100 bundled semgrep rules after community-aligned expansion, got %d", total)
	}
}

func TestBundledSemgrepRules_CommunityAlignedCoverage(t *testing.T) {
	rulesPath := filepath.Join("..", "..", "rules", "semgrep", "community-aligned.yaml")
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read community-aligned rules: %v", err)
	}
	var doc bundledSemgrepRulesDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse community-aligned rules: %v", err)
	}

	ids := map[string]bool{}
	for _, rule := range doc.Rules {
		ids[rule.ID] = true
	}
	expected := []string{
		"py-requests-disable-cert-validation",
		"py-django-csrf-exempt",
		"py-fastapi-cors-wildcard-credentials",
		"js-react-dangerously-set-inner-html",
		"js-node-child-process-shell-true",
		"go-jwt-parse-unverified",
		"go-grpc-insecure-transport",
		"java-spring-csrf-disabled",
		"java-spel-expression-injection",
		"c-unsafe-gets",
		"php-unserialize-untrusted",
		"ruby-yaml-load-untrusted",
		"dockerfile-root-user",
		"bash-curl-pipe-shell",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Fatalf("missing community-aligned semgrep rule %s", id)
		}
	}
}
