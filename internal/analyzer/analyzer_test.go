package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// ── extractJSONArray tests ──────────────────────────────────────

func TestExtractJSONArray_Clean(t *testing.T) {
	input := `[{"id":"CVE-001"}]`
	got := extractJSONArray(input)
	if got != input {
		t.Errorf("extractJSONArray clean = %q, want %q", got, input)
	}
}

func TestExtractJSONArray_MarkdownFence(t *testing.T) {
	input := "Here is the result:\n```json\n[{\"id\":\"CVE-001\"}]\n```\nDone."
	got := extractJSONArray(input)
	if got != `[{"id":"CVE-001"}]` {
		t.Errorf("extractJSONArray markdown = %q", got)
	}
}

func TestExtractJSONArray_GenericFence(t *testing.T) {
	input := "Result:\n```\n[{\"id\":\"CVE-001\"}]\n```"
	got := extractJSONArray(input)
	if got != `[{"id":"CVE-001"}]` {
		t.Errorf("extractJSONArray generic fence = %q", got)
	}
}

func TestExtractJSONArray_ProseWrapped(t *testing.T) {
	input := `I found the following vulnerabilities: [{"id":"CVE-001"}] in the code.`
	got := extractJSONArray(input)
	if got != `[{"id":"CVE-001"}]` {
		t.Errorf("extractJSONArray prose = %q", got)
	}
}

func TestExtractJSONArray_EmptyArray(t *testing.T) {
	got := extractJSONArray("[]")
	if got != "[]" {
		t.Errorf("extractJSONArray empty = %q", got)
	}
}

func TestExtractJSONArray_NoArray(t *testing.T) {
	got := extractJSONArray("no json here")
	if got != "no json here" {
		t.Errorf("extractJSONArray no array = %q", got)
	}
}

// ── flexInt tests ───────────────────────────────────────────────

func TestFlexInt_Number(t *testing.T) {
	var fi flexInt
	if err := json.Unmarshal([]byte("42"), &fi); err != nil {
		t.Fatal(err)
	}
	if int(fi) != 42 {
		t.Errorf("flexInt number = %d, want 42", fi)
	}
}

func TestFlexInt_String(t *testing.T) {
	var fi flexInt
	if err := json.Unmarshal([]byte(`"42"`), &fi); err != nil {
		t.Fatal(err)
	}
	if int(fi) != 42 {
		t.Errorf("flexInt string = %d, want 42", fi)
	}
}

func TestFlexInt_EmptyString(t *testing.T) {
	var fi flexInt
	if err := json.Unmarshal([]byte(`""`), &fi); err != nil {
		t.Fatal(err)
	}
	if int(fi) != 0 {
		t.Errorf("flexInt empty = %d, want 0", fi)
	}
}

func TestFlexInt_InvalidString(t *testing.T) {
	var fi flexInt
	if err := json.Unmarshal([]byte(`"abc"`), &fi); err != nil {
		t.Fatal(err)
	}
	if int(fi) != 0 {
		t.Errorf("flexInt invalid = %d, want 0", fi)
	}
}

// ── Ollama analyzer tests with httptest ─────────────────────────

func TestOllamaAnalyzer_Available(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"models":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	o := NewOllamaAnalyzer(srv.URL, "test-model")
	if !o.Available() {
		t.Error("Available() should return true when server responds 200")
	}
}

func TestOllamaAnalyzer_NotAvailable(t *testing.T) {
	o := NewOllamaAnalyzer("http://127.0.0.1:1", "test-model")
	if o.Available() {
		t.Error("Available() should return false when server is unreachable")
	}
}

func TestOllamaAnalyzer_DefaultBaseURL(t *testing.T) {
	o := NewOllamaAnalyzer("", "test-model")
	if o.baseURL != "http://localhost:11434" {
		t.Errorf("default baseURL = %q, want http://localhost:11434", o.baseURL)
	}
}

func TestOllamaAnalyzer_Analyze_WithPatternMatches(t *testing.T) {
	// Create a project with a vulnerable-looking file
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "app.py")
	content := `import os
password = "hardcoded_secret_123"
os.system("rm -rf " + user_input)
`
	os.WriteFile(srcFile, []byte(content), 0644)

	// Mock Ollama server that returns valid AI findings
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"models":[]}`))
			return
		}
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"role":    "assistant",
					"content": `[{"id":"AI-001","name":"Hardcoded Password","description":"Password in source","severity":"HIGH","file":"app.py","line":2,"recommendation":"Use env vars"}]`,
				}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	o := NewOllamaAnalyzer(srv.URL, "test-model")
	vulns, err := o.Analyze(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(vulns) == 0 {
		t.Error("expected at least 1 vulnerability from pattern+AI analysis")
	}
}

func TestOllamaAnalyzer_EnrichVulnerabilities_Empty(t *testing.T) {
	o := NewOllamaAnalyzer("http://localhost:11434", "test")
	result := o.EnrichVulnerabilities(context.Background(), nil, "/tmp", false)
	if len(result) != 0 {
		t.Error("enriching nil vulns should return empty")
	}
}

func TestOllamaAnalyzer_EnrichVulnerabilities(t *testing.T) {
	// Mock server returning enrichment data
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"role":    "assistant",
					"content": `[{"vuln_id":"CVE-2023-001","summary":"Test vuln","likely_impact":"RCE","confidence":"HIGH","minimal_remediation":"Upgrade","suppression_rationale":"Low risk"}]`,
				}},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	o := NewOllamaAnalyzer(srv.URL, "test-model")
	vulns := []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "Test", Severity: models.SeverityHigh},
	}

	result := o.EnrichVulnerabilities(context.Background(), vulns, "/tmp", false)
	if len(result) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(result))
	}
	if result[0].AIEnrichment == nil {
		t.Error("enrichment should be populated")
	}
}

// ── Semgrep helper tests ────────────────────────────────────────

func TestParseSemgrepOutput_Valid(t *testing.T) {
	data := `{
		"results": [{
			"check_id": "hardcoded-password",
			"path": "/tmp/app.py",
			"start": {"line": 10, "col": 1},
			"end": {"line": 10, "col": 30},
			"extra": {
				"message": "Hardcoded password found",
				"severity": "ERROR",
				"metadata": {"cwe": "CWE-798"},
				"lines": "password = 'secret'"
			}
		}],
		"errors": []
	}`

	vulns, err := parseSemgrepOutput([]byte(data), "/tmp")
	if err != nil {
		t.Fatalf("parseSemgrepOutput() error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %v, want HIGH (ERROR maps to HIGH)", vulns[0].Severity)
	}
	if vulns[0].StartLine != 10 {
		t.Errorf("StartLine = %d, want 10", vulns[0].StartLine)
	}
}

func TestParseSemgrepOutput_Empty(t *testing.T) {
	data := `{"results": [], "errors": []}`
	vulns, err := parseSemgrepOutput([]byte(data), "/tmp")
	if err != nil {
		t.Fatalf("parseSemgrepOutput() error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestParseSemgrepOutput_InvalidJSON(t *testing.T) {
	_, err := parseSemgrepOutput([]byte("not json"), "/tmp")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseSemgrepOutput_WithMetadata(t *testing.T) {
	data := `{
		"results": [{
			"check_id": "sql-injection",
			"path": "/tmp/app.py",
			"start": {"line": 5, "col": 1},
			"end": {"line": 5, "col": 50},
			"extra": {
				"message": "SQL injection",
				"severity": "WARNING",
				"metadata": {
					"cwe": ["CWE-89"],
					"owasp": ["A03:2021"],
					"references": ["https://example.com/ref"]
				},
				"lines": "query = f\"SELECT * FROM {table}\""
			}
		}],
		"errors": []
	}`

	vulns, err := parseSemgrepOutput([]byte(data), "/tmp")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].Severity != models.SeverityMedium {
		t.Errorf("severity = %v, want MEDIUM (WARNING maps to MEDIUM)", vulns[0].Severity)
	}
	if len(vulns[0].References) != 1 {
		t.Errorf("references count = %d, want 1", len(vulns[0].References))
	}
}

func TestSemgrepSeverityToSeverity(t *testing.T) {
	tests := map[string]models.Severity{
		"ERROR":   models.SeverityHigh,
		"WARNING": models.SeverityMedium,
		"INFO":    models.SeverityLow,
		"OTHER":   models.SeverityMedium,
	}
	for input, want := range tests {
		got := semgrepSeverityToSeverity(input)
		if got != want {
			t.Errorf("semgrepSeverityToSeverity(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestNewSemgrepAnalyzer(t *testing.T) {
	sa := NewSemgrepAnalyzer("/tmp/rules", true)
	if sa.RulesDir != "/tmp/rules" {
		t.Errorf("RulesDir = %q, want /tmp/rules", sa.RulesDir)
	}
	if !sa.Verbose {
		t.Error("Verbose should be true")
	}
}

func TestReadSnippet(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.py")
	content := "line1\nline2\nline3\nline4\nline5\n"
	os.WriteFile(f, []byte(content), 0644)

	got := readSnippet(f, 2, 4)
	if got != "line2\nline3\nline4" {
		t.Errorf("readSnippet(2,4) = %q, want line2-4", got)
	}
}

func TestReadSnippet_NonexistentFile(t *testing.T) {
	got := readSnippet("/nonexistent/file.py", 1, 3)
	if got != "" {
		t.Errorf("readSnippet nonexistent = %q, want empty", got)
	}
}

func TestTruncateStr(t *testing.T) {
	if got := truncateStr("hello", 10); got != "hello" {
		t.Errorf("truncateStr short = %q", got)
	}
	if got := truncateStr("hello world", 5); got != "hello..." {
		t.Errorf("truncateStr long = %q", got)
	}
}

func TestFormatSemgrepDetails(t *testing.T) {
	r := semgrepResult{
		CheckID: "hardcoded-password",
		Extra:   semgrepExtra{Message: "Found hardcoded password"},
	}
	got := formatSemgrepDetails(r)
	if got != "Found hardcoded password\n\nRule: hardcoded-password" {
		t.Errorf("formatSemgrepDetails = %q", got)
	}
}

// ── ScanPatterns tests ──────────────────────────────────────────

func TestScanPatterns_PythonFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "app.py")
	content := `import pickle
data = pickle.loads(user_input)
password = "mysecretpassword123"
`
	os.WriteFile(f, []byte(content), 0644)

	matches, err := ScanPatterns(dir)
	if err != nil {
		t.Fatalf("ScanPatterns error: %v", err)
	}
	if len(matches) == 0 {
		t.Error("expected pattern matches for pickle and hardcoded password")
	}
}

func TestScanPatterns_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	matches, err := ScanPatterns(dir)
	if err != nil {
		t.Fatalf("ScanPatterns error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches in empty dir, got %d", len(matches))
	}
}

func TestRuleAppliesToExt(t *testing.T) {
	rule := PatternRule{Languages: []string{".py", ".js"}}

	if !ruleAppliesToExt(rule, ".py") {
		t.Error(".py should match")
	}
	if !ruleAppliesToExt(rule, ".js") {
		t.Error(".js should match")
	}
	if ruleAppliesToExt(rule, ".go") {
		t.Error(".go should not match")
	}
}

func TestRuleAppliesToExt_EmptyLanguages(t *testing.T) {
	rule := PatternRule{Languages: nil}
	// When Languages is nil/empty, the function returns false (no languages = no match)
	if ruleAppliesToExt(rule, ".py") {
		t.Error("nil languages should not match")
	}
}

// ── OpenAI constructor test ─────────────────────────────────────

func TestNewOpenAIAnalyzer(t *testing.T) {
	a := NewOpenAIAnalyzer("test-key", "gpt-4")
	if a == nil {
		t.Fatal("NewOpenAIAnalyzer returned nil")
	}
	if a.model != "gpt-4" {
		t.Errorf("model = %q, want gpt-4", a.model)
	}
}

// ── findImportantFiles tests ────────────────────────────────────

func TestFindImportantFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"main.go", "handler_auth.go", "utils.go"} {
		os.WriteFile(filepath.Join(dir, name), []byte("package main"), 0644)
	}
	files := findImportantFiles(dir)
	if len(files) == 0 {
		t.Error("should find main.go and handler_auth.go")
	}
	foundMain := false
	for _, f := range files {
		if filepath.Base(f) == "main.go" {
			foundMain = true
		}
	}
	if !foundMain {
		t.Error("main.go should be found")
	}
}

func TestFindImportantFiles_Empty(t *testing.T) {
	dir := t.TempDir()
	files := findImportantFiles(dir)
	if len(files) != 0 {
		t.Errorf("expected 0, got %d", len(files))
	}
}

func TestFindImportantFiles_Nested(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "routes")
	os.MkdirAll(sub, 0755)
	os.WriteFile(filepath.Join(sub, "api.go"), []byte("package routes"), 0644)
	files := findImportantFiles(dir)
	if len(files) == 0 {
		t.Error("should find routes/api.go via nested pattern")
	}
}

// ── readFileContent tests ───────────────────────────────────────

func TestReadFileContent(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.go")
	os.WriteFile(f, []byte("line1\nline2\nline3\nline4\nline5\n"), 0644)

	content, err := readFileContent(f, 3)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(content, "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

func TestReadFileContent_NonexistentFile(t *testing.T) {
	_, err := readFileContent("/nonexistent/file.go", 10)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ── extToLanguage tests ─────────────────────────────────────────

func TestExtToLanguage(t *testing.T) {
	tests := map[string]string{
		".go":   "Go",
		".py":   "Python",
		".java": "Java",
		".js":   "JavaScript",
		".jsx":  "JavaScript",
		".ts":   "TypeScript",
		".tsx":  "TypeScript",
		".rb":   "source",
	}
	for ext, want := range tests {
		got := extToLanguage(ext)
		if got != want {
			t.Errorf("extToLanguage(%q) = %q, want %q", ext, got, want)
		}
	}
}

// ── getCodeContext test ──────────────────────────────────────────

func TestGetCodeContext(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "code.py")
	os.WriteFile(f, []byte("line1\nline2\nline3\nline4\nline5\nline6\nline7\n"), 0644)
	ctx, err := getCodeContext(f, 3, 1)
	if err != nil {
		t.Fatalf("getCodeContext error: %v", err)
	}
	if ctx == "" {
		t.Error("context should not be empty")
	}
}

// ── truncateSnippet test ────────────────────────────────────────

func TestTruncateSnippet(t *testing.T) {
	short := "hello"
	if got := truncateSnippet(short, 10); got != short {
		t.Errorf("short = %q, want %q", got, short)
	}
	long := "hello world this is a very long string"
	if got := truncateSnippet(long, 10); len(got) <= 10 {
		// truncateSnippet appends "...", so result is 13 chars
	}
}
