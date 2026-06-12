package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// newTestLMStudio creates an LMStudioAnalyzer pointing at the given test server URL.
func newTestLMStudio(url string) *LMStudioAnalyzer {
	return &LMStudioAnalyzer{
		baseURL: url,
		model:   "test-model",
		client:  &http.Client{},
	}
}

// ── Available tests ─────────────────────────────────────────────

func TestLMStudioAvailable_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[{"id":"test-model"}]}`))
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	if !l.Available() {
		t.Error("expected Available() to return true")
	}
}

func TestLMStudioAvailable_Unreachable(t *testing.T) {
	l := newTestLMStudio("http://127.0.0.1:1") // nothing listening
	if l.Available() {
		t.Error("expected Available() to return false for unreachable server")
	}
}

func TestLMStudioAvailable_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	if l.Available() {
		t.Error("expected Available() to return false on 500")
	}
}

// ── chatCompletion tests ────────────────────────────────────────

func TestLMStudioChatCompletion_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: "hello from lmstudio"}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	got, err := l.chatCompletion(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello from lmstudio" {
		t.Errorf("got %q, want %q", got, "hello from lmstudio")
	}
}

func TestLMStudioChatCompletion_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	_, err := l.chatCompletion(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestLMStudioChatCompletion_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("model not loaded"))
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	_, err := l.chatCompletion(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if got := err.Error(); !contains(got, "500") {
		t.Errorf("error should mention status code: %v", err)
	}
}

// ── callLMStudio tests ──────────────────────────────────────────

func TestLMStudioCallLMStudio_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"id":"VULN-1","name":"SQL Injection","description":"User input in query","severity":"HIGH","file":"app.py","line":10,"recommendation":"Use parameterized queries"}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns, err := l.callLMStudio(context.Background(), "system", "user prompt", "/project", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "VULN-1" {
		t.Errorf("ID = %q, want VULN-1", vulns[0].ID)
	}
	if vulns[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want HIGH", vulns[0].Severity)
	}
	if vulns[0].FilePath != filepath.Join("/project", "app.py") {
		t.Errorf("FilePath = %q, want %q", vulns[0].FilePath, filepath.Join("/project", "app.py"))
	}
}

func TestLMStudioCallLMStudio_EmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `[]`}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns, err := l.callLMStudio(context.Background(), "sys", "user", "/project", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestLMStudioCallLMStudio_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `not valid json at all`}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns, err := l.callLMStudio(context.Background(), "sys", "user", "/project", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("expected nil vulns for invalid JSON, got %d", len(vulns))
	}
}

func TestLMStudioCallLMStudio_Verbose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `[{"id":"V1","name":"test","description":"desc","severity":"LOW","file":"x.go","line":1,"recommendation":"fix"}]`}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns, err := l.callLMStudio(context.Background(), "sys", "user", "/project", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vuln, got %d", len(vulns))
	}
}

// ── callEnrichment tests ────────────────────────────────────────

func TestLMStudioCallEnrichment_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"vuln_id":"CVE-2023-001","summary":"RCE via deserialization","likely_impact":"Remote code execution","confidence":"HIGH","minimal_remediation":"Upgrade to 2.0","suppression_rationale":""}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	results, err := l.callEnrichment(context.Background(), "enrich these", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VulnID != "CVE-2023-001" {
		t.Errorf("VulnID = %q, want CVE-2023-001", results[0].VulnID)
	}
	if results[0].Confidence != "HIGH" {
		t.Errorf("Confidence = %q, want HIGH", results[0].Confidence)
	}
}

func TestLMStudioCallEnrichment_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `I cannot parse that request`}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	results, err := l.callEnrichment(context.Background(), "enrich", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results, got %d", len(results))
	}
}

func TestLMStudioCallEnrichment_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	_, err := l.callEnrichment(context.Background(), "enrich", false)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

// ── analyzeSourceFiles tests ────────────────────────────────────

func TestLMStudioAnalyzeSourceFiles_WithFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
import os
password = "secret123"
os.system(user_input)
`), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"id":"AI-001","name":"Command Injection","description":"User input in os.system","severity":"CRITICAL","file":"app.py","line":4,"recommendation":"Sanitize input"}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns, err := l.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) < 1 {
		t.Error("expected at least 1 vulnerability from source file analysis")
	}
}

func TestLMStudioAnalyzeSourceFiles_NoFiles(t *testing.T) {
	dir := t.TempDir()

	l := newTestLMStudio("http://127.0.0.1:1")
	vulns, err := l.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns for empty dir, got %d", len(vulns))
	}
}

// ── Analyze full pipeline tests ─────────────────────────────────

func TestLMStudioAnalyze_PatternMatchConfirmation(t *testing.T) {
	dir := t.TempDir()
	// Create a file with known vulnerable pattern
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
import os
def run(cmd):
    os.system(cmd)  # command injection
`), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"id":"AI-001","name":"Command Injection","description":"os.system with user input","severity":"CRITICAL","file":"app.py","line":4,"recommendation":"Use subprocess.run with shell=False"}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns, err := l.Analyze(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) == 0 {
		t.Fatal("expected at least 1 vulnerability")
	}
}

func TestLMStudioAnalyze_ServerDown(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
func main() {}
`), 0644)

	// Server that's unreachable
	l := newTestLMStudio("http://127.0.0.1:1")
	// Should gracefully fall back to pattern results (or nil)
	_, err := l.Analyze(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error (should degrade gracefully): %v", err)
	}
}

// ── EnrichVulnerabilities tests ─────────────────────────────────

func TestLMStudioEnrichVulnerabilities_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"vuln_id":"CVE-2023-001","summary":"Critical RCE","likely_impact":"Full system compromise","confidence":"HIGH","ai_code_indicator":"YES","minimal_remediation":"Upgrade dep","suppression_rationale":""}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	l := newTestLMStudio(srv.URL)
	vulns := []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "Test vuln", Severity: models.SeverityHigh},
	}

	enriched := l.EnrichVulnerabilities(context.Background(), vulns, "/project", false)
	if len(enriched) != 1 {
		t.Fatalf("expected 1, got %d", len(enriched))
	}
	if enriched[0].AIEnrichment == nil {
		t.Fatal("expected AIEnrichment to be set")
	}
	if enriched[0].AIEnrichment.Confidence != "HIGH" {
		t.Errorf("Confidence = %q, want HIGH", enriched[0].AIEnrichment.Confidence)
	}
}

func TestLMStudioEnrichVulnerabilities_Empty(t *testing.T) {
	l := newTestLMStudio("http://127.0.0.1:1")
	enriched := l.EnrichVulnerabilities(context.Background(), nil, "/project", false)
	if enriched != nil {
		t.Errorf("expected nil for empty input, got %v", enriched)
	}
}

// ── NewLMStudioAnalyzer tests ───────────────────────────────────

func TestNewLMStudioAnalyzer_DefaultURL(t *testing.T) {
	l := NewLMStudioAnalyzer("", "my-model")
	if l.baseURL != "http://localhost:1234" {
		t.Errorf("baseURL = %q, want http://localhost:1234", l.baseURL)
	}
	if l.model != "my-model" {
		t.Errorf("model = %q, want my-model", l.model)
	}
}

func TestNewLMStudioAnalyzer_CustomURL(t *testing.T) {
	l := NewLMStudioAnalyzer("http://gpu-server:1234/", "codellama")
	if l.baseURL != "http://gpu-server:1234" {
		t.Errorf("baseURL = %q, want http://gpu-server:1234", l.baseURL)
	}
}

// contains checks if substr is in s (helper to avoid importing strings in test).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
