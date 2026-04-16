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

// newTestOllama creates an OllamaAnalyzer pointing at the given test server URL.
func newTestOllama(url string) *OllamaAnalyzer {
	return &OllamaAnalyzer{
		baseURL: url,
		model:   "test-model",
		client:  &http.Client{},
	}
}

// ── chatCompletion tests ────────────────────────────────────────

func TestOllamaChatCompletion_OpenAICompat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: "hello world"}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	got, err := o.chatCompletion(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestOllamaChatCompletion_NativeMessage(t *testing.T) {
	// Server returns a response with Message field (Ollama native format, but 200 on /v1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := ollamaChatMessage{Role: "assistant", Content: "native response"}
		json.NewEncoder(w).Encode(ollamaChatResponse{Message: &msg})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	got, err := o.chatCompletion(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "native response" {
		t.Errorf("got %q, want %q", got, "native response")
	}
}

func TestOllamaChatCompletion_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 with empty choices and no message → empty response error
		json.NewEncoder(w).Encode(ollamaChatResponse{})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	_, err := o.chatCompletion(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestOllamaChatCompletion_FallbackToNative(t *testing.T) {
	// /v1/chat/completions returns 404 → falls back to /api/chat
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.WriteHeader(http.StatusNotFound)
		case "/api/chat":
			// Return Ollama native streaming format (JSON lines)
			chunk1 := `{"message":{"content":"fallback "},"done":false}`
			chunk2 := `{"message":{"content":"response"},"done":true}`
			w.Write([]byte(chunk1 + "\n" + chunk2 + "\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	got, err := o.chatCompletion(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "fallback response" {
		t.Errorf("got %q, want %q", got, "fallback response")
	}
}

// ── chatCompletionNative tests ──────────────────────────────────

func TestOllamaChatCompletionNative_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lines := []string{
			`{"message":{"content":"part1 "},"done":false}`,
			`{"message":{"content":"part2"},"done":true}`,
		}
		for _, l := range lines {
			w.Write([]byte(l + "\n"))
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	got, err := o.chatCompletionNative(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "part1 part2" {
		t.Errorf("got %q, want %q", got, "part1 part2")
	}
}

func TestOllamaChatCompletionNative_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("model not found"))
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	_, err := o.chatCompletionNative(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestOllamaChatCompletionNative_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 with no JSON lines → empty content
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	_, err := o.chatCompletionNative(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestOllamaChatCompletionNative_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Malformed JSON lines are silently skipped; if all lines are bad, result is empty
		w.Write([]byte("not json\n"))
		w.Write([]byte("{bad json}\n"))
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	_, err := o.chatCompletionNative(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for empty response from malformed JSON")
	}
}

// ── callOllama tests ────────────────────────────────────────────

func TestOllamaCallOllama_Success(t *testing.T) {
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

	o := newTestOllama(srv.URL)
	vulns, err := o.callOllama(context.Background(), "system", "user prompt", "/project", false)
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

func TestOllamaCallOllama_EmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `[]`}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns, err := o.callOllama(context.Background(), "sys", "user", "/project", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestOllamaCallOllama_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `not valid json at all`}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns, err := o.callOllama(context.Background(), "sys", "user", "/project", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Invalid JSON returns nil, nil (graceful degradation)
	if vulns != nil {
		t.Errorf("expected nil vulns for invalid JSON, got %d", len(vulns))
	}
}

func TestOllamaCallOllama_Verbose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `[{"id":"V1","name":"test","description":"desc","severity":"LOW","file":"x.go","line":1,"recommendation":"fix"}]`}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns, err := o.callOllama(context.Background(), "sys", "user", "/project", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 1 {
		t.Errorf("expected 1 vuln, got %d", len(vulns))
	}
}

func TestOllamaCallOllama_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/chat":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error"))
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	_, err := o.callOllama(context.Background(), "sys", "user", "/project", false)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

// ── callEnrichment tests ────────────────────────────────────────

func TestOllamaCallEnrichment_Success(t *testing.T) {
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

	o := newTestOllama(srv.URL)
	results, err := o.callEnrichment(context.Background(), "enrich these", false)
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

func TestOllamaCallEnrichment_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{Role: "assistant", Content: `I cannot parse that request`}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	results, err := o.callEnrichment(context.Background(), "enrich", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Invalid JSON returns nil, nil (graceful)
	if results != nil {
		t.Errorf("expected nil results, got %d", len(results))
	}
}

func TestOllamaCallEnrichment_Verbose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"vuln_id":"CVE-1","summary":"s","likely_impact":"i","confidence":"MEDIUM","minimal_remediation":"r","suppression_rationale":"sr"}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	results, err := o.callEnrichment(context.Background(), "enrich", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestOllamaCallEnrichment_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.WriteHeader(http.StatusBadGateway)
		case "/api/chat":
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("bad gateway"))
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	_, err := o.callEnrichment(context.Background(), "enrich", false)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

// ── analyzeSourceFiles tests ────────────────────────────────────

func TestOllamaAnalyzeSourceFiles_WithFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a source file that findImportantFiles will pick up
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

	o := newTestOllama(srv.URL)
	vulns, err := o.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) < 1 {
		t.Error("expected at least 1 vulnerability from source file analysis")
	}
}

func TestOllamaAnalyzeSourceFiles_NoFiles(t *testing.T) {
	dir := t.TempDir()
	// Empty directory — no important files

	o := newTestOllama("http://localhost:1")
	vulns, err := o.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns for empty dir, got %d", len(vulns))
	}
}

func TestOllamaAnalyzeSourceFiles_ServerError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "fmt"
func main() { fmt.Println("hello") }
`), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/chat":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error"))
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	// Errors are swallowed per-file; returns whatever was collected
	vulns, err := o.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns when server errors, got %d", len(vulns))
	}
}

// ── Analyze full pipeline tests ─────────────────────────────────

func TestOllamaAnalyze_SourceFileFallback(t *testing.T) {
	// Project with no pattern matches but with source files
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.js"), []byte(`
const express = require('express');
const app = express();
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id=" + req.query.id;
  res.send(query);
});
`), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role:    "assistant",
					Content: `[{"id":"AI-SQL","name":"SQL Injection","description":"String concat in query","severity":"HIGH","file":"server.js","line":5,"recommendation":"Use prepared statements"}]`,
				}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns, err := o.Analyze(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// Should get pattern matches + AI source analysis results
	if len(vulns) == 0 {
		t.Error("expected vulnerabilities from analysis")
	}
}

func TestOllamaAnalyze_PatternMatchesOnly_AIError(t *testing.T) {
	// Project with pattern matches but AI server is broken → falls back to pattern results
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.py"), []byte(`
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdef"
`), 0644)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/api/chat":
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("unavailable"))
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns, err := o.Analyze(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// Should still return pattern-based vulns even though AI failed
	if len(vulns) == 0 {
		t.Error("expected pattern-based vulnerabilities as fallback")
	}
}

// ── EnrichVulnerabilities full pipeline test ────────────────────

func TestOllamaEnrichVulnerabilities_WithBatching(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return enrichment for all vulns in the batch
		json.NewEncoder(w).Encode(ollamaChatResponse{
			Choices: []ollamaChatChoice{
				{Message: ollamaChatMessage{
					Role: "assistant",
					Content: `[
						{"vuln_id":"CVE-2023-001","summary":"s1","likely_impact":"i1","confidence":"HIGH","minimal_remediation":"r1","suppression_rationale":""},
						{"vuln_id":"CVE-2023-002","summary":"s2","likely_impact":"i2","confidence":"LOW","minimal_remediation":"r2","suppression_rationale":"Low risk component"}
					]`,
				}},
			},
		})
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns := []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "Vuln 1", Severity: models.SeverityHigh},
		{ID: "CVE-2023-002", Summary: "Vuln 2", Severity: models.SeverityLow},
	}

	result := o.EnrichVulnerabilities(context.Background(), vulns, "/project", false)
	if len(result) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(result))
	}

	enriched := 0
	for _, v := range result {
		if v.AIEnrichment != nil {
			enriched++
		}
	}
	if enriched != 2 {
		t.Errorf("expected 2 enriched vulns, got %d", enriched)
	}
	if result[0].AIEnrichment.Confidence != "HIGH" {
		t.Errorf("first vuln confidence = %q, want HIGH", result[0].AIEnrichment.Confidence)
	}
}

func TestOllamaEnrichVulnerabilities_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/chat":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error"))
		}
	}))
	defer srv.Close()

	o := newTestOllama(srv.URL)
	vulns := []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "Test", Severity: models.SeverityHigh},
	}

	result := o.EnrichVulnerabilities(context.Background(), vulns, "/project", false)
	if len(result) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(result))
	}
	// Enrichment should be nil when server fails
	if result[0].AIEnrichment != nil {
		t.Error("enrichment should be nil when server errors")
	}
}
