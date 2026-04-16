package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	openai "github.com/sashabaranov/go-openai"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func newMockOpenAIAnalyzer(serverURL string) *OpenAIAnalyzer {
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = serverURL
	return &OpenAIAnalyzer{
		client: openai.NewClientWithConfig(cfg),
		model:  "gpt-4",
	}
}

func TestOpenAIAnalyzer_CallOpenAI_Success(t *testing.T) {
	results := []aiVulnResult{
		{
			ID:             "CVE-2024-TEST",
			Name:           "SQL Injection",
			Description:    "Unsanitized user input in SQL query",
			Severity:       "HIGH",
			File:           "app.py",
			Line:           42,
			Recommendation: "Use parameterized queries",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(results)
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": string(body),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	vulns, err := a.callOpenAI(context.Background(), "test prompt", "/project", false)
	if err != nil {
		t.Fatalf("callOpenAI error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "CVE-2024-TEST" {
		t.Errorf("ID = %q, want CVE-2024-TEST", vulns[0].ID)
	}
	if vulns[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %v, want HIGH", vulns[0].Severity)
	}
	if vulns[0].Source != models.SourceAIAnalysis {
		t.Errorf("Source = %v, want AI-analysis", vulns[0].Source)
	}
	if vulns[0].StartLine != 42 {
		t.Errorf("StartLine = %d, want 42", vulns[0].StartLine)
	}
}

func TestOpenAIAnalyzer_CallOpenAI_EmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	_, err := a.callOpenAI(context.Background(), "test", "/project", false)
	if err == nil {
		t.Error("expected error for empty choices, got nil")
	}
}

func TestOpenAIAnalyzer_CallOpenAI_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": "I cannot analyze this code.",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	vulns, err := a.callOpenAI(context.Background(), "test", "/project", false)
	if err != nil {
		t.Fatalf("should not error on unparseable AI response: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns for invalid JSON, got %d", len(vulns))
	}
}

func TestOpenAIAnalyzer_CallEnrichment_Success(t *testing.T) {
	results := []aiEnrichmentResult{
		{
			VulnID:               "CVE-2024-TEST",
			Summary:              "SQL injection in login handler",
			LikelyImpact:         "Database compromise",
			Confidence:           "high",
			MinimalRemediation:   "Use parameterized queries",
			SuppressionRationale: "",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(results)
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": string(body),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	enriched, err := a.callEnrichment(context.Background(), "test prompt", false)
	if err != nil {
		t.Fatalf("callEnrichment error: %v", err)
	}
	if len(enriched) != 1 {
		t.Fatalf("expected 1 result, got %d", len(enriched))
	}
	if enriched[0].VulnID != "CVE-2024-TEST" {
		t.Errorf("VulnID = %q, want CVE-2024-TEST", enriched[0].VulnID)
	}
}

func TestOpenAIAnalyzer_EnrichVulnerabilities(t *testing.T) {
	results := []aiEnrichmentResult{
		{
			VulnID:             "CVE-1",
			Summary:            "Critical issue",
			LikelyImpact:       "Data leak",
			Confidence:         "HIGH",
			MinimalRemediation: "Fix it",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(results)
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": string(body),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	vulns := []models.Vulnerability{
		{ID: "CVE-1", Summary: "Test vuln"},
		{ID: "CVE-2", Summary: "Another vuln"},
	}

	enriched := a.EnrichVulnerabilities(context.Background(), vulns, "/project", false)
	if len(enriched) != 2 {
		t.Fatalf("expected 2 vulns back, got %d", len(enriched))
	}

	if enriched[0].AIEnrichment == nil {
		t.Error("CVE-1 should have AI enrichment")
	} else {
		if enriched[0].AIEnrichment.Summary != "Critical issue" {
			t.Errorf("enrichment summary = %q", enriched[0].AIEnrichment.Summary)
		}
		if enriched[0].AIEnrichment.Confidence != "HIGH" {
			t.Errorf("enrichment confidence = %q", enriched[0].AIEnrichment.Confidence)
		}
	}

	if enriched[1].AIEnrichment != nil {
		t.Error("CVE-2 should not have enrichment (not in response)")
	}
}

func TestOpenAIAnalyzer_EnrichVulnerabilities_Empty(t *testing.T) {
	a := newMockOpenAIAnalyzer("http://invalid")
	got := a.EnrichVulnerabilities(context.Background(), nil, "/project", false)
	if got != nil {
		t.Errorf("expected nil for empty vulns, got %d", len(got))
	}
}

func TestOpenAIAnalyzer_Analyze(t *testing.T) {
	// Create a project directory with a suspicious file
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(
		"import os\npassword = 'hardcoded_secret'\nos.system(user_input)\n",
	), 0644)

	results := []aiVulnResult{
		{
			ID:          "CVE-AI-001",
			Name:        "Hardcoded password",
			Description: "Password hardcoded in source",
			Severity:    "HIGH",
			File:        "app.py",
			Line:        2,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(results)
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": string(body),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	vulns, err := a.Analyze(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// Should get pattern matches + AI results
	if len(vulns) == 0 {
		t.Error("expected at least some vulnerabilities")
	}
}

func TestOpenAIAnalyzer_AnalyzePatternMatches(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.py")
	os.WriteFile(testFile, []byte("eval(user_input)\n"), 0644)

	results := []aiVulnResult{
		{
			ID:          "AI-001",
			Name:        "Code injection",
			Description: "eval with user input",
			Severity:    "CRITICAL",
			File:        "test.py",
			Line:        1,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(results)
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": string(body),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)

	matches := []PatternMatch{
		{
			FilePath: testFile,
			Line:     1,
			Content:  "eval(user_input)",
			Rule:     PatternRule{Name: "eval-injection"},
		},
	}

	vulns, err := a.analyzePatternMatches(context.Background(), dir, matches, false)
	if err != nil {
		t.Fatalf("analyzePatternMatches error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "AI-001" {
		t.Errorf("ID = %q, want AI-001", vulns[0].ID)
	}
}

func TestOpenAIAnalyzer_AnalyzeSourceFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a main.py which would be picked up by findImportantFiles
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('hello')\n"), 0644)

	results := []aiVulnResult{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(results)
		resp := map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": string(body),
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	a := newMockOpenAIAnalyzer(ts.URL)
	vulns, err := a.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("analyzeSourceFiles error: %v", err)
	}
	// With empty results from AI, should get 0 vulns
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
}

func TestOpenAIAnalyzer_AnalyzeSourceFiles_NoFiles(t *testing.T) {
	dir := t.TempDir()
	a := newMockOpenAIAnalyzer("http://invalid")
	vulns, err := a.analyzeSourceFiles(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns for empty dir, got %d", len(vulns))
	}
}
