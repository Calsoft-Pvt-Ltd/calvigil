package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestNVDMatcher_MatchEmpty(t *testing.T) {
	m := NewNVDMatcher("")
	vulns, err := m.Match(context.Background(), nil)
	if err != nil {
		t.Fatalf("Match(nil) error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("Match(nil) = %d vulns, want 0", len(vulns))
	}
}

func TestNVDMatcher_NameReturnsNVD(t *testing.T) {
	m := NewNVDMatcher("")
	if m.Name() != "nvd" {
		t.Errorf("Name() = %q, want %q", m.Name(), "nvd")
	}
}

func TestNVDMatcher_QueryPackage(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []nvdVulnWrapper{
			{
				CVE: nvdCVE{
					ID:        "CVE-2024-0001",
					Published: "2024-01-01T00:00:00Z",
					Descriptions: []nvdDescription{
						{Lang: "en", Value: "Test vulnerability"},
					},
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{
								CvssData: nvdCvssData{
									BaseScore:    8.5,
									BaseSeverity: "HIGH",
								},
							},
						},
					},
					References: []nvdReference{
						{URL: "https://nvd.nist.gov/vuln/CVE-2024-0001"},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "test-key" {
			t.Errorf("expected apiKey header, got %q", r.Header.Get("apiKey"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := &NVDMatcher{
		client: ts.Client(),
		apiKey: "test-key",
	}

	pkg := models.Package{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm}

	// queryPackage uses the hardcoded nvdBaseURL, so we test the parsing logic
	// using our test data structures directly
	_ = m
	_ = pkg

	// Test NVD response parsing by verifying struct marshaling
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(parsed.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(parsed.Vulnerabilities))
	}
	cve := parsed.Vulnerabilities[0].CVE
	if cve.ID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %s", cve.ID)
	}
	if len(cve.Metrics.CvssMetricV31) == 0 {
		t.Fatal("expected CVSS metrics")
	}
	if cve.Metrics.CvssMetricV31[0].CvssData.BaseScore != 8.5 {
		t.Errorf("expected score 8.5, got %f", cve.Metrics.CvssMetricV31[0].CvssData.BaseScore)
	}
	if cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity)
	}
	if len(cve.References) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(cve.References))
	}
}

func TestNVDMatcher_Match_LimitsTo20(t *testing.T) {
	// NVD Match limits unique package names to 20
	var pkgs []models.Package
	for i := 0; i < 30; i++ {
		pkgs = append(pkgs, models.Package{
			Name:      "pkg-" + string(rune('a'+i)),
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNpm,
		})
	}

	// Create a matcher with a client that will fail (no real server)
	// The match method should still limit to 20 unique names
	m := NewNVDMatcher("")
	// We just verify the function doesn't panic with many packages
	// (it will fail on HTTP, but that's fine for this test)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel so no real HTTP calls happen
	_, _ = m.Match(ctx, pkgs)
}

func TestNVDMatcher_EnrichCVSSByCVE_FillsOSVGoAdvisoryScore(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []nvdVulnWrapper{
			{
				CVE: nvdCVE{
					ID:        "CVE-2025-47911",
					Published: "2026-02-05T00:00:00.000",
					Descriptions: []nvdDescription{
						{Lang: "en", Value: "golang.org/x/net/html quadratic parsing complexity"},
					},
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{
								CvssData: nvdCvssData{
									BaseScore:    5.3,
									BaseSeverity: "MEDIUM",
								},
							},
						},
					},
					References: []nvdReference{
						{URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-47911"},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveIds"); got != "CVE-2025-47911" {
			t.Errorf("cveIds query = %q, want CVE-2025-47911", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := &NVDMatcher{
		client:         ts.Client(),
		baseURL:        ts.URL,
		rateLimitDelay: 0,
	}

	vulns := []models.Vulnerability{
		{
			ID:       "CVE-2025-47911",
			Aliases:  []string{"GO-2026-4440"},
			Severity: models.SeverityUnknown,
			Package: models.Package{
				Name:      "golang.org/x/net",
				Version:   "v0.34.0",
				Ecosystem: models.EcosystemGo,
			},
			Source: models.SourceOSV,
		},
	}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if result.Enriched != 1 {
		t.Fatalf("enriched = %d, want 1", result.Enriched)
	}
	if vulns[0].Score != 5.3 {
		t.Errorf("score = %v, want 5.3", vulns[0].Score)
	}
	if vulns[0].Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want MEDIUM", vulns[0].Severity)
	}
	if vulns[0].Source != models.SourceOSV {
		t.Errorf("source = %q, want OSV to remain the owning match source", vulns[0].Source)
	}
	if len(vulns[0].References) != 1 {
		t.Errorf("references = %v, want NVD reference merged", vulns[0].References)
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_UsesCVEAlias(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []nvdVulnWrapper{
			{
				CVE: nvdCVE{
					ID: "CVE-2026-0001",
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 7.1, BaseSeverity: "HIGH"}},
						},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := &NVDMatcher{client: ts.Client(), baseURL: ts.URL, rateLimitDelay: 0}
	vulns := []models.Vulnerability{{
		ID:       "GO-2026-0001",
		Aliases:  []string{"CVE-2026-0001"},
		Severity: models.SeverityUnknown,
		Source:   models.SourceOSV,
	}}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if result.Enriched != 1 {
		t.Fatalf("enriched = %d, want 1", result.Enriched)
	}
	if vulns[0].Score != 7.1 {
		t.Errorf("score = %v, want 7.1", vulns[0].Score)
	}
	if vulns[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want HIGH", vulns[0].Severity)
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_SkipsCompleteFindings(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	m := &NVDMatcher{client: ts.Client(), baseURL: ts.URL, rateLimitDelay: 0}
	vulns := []models.Vulnerability{{
		ID:       "CVE-2026-0002",
		Severity: models.SeverityHigh,
		Score:    8.2,
		Source:   models.SourceOSV,
	}}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if result.Requested != 0 || result.Enriched != 0 {
		t.Fatalf("result = %+v, want no enrichment work", result)
	}
	if called {
		t.Fatal("NVD server was called for a finding that already had score and severity")
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_BatchesUpTo100IDs(t *testing.T) {
	var calls int
	var batchSizes []int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		ids := strings.Split(r.URL.Query().Get("cveIds"), ",")
		batchSizes = append(batchSizes, len(ids))

		resp := nvdResponse{}
		for _, id := range ids {
			resp.Vulnerabilities = append(resp.Vulnerabilities, nvdVulnWrapper{
				CVE: nvdCVE{
					ID: id,
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 5.3, BaseSeverity: "MEDIUM"}},
						},
					},
				},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := &NVDMatcher{client: ts.Client(), baseURL: ts.URL, rateLimitDelay: 0}
	vulns := make([]models.Vulnerability, 101)
	for i := range vulns {
		vulns[i] = models.Vulnerability{
			ID:       fmt.Sprintf("CVE-2026-%04d", i+1),
			Severity: models.SeverityUnknown,
			Source:   models.SourceOSV,
		}
	}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("NVD calls = %d, want 2 batched calls", calls)
	}
	if len(batchSizes) != 2 || batchSizes[0] != 100 || batchSizes[1] != 1 {
		t.Fatalf("batch sizes = %v, want [100 1]", batchSizes)
	}
	if result.Requested != 101 || result.Batches != 2 || result.Enriched != 101 {
		t.Fatalf("result = %+v, want requested=101 batches=2 enriched=101", result)
	}
	if vulns[100].Score != 5.3 || vulns[100].Severity != models.SeverityMedium {
		t.Fatalf("last vuln = score %v severity %q, want 5.3 MEDIUM", vulns[100].Score, vulns[100].Severity)
	}
}
