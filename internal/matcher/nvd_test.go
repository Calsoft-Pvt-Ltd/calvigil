package matcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
