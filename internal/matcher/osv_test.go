package matcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestParseSeverity_CVSS3(t *testing.T) {
	sev := []osvSeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	got := parseSeverity(sev)
	if got != models.SeverityCritical {
		t.Errorf("parseSeverity CVSS3 = %v, want CRITICAL", got)
	}
}

func TestParseSeverity_CVSS2Fallback(t *testing.T) {
	sev := []osvSeverity{
		{Type: "CVSS_V2", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	got := parseSeverity(sev)
	if got == models.SeverityUnknown {
		t.Error("parseSeverity should use CVSS_V2 as fallback")
	}
}

func TestParseSeverity_Empty(t *testing.T) {
	got := parseSeverity(nil)
	if got != models.SeverityUnknown {
		t.Errorf("parseSeverity empty = %v, want UNKNOWN", got)
	}
}

func TestParseSeverityWithFallback_Database(t *testing.T) {
	vuln := &osvVuln{
		DatabaseSpecific: map[string]interface{}{
			"severity": "HIGH",
		},
	}
	got := parseSeverityWithFallback(vuln)
	if got != models.SeverityHigh {
		t.Errorf("parseSeverityWithFallback db = %v, want HIGH", got)
	}
}

func TestParseSeverityWithFallback_AffectedSeverity(t *testing.T) {
	vuln := &osvVuln{
		Affected: []osvAffected{
			{
				Severities: []osvSeverity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"},
				},
			},
		},
	}
	got := parseSeverityWithFallback(vuln)
	if got == models.SeverityUnknown {
		t.Error("should fall back to affected severity")
	}
}

func TestExtractCVSSScore_CVSS3(t *testing.T) {
	sev := []osvSeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	score := extractCVSSScore(sev)
	if score < 9.0 {
		t.Errorf("extractCVSSScore = %f, want >= 9.0", score)
	}
}

func TestExtractCVSSScore_GoQuadraticHTML(t *testing.T) {
	sev := []osvSeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"},
	}
	score := extractCVSSScore(sev)
	if score != 5.3 {
		t.Errorf("extractCVSSScore = %f, want 5.3", score)
	}
	if got := parseSeverity(sev); got != models.SeverityMedium {
		t.Errorf("parseSeverity = %v, want MEDIUM", got)
	}
}

func TestExtractCVSSScore_Empty(t *testing.T) {
	score := extractCVSSScore(nil)
	if score != 0 {
		t.Errorf("extractCVSSScore empty = %f, want 0", score)
	}
}

func TestCvssVectorToSeverity(t *testing.T) {
	tests := map[string]models.Severity{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": models.SeverityCritical,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": models.SeverityMedium,
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": models.SeverityLow,
		"invalid": models.SeverityUnknown,
	}
	for vector, want := range tests {
		got := cvssVectorToSeverity(vector)
		if got != want {
			t.Errorf("cvssVectorToSeverity(%q) = %v, want %v", vector, got, want)
		}
	}
}

func TestComputeCVSS3BaseScore_Critical(t *testing.T) {
	score := computeCVSS3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if score < 9.0 || score > 10.0 {
		t.Errorf("score = %f, want 9.0-10.0", score)
	}
}

func TestComputeCVSS3BaseScore_ScopeChanged(t *testing.T) {
	score := computeCVSS3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
	if score < 9.0 {
		t.Errorf("score with scope changed = %f, want >= 9.0", score)
	}
}

func TestComputeCVSS3BaseScore_Invalid(t *testing.T) {
	score := computeCVSS3BaseScore("invalid")
	if score != 0 {
		t.Errorf("invalid vector score = %f, want 0", score)
	}
}

func TestComputeCVSS3BaseScore_MissingMetric(t *testing.T) {
	score := computeCVSS3BaseScore("CVSS:3.1/AV:N/AC:L")
	if score != 0 {
		t.Errorf("incomplete vector score = %f, want 0", score)
	}
}

func TestRoundUp(t *testing.T) {
	tests := map[float64]float64{
		0.0:  0.0,
		7.51: 7.6,
		9.0:  9.0,
		3.14: 3.2,
	}
	for input, want := range tests {
		got := roundUp(input)
		if got != want {
			t.Errorf("roundUp(%f) = %f, want %f", input, got, want)
		}
	}
}

func TestOSVMatcher_MatchEmpty(t *testing.T) {
	m := NewOSVMatcher()
	vulns, err := m.Match(nil, nil)
	if err != nil {
		t.Fatalf("Match(nil) error: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("Match(nil) = %d vulns, want 0", len(vulns))
	}
}

func TestEcosystemMap(t *testing.T) {
	if ecosystemMap[models.EcosystemGo] != "Go" {
		t.Error("Go mapping wrong")
	}
	if ecosystemMap[models.EcosystemNpm] != "npm" {
		t.Error("npm mapping wrong")
	}
	if ecosystemMap[models.EcosystemPyPI] != "PyPI" {
		t.Error("PyPI mapping wrong")
	}
	if ecosystemMap[models.EcosystemCrates] != "crates.io" {
		t.Error("crates.io mapping wrong")
	}
}

// redirectTransport intercepts all outgoing requests and redirects them to a local test server.
type redirectTransport struct {
	server *httptest.Server
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect the request to the test server, preserving path and query
	req.URL.Scheme = "http"
	req.URL.Host = rt.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func TestOSVMatcher_Match_WithMockServer(t *testing.T) {
	batchResp := osvBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []osvVuln{
					{
						ID:      "GHSA-xxxx-yyyy-zzzz",
						Summary: "Test vuln in lodash",
						Aliases: []string{"CVE-2021-23337"},
					},
				},
			},
		},
	}

	vulnDetail := osvVuln{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Summary: "Prototype Pollution in lodash",
		Details: "Detailed description",
		Aliases: []string{"CVE-2021-23337"},
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "lodash", Ecosystem: "npm"},
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "4.17.21"},
						},
					},
				},
			},
		},
		References: []osvReference{
			{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/querybatch" {
			json.NewEncoder(w).Encode(batchResp)
		} else if r.URL.Path == "/v1/vulns/GHSA-xxxx-yyyy-zzzz" {
			json.NewEncoder(w).Encode(vulnDetail)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	m := &OSVMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkgs := []models.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
	}

	vulns, err := m.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}

	v := vulns[0]
	if v.ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("ID = %q, want %q", v.ID, "GHSA-xxxx-yyyy-zzzz")
	}
	if v.Summary != "Prototype Pollution in lodash" {
		t.Errorf("Summary = %q", v.Summary)
	}
	if v.FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q, want 4.17.21", v.FixedIn)
	}
	if v.Source != models.SourceOSV {
		t.Errorf("Source = %v, want OSV", v.Source)
	}
	if v.Score < 9.0 {
		t.Errorf("Score = %f, want >= 9.0", v.Score)
	}
	if v.Severity != models.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL", v.Severity)
	}
	if len(v.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(v.References))
	}
}

func TestOSVMatcher_Match_GoVulnDBCVSSSeverity(t *testing.T) {
	batchResp := osvBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []osvVuln{{ID: "GO-2026-4440"}},
			},
		},
	}

	goVulnDetail := osvVuln{
		ID:      "GO-2026-4440",
		Summary: "Quadratic parsing complexity in golang.org/x/net/html",
		Details: "The html.Parse function in golang.org/x/net/html has quadratic parsing complexity.",
		Aliases: []string{"CVE-2025-47911", "GHSA-w4gw-w5jq-g9jh"},
		DatabaseSpecific: map[string]interface{}{
			"severity": "MODERATE",
		},
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
				Ranges: []osvRange{{
					Type:   "SEMVER",
					Events: []osvEvent{{Introduced: "0"}, {Fixed: "0.45.0"}},
				}},
			},
		},
		References: []osvReference{
			{Type: "REPORT", URL: "https://github.com/golang/vulndb/issues/4440"},
		},
	}

	cveVulnDetail := osvVuln{
		ID:      "CVE-2025-47911",
		Summary: "Quadratic parsing complexity in golang.org/x/net/html",
		Details: "The html.Parse function in golang.org/x/net/html has quadratic parsing complexity.",
		Aliases: []string{"GHSA-w4gw-w5jq-g9jh", "GO-2026-4440"},
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"},
		},
		Affected: []osvAffected{
			{
				Package: osvPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
				Ranges: []osvRange{{
					Type:   "SEMVER",
					Events: []osvEvent{{Introduced: "0"}, {Fixed: "0.45.0"}},
				}},
			},
		},
		References: []osvReference{
			{Type: "ADVISORY", URL: "https://pkg.go.dev/vuln/GO-2026-4440"},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/querybatch":
			json.NewEncoder(w).Encode(batchResp)
		case "/v1/vulns/GO-2026-4440":
			json.NewEncoder(w).Encode(goVulnDetail)
		case "/v1/vulns/CVE-2025-47911":
			json.NewEncoder(w).Encode(cveVulnDetail)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	m := &OSVMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	vulns, err := m.Match(context.Background(), []models.Package{{
		Name:      "golang.org/x/net",
		Version:   "v0.34.0",
		Ecosystem: models.EcosystemGo,
	}})
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].ID != "GO-2026-4440" {
		t.Errorf("ID = %q, want original OSV ID before canonical normalization", vulns[0].ID)
	}
	if vulns[0].Score != 5.3 {
		t.Errorf("Score = %f, want 5.3", vulns[0].Score)
	}
	if vulns[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %v, want MEDIUM", vulns[0].Severity)
	}
	if vulns[0].FixedIn != "0.45.0" {
		t.Errorf("FixedIn = %q, want 0.45.0", vulns[0].FixedIn)
	}
}

func TestOSVMatcher_Match_BatchError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	m := &OSVMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkgs := []models.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
	}

	_, err := m.Match(context.Background(), pkgs)
	if err == nil {
		t.Error("expected error for server 500, got nil")
	}
}

func TestOSVMatcher_Match_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	m := &OSVMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkgs := []models.Package{
		{Name: "test", Version: "1.0", Ecosystem: models.EcosystemNpm},
	}

	_, err := m.Match(context.Background(), pkgs)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestOSVMatcher_FetchVulnDetails_Error(t *testing.T) {
	// Test when fetchVulnDetails fails — should fall back to batch data
	batchResp := osvBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []osvVuln{
					{
						ID:      "GHSA-test-1234-5678",
						Summary: "Test vuln",
						Aliases: []string{"CVE-2024-9999"},
						Severity: []osvSeverity{
							{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
						},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/querybatch" {
			json.NewEncoder(w).Encode(batchResp)
		} else {
			// Return 404 for vuln detail fetch
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	m := &OSVMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkgs := []models.Package{
		{Name: "testpkg", Version: "1.0.0", Ecosystem: models.EcosystemGo},
	}

	vulns, err := m.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln (fallback), got %d", len(vulns))
	}

	// Should fall back to minimal data from batch
	if vulns[0].ID != "GHSA-test-1234-5678" {
		t.Errorf("ID = %q, want GHSA-test-1234-5678", vulns[0].ID)
	}
	if vulns[0].Summary != "Test vuln" {
		t.Errorf("Summary = %q, want 'Test vuln'", vulns[0].Summary)
	}
	if vulns[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %v, want MEDIUM from batch fallback", vulns[0].Severity)
	}
	if vulns[0].Score == 0 {
		t.Error("Score = 0, want batch fallback CVSS score")
	}
}

func TestOSVMatcher_Match_FiltersShortNames(t *testing.T) {
	batchResp := osvBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []osvVuln{
					{ID: "GHSA-1111-2222-3333", Summary: "vuln"},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(batchResp)
	}))
	defer ts.Close()

	m := &OSVMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	// Package with very short name should be filtered out
	pkgs := []models.Package{
		{Name: "x", Version: "1.0", Ecosystem: models.EcosystemNpm},
	}

	vulns, err := m.Match(context.Background(), pkgs)
	if err != nil {
		t.Fatalf("Match error: %v", err)
	}

	// Short name "x" (len < 2) should be filtered
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns for short name, got %d", len(vulns))
	}
}

func TestNVDMatcher_QueryPackageWithMock(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []nvdVulnWrapper{
			{
				CVE: nvdCVE{
					ID:        "CVE-2024-0001",
					Published: "2024-01-01T00:00:00Z",
					Descriptions: []nvdDescription{
						{Lang: "en", Value: "Test vulnerability in lodash"},
						{Lang: "es", Value: "Vulnerabilidad de prueba"},
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
						{URL: "https://example.com/advisory"},
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

	m := &NVDMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
		apiKey: "test-key",
	}

	pkg := models.Package{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm}
	vulns, err := m.queryPackage(context.Background(), "lodash", pkg)
	if err != nil {
		t.Fatalf("queryPackage error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}

	v := vulns[0]
	if v.ID != "CVE-2024-0001" {
		t.Errorf("ID = %q, want CVE-2024-0001", v.ID)
	}
	if v.Summary != "Test vulnerability in lodash" {
		t.Errorf("Summary = %q", v.Summary)
	}
	if v.Score != 8.5 {
		t.Errorf("Score = %f, want 8.5", v.Score)
	}
	if v.Severity != models.SeverityHigh {
		t.Errorf("Severity = %v, want HIGH", v.Severity)
	}
	if v.Source != models.SourceNVD {
		t.Errorf("Source = %v, want NVD", v.Source)
	}
	if len(v.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(v.References))
	}
}

func TestNVDMatcher_QueryPackage_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	m := &NVDMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkg := models.Package{Name: "test", Version: "1.0", Ecosystem: models.EcosystemNpm}
	_, err := m.queryPackage(context.Background(), "test", pkg)
	if err == nil {
		t.Error("expected error for server 503, got nil")
	}
}

func TestNVDMatcher_QueryPackage_NoMetrics(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []nvdVulnWrapper{
			{
				CVE: nvdCVE{
					ID: "CVE-2024-0002",
					Descriptions: []nvdDescription{
						{Lang: "en", Value: "No metrics vuln"},
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

	m := &NVDMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkg := models.Package{Name: "test", Version: "1.0", Ecosystem: models.EcosystemNpm}
	vulns, err := m.queryPackage(context.Background(), "test", pkg)
	if err != nil {
		t.Fatalf("queryPackage error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].Severity != models.SeverityUnknown {
		t.Errorf("Severity = %v, want UNKNOWN", vulns[0].Severity)
	}
	if vulns[0].Score != 0 {
		t.Errorf("Score = %f, want 0", vulns[0].Score)
	}
}

func TestGitHubAdvisoryMatcher_QueryEcosystemWithMock(t *testing.T) {
	advisories := []ghAdvisory{
		{
			GHSAID:      "GHSA-abcd-1234-xxxx",
			CVEID:       "CVE-2024-0001",
			Summary:     "Test vulnerability",
			Description: "Detailed description of the vulnerability",
			Severity:    "high",
			CVSSScore:   8.5,
			HTMLURL:     "https://github.com/advisories/GHSA-abcd-1234-xxxx",
			Vulnerabilities: []ghVulnerability{
				{
					Package: ghPackage{
						Ecosystem: "npm",
						Name:      "lodash",
					},
					VulnerableVersionRange: "< 4.17.21",
					FirstPatchedVersion:    &ghVersion{Identifier: "4.17.21"},
				},
			},
		},
		{
			GHSAID:   "GHSA-efgh-5678-yyyy",
			Summary:  "Another vuln",
			Severity: "critical",
			Vulnerabilities: []ghVulnerability{
				{
					Package: ghPackage{
						Ecosystem: "npm",
						Name:      "express",
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authorization header
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(advisories)
	}))
	defer ts.Close()

	m := &GitHubAdvisoryMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
		token: "test-token",
	}

	pkgs := []models.Package{
		{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
	}

	vulns, err := m.queryEcosystem(context.Background(), "npm", pkgs)
	if err != nil {
		t.Fatalf("queryEcosystem error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln (only lodash matches), got %d", len(vulns))
	}

	v := vulns[0]
	if v.ID != "CVE-2024-0001" {
		t.Errorf("ID = %q, want CVE-2024-0001", v.ID)
	}
	if v.FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q, want 4.17.21", v.FixedIn)
	}
	if v.Severity != models.SeverityHigh {
		t.Errorf("Severity = %v, want HIGH", v.Severity)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "GHSA-abcd-1234-xxxx" {
		t.Errorf("Aliases = %v, want [GHSA-abcd-1234-xxxx]", v.Aliases)
	}
	if v.Source != models.SourceGitHubAdv {
		t.Errorf("Source = %v, want github-advisory", v.Source)
	}
}

func TestGitHubAdvisoryMatcher_QueryEcosystem_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	m := &GitHubAdvisoryMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	_, err := m.queryEcosystem(context.Background(), "npm", nil)
	if err == nil {
		t.Error("expected error for 403, got nil")
	}
}

func TestGitHubAdvisoryMatcher_QueryEcosystem_NilPatched(t *testing.T) {
	advisories := []ghAdvisory{
		{
			GHSAID:   "GHSA-only-ghsa-id",
			Summary:  "vuln without CVE",
			Severity: "medium",
			Vulnerabilities: []ghVulnerability{
				{
					Package: ghPackage{Ecosystem: "npm", Name: "mypkg"},
					// FirstPatchedVersion is nil
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(advisories)
	}))
	defer ts.Close()

	m := &GitHubAdvisoryMatcher{
		client: &http.Client{
			Transport: &redirectTransport{server: ts},
		},
	}

	pkgs := []models.Package{
		{Name: "mypkg", Version: "1.0", Ecosystem: models.EcosystemNpm},
	}

	vulns, err := m.queryEcosystem(context.Background(), "npm", pkgs)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}

	// When no CVE ID, should use GHSA ID
	if vulns[0].ID != "GHSA-only-ghsa-id" {
		t.Errorf("ID = %q, want GHSA-only-ghsa-id", vulns[0].ID)
	}
	if vulns[0].FixedIn != "" {
		t.Errorf("FixedIn = %q, want empty", vulns[0].FixedIn)
	}
	if len(vulns[0].Aliases) != 0 {
		t.Errorf("Aliases = %v, want empty", vulns[0].Aliases)
	}
}
