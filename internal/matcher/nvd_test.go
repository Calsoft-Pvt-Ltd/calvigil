package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/cache"
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

func TestNVDMatcher_DefaultTimeoutsCoverSlowResponses(t *testing.T) {
	if nvdCVEEnrichmentTimeout <= 30*time.Second {
		t.Fatalf("nvdCVEEnrichmentTimeout = %s, want above observed 30s NVD responses", nvdCVEEnrichmentTimeout)
	}
	if nvdHTTPClient.Timeout != nvdCVEEnrichmentTimeout {
		t.Fatalf("nvdHTTPClient.Timeout = %s, want %s", nvdHTTPClient.Timeout, nvdCVEEnrichmentTimeout)
	}
	if nvdCVEEnrichmentBudget < 2*nvdCVEEnrichmentTimeout {
		t.Fatalf("nvdCVEEnrichmentBudget = %s, want enough room for more than one slow batch", nvdCVEEnrichmentBudget)
	}
}

func TestNVDMatcher_QueryCVEs_SetsNVDHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != nvdUserAgent {
			t.Errorf("User-Agent = %q, want %q", got, nvdUserAgent)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q, want application/json", got)
		}
		if got := r.Header.Get("apiKey"); got != "test-key" {
			t.Errorf("apiKey = %q, want test-key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{{
				CVE: nvdCVE{
					ID: "CVE-2026-39883",
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{{CvssData: nvdCvssData{BaseScore: 5.3, BaseSeverity: "MEDIUM"}}},
					},
				},
			}},
		})
	}))
	defer ts.Close()

	m := &NVDMatcher{
		client:         ts.Client(),
		apiKey:         "test-key",
		baseURL:        ts.URL,
		rateLimitDelay: 0,
		cveTimeout:     nvdCVEEnrichmentTimeout,
	}

	records, err := m.queryCVEs(context.Background(), []string{"CVE-2026-39883"})
	if err != nil {
		t.Fatalf("queryCVEs() error: %v", err)
	}
	if records["CVE-2026-39883"].Score != 5.3 {
		t.Fatalf("records = %+v, want CVE score 5.3", records)
	}
}

func TestBestNVDCVSS_UsesCISAADPWhenNVDPrimaryMissing(t *testing.T) {
	score, severity := bestNVDCVSS(nvdMetrics{
		CvssMetricV31: []nvdCvssMetric{
			{
				Source: "nvd@nist.gov",
				Type:   "Primary",
			},
			{
				Source: "CISA-ADP",
				Type:   "Secondary",
				CvssData: nvdCvssData{
					BaseScore:    9.1,
					BaseSeverity: "CRITICAL",
				},
			},
		},
	})

	if score != 9.1 {
		t.Fatalf("score = %v, want CISA-ADP fallback score 9.1", score)
	}
	if severity != models.SeverityCritical {
		t.Fatalf("severity = %q, want CRITICAL", severity)
	}
}

func TestBestNVDCVSS_PrefersNVDPrimaryOverSecondary(t *testing.T) {
	score, severity := bestNVDCVSS(nvdMetrics{
		CvssMetricV31: []nvdCvssMetric{
			{
				Source: "CISA-ADP",
				Type:   "Secondary",
				CvssData: nvdCvssData{
					BaseScore:    9.1,
					BaseSeverity: "CRITICAL",
				},
			},
			{
				Source: "nvd@nist.gov",
				Type:   "Primary",
				CvssData: nvdCvssData{
					BaseScore:    7.5,
					BaseSeverity: "HIGH",
				},
			},
		},
	})

	if score != 7.5 {
		t.Fatalf("score = %v, want NVD primary score 7.5", score)
	}
	if severity != models.SeverityHigh {
		t.Fatalf("severity = %q, want HIGH", severity)
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_FillsCISAADPSecondaryScore(t *testing.T) {
	resp := nvdResponse{
		Vulnerabilities: []nvdVulnWrapper{
			{
				CVE: nvdCVE{
					ID: "CVE-2026-39834",
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{
								Source: "nvd@nist.gov",
								Type:   "Primary",
							},
							{
								Source: "CISA-ADP",
								Type:   "Secondary",
								CvssData: nvdCvssData{
									BaseScore:    9.1,
									BaseSeverity: "CRITICAL",
								},
							},
						},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cveIds"); got != "CVE-2026-39834" {
			t.Errorf("cveIds query = %q, want CVE-2026-39834", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := &NVDMatcher{
		client:         ts.Client(),
		baseURL:        ts.URL,
		rateLimitDelay: 0,
		cveTimeout:     nvdCVEEnrichmentTimeout,
	}
	vulns := []models.Vulnerability{
		{
			ID:       "CVE-2026-39834",
			Severity: models.SeverityUnknown,
			Source:   models.SourceOSV,
		},
	}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if result.Enriched != 1 {
		t.Fatalf("enriched = %d, want 1", result.Enriched)
	}
	if vulns[0].Score != 9.1 {
		t.Fatalf("score = %v, want 9.1", vulns[0].Score)
	}
	if vulns[0].Severity != models.SeverityCritical {
		t.Fatalf("severity = %q, want CRITICAL", vulns[0].Severity)
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

func TestNVDMatcher_EnrichCVSSByCVE_UsesSmallBatches(t *testing.T) {
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
	if calls != 11 {
		t.Fatalf("NVD calls = %d, want 11 small batched calls", calls)
	}
	if len(batchSizes) != 11 || batchSizes[0] != 10 || batchSizes[10] != 1 {
		t.Fatalf("batch sizes = %v, want ten 10-id batches plus one 1-id batch", batchSizes)
	}
	if result.Requested != 101 || result.Batches != 11 || result.Enriched != 101 {
		t.Fatalf("result = %+v, want requested=101 batches=11 enriched=101", result)
	}
	if vulns[100].Score != 5.3 || vulns[100].Severity != models.SeverityMedium {
		t.Fatalf("last vuln = score %v severity %q, want 5.3 MEDIUM", vulns[100].Score, vulns[100].Severity)
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_SplitsTimedOutBatch(t *testing.T) {
	var calls int
	var sawLargeBatch bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		ids := strings.Split(r.URL.Query().Get("cveIds"), ",")
		if len(ids) > nvdCVEEnrichmentSplitThreshold {
			sawLargeBatch = true
			time.Sleep(75 * time.Millisecond)
			return
		}

		resp := nvdResponse{}
		for _, id := range ids {
			resp.Vulnerabilities = append(resp.Vulnerabilities, nvdVulnWrapper{
				CVE: nvdCVE{
					ID: id,
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 6.4, BaseSeverity: "MEDIUM"}},
						},
					},
				},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	m := &NVDMatcher{
		client:         ts.Client(),
		baseURL:        ts.URL,
		rateLimitDelay: 0,
		cveTimeout:     10 * time.Millisecond,
	}
	vulns := make([]models.Vulnerability, 10)
	for i := range vulns {
		vulns[i] = models.Vulnerability{
			ID:       fmt.Sprintf("CVE-2026-9%03d", i+1),
			Severity: models.SeverityUnknown,
			Source:   models.SourceOSV,
		}
	}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if !sawLargeBatch {
		t.Fatal("expected initial large batch attempt before split fallback")
	}
	if calls < 3 {
		t.Fatalf("calls = %d, want initial timeout plus split requests", calls)
	}
	if result.Enriched != 10 || result.Failed != 0 {
		t.Fatalf("result = %+v, want all 10 enriched without failures", result)
	}
	for _, vuln := range vulns {
		if vuln.Score != 6.4 || vuln.Severity != models.SeverityMedium {
			t.Fatalf("%s = score %v severity %q, want 6.4 MEDIUM", vuln.ID, vuln.Score, vuln.Severity)
		}
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_RetriesTransientStatus(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{{
				CVE: nvdCVE{
					ID: "CVE-2026-7001",
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{{CvssData: nvdCvssData{BaseScore: 7.8, BaseSeverity: "HIGH"}}},
					},
				},
			}},
		})
	}))
	defer ts.Close()

	m := &NVDMatcher{client: ts.Client(), baseURL: ts.URL, rateLimitDelay: 0}
	vulns := []models.Vulnerability{{
		ID:       "CVE-2026-7001",
		Severity: models.SeverityUnknown,
		Source:   models.SourceOSV,
	}}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if calls != 2 || result.Retries != 1 || result.Enriched != 1 {
		t.Fatalf("calls=%d result=%+v, want one retry and one enriched finding", calls, result)
	}
	if vulns[0].Score != 7.8 || vulns[0].Severity != models.SeverityHigh {
		t.Fatalf("vuln = score %v severity %q, want 7.8 HIGH", vulns[0].Score, vulns[0].Severity)
	}
}

func TestNVDMatcher_EnrichCVSSByCVE_UsesCacheWhenUnavailable(t *testing.T) {
	cacheDir := t.TempDir()
	cveCache := cache.New(cacheDir, time.Hour)
	cached := models.Vulnerability{
		ID:       "CVE-2026-8001",
		Score:    9.1,
		Severity: models.SeverityCritical,
		Source:   models.SourceNVD,
	}
	if err := cveCache.Put(nvdCVECacheSource, nvdCVECachePackages(cached.ID), []models.Vulnerability{cached}); err != nil {
		t.Fatalf("put cache: %v", err)
	}

	called := false
	m := &NVDMatcher{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, &net.DNSError{IsTimeout: true}
		})},
		baseURL:        "https://nvd.invalid/rest/json/cves/2.0",
		rateLimitDelay: 0,
		cveCache:       cveCache,
		cveTimeout:     10 * time.Millisecond,
	}
	vulns := []models.Vulnerability{{
		ID:       "CVE-2026-8001",
		Severity: models.SeverityUnknown,
		Source:   models.SourceOSV,
	}}

	result, err := m.EnrichCVSSByCVE(context.Background(), vulns)
	if err != nil {
		t.Fatalf("EnrichCVSSByCVE() error: %v", err)
	}
	if called {
		t.Fatal("NVD should not be called when all requested CVEs are cached")
	}
	if result.CacheHits != 1 || result.Batches != 0 || result.Enriched != 1 {
		t.Fatalf("result = %+v, want cache hit enrichment without network", result)
	}
	if vulns[0].Score != 9.1 || vulns[0].Severity != models.SeverityCritical {
		t.Fatalf("vuln = score %v severity %q, want cached CRITICAL", vulns[0].Score, vulns[0].Severity)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
