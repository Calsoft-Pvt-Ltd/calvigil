package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDMatcher queries the NIST National Vulnerability Database.
type NVDMatcher struct {
	client *http.Client
	apiKey string
}

// NewNVDMatcher creates a new NVD matcher. apiKey is optional but recommended for higher rate limits.
func NewNVDMatcher(apiKey string) *NVDMatcher {
	return &NVDMatcher{
		client: sharedHTTPClient,
		apiKey: apiKey,
	}
}

func (m *NVDMatcher) Name() string { return "nvd" }

type nvdResponse struct {
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
}

type nvdCvssMetric struct {
	CvssData nvdCvssData `json:"cvssData"`
}

type nvdCvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdReference struct {
	URL string `json:"url"`
}

func (m *NVDMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// NVD doesn't have a batch API for package queries, so we search by keyword
	// To avoid excessive API calls, we query by unique package names only
	seen := make(map[string]bool)
	var uniqueNames []string
	pkgMap := make(map[string]models.Package)

	for _, pkg := range packages {
		if !seen[pkg.Name] {
			seen[pkg.Name] = true
			uniqueNames = append(uniqueNames, pkg.Name)
			pkgMap[pkg.Name] = pkg
		}
	}

	// Limit to 20 NVD queries to keep scan times reasonable.
	if len(uniqueNames) > 20 {
		uniqueNames = uniqueNames[:20]
	}

	// NVD rate limits: 5 req/30s without key (~6s gap), 50 req/30s with key (~600ms gap).
	// Use bounded concurrency that respects these limits.
	concurrency := 1
	if m.apiKey != "" {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)

	delay := 6 * time.Second
	if m.apiKey != "" {
		delay = 600 * time.Millisecond
	}

	type nvdResult struct {
		vulns []models.Vulnerability
	}
	results := make([]nvdResult, len(uniqueNames))
	var wg sync.WaitGroup

	for i, name := range uniqueNames {
		// Stagger requests using rate-limit delay.
		if i > 0 {
			select {
			case <-ctx.Done():
				break
			case <-time.After(delay):
			}
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, n string) {
			defer wg.Done()
			defer func() { <-sem }()
			vulns, err := m.queryPackage(ctx, n, pkgMap[n])
			if err == nil {
				results[idx] = nvdResult{vulns: vulns}
			}
		}(i, name)
	}
	wg.Wait()

	var allVulns []models.Vulnerability
	for _, r := range results {
		allVulns = append(allVulns, r.vulns...)
	}
	return allVulns, nil
}

func (m *NVDMatcher) queryPackage(ctx context.Context, keyword string, pkg models.Package) ([]models.Vulnerability, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "10")

	reqURL := nvdBaseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	if m.apiKey != "" {
		req.Header.Set("apiKey", m.apiKey)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd api returned status %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode nvd response: %w", err)
	}

	var vulns []models.Vulnerability
	for _, wrapper := range nvdResp.Vulnerabilities {
		cve := wrapper.CVE

		summary := ""
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				summary = desc.Value
				break
			}
		}

		severity := models.SeverityUnknown
		var score float64
		if len(cve.Metrics.CvssMetricV31) > 0 {
			metric := cve.Metrics.CvssMetricV31[0]
			score = metric.CvssData.BaseScore
			severity = models.ParseSeverity(metric.CvssData.BaseSeverity)
		}

		var refs []string
		for _, ref := range cve.References {
			refs = append(refs, ref.URL)
		}

		vulns = append(vulns, models.Vulnerability{
			ID:         cve.ID,
			Summary:    summary,
			Severity:   severity,
			Score:      score,
			Package:    pkg,
			References: refs,
			Source:     models.SourceNVD,
		})
	}

	return vulns, nil
}
