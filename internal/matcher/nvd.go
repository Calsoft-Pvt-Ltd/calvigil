package matcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const nvdCVEEnrichmentBatchSize = 100

// NVDMatcher queries the NIST National Vulnerability Database.
type NVDMatcher struct {
	client         *http.Client
	apiKey         string
	baseURL        string
	rateLimitDelay time.Duration
}

// NewNVDMatcher creates a new NVD matcher. apiKey is optional but recommended for higher rate limits.
func NewNVDMatcher(apiKey string) *NVDMatcher {
	return &NVDMatcher{
		client:         sharedHTTPClient,
		apiKey:         apiKey,
		baseURL:        nvdBaseURL,
		rateLimitDelay: nvdRequestDelay(apiKey),
	}
}

func (m *NVDMatcher) Name() string { return "nvd" }

// NVDEnrichmentResult summarizes a best-effort CVSS enrichment pass.
type NVDEnrichmentResult struct {
	Requested int
	Enriched  int
	Batches   int
}

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
	CvssMetricV40 []nvdCvssMetric `json:"cvssMetricV40"`
	CvssMetricV31 []nvdCvssMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCvssMetric `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCvssMetric `json:"cvssMetricV2"`
}

type nvdCvssMetric struct {
	CvssData     nvdCvssData `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity"`
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
	// Dispatch sequentially with delay between sends to respect rate limits.
	delay := nvdRequestDelay(m.apiKey)

	type nvdResult struct {
		vulns []models.Vulnerability
		err   error
	}
	results := make([]nvdResult, len(uniqueNames))
	var wg sync.WaitGroup

	cancelled := false
dispatch:
	for i, name := range uniqueNames {
		// Rate-limit: wait before dispatching each request (except the first).
		if i > 0 {
			select {
			case <-ctx.Done():
				cancelled = true
				break dispatch
			case <-time.After(delay):
			}
		}

		wg.Add(1)
		go func(idx int, n string) {
			defer wg.Done()
			vulns, err := m.queryPackage(ctx, n, pkgMap[n])
			results[idx] = nvdResult{vulns: vulns, err: err}
		}(i, name)
	}
	wg.Wait()

	var allVulns []models.Vulnerability
	var errs []error
	for _, r := range results {
		allVulns = append(allVulns, r.vulns...)
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}
	if cancelled {
		return allVulns, ctx.Err()
	}
	// Keep partial results; only report failure when every query failed so
	// the aggregator can surface it to the user instead of silently
	// returning an empty result set.
	if len(errs) > 0 && len(errs) == len(uniqueNames) {
		return nil, fmt.Errorf("all nvd queries failed: %w", errors.Join(errs...))
	}
	return allVulns, nil
}

func (m *NVDMatcher) queryPackage(ctx context.Context, keyword string, pkg models.Package) ([]models.Vulnerability, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "10")

	reqURL := m.endpoint() + "?" + params.Encode()

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
		vuln := nvdCVEToVulnerability(wrapper.CVE)
		vuln.Package = pkg
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// EnrichCVSSByCVE fills missing severity/CVSS score fields for already-detected
// CVE findings. It does not create new vulnerabilities; it only asks NVD for
// the exact CVE IDs that another source already reported.
func (m *NVDMatcher) EnrichCVSSByCVE(ctx context.Context, vulns []models.Vulnerability) (NVDEnrichmentResult, error) {
	cveIDs := cveIDsNeedingNVDCVSS(vulns)
	result := NVDEnrichmentResult{Requested: len(cveIDs)}
	if len(cveIDs) == 0 {
		return result, nil
	}

	records := make(map[string]models.Vulnerability, len(cveIDs))
	var errs []error
	chunks := chunkStrings(cveIDs, nvdCVEEnrichmentBatchSize)
	result.Batches = len(chunks)
	for i, chunk := range chunks {
		if i > 0 && m.rateLimitDelay > 0 {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-time.After(m.rateLimitDelay):
			}
		}

		batchRecords, err := m.queryCVEs(ctx, chunk)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for cveID, v := range batchRecords {
			records[cveID] = v
		}
	}

	for i := range vulns {
		for _, cveID := range cveIDsForVulnerability(vulns[i]) {
			src, ok := records[cveID]
			if !ok {
				continue
			}
			if applyNVDCVSSEnrichment(&vulns[i], src) {
				result.Enriched++
			}
			break
		}
	}

	if len(errs) > 0 && len(records) == 0 {
		return result, fmt.Errorf("all nvd cve enrichment lookups failed: %w", errors.Join(errs...))
	}
	return result, nil
}

func (m *NVDMatcher) queryCVEs(ctx context.Context, cveIDs []string) (map[string]models.Vulnerability, error) {
	records := make(map[string]models.Vulnerability, len(cveIDs))
	if len(cveIDs) == 0 {
		return records, nil
	}

	params := url.Values{}
	params.Set("cveIds", strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint()+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if m.apiKey != "" {
		req.Header.Set("apiKey", m.apiKey)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd cve lookup failed for %d id(s): %w", len(cveIDs), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd cve lookup for %d id(s) returned status %d", len(cveIDs), resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode nvd cve lookup for %d id(s): %w", len(cveIDs), err)
	}

	for _, wrapper := range nvdResp.Vulnerabilities {
		v := nvdCVEToVulnerability(wrapper.CVE)
		cveID := normalizeCVEID(v.ID)
		if cveID == "" {
			continue
		}
		records[cveID] = v
	}

	return records, nil
}

func (m *NVDMatcher) endpoint() string {
	if m.baseURL != "" {
		return m.baseURL
	}
	return nvdBaseURL
}

func nvdRequestDelay(apiKey string) time.Duration {
	if apiKey != "" {
		return 650 * time.Millisecond
	}
	return 6 * time.Second
}

func nvdCVEToVulnerability(cve nvdCVE) models.Vulnerability {
	summary := ""
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			summary = desc.Value
			break
		}
	}

	score, severity := bestNVDCVSS(cve.Metrics)

	var refs []string
	for _, ref := range cve.References {
		refs = append(refs, ref.URL)
	}

	vuln := models.Vulnerability{
		ID:         cve.ID,
		Summary:    summary,
		Severity:   severity,
		Score:      score,
		References: refs,
		Source:     models.SourceNVD,
	}
	if published, err := time.Parse(time.RFC3339, cve.Published); err == nil {
		vuln.PublishedAt = published
	} else if published, err := time.Parse("2006-01-02T15:04:05.000", cve.Published); err == nil {
		vuln.PublishedAt = published
	}
	return vuln
}

func bestNVDCVSS(metrics nvdMetrics) (float64, models.Severity) {
	for _, candidates := range [][]nvdCvssMetric{
		metrics.CvssMetricV31,
		metrics.CvssMetricV30,
		metrics.CvssMetricV40,
		metrics.CvssMetricV2,
	} {
		for _, metric := range candidates {
			score := metric.CvssData.BaseScore
			severity := models.ParseSeverity(metric.CvssData.BaseSeverity)
			if severity == models.SeverityUnknown {
				severity = models.ParseSeverity(metric.BaseSeverity)
			}
			if severity == models.SeverityUnknown && score > 0 {
				severity = models.ScoreToSeverity(score)
			}
			if score > 0 || severity != models.SeverityUnknown {
				return score, severity
			}
		}
	}
	return 0, models.SeverityUnknown
}

func cveIDsNeedingNVDCVSS(vulns []models.Vulnerability) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, vuln := range vulns {
		if vuln.Score > 0 && vuln.Severity != "" && vuln.Severity != models.SeverityUnknown {
			continue
		}
		for _, cveID := range cveIDsForVulnerability(vuln) {
			if seen[cveID] {
				continue
			}
			seen[cveID] = true
			ids = append(ids, cveID)
		}
	}
	return ids
}

func cveIDsForVulnerability(vuln models.Vulnerability) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, candidate := range append([]string{vuln.ID}, vuln.Aliases...) {
		cveID := normalizeCVEID(candidate)
		if cveID == "" || seen[cveID] {
			continue
		}
		seen[cveID] = true
		ids = append(ids, cveID)
	}
	return ids
}

func normalizeCVEID(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if !strings.HasPrefix(id, "CVE-") {
		return ""
	}
	return id
}

func chunkStrings(values []string, size int) [][]string {
	if size <= 0 || len(values) == 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, values[start:end])
	}
	return chunks
}

func applyNVDCVSSEnrichment(dst *models.Vulnerability, src models.Vulnerability) bool {
	changed := false
	if dst.Score == 0 && src.Score > 0 {
		dst.Score = src.Score
		changed = true
	}
	if (dst.Severity == "" || dst.Severity == models.SeverityUnknown) && src.Severity != models.SeverityUnknown && src.Severity != "" {
		dst.Severity = src.Severity
		changed = true
	}
	if (dst.Severity == "" || dst.Severity == models.SeverityUnknown) && dst.Score > 0 {
		dst.Severity = models.ScoreToSeverity(dst.Score)
		changed = true
	}
	if dst.Summary == "" && src.Summary != "" {
		dst.Summary = src.Summary
		changed = true
	}
	if dst.PublishedAt.IsZero() && !src.PublishedAt.IsZero() {
		dst.PublishedAt = src.PublishedAt
		changed = true
	}

	seenRefs := make(map[string]bool, len(dst.References))
	for _, ref := range dst.References {
		seenRefs[ref] = true
	}
	for _, ref := range src.References {
		if ref == "" || seenRefs[ref] {
			continue
		}
		dst.References = append(dst.References, ref)
		seenRefs[ref] = true
		changed = true
	}

	return changed
}
