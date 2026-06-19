package matcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/cache"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const nvdCVEEnrichmentBatchSize = 100
const nvdCVEEnrichmentSplitThreshold = 5
const nvdCVEEnrichmentMaxAttempts = 3
const nvdCVEEnrichmentTimeout = 2 * time.Minute
const nvdCVEEnrichmentBudget = 10 * time.Minute
const nvdCVEEnrichmentPublicConcurrency = 1
const nvdCVEEnrichmentKeyedConcurrency = 4
const nvdCVEBackoffInitial = 5 * time.Second
const nvdCVEBackoffMax = 30 * time.Second
const nvdUserAgent = "calvigil/dev (+https://github.com/Calsoft-Pvt-Ltd/calvigil)"
const nvdCVECacheSource = "nvd-cve-enrichment-v1"
const nvdCVECacheTTL = 24 * time.Hour

var nvdHTTPClient = &http.Client{
	Timeout:   nvdCVEEnrichmentTimeout,
	Transport: sharedHTTPTransport,
}

// NVDMatcher queries the NIST National Vulnerability Database.
type NVDMatcher struct {
	client         *http.Client
	apiKey         string
	baseURL        string
	rateLimitDelay time.Duration
	cveCache       *cache.Cache
	cveTimeout     time.Duration
	cveBackoffBase time.Duration
}

// NewNVDMatcher creates a new NVD matcher. apiKey is optional but recommended for higher rate limits.
func NewNVDMatcher(apiKey string) *NVDMatcher {
	return &NVDMatcher{
		client:         nvdHTTPClient,
		apiKey:         apiKey,
		baseURL:        nvdBaseURL,
		rateLimitDelay: nvdRequestDelay(apiKey),
		cveCache:       cache.New("", nvdCVECacheTTL),
		cveTimeout:     nvdCVEEnrichmentTimeout,
		cveBackoffBase: nvdCVEBackoffInitial,
	}
}

func (m *NVDMatcher) Name() string { return "nvd" }

// SetCacheEnabled controls the local CVE enrichment cache. Scanners call this
// to honor --no-cache while keeping NVD resilience enabled by default.
func (m *NVDMatcher) SetCacheEnabled(enabled bool) {
	if !enabled {
		m.cveCache = nil
		return
	}
	if m.cveCache == nil {
		m.cveCache = cache.New("", nvdCVECacheTTL)
	}
}

// NVDEnrichmentResult summarizes a best-effort CVSS enrichment pass.
type NVDEnrichmentResult struct {
	Requested int
	Enriched  int
	Batches   int
	Workers   int
	CacheHits int
	Failed    int
	Retries   int
}

type nvdCVEQueryStats struct {
	Batches int
	Retries int
}

type nvdCVEQueryResult struct {
	records map[string]models.Vulnerability
	stats   nvdCVEQueryStats
	errs    []error
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
	Source       string      `json:"source"`
	Type         string      `json:"type"`
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

	// Dispatch sequentially with a conservative delay between sends. NVD
	// package keyword search has no batch API, so this path stays deliberately
	// paced even when an API key is configured.
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

	setNVDHeaders(req, m.apiKey)

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
	workCtx, cancel := nvdEnrichmentContext(ctx)
	defer cancel()

	records := make(map[string]models.Vulnerability, len(cveIDs))
	var missing []string
	for _, cveID := range cveIDs {
		if cached, ok := m.getCachedCVE(cveID); ok {
			records[cveID] = cached
			result.CacheHits++
			continue
		}
		missing = append(missing, cveID)
	}

	var errs []error
	chunks := chunkStrings(missing, nvdCVEEnrichmentBatchSize)
	for _, batch := range m.queryCVEBatches(workCtx, chunks) {
		result.Batches += batch.stats.Batches
		result.Retries += batch.stats.Retries
		for cveID, v := range batch.records {
			records[cveID] = v
			m.putCachedCVE(cveID, v)
		}
		errs = append(errs, batch.errs...)
	}
	if len(chunks) > 0 {
		result.Workers = minInt(nvdCVEEnrichmentConcurrency(m.apiKey), len(chunks))
	}

	for _, cveID := range cveIDs {
		if _, ok := records[cveID]; !ok {
			result.Failed++
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

func nvdEnrichmentContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= nvdCVEEnrichmentBudget {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, nvdCVEEnrichmentBudget)
}

func (m *NVDMatcher) queryCVEBatches(ctx context.Context, chunks [][]string) []nvdCVEQueryResult {
	if len(chunks) == 0 {
		return nil
	}

	workerCount := minInt(nvdCVEEnrichmentConcurrency(m.apiKey), len(chunks))
	pacer := newNVDRequestPacer(m.rateLimitDelay)
	jobs := make(chan []string, len(chunks))
	results := make(chan nvdCVEQueryResult, len(chunks))

	for _, chunk := range chunks {
		jobs <- chunk
	}
	close(jobs)

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for chunk := range jobs {
				records, stats, errs := m.queryCVEsAdaptive(ctx, chunk, pacer)
				results <- nvdCVEQueryResult{records: records, stats: stats, errs: errs}
			}
		}()
	}

	wg.Wait()
	close(results)

	batches := make([]nvdCVEQueryResult, 0, len(chunks))
	for result := range results {
		batches = append(batches, result)
	}
	return batches
}

func (m *NVDMatcher) queryCVEsAdaptive(ctx context.Context, cveIDs []string, pacer *nvdRequestPacer) (map[string]models.Vulnerability, nvdCVEQueryStats, []error) {
	records := make(map[string]models.Vulnerability, len(cveIDs))
	var stats nvdCVEQueryStats
	if len(cveIDs) == 0 {
		return records, stats, nil
	}

	attempts := 1
	if len(cveIDs) <= nvdCVEEnrichmentSplitThreshold {
		attempts = nvdCVEEnrichmentMaxAttempts
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := pacer.Wait(ctx); err != nil {
			return records, stats, []error{err}
		}

		stats.Batches++
		batchRecords, err := m.queryCVEs(ctx, cveIDs)
		if err != nil {
			lastErr = err
			if !isTransientNVDError(err) || errors.Is(ctx.Err(), context.Canceled) {
				break
			}
			if attempt < attempts {
				stats.Retries++
				if waitErr := m.waitNVDBackoff(ctx, err, attempt); waitErr != nil {
					return records, stats, []error{waitErr}
				}
			}
			continue
		}
		for cveID, v := range batchRecords {
			records[cveID] = v
		}
		return records, stats, nil
	}

	if lastErr == nil {
		return records, stats, nil
	}
	if len(cveIDs) > 1 && isTransientNVDError(lastErr) {
		if waitErr := m.waitNVDBackoff(ctx, lastErr, attempts); waitErr != nil {
			return records, stats, []error{waitErr}
		}
		mid := len(cveIDs) / 2
		leftRecords, leftStats, leftErrs := m.queryCVEsAdaptive(ctx, cveIDs[:mid], pacer)
		rightRecords, rightStats, rightErrs := m.queryCVEsAdaptive(ctx, cveIDs[mid:], pacer)
		for cveID, v := range leftRecords {
			records[cveID] = v
		}
		for cveID, v := range rightRecords {
			records[cveID] = v
		}
		stats.Batches += leftStats.Batches + rightStats.Batches
		stats.Retries += leftStats.Retries + rightStats.Retries
		return records, stats, append(leftErrs, rightErrs...)
	}

	return records, stats, []error{lastErr}
}

func (m *NVDMatcher) queryCVEs(ctx context.Context, cveIDs []string) (map[string]models.Vulnerability, error) {
	records := make(map[string]models.Vulnerability, len(cveIDs))
	if len(cveIDs) == 0 {
		return records, nil
	}

	reqCtx, cancel := m.cveRequestContext(ctx)
	defer cancel()

	params := url.Values{}
	params.Set("cveIds", strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, m.endpoint()+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	setNVDHeaders(req, m.apiKey)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd cve lookup failed for %d id(s): %w", len(cveIDs), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &nvdStatusError{
			status:     resp.StatusCode,
			ids:        len(cveIDs),
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
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

func setNVDHeaders(req *http.Request, apiKey string) {
	req.Header.Set("User-Agent", nvdUserAgent)
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}
}

func (m *NVDMatcher) cveRequestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := m.cveTimeout
	if timeout <= 0 {
		return ctx, func() {}
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

type nvdStatusError struct {
	status     int
	ids        int
	retryAfter time.Duration
}

func (e *nvdStatusError) Error() string {
	return fmt.Sprintf("nvd cve lookup for %d id(s) returned status %d", e.ids, e.status)
}

func isTransientNVDError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var statusErr *nvdStatusError
	if errors.As(err, &statusErr) {
		switch statusErr.status {
		case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func (m *NVDMatcher) waitNVDBackoff(ctx context.Context, err error, attempt int) error {
	delay := m.nvdBackoffDelay(err, attempt)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (m *NVDMatcher) nvdBackoffDelay(err error, attempt int) time.Duration {
	base := m.cveBackoffBase
	if base < 0 {
		return 0
	}
	if base == 0 {
		base = nvdCVEBackoffInitial
	}
	if attempt < 1 {
		attempt = 1
	}
	delay := base * time.Duration(1<<(attempt-1))
	var statusErr *nvdStatusError
	if errors.As(err, &statusErr) && statusErr.retryAfter > 0 {
		delay = statusErr.retryAfter
	}
	if delay > nvdCVEBackoffMax {
		delay = nvdCVEBackoffMax
	}
	return delay
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		return time.Until(when)
	}
	return 0
}

func (m *NVDMatcher) getCachedCVE(cveID string) (models.Vulnerability, bool) {
	if m.cveCache == nil {
		return models.Vulnerability{}, false
	}
	vulns, ok := m.cveCache.Get(nvdCVECacheSource, nvdCVECachePackages(cveID))
	if !ok || len(vulns) == 0 {
		return models.Vulnerability{}, false
	}
	return vulns[0], true
}

func (m *NVDMatcher) putCachedCVE(cveID string, vuln models.Vulnerability) {
	if m.cveCache == nil || cveID == "" {
		return
	}
	_ = m.cveCache.Put(nvdCVECacheSource, nvdCVECachePackages(cveID), []models.Vulnerability{vuln})
}

func nvdCVECachePackages(cveID string) []models.Package {
	return []models.Package{{
		Name:      cveID,
		Version:   "2.0",
		Ecosystem: models.Ecosystem("NVD"),
	}}
}

func (m *NVDMatcher) endpoint() string {
	if m.baseURL != "" {
		return m.baseURL
	}
	return nvdBaseURL
}

func nvdRequestDelay(apiKey string) time.Duration {
	// NVD publishes higher keyed rate limits, but also recommends clients keep
	// requests paced. Use the conservative interval for reliability; CVE
	// enrichment batches up to 100 IDs per request, so this is still efficient.
	return 6 * time.Second
}

func nvdCVEEnrichmentConcurrency(apiKey string) int {
	if apiKey != "" {
		return nvdCVEEnrichmentKeyedConcurrency
	}
	return nvdCVEEnrichmentPublicConcurrency
}

type nvdRequestPacer struct {
	delay time.Duration
	mu    sync.Mutex
	next  time.Time
}

func newNVDRequestPacer(delay time.Duration) *nvdRequestPacer {
	return &nvdRequestPacer{delay: delay}
}

func (p *nvdRequestPacer) Wait(ctx context.Context) error {
	if p == nil || p.delay <= 0 {
		return nil
	}

	p.mu.Lock()
	now := time.Now()
	if p.next.IsZero() || p.next.Before(now) {
		p.next = now.Add(p.delay)
		p.mu.Unlock()
		return nil
	}
	wait := time.Until(p.next)
	p.next = p.next.Add(p.delay)
	p.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
		if score, severity, ok := bestNVDCVSSCandidate(candidates); ok {
			return score, severity
		}
	}
	return 0, models.SeverityUnknown
}

func bestNVDCVSSCandidate(candidates []nvdCvssMetric) (float64, models.Severity, bool) {
	bestRank := -1
	bestScore := 0.0
	bestSeverity := models.SeverityUnknown

	for _, metric := range candidates {
		score, severity, ok := metricCVSS(metric)
		if !ok {
			continue
		}
		rank := nvdMetricSourceRank(metric)
		if rank > bestRank {
			bestRank = rank
			bestScore = score
			bestSeverity = severity
		}
	}

	if bestRank < 0 {
		return 0, models.SeverityUnknown, false
	}
	return bestScore, bestSeverity, true
}

func metricCVSS(metric nvdCvssMetric) (float64, models.Severity, bool) {
	score := metric.CvssData.BaseScore
	severity := models.ParseSeverity(metric.CvssData.BaseSeverity)
	if severity == models.SeverityUnknown {
		severity = models.ParseSeverity(metric.BaseSeverity)
	}
	if severity == models.SeverityUnknown && score > 0 {
		severity = models.ScoreToSeverity(score)
	}
	return score, severity, score > 0 || severity != models.SeverityUnknown
}

func nvdMetricSourceRank(metric nvdCvssMetric) int {
	source := strings.ToLower(strings.TrimSpace(metric.Source))
	metricType := strings.ToLower(strings.TrimSpace(metric.Type))
	switch {
	case metricType == "primary" || source == "nvd@nist.gov":
		return 3
	case strings.Contains(source, "cisa") || strings.Contains(source, "adp"):
		return 2
	case metricType == "secondary":
		return 1
	default:
		return 0
	}
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
