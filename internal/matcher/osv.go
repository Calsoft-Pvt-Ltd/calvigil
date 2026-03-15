package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/models"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// OSVMatcher queries the OSV.dev vulnerability database.
type OSVMatcher struct {
	client *http.Client
}

// NewOSVMatcher creates a new OSV matcher.
func NewOSVMatcher() *OSVMatcher {
	return &OSVMatcher{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *OSVMatcher) Name() string { return "osv" }

// osvBatchRequest is the batch query format for OSV API.
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	Severity         []osvSeverity          `json:"severity"`
	Affected         []osvAffected          `json:"affected"`
	References       []osvReference         `json:"references"`
	Published        time.Time              `json:"published"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package    osvPackage    `json:"package"`
	Ranges     []osvRange    `json:"ranges"`
	Severities []osvSeverity `json:"severity"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ecosystemMap converts our internal ecosystem names to OSV API names.
var ecosystemMap = map[models.Ecosystem]string{
	models.EcosystemGo:    "Go",
	models.EcosystemPyPI:  "PyPI",
	models.EcosystemNpm:   "npm",
	models.EcosystemMaven: "Maven",
}

func (m *OSVMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// Build batch request — process in chunks of 1000 (OSV limit)
	var allVulns []models.Vulnerability
	chunkSize := 1000

	for i := 0; i < len(packages); i += chunkSize {
		end := i + chunkSize
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[i:end]

		vulns, err := m.queryBatch(ctx, chunk)
		if err != nil {
			return allVulns, err
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (m *OSVMatcher) queryBatch(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	batchReq := osvBatchRequest{
		Queries: make([]osvQuery, len(packages)),
	}

	for i, pkg := range packages {
		eco := ecosystemMap[pkg.Ecosystem]
		if eco == "" {
			eco = string(pkg.Ecosystem)
		}
		batchReq.Queries[i] = osvQuery{
			Package: osvPackage{
				Name:      pkg.Name,
				Ecosystem: eco,
			},
			Version: pkg.Version,
		}
	}

	body, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api returned status %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	// The batch endpoint only returns vuln IDs. We need to fetch full details
	// for each matched vulnerability individually.
	var vulns []models.Vulnerability
	seen := make(map[string]bool)

	for i, result := range batchResp.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]

		// Skip packages with invalid names (e.g. parsing artifacts)
		if pkg.Name == "" || pkg.Name == "\"" || len(pkg.Name) < 2 {
			continue
		}

		for _, batchVuln := range result.Vulns {
			// Deduplicate within the batch (same vuln can match multiple packages)
			vulnKey := batchVuln.ID + "|" + pkg.Name
			if seen[vulnKey] {
				continue
			}
			seen[vulnKey] = true

			// Fetch full vulnerability details
			fullVuln, err := m.fetchVulnDetails(ctx, batchVuln.ID)
			if err != nil {
				// Fall back to minimal data from batch response
				vulns = append(vulns, models.Vulnerability{
					ID:      batchVuln.ID,
					Aliases: batchVuln.Aliases,
					Summary: batchVuln.Summary,
					Package: pkg,
					Source:  models.SourceOSV,
				})
				continue
			}

			vuln := models.Vulnerability{
				ID:          fullVuln.ID,
				Aliases:     fullVuln.Aliases,
				Summary:     fullVuln.Summary,
				Details:     fullVuln.Details,
				Severity:    parseSeverityWithFallback(fullVuln),
				Package:     pkg,
				Source:      models.SourceOSV,
				PublishedAt: fullVuln.Published,
			}

			// Also extract CVSS score as a numeric value
			vuln.Score = extractCVSSScore(fullVuln.Severity)

			// Extract fixed version from affected ranges
			for _, affected := range fullVuln.Affected {
				for _, r := range affected.Ranges {
					for _, event := range r.Events {
						if event.Fixed != "" {
							vuln.FixedIn = event.Fixed
						}
					}
				}
			}

			// Extract references
			for _, ref := range fullVuln.References {
				vuln.References = append(vuln.References, ref.URL)
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

const osvVulnURL = "https://api.osv.dev/v1/vulns/"

// fetchVulnDetails retrieves full vulnerability details from OSV by ID.
func (m *OSVMatcher) fetchVulnDetails(ctx context.Context, id string) (*osvVuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvVulnURL+id, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln api returned status %d for %s", resp.StatusCode, id)
	}

	var vuln osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, err
	}

	return &vuln, nil
}

// parseSeverity converts OSV severity entries to our Severity type.
func parseSeverity(severities []osvSeverity) models.Severity {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			return cvssVectorToSeverity(s.Score)
		}
	}
	// Try CVSS_V2 as fallback
	for _, s := range severities {
		if s.Type == "CVSS_V2" {
			return cvssVectorToSeverity(s.Score)
		}
	}
	return models.SeverityUnknown
}

// parseSeverityWithFallback tries CVSS vectors first, then falls back to
// database_specific.severity which many GHSA entries use.
func parseSeverityWithFallback(vuln *osvVuln) models.Severity {
	sev := parseSeverity(vuln.Severity)
	if sev != models.SeverityUnknown {
		return sev
	}

	// Fall back to database_specific.severity (used by GitHub Advisory)
	if vuln.DatabaseSpecific != nil {
		if sevStr, ok := vuln.DatabaseSpecific["severity"].(string); ok {
			switch strings.ToUpper(sevStr) {
			case "CRITICAL":
				return models.SeverityCritical
			case "HIGH":
				return models.SeverityHigh
			case "MODERATE", "MEDIUM":
				return models.SeverityMedium
			case "LOW":
				return models.SeverityLow
			}
		}
	}

	// Also check affected[].database_specific.severity
	for _, aff := range vuln.Affected {
		for _, sev := range aff.Severities {
			if sev.Type == "CVSS_V3" {
				return cvssVectorToSeverity(sev.Score)
			}
		}
	}

	return models.SeverityUnknown
}

// extractCVSSScore extracts the numeric CVSS base score from severity entries.
func extractCVSSScore(severities []osvSeverity) float64 {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			return computeCVSS3BaseScore(s.Score)
		}
	}
	return 0
}

// cvssVectorToSeverity converts a CVSS v3 vector string to a severity level.
// Vector format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
func cvssVectorToSeverity(vector string) models.Severity {
	score := computeCVSS3BaseScore(vector)
	if score == 0 {
		return models.SeverityUnknown
	}
	return scoreToSeverity(score)
}

// scoreToSeverity maps a numeric CVSS score to a severity level.
func scoreToSeverity(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}

// computeCVSS3BaseScore calculates the CVSS v3 base score from a vector string.
// Implements the CVSS v3.1 specification for base score calculation.
func computeCVSS3BaseScore(vector string) float64 {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return 0
	}

	metrics := make(map[string]string)
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// Attack Vector
	var av float64
	switch metrics["AV"] {
	case "N":
		av = 0.85
	case "A":
		av = 0.62
	case "L":
		av = 0.55
	case "P":
		av = 0.20
	default:
		return 0
	}

	// Attack Complexity
	var ac float64
	switch metrics["AC"] {
	case "L":
		ac = 0.77
	case "H":
		ac = 0.44
	default:
		return 0
	}

	// Privileges Required (depends on Scope)
	scope := metrics["S"]
	var pr float64
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if scope == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scope == "C" {
			pr = 0.50
		} else {
			pr = 0.27
		}
	default:
		return 0
	}

	// User Interaction
	var ui float64
	switch metrics["UI"] {
	case "N":
		ui = 0.85
	case "R":
		ui = 0.62
	default:
		return 0
	}

	// Confidentiality, Integrity, Availability Impact
	impactValue := func(val string) float64 {
		switch val {
		case "H":
			return 0.56
		case "L":
			return 0.22
		case "N":
			return 0.0
		default:
			return -1
		}
	}

	c := impactValue(metrics["C"])
	i := impactValue(metrics["I"])
	a := impactValue(metrics["A"])
	if c < 0 || i < 0 || a < 0 {
		return 0
	}

	// ISS = 1 - [(1 - Confidentiality) × (1 - Integrity) × (1 - Availability)]
	iss := 1 - (1-c)*(1-i)*(1-a)

	// Impact
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		return 0
	}

	if impact <= 0 {
		return 0
	}

	// Exploitability = 8.22 × AV × AC × PR × UI
	exploitability := 8.22 * av * ac * pr * ui

	// Base Score
	var base float64
	if scope == "U" {
		base = math.Min(impact+exploitability, 10)
	} else {
		base = math.Min(1.08*(impact+exploitability), 10)
	}

	// Round up to one decimal place
	return roundUp(base)
}

// roundUp rounds a float64 up to the nearest tenth per CVSS spec.
func roundUp(val float64) float64 {
	return math.Ceil(val*10) / 10
}
