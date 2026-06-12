package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const (
	ossIndexDefaultURL = "https://ossindex.sonatype.org/api/v3/component-report"
	// OSS Index accepts at most 128 coordinates per request.
	ossIndexBatchSize = 128
)

// OSSIndexMatcher queries the Sonatype OSS Index vulnerability database.
// OSS Index is a free, PURL-based service covering all major ecosystems
// (npm, PyPI, Maven, Go, crates.io, RubyGems, Packagist, Conan, ...).
// Authentication is optional; providing credentials raises rate limits.
type OSSIndexMatcher struct {
	client   *http.Client
	baseURL  string
	username string // optional: OSS Index account email
	token    string // optional: OSS Index API token
}

// NewOSSIndexMatcher creates a new OSS Index matcher. username and token are
// optional; anonymous requests are allowed at a lower rate limit.
func NewOSSIndexMatcher(username, token string) *OSSIndexMatcher {
	return &OSSIndexMatcher{
		client:   sharedHTTPClient,
		baseURL:  ossIndexDefaultURL,
		username: username,
		token:    token,
	}
}

func (m *OSSIndexMatcher) Name() string { return "oss-index" }

type ossIndexRequest struct {
	Coordinates []string `json:"coordinates"`
}

type ossIndexComponent struct {
	Coordinates     string         `json:"coordinates"`
	Description     string         `json:"description"`
	Reference       string         `json:"reference"`
	Vulnerabilities []ossIndexVuln `json:"vulnerabilities"`
}

type ossIndexVuln struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"displayName"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	CVSSScore          float64  `json:"cvssScore"`
	CVSSVector         string   `json:"cvssVector"`
	CVE                string   `json:"cve"`
	Reference          string   `json:"reference"`
	ExternalReferences []string `json:"externalReferences"`
}

func (m *OSSIndexMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// Build PURL coordinates and a reverse lookup back to packages.
	pkgByPURL := make(map[string]models.Package, len(packages))
	var coordinates []string
	for _, pkg := range packages {
		pkg.EnsurePURL()
		if pkg.PURL == "" {
			continue
		}
		key := strings.ToLower(pkg.PURL)
		if _, dup := pkgByPURL[key]; dup {
			continue
		}
		pkgByPURL[key] = pkg
		coordinates = append(coordinates, pkg.PURL)
	}
	if len(coordinates) == 0 {
		return nil, nil
	}

	var allVulns []models.Vulnerability
	for i := 0; i < len(coordinates); i += ossIndexBatchSize {
		end := i + ossIndexBatchSize
		if end > len(coordinates) {
			end = len(coordinates)
		}
		vulns, err := m.queryBatch(ctx, coordinates[i:end], pkgByPURL)
		if err != nil {
			return allVulns, err
		}
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (m *OSSIndexMatcher) queryBatch(ctx context.Context, coordinates []string, pkgByPURL map[string]models.Package) ([]models.Vulnerability, error) {
	body, err := json.Marshal(ossIndexRequest{Coordinates: coordinates})
	if err != nil {
		return nil, fmt.Errorf("marshal oss index request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create oss index request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if m.username != "" && m.token != "" {
		req.SetBasicAuth(m.username, m.token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oss index api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("oss index rate limit exceeded (configure credentials for higher limits)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oss index api returned status %d", resp.StatusCode)
	}

	var components []ossIndexComponent
	if err := json.NewDecoder(resp.Body).Decode(&components); err != nil {
		return nil, fmt.Errorf("decode oss index response: %w", err)
	}

	var vulns []models.Vulnerability
	for _, comp := range components {
		if len(comp.Vulnerabilities) == 0 {
			continue
		}

		// Coordinates come back in the same shape we sent them; strip any
		// qualifiers OSS Index may have appended before lookup.
		coordKey := strings.ToLower(comp.Coordinates)
		if idx := strings.IndexByte(coordKey, '?'); idx >= 0 {
			coordKey = coordKey[:idx]
		}
		pkg, ok := pkgByPURL[coordKey]
		if !ok {
			continue
		}

		for _, v := range comp.Vulnerabilities {
			vulns = append(vulns, ossVulnToModel(v, pkg))
		}
	}

	return vulns, nil
}

// ossVulnToModel converts an OSS Index vulnerability into the canonical model.
func ossVulnToModel(v ossIndexVuln, pkg models.Package) models.Vulnerability {
	// Prefer the CVE as the primary ID; keep the OSS Index identifiers
	// as aliases so the aggregator can deduplicate across sources.
	id := v.CVE
	var aliases []string
	if id == "" {
		id = v.DisplayName
		if id == "" {
			id = v.ID
		}
	} else if v.DisplayName != "" && v.DisplayName != id {
		aliases = append(aliases, v.DisplayName)
	}

	summary := v.Title
	if summary == "" {
		summary = v.Description
	}

	// Severity chain: CVSS score first, then vector computation.
	severity := models.ScoreToSeverity(v.CVSSScore)
	if severity == models.SeverityUnknown && v.CVSSVector != "" {
		severity = cvssVectorToSeverity(v.CVSSVector)
	}

	var refs []string
	if v.Reference != "" {
		refs = append(refs, v.Reference)
	}
	refs = append(refs, v.ExternalReferences...)

	return models.Vulnerability{
		ID:         id,
		Aliases:    aliases,
		Summary:    summary,
		Details:    v.Description,
		Severity:   severity,
		Score:      v.CVSSScore,
		Package:    pkg,
		References: refs,
		Source:     models.SourceOSSIndex,
	}
}
