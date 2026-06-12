package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// kevDefaultURL is the CISA Known Exploited Vulnerabilities catalog feed.
const kevDefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVEnricher downloads the CISA Known Exploited Vulnerabilities (KEV)
// catalog and flags vulnerabilities that are being actively exploited in
// the wild. KEV is an authoritative, freely available US-CERT source and
// requires no API key. It is an enrichment layer, not a matcher: it never
// adds new findings, it only annotates existing ones.
type KEVEnricher struct {
	client  *http.Client
	baseURL string
}

// NewKEVEnricher creates a new CISA KEV enrichment source.
func NewKEVEnricher() *KEVEnricher {
	return &KEVEnricher{
		client:  sharedHTTPClient,
		baseURL: kevDefaultURL,
	}
}

type kevCatalog struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID string `json:"cveID"`
}

// Enrich downloads the KEV catalog and sets KnownExploited on every
// vulnerability whose CVE ID (or alias) appears in the catalog. Failures are
// returned as an error but never remove or alter existing findings.
func (k *KEVEnricher) Enrich(ctx context.Context, vulns []models.Vulnerability) error {
	if len(vulns) == 0 {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.baseURL, nil)
	if err != nil {
		return fmt.Errorf("create kev request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("kev catalog request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kev catalog returned status %d", resp.StatusCode)
	}

	var catalog kevCatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return fmt.Errorf("decode kev catalog: %w", err)
	}

	exploited := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, e := range catalog.Vulnerabilities {
		if e.CVEID != "" {
			exploited[strings.ToUpper(e.CVEID)] = true
		}
	}

	for i := range vulns {
		if exploited[strings.ToUpper(vulns[i].ID)] {
			vulns[i].KnownExploited = true
			continue
		}
		for _, alias := range vulns[i].Aliases {
			if exploited[strings.ToUpper(alias)] {
				vulns[i].KnownExploited = true
				break
			}
		}
	}

	return nil
}
