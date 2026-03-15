package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/models"
)

// CycloneDXReporter outputs scan results as a CycloneDX v1.5 BOM with VDR (vulnerability data).
type CycloneDXReporter struct{}

// CycloneDX v1.5 types

type cdxBOM struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []cdxComponent     `json:"components,omitempty"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Group   string `json:"group,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

type cdxVulnerability struct {
	BOMRef      string        `json:"bom-ref,omitempty"`
	ID          string        `json:"id"`
	Source      *cdxSource    `json:"source,omitempty"`
	Ratings     []cdxRating   `json:"ratings,omitempty"`
	CWEs        []int         `json:"cwes,omitempty"`
	Description string        `json:"description,omitempty"`
	Detail      string        `json:"detail,omitempty"`
	Advisories  []cdxAdvisory `json:"advisories,omitempty"`
	Affects     []cdxAffects  `json:"affects,omitempty"`
	Analysis    *cdxAnalysis  `json:"analysis,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxRating struct {
	Source   *cdxSource `json:"source,omitempty"`
	Score    float64    `json:"score,omitempty"`
	Severity string     `json:"severity,omitempty"`
	Method   string     `json:"method,omitempty"`
}

type cdxAdvisory struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

type cdxAffects struct {
	Ref      string       `json:"ref"`
	Versions []cdxVersion `json:"versions,omitempty"`
}

type cdxVersion struct {
	Version string `json:"version,omitempty"`
	Status  string `json:"status"`
}

type cdxAnalysis struct {
	State         string `json:"state,omitempty"`
	Detail        string `json:"detail,omitempty"`
	Justification string `json:"justification,omitempty"`
}

func (r *CycloneDXReporter) Report(result *models.ScanResult, w io.Writer) error {
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", generateUUID(result)),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: result.ScannedAt.UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{Vendor: "calvigil", Name: "calvigil", Version: "0.1.0"},
			},
		},
	}

	// Build component inventory from packages in vulnerabilities
	componentMap := make(map[string]*cdxComponent)
	for _, v := range result.Vulnerabilities {
		if v.Package.Name == "" {
			continue
		}
		key := v.Package.PURL
		if key == "" {
			key = v.Package.Name + "@" + v.Package.Version
		}
		if _, exists := componentMap[key]; !exists {
			comp := &cdxComponent{
				Type:    "library",
				BOMRef:  key,
				Name:    v.Package.Name,
				Version: v.Package.Version,
				PURL:    v.Package.PURL,
			}
			componentMap[key] = comp
		}
	}

	for _, comp := range componentMap {
		bom.Components = append(bom.Components, *comp)
	}

	// Build vulnerability entries
	for _, v := range result.Vulnerabilities {
		cdxVuln := cdxVulnerability{
			ID:          v.ID,
			Description: v.Summary,
			Detail:      v.Details,
			Source:      vulnSourceToCDXSource(v.Source),
		}

		// Ratings
		if v.Score > 0 || v.Severity != models.SeverityUnknown {
			rating := cdxRating{
				Severity: strings.ToLower(string(v.Severity)),
			}
			if v.Score > 0 {
				rating.Score = v.Score
				rating.Method = "CVSSv3"
			}
			cdxVuln.Ratings = []cdxRating{rating}
		}

		// Advisories from references
		for _, ref := range v.References {
			cdxVuln.Advisories = append(cdxVuln.Advisories, cdxAdvisory{URL: ref})
		}

		// Affects
		if v.Package.Name != "" {
			ref := v.Package.PURL
			if ref == "" {
				ref = v.Package.Name + "@" + v.Package.Version
			}
			affects := cdxAffects{
				Ref: ref,
				Versions: []cdxVersion{
					{Version: v.Package.Version, Status: "affected"},
				},
			}
			cdxVuln.Affects = []cdxAffects{affects}
		}

		// Analysis from AI enrichment
		if v.AIEnrichment != nil {
			analysis := &cdxAnalysis{}
			if v.AIEnrichment.Confidence == "LOW" {
				analysis.State = "false_positive"
			} else if v.AIEnrichment.Confidence == "HIGH" {
				analysis.State = "exploitable"
			} else {
				analysis.State = "in_triage"
			}
			if v.AIEnrichment.SuppressionRationale != "" {
				analysis.Justification = "requires_environment"
				analysis.Detail = v.AIEnrichment.SuppressionRationale
			}
			cdxVuln.Analysis = analysis
		}

		bom.Vulnerabilities = append(bom.Vulnerabilities, cdxVuln)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(bom)
}

func vulnSourceToCDXSource(source models.VulnerabilitySource) *cdxSource {
	switch source {
	case models.SourceOSV:
		return &cdxSource{Name: "OSV", URL: "https://osv.dev"}
	case models.SourceNVD:
		return &cdxSource{Name: "NVD", URL: "https://nvd.nist.gov"}
	case models.SourceGitHubAdv:
		return &cdxSource{Name: "GitHub Advisory", URL: "https://github.com/advisories"}
	case models.SourceSemgrep:
		return &cdxSource{Name: "Semgrep"}
	case models.SourcePatternMatch:
		return &cdxSource{Name: "Pattern Scanner"}
	case models.SourceAIAnalysis:
		return &cdxSource{Name: "AI Analysis"}
	default:
		return &cdxSource{Name: string(source)}
	}
}

// generateUUID creates a deterministic UUID-like string for the BOM serial number.
func generateUUID(result *models.ScanResult) string {
	// Simple hash-based approach from project path + timestamp
	h := uint64(0)
	for _, c := range result.ProjectPath {
		h = h*31 + uint64(c)
	}
	h += uint64(result.ScannedAt.UnixNano())

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		h&0xFFFFFFFF,
		(h>>32)&0xFFFF,
		(h>>48)&0x0FFF|0x4000, // version 4
		(h>>60)&0x3F|0x80,     // variant
		h&0xFFFFFFFFFFFF,
	)
}
