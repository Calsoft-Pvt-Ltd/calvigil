package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/models"
)

// OpenVEXReporter outputs scan results as an OpenVEX v0.2.0 document.
// OpenVEX (Vulnerability Exploitability eXchange) communicates the exploitability
// status of vulnerabilities in software products.
type OpenVEXReporter struct{}

// OpenVEX v0.2.0 types (https://github.com/openvex/spec)

type vexDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Role       string         `json:"role"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling,omitempty"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexVulnerability `json:"vulnerability"`
	Products        []vexProduct     `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
	StatusNotes     string           `json:"status_notes,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"`
}

type vexVulnerability struct {
	ID          string   `json:"@id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

type vexProduct struct {
	ID            string            `json:"@id"`
	Subcomponents []vexSubcomponent `json:"subcomponents,omitempty"`
}

type vexSubcomponent struct {
	ID string `json:"@id"`
}

func (r *OpenVEXReporter) Report(result *models.ScanResult, w io.Writer) error {
	doc := vexDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("https://calvigil/vex/%s", generateVEXID(result)),
		Author:    "calvigil",
		Role:      "tool",
		Timestamp: result.ScannedAt.UTC().Format(time.RFC3339),
		Version:   1,
		Tooling:   "calvigil/0.1.0",
	}

	// The "product" is the scanned project itself
	productID := "pkg:generic/" + sanitizeProductName(result.ProjectPath)

	for _, v := range result.Vulnerabilities {
		stmt := vexStatement{
			Vulnerability: vexVulnerability{
				Name:        v.ID,
				Description: v.Summary,
				Aliases:     v.Aliases,
			},
			Products: []vexProduct{
				{
					ID: productID,
				},
			},
			Timestamp: result.ScannedAt.UTC().Format(time.RFC3339),
		}

		// Set vulnerability ID using standard scheme
		if strings.HasPrefix(v.ID, "CVE-") {
			stmt.Vulnerability.ID = "https://nvd.nist.gov/vuln/detail/" + v.ID
		} else if strings.HasPrefix(v.ID, "GHSA-") {
			stmt.Vulnerability.ID = "https://github.com/advisories/" + v.ID
		}

		// Add affected subcomponent (the vulnerable package)
		if v.Package.PURL != "" {
			stmt.Products[0].Subcomponents = []vexSubcomponent{
				{ID: v.Package.PURL},
			}
		}

		// Determine VEX status from AI enrichment or scan data
		stmt.Status, stmt.Justification, stmt.ImpactStatement, stmt.ActionStatement = determineVEXStatus(v)

		// Add status notes from AI enrichment
		if v.AIEnrichment != nil && v.AIEnrichment.Summary != "" {
			stmt.StatusNotes = v.AIEnrichment.Summary
		}

		doc.Statements = append(doc.Statements, stmt)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

// determineVEXStatus maps our vulnerability data to OpenVEX status values.
// Valid statuses: "not_affected", "affected", "fixed", "under_investigation"
func determineVEXStatus(v models.Vulnerability) (status, justification, impact, action string) {
	// If AI enrichment provides confidence assessment
	if v.AIEnrichment != nil {
		switch v.AIEnrichment.Confidence {
		case "HIGH":
			status = "affected"
			impact = v.AIEnrichment.LikelyImpact
			action = v.AIEnrichment.MinimalRemediation
			return
		case "LOW":
			status = "not_affected"
			justification = "requires_environment"
			if v.AIEnrichment.SuppressionRationale != "" {
				impact = v.AIEnrichment.SuppressionRationale
			}
			return
		case "MEDIUM":
			status = "under_investigation"
			impact = v.AIEnrichment.LikelyImpact
			return
		}
	}

	// If there's a fix available, status is "affected" with action to upgrade
	if v.FixedIn != "" {
		status = "affected"
		action = fmt.Sprintf("Upgrade %s to %s", v.Package.Name, v.FixedIn)
		return
	}

	// Default: affected (we found a vulnerability)
	status = "affected"
	return
}

func sanitizeProductName(path string) string {
	// Extract just the project directory name
	parts := strings.Split(strings.TrimRight(path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

func generateVEXID(result *models.ScanResult) string {
	h := uint64(0)
	for _, c := range result.ProjectPath {
		h = h*31 + uint64(c)
	}
	h += uint64(result.ScannedAt.UnixNano())
	return fmt.Sprintf("%016x", h)
}
