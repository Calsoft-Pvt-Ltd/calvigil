package reporter

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/chavakula/calvigil/internal/models"
)

// SARIFReporter outputs scan results in SARIF v2.1.0 format.
type SARIFReporter struct{}

// SARIF v2.1.0 types

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	ShortDescription sarifMessage     `json:"shortDescription"`
	FullDescription  *sarifMessage    `json:"fullDescription,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	DefaultConfig    *sarifRuleConfig `json:"defaultConfiguration,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
}

func (r *SARIFReporter) Report(result *models.ScanResult, w io.Writer) error {
	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "calvigil",
						Version:        "0.1.0",
						InformationURI: "https://github.com/chavakula/calvigil",
						Rules:          buildRules(result.Vulnerabilities),
					},
				},
				Results: buildResults(result.Vulnerabilities, result.ProjectPath),
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func buildRules(vulns []models.Vulnerability) []sarifRule {
	seen := make(map[string]bool)
	var rules []sarifRule

	for _, v := range vulns {
		if seen[v.ID] {
			continue
		}
		seen[v.ID] = true

		rule := sarifRule{
			ID:               v.ID,
			ShortDescription: sarifMessage{Text: v.Summary},
			DefaultConfig:    &sarifRuleConfig{Level: severityToSARIFLevel(v.Severity)},
		}

		if v.Details != "" {
			rule.FullDescription = &sarifMessage{Text: v.Details}
		}

		if len(v.References) > 0 {
			rule.HelpURI = v.References[0]
		}

		rules = append(rules, rule)
	}

	return rules
}

func buildResults(vulns []models.Vulnerability, projectPath string) []sarifResult {
	var results []sarifResult

	for _, v := range vulns {
		r := sarifResult{
			RuleID:  v.ID,
			Level:   severityToSARIFLevel(v.Severity),
			Message: sarifMessage{Text: formatSARIFMessage(v)},
		}

		// Add location if available
		if v.FilePath != "" {
			relPath, _ := filepath.Rel(projectPath, v.FilePath)
			if relPath == "" {
				relPath = v.FilePath
			}

			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: relPath},
				},
			}

			if v.StartLine > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{
					StartLine: v.StartLine,
					EndLine:   v.EndLine,
				}
			}

			r.Locations = []sarifLocation{loc}
		} else if v.Package.FilePath != "" {
			relPath, _ := filepath.Rel(projectPath, v.Package.FilePath)
			if relPath == "" {
				relPath = v.Package.FilePath
			}
			r.Locations = []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: relPath},
					},
				},
			}
		}

		results = append(results, r)
	}

	return results
}

func severityToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

func formatSARIFMessage(v models.Vulnerability) string {
	msg := v.Summary
	if v.Package.Name != "" {
		msg += " in " + v.Package.Name + "@" + v.Package.Version
	}
	if v.FixedIn != "" {
		msg += " (fix available: " + v.FixedIn + ")"
	}
	if v.AIEnrichment != nil {
		e := v.AIEnrichment
		if e.Summary != "" {
			msg += "\n\nAI Analysis:\n" + e.Summary
		}
		if e.LikelyImpact != "" {
			msg += "\nImpact: " + e.LikelyImpact
		}
		if string(e.Confidence) != "" {
			msg += "\nConfidence: " + string(e.Confidence)
		}
		if e.MinimalRemediation != "" {
			msg += "\nRemediation: " + e.MinimalRemediation
		}
		if e.SuppressionRationale != "" {
			msg += "\nSuppression Rationale: " + e.SuppressionRationale
		}
	}
	return msg
}
