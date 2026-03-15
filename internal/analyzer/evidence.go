package analyzer

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
)

// Evidence is a structured packet of information about a single vulnerability
// that gets sent to the AI model for enrichment.
type Evidence struct {
	// Identity
	VulnID    string `json:"vuln_id"`
	VulnIndex int    `json:"vuln_index"` // position in the original slice

	// Package info
	PackageName    string `json:"package_name,omitempty"`
	PackageVersion string `json:"package_version,omitempty"`
	Ecosystem      string `json:"ecosystem,omitempty"`

	// Advisory info
	AdvisoryText string  `json:"advisory_text,omitempty"`
	Severity     string  `json:"severity"`
	CVSSScore    float64 `json:"cvss_score,omitempty"`

	// Dependency path
	DepPath string `json:"dep_path,omitempty"`

	// File location
	FilePath  string `json:"file_path,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`

	// Code context
	Snippet string `json:"snippet,omitempty"`

	// Detection info
	MatchedRule string `json:"matched_rule,omitempty"`

	// Reachability
	Reachable string `json:"reachable,omitempty"`

	// Fix candidates
	FixedIn    string   `json:"fixed_in,omitempty"`
	References []string `json:"references,omitempty"`
}

// BuildEvidence converts a Vulnerability into a structured Evidence packet
// suitable for AI enrichment.
func BuildEvidence(v models.Vulnerability, projectPath string) Evidence {
	relPath := v.FilePath
	if relPath != "" && projectPath != "" {
		if rel, err := filepath.Rel(projectPath, v.FilePath); err == nil {
			relPath = rel
		}
	}
	if relPath == "" && v.Package.FilePath != "" {
		if rel, err := filepath.Rel(projectPath, v.Package.FilePath); err == nil {
			relPath = rel
		}
	}

	e := Evidence{
		VulnID:         v.ID,
		PackageName:    v.Package.Name,
		PackageVersion: v.Package.Version,
		Ecosystem:      string(v.Package.Ecosystem),
		Severity:       string(v.Severity),
		CVSSScore:      v.Score,
		DepPath:        v.DepPath,
		FilePath:       relPath,
		StartLine:      v.StartLine,
		EndLine:        v.EndLine,
		Snippet:        v.Snippet,
		MatchedRule:    v.MatchedRule,
		Reachable:      v.Reachable,
		FixedIn:        v.FixedIn,
		References:     v.References,
	}

	// Build advisory text from available fields
	var advisory []string
	if v.Summary != "" {
		advisory = append(advisory, v.Summary)
	}
	if v.Details != "" {
		advisory = append(advisory, v.Details)
	}
	e.AdvisoryText = strings.Join(advisory, "\n")

	return e
}

// FormatEvidenceForPrompt renders a single Evidence into a human-readable block
// for inclusion in the AI prompt.
func FormatEvidenceForPrompt(e Evidence, index int) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("--- Finding #%d: %s ---\n", index+1, e.VulnID))

	if e.PackageName != "" {
		sb.WriteString(fmt.Sprintf("Package: %s@%s (%s)\n", e.PackageName, e.PackageVersion, e.Ecosystem))
	}

	sb.WriteString(fmt.Sprintf("Severity: %s", e.Severity))
	if e.CVSSScore > 0 {
		sb.WriteString(fmt.Sprintf(" (CVSS: %.1f)", e.CVSSScore))
	}
	sb.WriteString("\n")

	if e.AdvisoryText != "" {
		sb.WriteString(fmt.Sprintf("Advisory: %s\n", truncateText(e.AdvisoryText, 500)))
	}

	if e.DepPath != "" {
		sb.WriteString(fmt.Sprintf("Dependency path: %s\n", e.DepPath))
	}

	if e.FilePath != "" {
		sb.WriteString(fmt.Sprintf("File: %s", e.FilePath))
		if e.StartLine > 0 {
			sb.WriteString(fmt.Sprintf(" (line %d", e.StartLine))
			if e.EndLine > e.StartLine {
				sb.WriteString(fmt.Sprintf("-%d", e.EndLine))
			}
			sb.WriteString(")")
		}
		sb.WriteString("\n")
	}

	if e.MatchedRule != "" {
		sb.WriteString(fmt.Sprintf("Matched rule: %s\n", e.MatchedRule))
	}

	if e.Reachable != "" {
		sb.WriteString(fmt.Sprintf("Reachability: %s\n", e.Reachable))
	}

	if e.FixedIn != "" {
		sb.WriteString(fmt.Sprintf("Fix available: upgrade to %s\n", e.FixedIn))
	}

	if len(e.References) > 0 {
		sb.WriteString(fmt.Sprintf("References: %s\n", strings.Join(e.References[:min(len(e.References), 3)], ", ")))
	}

	if e.Snippet != "" {
		sb.WriteString(fmt.Sprintf("Code:\n```\n%s\n```\n", truncateText(e.Snippet, 800)))
	}

	return sb.String()
}

func truncateText(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
