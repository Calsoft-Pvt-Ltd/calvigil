package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestTableReporterWithSlopCodeSmells(t *testing.T) {
	result := slopReportFixture()

	var buf bytes.Buffer
	if err := (&TableReporter{}).Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"AI Slop Code Smells",
		"Resource lifecycle",
		"not proof that code was AI-generated",
		"AI-SEC-001",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLReporterWithSlopCodeSmells(t *testing.T) {
	result := slopReportFixture()

	var buf bytes.Buffer
	if err := (&HTMLReporter{}).Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"AI Slop Code Smells",
		"Smell score",
		"Resource lifecycle",
		"not proof that code was AI-generated",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML output missing %q:\n%s", want, out)
		}
	}
}

func slopReportFixture() *models.ScanResult {
	return &models.ScanResult{
		ProjectPath:   "/repo",
		TotalPackages: 1,
		Ecosystems:    []models.Ecosystem{models.EcosystemGo},
		ScannedAt:     time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC),
		Duration:      time.Second,
		Vulnerabilities: []models.Vulnerability{
			{
				ID:          "AI-SEC-001",
				MatchedRule: "AI-SEC-001",
				Summary:     "HTTP response body not closed",
				Severity:    models.SeverityMedium,
				Source:      models.SourcePatternMatch,
				FilePath:    "/repo/client.go",
				StartLine:   17,
			},
		},
		SlopCodeSmells: &models.SlopCodeSmellSummary{
			Score:                13,
			Level:                "LOW",
			SignalCount:          1,
			GeneratedCodeSignal:  "",
			Confidence:           "MEDIUM",
			AuthorshipDisclaimer: "Slop code smells are quality and security symptoms, not proof that code was AI-generated.",
			Categories: []models.SlopCodeSmellCategory{
				{
					ID:          "resource_leak",
					Name:        "Resource lifecycle",
					Description: "Resources are opened without deterministic cleanup.",
					Count:       1,
					Weight:      13,
				},
			},
			TopSignals: []models.SlopCodeSmellSignal{
				{
					FindingID:  "AI-SEC-001",
					RuleID:     "AI-SEC-001",
					CategoryID: "resource_leak",
					Title:      "HTTP response body not closed",
					Severity:   models.SeverityMedium,
					Source:     string(models.SourcePatternMatch),
					FilePath:   "/repo/client.go",
					StartLine:  17,
					Confidence: "HIGH",
					Reason:     "Matched built-in AI-SEC rule.",
					Weight:     13,
				},
			},
			Guidance: []string{"Close files, HTTP bodies, DB rows, streams, and sockets immediately after successful creation."},
		},
	}
}
