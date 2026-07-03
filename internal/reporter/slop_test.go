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
		"Top categories",
		"Top signals to review",
		"Resource lifecycle",
		"HTTP response body not closed",
		"not proof that code was AI-generated",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML output missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLReporterDependencyRowsUseCompactReviewLayout(t *testing.T) {
	result := slopReportFixture()
	result.SlopCodeSmells = nil
	result.Vulnerabilities = []models.Vulnerability{
		{
			ID:       "CVE-2026-32286",
			Summary:  "Denial of service in github.com/jackc/pgproto3/v2",
			Severity: models.SeverityHigh,
			Score:    7.5,
			Source:   models.SourceOSV,
			Package: models.Package{
				Name:      "github.com/jackc/pgproto3/v2",
				Version:   "v2.3.3",
				Ecosystem: models.EcosystemGo,
				Indirect:  true,
				PURL:      "pkg:golang/github.com%2Fjackc%2Fpgproto3%2Fv2@v2.3.3",
			},
		},
	}

	var buf bytes.Buffer
	if err := (&HTMLReporter{}).Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Dependency vulnerabilities",
		"enriched with AI reachability analysis",
		"Go</span><span class=\"sec-count\">1</span>",
		"class=\"tag reach-chip\"",
		"transitive",
		"Denial of service in github.com/jackc/pgproto3/v2",
		"CVSS 7.5",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML output missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLReporterWithSupplyChainRisk(t *testing.T) {
	result := slopReportFixture()
	result.SupplyChainRisk = &models.SupplyChainRisk{
		Score:               74,
		Level:               "HIGH",
		Decision:            "review_before_merge",
		FindingCount:        2,
		NewDependencies:     1,
		InstallScripts:      1,
		PhantomDependencies: 0,
		Guidance:            []string{"Review new direct dependencies before release."},
		Findings: []models.SupplyChainFinding{
			{
				ID:             "SCM-301",
				Category:       "install-behavior",
				Title:          "Dependency declares install-time script",
				Description:    "Install scripts execute during package installation.",
				Severity:       models.SeverityHigh,
				Confidence:     "HIGH",
				Package:        models.Package{Name: "esbuild", Version: "0.21.5", Ecosystem: models.EcosystemNpm, FilePath: "/repo/package-lock.json"},
				FilePath:       "/repo/package-lock.json",
				Evidence:       "esbuild has hasInstallScript=true",
				Recommendation: "Review the install hook before release.",
			},
		},
	}

	var buf bytes.Buffer
	if err := (&HTMLReporter{}).Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Supply chain guard",
		"Install-time behavior, lockfile integrity and dependency provenance",
		"Risk score",
		"Recommended decision",
		"review_before_merge",
		"Signals to review",
		"SCM-301",
		"Dependency declares install-time script",
		"<b>pkg</b>",
		"esbuild@0.21.5",
		"<b>Action</b>",
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
