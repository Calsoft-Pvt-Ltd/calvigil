package analyzer

import (
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestBuildSlopCodeSmellSummaryAggregatesAISecSemgrepAndAIEnrichment(t *testing.T) {
	vulns := []models.Vulnerability{
		{
			ID:          "AI-SEC-003",
			MatchedRule: "AI-SEC-003",
			Summary:     "Concurrent map access without synchronization",
			Severity:    models.SeverityHigh,
			Source:      models.SourcePatternMatch,
			FilePath:    "/repo/main.go",
			StartLine:   42,
			AIEnrichment: &models.AIEnrichment{
				AICodeIndicator: "LIKELY_AI",
			},
		},
		{
			ID:          "SG-ai-go-http-body-leak",
			MatchedRule: "ai-go-http-body-leak",
			Summary:     "HTTP response body is not closed",
			Severity:    models.SeverityMedium,
			Source:      models.SourceSemgrep,
			FilePath:    "/repo/client.go",
			StartLine:   12,
		},
		{
			ID:       "CVE-2026-0001",
			Summary:  "Dependency vulnerability should not affect slop score",
			Severity: models.SeverityCritical,
			Source:   models.SourceOSV,
		},
	}

	got := BuildSlopCodeSmellSummary(vulns)
	if got == nil {
		t.Fatal("expected slop summary")
	}
	if got.SignalCount != 2 {
		t.Fatalf("SignalCount = %d, want 2", got.SignalCount)
	}
	if got.Score < 35 {
		t.Fatalf("Score = %d, want reviewable smell score", got.Score)
	}
	if got.Level != "MODERATE" {
		t.Fatalf("Level = %q, want MODERATE", got.Level)
	}
	if got.GeneratedCodeSignal != "LIKELY_AI" {
		t.Fatalf("GeneratedCodeSignal = %q, want LIKELY_AI", got.GeneratedCodeSignal)
	}
	if got.Confidence != "HIGH" {
		t.Fatalf("Confidence = %q, want HIGH", got.Confidence)
	}
	if got.AuthorshipDisclaimer == "" {
		t.Fatal("expected authorship disclaimer")
	}
	if len(got.Categories) == 0 || got.Categories[0].ID != "concurrency" {
		t.Fatalf("top category = %+v, want concurrency first", got.Categories)
	}
	if len(got.TopSignals) == 0 || got.TopSignals[0].RuleID != "AI-SEC-003" {
		t.Fatalf("top signal = %+v, want AI-SEC-003 first", got.TopSignals)
	}
}

func TestBuildSlopCodeSmellSummaryReturnsNilWithoutSignals(t *testing.T) {
	got := BuildSlopCodeSmellSummary([]models.Vulnerability{
		{
			ID:       "CVE-2026-0002",
			Summary:  "dependency vulnerability only",
			Severity: models.SeverityHigh,
			Source:   models.SourceOSV,
		},
	})
	if got != nil {
		t.Fatalf("expected nil summary for dependency-only findings, got %+v", got)
	}
}

func TestBuildSlopCodeSmellSummaryMapsSecurityPatterns(t *testing.T) {
	got := BuildSlopCodeSmellSummary([]models.Vulnerability{
		{
			ID:          "SEC-010",
			MatchedRule: "SEC-010",
			Summary:     "TLS verification disabled",
			Severity:    models.SeverityHigh,
			Source:      models.SourcePatternMatch,
		},
	})
	if got == nil {
		t.Fatal("expected slop summary")
	}
	if got.Categories[0].ID != "insecure_defaults" {
		t.Fatalf("category = %q, want insecure_defaults", got.Categories[0].ID)
	}
	if got.TopSignals[0].Confidence != "MEDIUM" {
		t.Fatalf("confidence = %q, want MEDIUM", got.TopSignals[0].Confidence)
	}
}

func TestBuildSlopCodeSmellSummaryMapsNewAISecRules(t *testing.T) {
	got := BuildSlopCodeSmellSummary([]models.Vulnerability{
		{
			ID:          "AI-SEC-020",
			MatchedRule: "AI-SEC-020",
			Summary:     "Fail-open error handling",
			Severity:    models.SeverityHigh,
			Source:      models.SourcePatternMatch,
		},
		{
			ID:          "AI-SEC-023",
			MatchedRule: "AI-SEC-023",
			Summary:     "HTTP server without timeouts",
			Severity:    models.SeverityMedium,
			Source:      models.SourcePatternMatch,
		},
	})
	if got == nil {
		t.Fatal("expected slop summary")
	}
	if got.SignalCount != 2 {
		t.Fatalf("SignalCount = %d, want 2", got.SignalCount)
	}
	if got.TopSignals[0].Confidence != "HIGH" {
		t.Fatalf("top confidence = %q, want HIGH", got.TopSignals[0].Confidence)
	}
}
