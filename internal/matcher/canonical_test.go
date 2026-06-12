package matcher

import (
	"context"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestNormalize_PrefersCVEAsPrimaryID(t *testing.T) {
	v := models.Vulnerability{
		ID:      "GHSA-xxxx-yyyy-zzzz",
		Aliases: []string{"CVE-2024-1234"},
	}
	Normalize(&v)
	if v.ID != "CVE-2024-1234" {
		t.Errorf("ID = %q, want CVE-2024-1234", v.ID)
	}
	found := false
	for _, a := range v.Aliases {
		if a == "GHSA-xxxx-yyyy-zzzz" {
			found = true
		}
		if a == v.ID {
			t.Errorf("alias list contains primary ID %q", a)
		}
	}
	if !found {
		t.Error("old primary ID not demoted to alias")
	}
}

func TestNormalize_GHSAOverEcosystemID(t *testing.T) {
	v := models.Vulnerability{
		ID:      "GO-2024-0001",
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
	}
	Normalize(&v)
	if v.ID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("ID = %q, want GHSA-aaaa-bbbb-cccc", v.ID)
	}
}

func TestNormalize_KeepsCVEPrimary(t *testing.T) {
	v := models.Vulnerability{
		ID:      "CVE-2024-1234",
		Aliases: []string{"GHSA-xxxx-yyyy-zzzz", "GO-2024-0001"},
	}
	Normalize(&v)
	if v.ID != "CVE-2024-1234" {
		t.Errorf("ID = %q, want CVE-2024-1234", v.ID)
	}
	if len(v.Aliases) != 2 {
		t.Errorf("aliases = %v, want 2 entries", v.Aliases)
	}
}

func TestNormalize_DerivesSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  models.Severity
	}{
		{9.8, models.SeverityCritical},
		{7.5, models.SeverityHigh},
		{5.0, models.SeverityMedium},
		{2.1, models.SeverityLow},
		{0, models.SeverityUnknown},
	}
	for _, tt := range tests {
		v := models.Vulnerability{ID: "CVE-2024-1", Severity: models.SeverityUnknown, Score: tt.score}
		Normalize(&v)
		if v.Severity != tt.want {
			t.Errorf("score %.1f: severity = %q, want %q", tt.score, v.Severity, tt.want)
		}
	}
}

func TestNormalize_EmptySeverityBecomesUnknown(t *testing.T) {
	v := models.Vulnerability{ID: "CVE-2024-1"}
	Normalize(&v)
	if v.Severity != models.SeverityUnknown {
		t.Errorf("severity = %q, want UNKNOWN", v.Severity)
	}
}

func TestNormalize_DoesNotOverrideExistingSeverity(t *testing.T) {
	v := models.Vulnerability{ID: "CVE-2024-1", Severity: models.SeverityLow, Score: 9.8}
	Normalize(&v)
	if v.Severity != models.SeverityLow {
		t.Errorf("severity = %q, want LOW (source-provided severity must win)", v.Severity)
	}
}

func TestNormalize_DeduplicatesAliases(t *testing.T) {
	v := models.Vulnerability{
		ID:      "CVE-2024-1",
		Aliases: []string{"GHSA-1", "GHSA-1", "", "CVE-2024-1"},
	}
	Normalize(&v)
	if len(v.Aliases) != 1 || v.Aliases[0] != "GHSA-1" {
		t.Errorf("aliases = %v, want [GHSA-1]", v.Aliases)
	}
}

func TestMerge_FillsUnknownSeverity(t *testing.T) {
	dst := models.Vulnerability{ID: "CVE-2024-1", Severity: models.SeverityUnknown}
	src := models.Vulnerability{ID: "CVE-2024-1", Severity: models.SeverityHigh, Score: 8.1}
	Merge(&dst, src)
	if dst.Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want HIGH", dst.Severity)
	}
	if dst.Score != 8.1 {
		t.Errorf("score = %v, want 8.1", dst.Score)
	}
}

func TestMerge_ScoreUpgradesUnknownSeverity(t *testing.T) {
	dst := models.Vulnerability{ID: "CVE-2024-1", Severity: models.SeverityUnknown}
	src := models.Vulnerability{ID: "CVE-2024-1", Score: 9.9}
	Merge(&dst, src)
	if dst.Severity != models.SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL (derived from merged score)", dst.Severity)
	}
}

func TestMerge_ExistingDataWins(t *testing.T) {
	dst := models.Vulnerability{
		ID: "CVE-2024-1", Severity: models.SeverityLow, Score: 3.0,
		Summary: "original", FixedIn: "1.2.3",
	}
	src := models.Vulnerability{
		ID: "CVE-2024-1", Severity: models.SeverityCritical, Score: 9.8,
		Summary: "other", FixedIn: "9.9.9",
	}
	Merge(&dst, src)
	if dst.Severity != models.SeverityLow || dst.Score != 3.0 ||
		dst.Summary != "original" || dst.FixedIn != "1.2.3" {
		t.Errorf("existing fields were overwritten: %+v", dst)
	}
}

func TestMerge_FillsMissingFields(t *testing.T) {
	pub := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	dst := models.Vulnerability{ID: "CVE-2024-1"}
	src := models.Vulnerability{
		ID: "GHSA-1", Summary: "sum", Details: "det", FixedIn: "2.0.0",
		PublishedAt: pub, KnownExploited: true,
		References: []string{"https://example.com/a"},
	}
	Merge(&dst, src)
	if dst.Summary != "sum" || dst.Details != "det" || dst.FixedIn != "2.0.0" {
		t.Errorf("missing fields not filled: %+v", dst)
	}
	if !dst.PublishedAt.Equal(pub) {
		t.Errorf("published = %v, want %v", dst.PublishedAt, pub)
	}
	if !dst.KnownExploited {
		t.Error("KnownExploited not propagated")
	}
	if len(dst.Aliases) != 1 || dst.Aliases[0] != "GHSA-1" {
		t.Errorf("aliases = %v, want [GHSA-1]", dst.Aliases)
	}
	if len(dst.References) != 1 {
		t.Errorf("references = %v, want 1 entry", dst.References)
	}
}

func TestMerge_UnionsReferencesWithoutDuplicates(t *testing.T) {
	dst := models.Vulnerability{ID: "CVE-1", References: []string{"https://a", "https://b"}}
	src := models.Vulnerability{ID: "CVE-1", References: []string{"https://b", "https://c"}}
	Merge(&dst, src)
	if len(dst.References) != 3 {
		t.Errorf("references = %v, want 3 unique entries", dst.References)
	}
}

// TestAggregatedMatcher_MergesDuplicateData verifies the original UNKNOWN
// severity bug: when the first source returns a record without severity and
// a second source returns the same CVE with severity, the merged record must
// carry the severity instead of staying UNKNOWN.
func TestAggregatedMatcher_MergesDuplicateData(t *testing.T) {
	src1 := &mockMatcher{name: "src1", vulns: []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "from src1", Severity: models.SeverityUnknown},
	}}
	src2 := &mockMatcher{name: "src2", vulns: []models.Vulnerability{
		{ID: "CVE-2023-001", Severity: models.SeverityCritical, Score: 9.8, FixedIn: "2.0.0"},
	}}
	m := NewAggregatedMatcher(src1, src2)

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 merged vuln, got %d", len(result))
	}
	v := result[0]
	if v.Severity != models.SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL (merged from src2)", v.Severity)
	}
	if v.Score != 9.8 {
		t.Errorf("score = %v, want 9.8", v.Score)
	}
	if v.FixedIn != "2.0.0" {
		t.Errorf("fixedIn = %q, want 2.0.0", v.FixedIn)
	}
	if v.Summary != "from src1" {
		t.Errorf("summary = %q, want original from src1", v.Summary)
	}
}

// TestAggregatedMatcher_MergesByAlias verifies records are merged when one
// source reports by GHSA ID and another by the corresponding CVE alias.
func TestAggregatedMatcher_MergesByAlias(t *testing.T) {
	src1 := &mockMatcher{name: "src1", vulns: []models.Vulnerability{
		{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2023-100"}, Severity: models.SeverityUnknown},
	}}
	src2 := &mockMatcher{name: "src2", vulns: []models.Vulnerability{
		{ID: "CVE-2023-100", Severity: models.SeverityHigh},
	}}
	m := NewAggregatedMatcher(src1, src2)

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 merged vuln, got %d", len(result))
	}
	if result[0].ID != "CVE-2023-100" {
		t.Errorf("ID = %q, want CVE-2023-100 (canonical ID)", result[0].ID)
	}
	if result[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %q, want HIGH", result[0].Severity)
	}
}
