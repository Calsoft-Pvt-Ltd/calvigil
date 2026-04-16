package matcher

import (
	"context"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

type mockMatcher struct {
	name  string
	vulns []models.Vulnerability
	err   error
}

func (m *mockMatcher) Name() string { return m.name }

func (m *mockMatcher) Match(_ context.Context, _ []models.Package) ([]models.Vulnerability, error) {
	return m.vulns, m.err
}

func TestNewAggregatedMatcher(t *testing.T) {
	m := NewAggregatedMatcher(&mockMatcher{name: "test"})
	if m == nil {
		t.Fatal("NewAggregatedMatcher returned nil")
	}
}

func TestAggregatedMatcher_SingleSource(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "vuln1"},
		{ID: "CVE-2023-002", Summary: "vuln2"},
	}
	m := NewAggregatedMatcher(&mockMatcher{name: "src1", vulns: vulns})

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg", Version: "1.0"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(result))
	}
}

func TestAggregatedMatcher_DeduplicateByID(t *testing.T) {
	src1 := &mockMatcher{name: "src1", vulns: []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "from src1"},
	}}
	src2 := &mockMatcher{name: "src2", vulns: []models.Vulnerability{
		{ID: "CVE-2023-001", Summary: "from src2"},
	}}
	m := NewAggregatedMatcher(src1, src2)

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 unique vuln, got %d", len(result))
	}
}

func TestAggregatedMatcher_DeduplicateByAlias(t *testing.T) {
	src1 := &mockMatcher{name: "src1", vulns: []models.Vulnerability{
		{ID: "GHSA-xxxx", Aliases: []string{"CVE-2023-999"}},
	}}
	src2 := &mockMatcher{name: "src2", vulns: []models.Vulnerability{
		{ID: "CVE-2023-999"},
	}}
	m := NewAggregatedMatcher(src1, src2)

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 unique vuln (alias dedup), got %d", len(result))
	}
}

func TestAggregatedMatcher_MultipleUniqueVulns(t *testing.T) {
	src1 := &mockMatcher{name: "src1", vulns: []models.Vulnerability{
		{ID: "CVE-2023-001"},
	}}
	src2 := &mockMatcher{name: "src2", vulns: []models.Vulnerability{
		{ID: "CVE-2023-002"},
	}}
	m := NewAggregatedMatcher(src1, src2)

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 vulns, got %d", len(result))
	}
}

func TestAggregatedMatcher_ErrorSource(t *testing.T) {
	src1 := &mockMatcher{name: "bad", err: context.DeadlineExceeded}
	src2 := &mockMatcher{name: "good", vulns: []models.Vulnerability{
		{ID: "CVE-2023-001"},
	}}
	m := NewAggregatedMatcher(src1, src2)

	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() should not return error, got: %v", err)
	}
	// Should have the error entry plus the real vuln
	if len(result) != 2 {
		t.Fatalf("expected 2 entries (1 error + 1 vuln), got %d", len(result))
	}

	foundErr := false
	for _, v := range result {
		if v.ID == "SCAN-ERR-bad" {
			foundErr = true
		}
	}
	if !foundErr {
		t.Error("expected SCAN-ERR-bad entry for failed matcher")
	}
}

func TestAggregatedMatcher_SetVerbose(t *testing.T) {
	m := NewAggregatedMatcher(&mockMatcher{name: "test"})
	m.SetVerbose(true)
	if !m.verbose {
		t.Error("SetVerbose(true) did not set verbose")
	}
}

func TestAggregatedMatcher_EmptyMatchers(t *testing.T) {
	m := NewAggregatedMatcher()
	result, err := m.Match(context.Background(), []models.Package{{Name: "pkg"}})
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 vulns from empty matcher, got %d", len(result))
	}
}

func TestOSVMatcher_Name(t *testing.T) {
	m := NewOSVMatcher()
	if m.Name() != "osv" {
		t.Errorf("Name() = %q, want osv", m.Name())
	}
}

func TestNVDMatcher_Name(t *testing.T) {
	m := NewNVDMatcher("test-key")
	if m.Name() != "nvd" {
		t.Errorf("Name() = %q, want nvd", m.Name())
	}
}

func TestGitHubAdvisoryMatcher_Name(t *testing.T) {
	m := NewGitHubAdvisoryMatcher("test-token")
	if m.Name() != "github-advisory" {
		t.Errorf("Name() = %q, want github-advisory", m.Name())
	}
}
