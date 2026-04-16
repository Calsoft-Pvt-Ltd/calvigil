package reporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestSeverityCSS(t *testing.T) {
	tests := map[models.Severity]string{
		models.SeverityCritical: "critical",
		models.SeverityHigh:     "high",
		models.SeverityMedium:   "medium",
		models.SeverityLow:      "low",
		models.SeverityUnknown:  "unknown",
		"OTHER":                 "unknown",
	}
	for sev, want := range tests {
		got := severityCSS(sev)
		if got != want {
			t.Errorf("severityCSS(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestFmtScore(t *testing.T) {
	if got := fmtScore(0); got != "" {
		t.Errorf("fmtScore(0) = %q, want empty", got)
	}
	if got := fmtScore(7.5); got != "7.5" {
		t.Errorf("fmtScore(7.5) = %q, want 7.5", got)
	}
	if got := fmtScore(10.0); got != "10.0" {
		t.Errorf("fmtScore(10.0) = %q, want 10.0", got)
	}
}

func TestHtmlEcoIcon(t *testing.T) {
	tests := map[string]string{
		"Go":          "🐹",
		"npm":         "📗",
		"PyPI":        "🐍",
		"Maven":       "☕",
		"crates.io":   "🦀",
		"RubyGems":    "💎",
		"Packagist":   "🐘",
		"ConanCenter": "⚙️",
		"unknown":     "📦",
	}
	for eco, want := range tests {
		got := htmlEcoIcon(eco)
		if got != want {
			t.Errorf("htmlEcoIcon(%q) = %q, want %q", eco, got, want)
		}
	}
}

func TestEcosystemIcon(t *testing.T) {
	tests := map[models.Ecosystem]string{
		models.EcosystemGo:      "🐹",
		models.EcosystemNpm:     "📗",
		models.EcosystemPyPI:    "🐍",
		models.EcosystemMaven:   "☕",
		models.EcosystemCrates:  "🦀",
		models.EcosystemRubyGem: "💎",
		models.EcosystemPHP:     "🐘",
		models.EcosystemConan:   "⚙️",
		"unknown":               "📦",
	}
	for eco, want := range tests {
		got := ecosystemIcon(eco)
		if got != want {
			t.Errorf("ecosystemIcon(%q) = %q, want %q", eco, got, want)
		}
	}
}

func TestColorSeverity(t *testing.T) {
	// colorSeverity returns ANSI-colored strings; just verify non-empty
	sevs := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityUnknown,
	}
	for _, s := range sevs {
		got := colorSeverity(s)
		if got == "" {
			t.Errorf("colorSeverity(%q) = empty", s)
		}
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := map[models.Severity]string{
		models.SeverityCritical: "error",
		models.SeverityHigh:     "error",
		models.SeverityMedium:   "warning",
		models.SeverityLow:      "note",
		models.SeverityUnknown:  "note",
	}
	for sev, want := range tests {
		got := severityToSARIFLevel(sev)
		if got != want {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestVulnSourceToCDXSource(t *testing.T) {
	tests := map[models.VulnerabilitySource]string{
		models.SourceOSV:          "OSV",
		models.SourceNVD:          "NVD",
		models.SourceGitHubAdv:    "GitHub Advisory",
		models.SourceSemgrep:      "Semgrep",
		models.SourcePatternMatch: "Pattern Scanner",
		models.SourceAIAnalysis:   "AI Analysis",
		"custom":                  "custom",
	}
	for src, wantName := range tests {
		got := vulnSourceToCDXSource(src)
		if got == nil {
			t.Errorf("vulnSourceToCDXSource(%q) = nil", src)
			continue
		}
		if got.Name != wantName {
			t.Errorf("vulnSourceToCDXSource(%q).Name = %q, want %q", src, got.Name, wantName)
		}
	}
}

func TestDetermineVEXStatus_FixedAvailable(t *testing.T) {
	v := models.Vulnerability{
		ID:      "CVE-1",
		FixedIn: "1.2.3",
		Package: models.Package{Name: "testpkg"},
	}
	status, _, _, action := determineVEXStatus(v)
	if status != "affected" {
		t.Errorf("status = %q, want affected", status)
	}
	if !strings.Contains(action, "1.2.3") {
		t.Errorf("action should mention fix version, got: %q", action)
	}
}

func TestDetermineVEXStatus_Default(t *testing.T) {
	v := models.Vulnerability{ID: "CVE-1"}
	status, _, _, _ := determineVEXStatus(v)
	if status != "affected" {
		t.Errorf("status = %q, want affected", status)
	}
}

func TestDetermineVEXStatus_AIHigh(t *testing.T) {
	v := models.Vulnerability{
		ID: "CVE-1",
		AIEnrichment: &models.AIEnrichment{
			Confidence:         "HIGH",
			LikelyImpact:       "Data breach",
			MinimalRemediation: "Upgrade now",
		},
	}
	status, _, impact, action := determineVEXStatus(v)
	if status != "affected" {
		t.Errorf("status = %q, want affected", status)
	}
	if impact != "Data breach" {
		t.Errorf("impact = %q, want 'Data breach'", impact)
	}
	if action != "Upgrade now" {
		t.Errorf("action = %q, want 'Upgrade now'", action)
	}
}

func TestDetermineVEXStatus_AILow(t *testing.T) {
	v := models.Vulnerability{
		ID: "CVE-1",
		AIEnrichment: &models.AIEnrichment{
			Confidence:           "LOW",
			SuppressionRationale: "Test environment only",
		},
	}
	status, justification, impact, _ := determineVEXStatus(v)
	if status != "not_affected" {
		t.Errorf("status = %q, want not_affected", status)
	}
	if justification != "requires_environment" {
		t.Errorf("justification = %q, want requires_environment", justification)
	}
	if impact != "Test environment only" {
		t.Errorf("impact = %q", impact)
	}
}

func TestDetermineVEXStatus_AIMedium(t *testing.T) {
	v := models.Vulnerability{
		ID: "CVE-1",
		AIEnrichment: &models.AIEnrichment{
			Confidence:   "MEDIUM",
			LikelyImpact: "Possible denial of service",
		},
	}
	status, _, impact, _ := determineVEXStatus(v)
	if status != "under_investigation" {
		t.Errorf("status = %q, want under_investigation", status)
	}
	if impact != "Possible denial of service" {
		t.Errorf("impact = %q", impact)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("this is a long string that should be truncated", 20); len(got) != 20 {
		t.Errorf("truncate long len = %d, want 20", len(got))
	}
	if got := truncate("line1\nline2", 50); strings.Contains(got, "\n") {
		t.Error("truncate should replace newlines")
	}
}

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "-" {
		t.Errorf("orDash empty = %q, want -", got)
	}
	if got := orDash("value"); got != "value" {
		t.Errorf("orDash value = %q, want value", got)
	}
}

func TestFilterBySource(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "1", Source: models.SourceOSV},
		{ID: "2", Source: models.SourceNVD},
		{ID: "3", Source: models.SourcePatternMatch},
		{ID: "4", Source: models.SourceSemgrep},
	}
	got := filterBySource(vulns, models.SourceOSV, models.SourceNVD)
	if len(got) != 2 {
		t.Errorf("filterBySource = %d, want 2", len(got))
	}
}

func TestGroupByEcosystem(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "1", Package: models.Package{Ecosystem: models.EcosystemNpm}},
		{ID: "2", Package: models.Package{Ecosystem: models.EcosystemGo}},
		{ID: "3", Package: models.Package{Ecosystem: models.EcosystemNpm}},
	}
	groups := groupByEcosystem(vulns)
	if len(groups[models.EcosystemNpm]) != 2 {
		t.Errorf("npm group = %d, want 2", len(groups[models.EcosystemNpm]))
	}
	if len(groups[models.EcosystemGo]) != 1 {
		t.Errorf("go group = %d, want 1", len(groups[models.EcosystemGo]))
	}
}

func TestPrintEnrichmentDetails_WithEnrichment(t *testing.T) {
	vulns := []models.Vulnerability{
		{
			ID:       "CVE-1",
			Severity: models.SeverityHigh,
			AIEnrichment: &models.AIEnrichment{
				Summary:              "Critical SQL injection",
				LikelyImpact:         "Database compromise",
				Confidence:           "HIGH",
				MinimalRemediation:   "Use prepared statements",
				SuppressionRationale: "",
			},
		},
	}
	var buf bytes.Buffer
	printEnrichmentDetails(&buf, vulns)
	output := buf.String()
	if !strings.Contains(output, "AI Enrichment") {
		t.Error("should contain AI Enrichment header")
	}
	if !strings.Contains(output, "CVE-1") {
		t.Error("should contain vuln ID")
	}
	if !strings.Contains(output, "Database compromise") {
		t.Error("should contain impact")
	}
	if !strings.Contains(output, "Use prepared statements") {
		t.Error("should contain remediation")
	}
}

func TestPrintEnrichmentDetails_NoEnrichment(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "CVE-1", Severity: models.SeverityHigh},
	}
	var buf bytes.Buffer
	printEnrichmentDetails(&buf, vulns)
	if buf.Len() != 0 {
		t.Errorf("expected empty output for no enrichment, got: %s", buf.String())
	}
}

func TestPrintEnrichmentDetails_WithSuppression(t *testing.T) {
	vulns := []models.Vulnerability{
		{
			ID:       "CVE-2",
			Severity: models.SeverityLow,
			AIEnrichment: &models.AIEnrichment{
				Confidence:           "LOW",
				SuppressionRationale: "Not applicable in this context",
			},
		},
	}
	var buf bytes.Buffer
	printEnrichmentDetails(&buf, vulns)
	output := buf.String()
	if !strings.Contains(output, "Suppress") {
		t.Error("should contain suppression rationale")
	}
}

func TestBuildResults_WithFilePath(t *testing.T) {
	vulns := []models.Vulnerability{
		{
			ID:        "CVE-1",
			Severity:  models.SeverityHigh,
			Summary:   "Test vuln",
			FilePath:  "/project/src/app.py",
			StartLine: 10,
			EndLine:   15,
		},
	}
	results := buildResults(vulns, "/project")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].RuleID != "CVE-1" {
		t.Errorf("RuleID = %q", results[0].RuleID)
	}
	if results[0].Level != "error" {
		t.Errorf("Level = %q, want error", results[0].Level)
	}
	if len(results[0].Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(results[0].Locations))
	}
	if results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/app.py" {
		t.Errorf("URI = %q, want src/app.py", results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if results[0].Locations[0].PhysicalLocation.Region == nil {
		t.Error("Region should be set when StartLine > 0")
	} else if results[0].Locations[0].PhysicalLocation.Region.StartLine != 10 {
		t.Errorf("StartLine = %d, want 10", results[0].Locations[0].PhysicalLocation.Region.StartLine)
	}
}

func TestBuildResults_WithPackageFilePath(t *testing.T) {
	vulns := []models.Vulnerability{
		{
			ID:       "CVE-2",
			Severity: models.SeverityMedium,
			Package:  models.Package{FilePath: "/project/package.json"},
		},
	}
	results := buildResults(vulns, "/project")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].Locations) != 1 {
		t.Fatalf("expected 1 location from package filepath, got %d", len(results[0].Locations))
	}
	if results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "package.json" {
		t.Errorf("URI = %q, want package.json", results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestBuildResults_NoLocation(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "CVE-3", Severity: models.SeverityLow},
	}
	results := buildResults(vulns, "/project")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].Locations) != 0 {
		t.Errorf("expected 0 locations, got %d", len(results[0].Locations))
	}
}

func TestSanitizeProductName(t *testing.T) {
	tests := map[string]string{
		"/tmp/my-project/": "my-project",
		"/home/user/app":   "app",
		"simple":           "simple",
	}
	for input, want := range tests {
		got := sanitizeProductName(input)
		if got != want {
			t.Errorf("sanitizeProductName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCycloneDX_WithMultipleSources(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/test",
		Packages: []models.Package{
			{Name: "pkg1", Version: "1.0", Ecosystem: models.EcosystemNpm, PURL: "pkg:npm/pkg1@1.0"},
		},
		Vulnerabilities: []models.Vulnerability{
			{ID: "CVE-1", Severity: models.SeverityHigh, Source: models.SourceOSV, Package: models.Package{Name: "pkg1", PURL: "pkg:npm/pkg1@1.0"}},
			{ID: "CVE-2", Severity: models.SeverityMedium, Source: models.SourceNVD, Package: models.Package{Name: "pkg1", PURL: "pkg:npm/pkg1@1.0"}},
			{ID: "CVE-3", Source: models.SourcePatternMatch, FilePath: "/test/app.py", StartLine: 10},
			{ID: "CVE-4", Source: models.SourceAIAnalysis, FilePath: "/test/main.go"},
			{ID: "CVE-5", Source: models.SourceSemgrep, FilePath: "/test/handler.js"},
			{ID: "CVE-6", Source: models.SourceGitHubAdv, Package: models.Package{Name: "pkg1", PURL: "pkg:npm/pkg1@1.0"}},
		},
	}

	var buf bytes.Buffer
	r := ForFormat("cyclonedx")
	err := r.Report(result, &buf)
	if err != nil {
		t.Fatalf("CycloneDX report error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "CVE-1") {
		t.Error("should contain CVE-1")
	}
}

func TestOpenVEX_WithAIEnrichment(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/test",
		Vulnerabilities: []models.Vulnerability{
			{
				ID:       "CVE-1",
				Severity: models.SeverityHigh,
				Package:  models.Package{Name: "pkg", PURL: "pkg:npm/pkg@1.0"},
				AIEnrichment: &models.AIEnrichment{
					Confidence:         "HIGH",
					LikelyImpact:       "Critical data breach",
					MinimalRemediation: "Upgrade immediately",
				},
			},
			{
				ID:       "CVE-2",
				Severity: models.SeverityLow,
				Package:  models.Package{Name: "pkg2", PURL: "pkg:npm/pkg2@1.0"},
				AIEnrichment: &models.AIEnrichment{
					Confidence:           "LOW",
					SuppressionRationale: "Dev dependency only",
				},
			},
			{
				ID:       "CVE-3",
				Severity: models.SeverityMedium,
				Package:  models.Package{Name: "pkg3", PURL: "pkg:npm/pkg3@1.0"},
				AIEnrichment: &models.AIEnrichment{
					Confidence:   "MEDIUM",
					LikelyImpact: "Possible DoS",
				},
			},
		},
	}
	var buf bytes.Buffer
	r := ForFormat("openvex")
	err := r.Report(result, &buf)
	if err != nil {
		t.Fatalf("OpenVEX report error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "affected") {
		t.Error("should contain 'affected' status")
	}
}

func TestTableReporter_WithEnrichment(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath:   "/test",
		TotalPackages: 1,
		Vulnerabilities: []models.Vulnerability{
			{
				ID:       "CVE-1",
				Summary:  "Test vuln",
				Severity: models.SeverityHigh,
				Source:   models.SourceOSV,
				Package:  models.Package{Name: "pkg", Version: "1.0", Ecosystem: models.EcosystemNpm},
				AIEnrichment: &models.AIEnrichment{
					Summary:            "Critical issue needs attention",
					LikelyImpact:       "Data breach possible",
					Confidence:         "HIGH",
					MinimalRemediation: "Upgrade to 2.0",
				},
			},
		},
	}
	var buf bytes.Buffer
	r := ForFormat("table")
	err := r.Report(result, &buf)
	if err != nil {
		t.Fatalf("table report error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "AI Enrichment") {
		t.Error("should contain AI enrichment section")
	}
	if !strings.Contains(output, "Data breach possible") {
		t.Error("should contain impact text")
	}
}

func TestHTML_AllSeverityLevels(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/test",
		Vulnerabilities: []models.Vulnerability{
			{ID: "C1", Severity: models.SeverityCritical, Source: models.SourceOSV, Package: models.Package{Name: "a", Ecosystem: models.EcosystemNpm}},
			{ID: "H1", Severity: models.SeverityHigh, Source: models.SourceOSV, Package: models.Package{Name: "b", Ecosystem: models.EcosystemPyPI}},
			{ID: "M1", Severity: models.SeverityMedium, Source: models.SourceOSV, Package: models.Package{Name: "c", Ecosystem: models.EcosystemGo}},
			{ID: "L1", Severity: models.SeverityLow, Source: models.SourceOSV, Package: models.Package{Name: "d", Ecosystem: models.EcosystemMaven}},
			{ID: "U1", Severity: models.SeverityUnknown, Source: models.SourceOSV, Package: models.Package{Name: "e", Ecosystem: models.EcosystemCrates}},
		},
	}
	var buf bytes.Buffer
	r := ForFormat("html")
	err := r.Report(result, &buf)
	if err != nil {
		t.Fatalf("HTML report error: %v", err)
	}
	output := buf.String()
	for _, id := range []string{"C1", "H1", "M1", "L1", "U1"} {
		if !strings.Contains(output, id) {
			t.Errorf("HTML should contain %s", id)
		}
	}
}
