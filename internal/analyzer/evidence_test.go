package analyzer

import (
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestBuildEvidence_Basic(t *testing.T) {
	v := models.Vulnerability{
		ID:       "CVE-2021-23337",
		Summary:  "Prototype Pollution",
		Details:  "lodash allows prototype pollution",
		Severity: models.SeverityHigh,
		Score:    7.5,
		Package: models.Package{
			Name:      "lodash",
			Version:   "4.17.20",
			Ecosystem: models.EcosystemNpm,
			FilePath:  "/project/package-lock.json",
		},
		FixedIn:  "4.17.21",
		DepPath:  "app -> lodash",
		Source:   models.SourceOSV,
		FilePath: "/project/src/index.js",
	}

	e := BuildEvidence(v, "/project")

	if e.VulnID != "CVE-2021-23337" {
		t.Errorf("VulnID = %q, want CVE-2021-23337", e.VulnID)
	}
	if e.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want lodash", e.PackageName)
	}
	if e.PackageVersion != "4.17.20" {
		t.Errorf("PackageVersion = %q, want 4.17.20", e.PackageVersion)
	}
	if e.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want npm", e.Ecosystem)
	}
	if e.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", e.Severity)
	}
	if e.CVSSScore != 7.5 {
		t.Errorf("CVSSScore = %f, want 7.5", e.CVSSScore)
	}
	if e.FixedIn != "4.17.21" {
		t.Errorf("FixedIn = %q, want 4.17.21", e.FixedIn)
	}
	if e.DepPath != "app -> lodash" {
		t.Errorf("DepPath = %q, want app -> lodash", e.DepPath)
	}
	// FilePath should be relative
	if e.FilePath != "src/index.js" {
		t.Errorf("FilePath = %q, want src/index.js (relative)", e.FilePath)
	}
	if !strings.Contains(e.AdvisoryText, "Prototype Pollution") {
		t.Errorf("AdvisoryText should contain Summary")
	}
	if !strings.Contains(e.AdvisoryText, "lodash allows") {
		t.Errorf("AdvisoryText should contain Details")
	}
}

func TestBuildEvidence_EmptyFilePath(t *testing.T) {
	v := models.Vulnerability{
		ID:      "CVE-2022-1234",
		Package: models.Package{FilePath: "/project/go.mod"},
	}
	e := BuildEvidence(v, "/project")

	// Should fall back to package file path
	if e.FilePath != "go.mod" {
		t.Errorf("FilePath = %q, want go.mod (from package)", e.FilePath)
	}
}

func TestBuildEvidence_WithSnippet(t *testing.T) {
	v := models.Vulnerability{
		ID:       "AI-001",
		Snippet:  "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE name='%s'\", input))",
		FilePath: "/project/main.go",
	}
	e := BuildEvidence(v, "/project")
	if e.Snippet == "" {
		t.Error("Snippet should be preserved")
	}
}

func TestFormatEvidenceForPrompt_Basic(t *testing.T) {
	e := Evidence{
		VulnID:         "CVE-2021-23337",
		PackageName:    "lodash",
		PackageVersion: "4.17.20",
		Ecosystem:      "npm",
		Severity:       "HIGH",
		CVSSScore:      7.5,
		AdvisoryText:   "Prototype Pollution in lodash",
		DepPath:        "app -> lodash",
		FilePath:       "package-lock.json",
		StartLine:      10,
		EndLine:        20,
		FixedIn:        "4.17.21",
		MatchedRule:    "SEC-001",
		Reachable:      "function handleInput calls lodash.merge",
		References:     []string{"https://nvd.nist.gov/CVE-2021-23337"},
	}

	out := FormatEvidenceForPrompt(e, 0)

	for _, want := range []string{
		"Finding #1: CVE-2021-23337",
		"Package: lodash@4.17.20 (npm)",
		"Severity: HIGH (CVSS: 7.5)",
		"Advisory: Prototype Pollution",
		"Dependency path: app -> lodash",
		"File: package-lock.json (line 10-20)",
		"Matched rule: SEC-001",
		"Reachability: function handleInput",
		"Fix available: upgrade to 4.17.21",
		"https://nvd.nist.gov",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output should contain %q\ngot:\n%s", want, out)
		}
	}
}

func TestFormatEvidenceForPrompt_Minimal(t *testing.T) {
	e := Evidence{
		VulnID:   "CVE-2022-1234",
		Severity: "MEDIUM",
	}
	out := FormatEvidenceForPrompt(e, 5)
	if !strings.Contains(out, "Finding #6") {
		t.Errorf("should use 1-based index: %s", out)
	}
	if !strings.Contains(out, "CVE-2022-1234") {
		t.Errorf("should contain vuln ID: %s", out)
	}
}

func TestFormatEvidenceForPrompt_WithSnippet(t *testing.T) {
	e := Evidence{
		VulnID:   "AI-001",
		Severity: "CRITICAL",
		Snippet:  "db.Query(query)",
		FilePath: "main.go",
	}
	out := FormatEvidenceForPrompt(e, 0)
	if !strings.Contains(out, "```") {
		t.Error("snippet should be wrapped in code fences")
	}
	if !strings.Contains(out, "db.Query") {
		t.Error("snippet content should be present")
	}
}

func TestTruncateText(t *testing.T) {
	short := "hello"
	if got := truncateText(short, 100); got != short {
		t.Errorf("truncateText(%q, 100) = %q", short, got)
	}

	long := strings.Repeat("a", 200)
	got := truncateText(long, 50)
	if len(got) != 53 { // 50 + "..."
		t.Errorf("truncateText should truncate to 50+..., got len %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("truncated text should end with ...")
	}
}

func TestPatternMatchesToVulnerabilities(t *testing.T) {
	matches := []PatternMatch{
		{
			Rule: PatternRule{
				ID:          "SEC-001",
				Name:        "SQL Injection",
				Description: "SQL injection vulnerability",
				Severity:    "CRITICAL",
			},
			FilePath: "/project/main.go",
			Line:     42,
			Content:  "db.Query(fmt.Sprintf(query, input))",
		},
		{
			Rule: PatternRule{
				ID:          "SEC-004",
				Name:        "Hardcoded Secret",
				Description: "Hardcoded password or secret",
				Severity:    "HIGH",
			},
			FilePath: "/project/config.go",
			Line:     10,
			Content:  "password := \"supersecret\"",
		},
	}

	vulns := PatternMatchesToVulnerabilities(matches)
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(vulns))
	}

	if vulns[0].ID != "SEC-001" {
		t.Errorf("vuln[0].ID = %q, want SEC-001", vulns[0].ID)
	}
	if vulns[0].Severity != models.SeverityCritical {
		t.Errorf("vuln[0].Severity = %q, want CRITICAL", vulns[0].Severity)
	}
	if vulns[0].FilePath != "/project/main.go" {
		t.Errorf("vuln[0].FilePath = %q", vulns[0].FilePath)
	}
	if vulns[0].StartLine != 42 {
		t.Errorf("vuln[0].StartLine = %d, want 42", vulns[0].StartLine)
	}
	if vulns[0].Source != models.SourcePatternMatch {
		t.Errorf("vuln[0].Source = %q, want pattern-match", vulns[0].Source)
	}

	if vulns[1].ID != "SEC-004" {
		t.Errorf("vuln[1].ID = %q, want SEC-004", vulns[1].ID)
	}
}

func TestPatternMatchesToVulnerabilities_Empty(t *testing.T) {
	vulns := PatternMatchesToVulnerabilities(nil)
	if len(vulns) != 0 {
		t.Errorf("empty matches should produce 0 vulns, got %d", len(vulns))
	}
}
