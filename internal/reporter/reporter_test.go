package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// shared test fixture
func testResult() *models.ScanResult {
	return &models.ScanResult{
		ProjectPath:   "/tmp/test-project",
		Ecosystems:    []models.Ecosystem{models.EcosystemNpm, models.EcosystemGo},
		TotalPackages: 3,
		Packages: []models.Package{
			{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm, PURL: "pkg:npm/lodash@4.17.20"},
			{Name: "express", Version: "4.17.1", Ecosystem: models.EcosystemNpm, PURL: "pkg:npm/express@4.17.1", Indirect: true},
			{Name: "golang.org/x/text", Version: "v0.3.0", Ecosystem: models.EcosystemGo, PURL: "pkg:golang/golang.org/x/text@v0.3.0"},
		},
		Vulnerabilities: []models.Vulnerability{
			{
				ID:       "CVE-2021-23337",
				Summary:  "Prototype Pollution in lodash",
				Severity: models.SeverityHigh,
				Score:    7.5,
				Source:   models.SourceOSV,
				Package:  models.Package{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
				FixedIn:  "4.17.21",
			},
			{
				ID:       "CVE-2022-32149",
				Summary:  "golang.org/x/text denial of service",
				Severity: models.SeverityMedium,
				Score:    5.3,
				Source:   models.SourceNVD,
				Package:  models.Package{Name: "golang.org/x/text", Version: "v0.3.0", Ecosystem: models.EcosystemGo},
				FixedIn:  "v0.3.8",
			},
		},
		ScannedAt: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		Duration:  5 * time.Second,
	}
}

func emptyResult() *models.ScanResult {
	return &models.ScanResult{
		ProjectPath:   "/tmp/empty",
		TotalPackages: 0,
		ScannedAt:     time.Now(),
	}
}

// ── Registry tests ──────────────────────────────────────────────────────────

func TestRegisterAndFormats(t *testing.T) {
	// All built-in reporters register via init()
	formats := Formats()
	expected := []string{"json", "sarif", "cyclonedx", "openvex", "spdx", "table", "html", "pdf"}
	for _, want := range expected {
		found := false
		for _, f := range formats {
			if f == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("format %q should be registered", want)
		}
	}
}

func TestForFormat_Known(t *testing.T) {
	for _, format := range []string{"json", "sarif", "cyclonedx", "openvex"} {
		r := ForFormat(format)
		if r == nil {
			t.Errorf("ForFormat(%q) returned nil", format)
		}
	}
}

func TestForFormat_Unknown(t *testing.T) {
	r := ForFormat("doesnotexist")
	if r == nil {
		t.Fatal("ForFormat with unknown format should return fallback, not nil")
	}
	// Should be a TableReporter
	if _, ok := r.(*TableReporter); !ok {
		t.Error("ForFormat with unknown format should return TableReporter")
	}
}

// ── JSON reporter tests ─────────────────────────────────────────────────────

func TestJSONReporter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{}
	if err := r.Report(testResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestJSONReporter_Fields(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{}
	r.Report(testResult(), &buf)

	var result models.ScanResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.ProjectPath != "/tmp/test-project" {
		t.Errorf("project_path = %q, want /tmp/test-project", result.ProjectPath)
	}
	if result.TotalPackages != 3 {
		t.Errorf("total_packages = %d, want 3", result.TotalPackages)
	}
	if len(result.Vulnerabilities) != 2 {
		t.Errorf("vulnerabilities count = %d, want 2", len(result.Vulnerabilities))
	}
}

func TestJSONReporter_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{}
	if err := r.Report(emptyResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Error("empty result should produce valid JSON")
	}
}

// ── SARIF reporter tests ────────────────────────────────────────────────────

func TestSARIFReporter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{}
	if err := r.Report(testResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF output not valid JSON: %v", err)
	}
	if v, _ := sarif["version"].(string); v != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", v)
	}
	runs, _ := sarif["runs"].([]interface{})
	if len(runs) == 0 {
		t.Error("SARIF should have at least 1 run")
	}
}

func TestSARIFReporter_Results(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{}
	r.Report(testResult(), &buf)

	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	json.Unmarshal(buf.Bytes(), &sarif)

	if len(sarif.Runs[0].Results) != 2 {
		t.Errorf("results count = %d, want 2", len(sarif.Runs[0].Results))
	}
	if len(sarif.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("rules count = %d, want 2", len(sarif.Runs[0].Tool.Driver.Rules))
	}
}

func TestSARIFReporter_Empty(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{}
	if err := r.Report(emptyResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Error("empty result should produce valid SARIF JSON")
	}
}

func TestSARIFReporter_WithAIEnrichment(t *testing.T) {
	result := testResult()
	result.Vulnerabilities[0].AIEnrichment = &models.AIEnrichment{
		Summary:            "This is a prototype pollution vulnerability.",
		LikelyImpact:       "Remote code execution",
		Confidence:         "HIGH",
		MinimalRemediation: "Upgrade lodash to 4.17.21",
	}

	var buf bytes.Buffer
	r := &SARIFReporter{}
	r.Report(result, &buf)

	out := buf.String()
	if !strings.Contains(out, "AI Analysis") {
		t.Error("SARIF with AI enrichment should contain AI Analysis text")
	}
}

// ── CycloneDX reporter tests ───────────────────────────────────────────────

func TestCycloneDXReporter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &CycloneDXReporter{}
	if err := r.Report(testResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	var cdx map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &cdx); err != nil {
		t.Fatalf("CycloneDX output not valid JSON: %v", err)
	}
	if cdx["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", cdx["bomFormat"])
	}
	if cdx["specVersion"] != "1.5" {
		t.Errorf("specVersion = %v, want 1.5", cdx["specVersion"])
	}
}

func TestCycloneDXReporter_Components(t *testing.T) {
	var buf bytes.Buffer
	r := &CycloneDXReporter{}
	r.Report(testResult(), &buf)

	var cdx struct {
		Components      []map[string]interface{} `json:"components"`
		Vulnerabilities []map[string]interface{} `json:"vulnerabilities"`
	}
	json.Unmarshal(buf.Bytes(), &cdx)

	if len(cdx.Components) == 0 {
		t.Error("CycloneDX should have components")
	}
	if len(cdx.Vulnerabilities) != 2 {
		t.Errorf("vulnerabilities = %d, want 2", len(cdx.Vulnerabilities))
	}
}

func TestCycloneDXReporter_Empty(t *testing.T) {
	var buf bytes.Buffer
	r := &CycloneDXReporter{}
	if err := r.Report(emptyResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Error("empty result should produce valid CycloneDX JSON")
	}
}

// ── OpenVEX reporter tests ─────────────────────────────────────────────────

func TestOpenVEXReporter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	r := &OpenVEXReporter{}
	if err := r.Report(testResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	var vex map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &vex); err != nil {
		t.Fatalf("OpenVEX output not valid JSON: %v", err)
	}
}

func TestOpenVEXReporter_Statements(t *testing.T) {
	var buf bytes.Buffer
	r := &OpenVEXReporter{}
	r.Report(testResult(), &buf)

	var vex struct {
		Statements []interface{} `json:"statements"`
	}
	json.Unmarshal(buf.Bytes(), &vex)

	if len(vex.Statements) != 2 {
		t.Errorf("statements count = %d, want 2", len(vex.Statements))
	}
}

func TestOpenVEXReporter_Empty(t *testing.T) {
	var buf bytes.Buffer
	r := &OpenVEXReporter{}
	if err := r.Report(emptyResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Error("empty result should produce valid OpenVEX JSON")
	}
}

// ── HTML reporter tests ────────────────────────────────────────────────────

func TestHTMLReporter_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	r := &HTMLReporter{}
	if err := r.Report(testResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<html") {
		t.Error("HTML output should contain <html tag")
	}
	if !strings.Contains(out, "Calvigil") {
		t.Error("HTML output should contain Calvigil branding")
	}
}

func TestHTMLReporter_ContainsVulnData(t *testing.T) {
	var buf bytes.Buffer
	r := &HTMLReporter{}
	r.Report(testResult(), &buf)
	out := buf.String()

	if !strings.Contains(out, "CVE-2021-23337") {
		t.Error("HTML should contain CVE ID")
	}
	if !strings.Contains(out, "lodash") {
		t.Error("HTML should contain package name")
	}
}

func TestHTMLReporter_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	r := &HTMLReporter{}
	if err := r.Report(emptyResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(buf.String(), "<html") {
		t.Error("empty result should still produce valid HTML")
	}
}

func TestHTMLReporter_WithAIEnrichment(t *testing.T) {
	result := testResult()
	result.Vulnerabilities[0].AIEnrichment = &models.AIEnrichment{
		Summary:            "Prototype pollution vulnerability",
		LikelyImpact:       "Remote code execution",
		Confidence:         "HIGH",
		MinimalRemediation: "Upgrade lodash to 4.17.21",
	}
	var buf bytes.Buffer
	r := &HTMLReporter{}
	r.Report(result, &buf)
	out := buf.String()

	if !strings.Contains(out, "Prototype pollution") {
		t.Error("HTML should contain AI enrichment summary")
	}
}

func TestHTMLReporter_WithLicenseIssues(t *testing.T) {
	result := testResult()
	result.LicenseIssues = []models.LicenseIssue{
		{
			Package: models.Package{Name: "gpl-pkg", Version: "1.0", Ecosystem: models.EcosystemNpm},
			License: "GPL-3.0",
			Risk:    models.LicenseCopyleft,
			Reason:  "Copyleft license",
		},
	}
	var buf bytes.Buffer
	r := &HTMLReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
}

// ── Table reporter tests ───────────────────────────────────────────────────

func TestTableReporter_NoVulns(t *testing.T) {
	var buf bytes.Buffer
	r := &TableReporter{}
	result := emptyResult()
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	if !strings.Contains(buf.String(), "No vulnerabilities") {
		t.Error("should show no vulns message")
	}
}

func TestTableReporter_WithVulns(t *testing.T) {
	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(testResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CVE-2021-23337") {
		t.Error("table should contain CVE ID")
	}
	if !strings.Contains(out, "lodash") {
		t.Error("table should contain package name")
	}
}

func TestTableReporter_WithCodeAnalysis(t *testing.T) {
	result := testResult()
	result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
		ID:       "AI-001",
		Summary:  "Hardcoded password",
		Severity: models.SeverityHigh,
		Source:   models.SourcePatternMatch,
		FilePath: "/tmp/test-project/app.py",
	})
	var buf bytes.Buffer
	r := &TableReporter{}
	r.Report(result, &buf)
	out := buf.String()
	if !strings.Contains(out, "Code Analysis") {
		t.Error("should show Code Analysis section")
	}
}

func TestTableReporter_WithSemgrep(t *testing.T) {
	result := testResult()
	result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability{
		ID:       "SG-hardcoded-password",
		Summary:  "Hardcoded password in source",
		Severity: models.SeverityHigh,
		Source:   models.SourceSemgrep,
		FilePath: "/tmp/test-project/config.py",
	})
	var buf bytes.Buffer
	r := &TableReporter{}
	r.Report(result, &buf)
	out := buf.String()
	if !strings.Contains(out, "Semgrep") {
		t.Error("should show Semgrep section")
	}
}

func TestTableReporter_LicenseOnly(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath:   "/tmp/test",
		TotalPackages: 2,
		LicenseOnly:   true,
		Packages: []models.Package{
			{Name: "lodash", Version: "4.17.21", License: "MIT"},
			{Name: "gpl-pkg", Version: "1.0", License: "GPL-3.0"},
		},
		LicenseIssues: []models.LicenseIssue{
			{
				Package: models.Package{Name: "gpl-pkg", Version: "1.0"},
				License: "GPL-3.0",
				Risk:    models.LicenseCopyleft,
				Reason:  "Copyleft",
			},
		},
		ScannedAt: time.Now(),
	}
	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
}

// ── PDF reporter tests ─────────────────────────────────────────────────────

func TestPDFReporter_ChromeAvailable(t *testing.T) {
	// Just test the function exists and returns a bool
	_ = ChromeAvailable()
}

func TestPDFReporter_NoChromeError(t *testing.T) {
	// If Chrome is not available, Report should fail with a helpful message
	if ChromeAvailable() {
		t.Skip("Chrome is available, skip no-chrome test")
	}
	var buf bytes.Buffer
	r := &PDFReporter{}
	err := r.Report(testResult(), &buf)
	if err == nil {
		t.Error("expected error when Chrome is not available")
	}
}
