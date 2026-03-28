package reporter

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestSPDX_Registry(t *testing.T) {
	r := ForFormat("spdx")
	if r == nil {
		t.Fatal("ForFormat('spdx') returned nil")
	}
	if _, ok := r.(*SPDXReporter); !ok {
		t.Errorf("expected *SPDXReporter, got %T", r)
	}
}

func TestSPDX_EmptyResult(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/home/user/myproject",
		ScannedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	var buf bytes.Buffer
	r := &SPDXReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX-2.3, got %s", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("expected CC0-1.0, got %s", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("expected SPDXRef-DOCUMENT, got %s", doc.SPDXID)
	}
	if doc.Name != "myproject" {
		t.Errorf("expected 'myproject', got %s", doc.Name)
	}
	if len(doc.Packages) != 1 {
		t.Errorf("expected 1 root package, got %d", len(doc.Packages))
	}
	if doc.Packages[0].SPDXID != "SPDXRef-RootPackage" {
		t.Errorf("expected SPDXRef-RootPackage, got %s", doc.Packages[0].SPDXID)
	}
}

func TestSPDX_WithPackages(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/project",
		ScannedAt:   time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
		Packages: []models.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm, License: "MIT"},
			{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, License: ""},
		},
	}

	var buf bytes.Buffer
	r := &SPDXReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// 1 root + 2 packages
	if len(doc.Packages) != 3 {
		t.Fatalf("expected 3 packages (root + 2), got %d", len(doc.Packages))
	}

	// Check license fields
	expressPkg := doc.Packages[1]
	if expressPkg.LicenseDeclared != "MIT" {
		t.Errorf("expected MIT license, got %s", expressPkg.LicenseDeclared)
	}

	lodashPkg := doc.Packages[2]
	if lodashPkg.LicenseDeclared != "NOASSERTION" {
		t.Errorf("expected NOASSERTION for empty license, got %s", lodashPkg.LicenseDeclared)
	}
}

func TestSPDX_WithVulnerabilities(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/project",
		ScannedAt:   time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
		Packages: []models.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
		},
		Vulnerabilities: []models.Vulnerability{
			{
				ID:      "CVE-2024-1234",
				Summary: "Test vuln",
				Severity: models.SeverityHigh,
				Package: models.Package{Name: "express", Version: "4.18.2"},
				FixedIn: "4.18.3",
			},
		},
	}

	var buf bytes.Buffer
	r := &SPDXReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check annotations on the express package
	found := false
	for _, pkg := range doc.Packages {
		if pkg.Name == "express" && len(pkg.Annotations) > 0 {
			found = true
			ann := pkg.Annotations[0]
			if ann.AnnotationType != "REVIEW" {
				t.Errorf("expected REVIEW annotation, got %s", ann.AnnotationType)
			}
		}
	}
	if !found {
		t.Error("expected vulnerability annotation on express package")
	}
}

func TestSPDX_Relationships(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/project",
		ScannedAt:   time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
		Packages: []models.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
		},
	}

	var buf bytes.Buffer
	r := &SPDXReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Should have DEPENDS_ON + DESCRIBES relationships
	hasDescribes := false
	hasDependsOn := false
	for _, rel := range doc.Relationships {
		if rel.RelationshipType == "DESCRIBES" {
			hasDescribes = true
		}
		if rel.RelationshipType == "DEPENDS_ON" {
			hasDependsOn = true
		}
	}
	if !hasDescribes {
		t.Error("missing DESCRIBES relationship")
	}
	if !hasDependsOn {
		t.Error("missing DEPENDS_ON relationship")
	}
}

func TestSPDX_ValidJSON(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/project/with spaces",
		ScannedAt:   time.Now(),
		Packages: []models.Package{
			{Name: "pkg-with-special/chars", Version: "1.0.0-beta.1", Ecosystem: models.EcosystemNpm},
		},
	}

	var buf bytes.Buffer
	r := &SPDXReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Error("output is not valid JSON")
	}
}

func TestSPDX_FallbackToVulnPackages(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/project",
		ScannedAt:   time.Date(2025, 3, 15, 12, 0, 0, 0, time.UTC),
		// No Packages field set - should extract from vulnerabilities
		Vulnerabilities: []models.Vulnerability{
			{
				ID:       "CVE-2024-1234",
				Summary:  "Test vuln",
				Severity: models.SeverityHigh,
				Package:  models.Package{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
			},
		},
	}

	var buf bytes.Buffer
	r := &SPDXReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(doc.Packages) != 2 {
		t.Errorf("expected 2 packages (root + express), got %d", len(doc.Packages))
	}
}

func TestOrEmpty(t *testing.T) {
	if got := orEmpty("hello", "world"); got != "hello" {
		t.Errorf("expected 'hello', got %s", got)
	}
	if got := orEmpty("", "fallback"); got != "fallback" {
		t.Errorf("expected 'fallback', got %s", got)
	}
}
