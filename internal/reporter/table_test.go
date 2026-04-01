package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestSplitMalicious(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "MAL-2024-1234", Package: models.Package{Name: "evil-pkg"}, Source: models.SourceOSV},
		{ID: "CVE-2024-5678", Package: models.Package{Name: "lodash"}, Source: models.SourceOSV},
		{ID: "GHSA-xxxx", Aliases: []string{"MAL-2024-9999"}, Package: models.Package{Name: "sneaky"}, Source: models.SourceGitHubAdv},
		{ID: "CVE-2024-1111", Package: models.Package{Name: "express"}, Source: models.SourceNVD},
	}

	mal, clean := splitMalicious(vulns)

	if len(mal) != 2 {
		t.Fatalf("expected 2 malicious, got %d", len(mal))
	}
	if len(clean) != 2 {
		t.Fatalf("expected 2 clean, got %d", len(clean))
	}

	if mal[0].ID != "MAL-2024-1234" && mal[1].ID != "MAL-2024-1234" {
		t.Error("expected MAL-2024-1234 in malicious set")
	}
	if mal[0].ID != "GHSA-xxxx" && mal[1].ID != "GHSA-xxxx" {
		t.Error("expected GHSA-xxxx (with MAL alias) in malicious set")
	}
}

func TestTableReport_MaliciousSection(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath: "/test/project",
		TotalPackages: 10,
		Ecosystems:    []models.Ecosystem{models.EcosystemNpm},
		ScannedAt:     time.Now(),
		Duration:      time.Second,
		Vulnerabilities: []models.Vulnerability{
			{
				ID:       "MAL-2024-1234",
				Summary:  "Malicious package steals credentials",
				Severity: models.SeverityCritical,
				Package:  models.Package{Name: "evil-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
				Source:   models.SourceOSV,
			},
			{
				ID:       "CVE-2024-5678",
				Summary:  "XSS vulnerability",
				Severity: models.SeverityHigh,
				Package:  models.Package{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm},
				Source:   models.SourceOSV,
			},
		},
	}

	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Malicious Packages Detected") {
		t.Error("expected malicious packages section in output")
	}
	if !strings.Contains(output, "evil-pkg") {
		t.Error("expected evil-pkg in malicious section")
	}
	if !strings.Contains(output, "Dependency Vulnerabilities") {
		t.Error("expected dependency vulnerabilities section in output")
	}
}

func TestTableReport_IntegritySection(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath:   "/test/project",
		TotalPackages: 5,
		Ecosystems:    []models.Ecosystem{models.EcosystemNpm},
		ScannedAt:     time.Now(),
		Duration:      time.Second,
		IntegrityIssues: []models.IntegrityIssue{
			{
				Package: models.Package{Name: "suspicious", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
				Reason:  "integrity hash in lockfile does not match npm registry",
			},
		},
	}

	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Lockfile Integrity Issues") {
		t.Error("expected integrity issues section in output")
	}
}

func TestTableReport_ConsistencySection(t *testing.T) {
	result := &models.ScanResult{
		ProjectPath:   "/test/project",
		TotalPackages: 5,
		Ecosystems:    []models.Ecosystem{models.EcosystemNpm},
		ScannedAt:     time.Now(),
		Duration:      time.Second,
		ConsistencyIssues: []models.ConsistencyIssue{
			{
				Package:  models.Package{Name: "phantom-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
				LockFile: "/test/project/package-lock.json",
				Manifest: "/test/project/package.json",
				Reason:   "package in lockfile but not declared in manifest",
			},
		},
	}

	var buf bytes.Buffer
	r := &TableReporter{}
	if err := r.Report(result, &buf); err != nil {
		t.Fatalf("Report error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Phantom Dependencies") {
		t.Error("expected phantom dependencies section in output")
	}
	if !strings.Contains(output, "phantom-pkg") {
		t.Error("expected phantom-pkg in output")
	}
}
