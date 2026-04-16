//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	binaryPath string
	buildOnce  sync.Once
	buildErr   error
)

func ensureBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		repoRoot := filepath.Join(testdataDir(), "..", "..", "..")
		binaryPath = filepath.Join(os.TempDir(), "calvigil-integration-test")
		if runtime.GOOS == "windows" {
			binaryPath += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", binaryPath, ".")
		cmd.Dir = repoRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = err
			t.Logf("build output: %s", out)
		}
	})
	if buildErr != nil {
		t.Fatalf("failed to build calvigil: %v", buildErr)
	}
	return binaryPath
}

func testdataDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "testdata")
}

func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	bin := ensureBinary(t)
	cmd := exec.Command(bin, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, err := run(t, args...)
	if err != nil {
		t.Fatalf("command failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return stdout
}

// ── 1. CLI basics ───────────────────────────────────────────────────────────

func TestVersionCommand(t *testing.T) {
	out := runOK(t, "version")
	if !strings.Contains(out, "calvigil") {
		t.Errorf("version output should contain 'calvigil', got: %s", out)
	}
}

func TestRootHelpCommand(t *testing.T) {
	out := runOK(t, "--help")
	for _, want := range []string{"scan", "scan-iac", "scan-binary", "scan-license", "scan-image", "config", "version"} {
		if !strings.Contains(out, want) {
			t.Errorf("help output should mention %q", want)
		}
	}
}

func TestScanHelp(t *testing.T) {
	out := runOK(t, "scan", "--help")
	for _, flag := range []string{
		"--format", "--severity", "--skip-ai", "--skip-deps",
		"--skip-semgrep", "--verify-integrity", "--no-cache",
		"--check-licenses", "--provider",
	} {
		if !strings.Contains(out, flag) {
			t.Errorf("scan --help should mention %s", flag)
		}
	}
}

func TestScanInvalidPath(t *testing.T) {
	_, _, err := run(t, "scan", "/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("scan with invalid path should fail")
	}
}

func TestScanInvalidFormat(t *testing.T) {
	_, _, err := run(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "doesnotexist", "--no-cache")
	if err != nil {
		t.Errorf("scan with unknown format should not crash: %v", err)
	}
}

// ── 2. Ecosystem detection & dependency parsing ─────────────────────────────

func TestScanDetectsMultiEcosystem(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	ecosystems, ok := result["ecosystems"].([]interface{})
	if !ok {
		t.Fatal("JSON output should contain 'ecosystems' array")
	}
	ecoSet := make(map[string]bool)
	for _, e := range ecosystems {
		ecoSet[e.(string)] = true
	}
	for _, want := range []string{"Go", "npm", "PyPI", "crates.io", "Maven"} {
		if !ecoSet[want] {
			t.Errorf("expected ecosystem %q in output, found: %v", want, ecoSet)
		}
	}
}

func TestScanCountsPackages(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	total, ok := result["total_packages"].(float64)
	if !ok || total < 5 {
		t.Errorf("expected at least 5 packages, got %.0f", total)
	}
}

// ── 3. Output format validation ─────────────────────────────────────────────

func TestOutputFormatJSON(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("JSON output should be valid JSON: %v", err)
	}
	for _, key := range []string{"project_path", "ecosystems", "total_packages", "vulnerabilities", "scanned_at", "duration"} {
		if _, exists := result[key]; !exists {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}

func TestOutputFormatSARIF(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "sarif", "--no-cache")
	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("SARIF output should be valid JSON: %v", err)
	}
	if v, ok := sarif["version"].(string); !ok || v != "2.1.0" {
		t.Errorf("SARIF version should be 2.1.0, got %v", sarif["version"])
	}
	if _, ok := sarif["runs"].([]interface{}); !ok {
		t.Error("SARIF output should contain 'runs' array")
	}
}

func TestOutputFormatCycloneDX(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "cyclonedx", "--no-cache")
	var cdx map[string]interface{}
	if err := json.Unmarshal([]byte(out), &cdx); err != nil {
		t.Fatalf("CycloneDX output should be valid JSON: %v", err)
	}
	if _, ok := cdx["bomFormat"]; !ok {
		t.Error("CycloneDX output should have 'bomFormat'")
	}
}

func TestOutputFormatOpenVEX(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "openvex", "--no-cache")
	var vex map[string]interface{}
	if err := json.Unmarshal([]byte(out), &vex); err != nil {
		t.Fatalf("OpenVEX output should be valid JSON: %v", err)
	}
}

func TestOutputFormatSPDX(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "spdx", "--no-cache")
	var spdx map[string]interface{}
	if err := json.Unmarshal([]byte(out), &spdx); err != nil {
		t.Fatalf("SPDX output should be valid JSON: %v", err)
	}
}

func TestOutputFormatTable(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "table", "--no-cache")
	if !strings.Contains(out, "vulnerabilit") &&
		!strings.Contains(out, "Scan Results") &&
		!strings.Contains(out, "No vulnerabilities") {
		t.Error("table output should contain vulnerability-related text")
	}
}

func TestOutputToFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "output.json")
	runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--output", tmp, "--no-cache")

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("output file should exist: %v", err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("output file should contain valid JSON: %v", err)
	}
}

// ── 4. Severity filtering ───────────────────────────────────────────────────

func TestSeverityFilterHigh(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--severity", "high", "--no-cache")

	var result struct {
		Vulnerabilities []struct {
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, v := range result.Vulnerabilities {
		sev := strings.ToUpper(v.Severity)
		if sev != "HIGH" && sev != "CRITICAL" {
			t.Errorf("with --severity high, found vuln with severity %s", v.Severity)
		}
	}
}

func TestSeverityFilterCritical(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--severity", "critical", "--no-cache")

	var result struct {
		Vulnerabilities []struct {
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, v := range result.Vulnerabilities {
		if strings.ToUpper(v.Severity) != "CRITICAL" {
			t.Errorf("with --severity critical, found vuln with severity %s", v.Severity)
		}
	}
}

// ── 5. Supply chain: phantom dependency detection ───────────────────────────

func TestPhantomDependencyDetection(t *testing.T) {
	phantomDir := filepath.Join(testdataDir(), "phantom")
	out := runOK(t, "scan", phantomDir,
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		ConsistencyIssues []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Reason string `json:"reason"`
		} `json:"consistency_issues"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	found := false
	for _, issue := range result.ConsistencyIssues {
		if issue.Package.Name == "sneaky-inject" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'sneaky-inject' to be flagged as phantom dependency")
	}
}

func TestPhantomTransitiveNotFlagged(t *testing.T) {
	phantomDir := filepath.Join(testdataDir(), "phantom")
	out := runOK(t, "scan", phantomDir,
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		ConsistencyIssues []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"consistency_issues"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, issue := range result.ConsistencyIssues {
		if issue.Package.Name == "cookie" {
			t.Error("transitive dep 'cookie' should NOT be flagged as phantom")
		}
	}
}

// ── 6. Supply chain: integrity verification ─────────────────────────────────

func TestIntegrityVerificationTableOutput(t *testing.T) {
	phantomDir := filepath.Join(testdataDir(), "phantom")
	stdout, _, _ := run(t, "scan", phantomDir,
		"--skip-ai", "--skip-semgrep", "--verify-integrity", "--no-cache")

	if !strings.Contains(stdout, "Integrity") &&
		!strings.Contains(stdout, "No vulnerabilities") {
		t.Log("stdout:", stdout)
		t.Error("expected integrity-related output when --verify-integrity is used")
	}
}

func TestSkipDepsWithVerifyIntegrity(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-deps", "--skip-ai", "--skip-semgrep",
		"--verify-integrity", "--format", "json", "--no-cache")

	var result struct {
		TotalPackages int `json:"total_packages"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.TotalPackages == 0 {
		t.Error("--skip-deps + --verify-integrity should still parse packages")
	}
}

// ── 7. IaC scanning ────────────────────────────────────────────────────────

func TestIaCScanFindsIssues(t *testing.T) {
	out := runOK(t, "scan-iac", testdataDir(), "--format", "json")

	var result struct {
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			FilePath string `json:"file_path"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Vulnerabilities) == 0 {
		t.Fatal("IaC scan should find misconfigurations in Dockerfile and insecure.tf")
	}

	foundDockerfile := false
	foundTerraform := false
	for _, v := range result.Vulnerabilities {
		if strings.Contains(v.FilePath, "Dockerfile") {
			foundDockerfile = true
		}
		if strings.Contains(v.FilePath, ".tf") {
			foundTerraform = true
		}
	}
	if !foundDockerfile {
		t.Error("expected IaC findings from Dockerfile")
	}
	if !foundTerraform {
		t.Error("expected IaC findings from insecure.tf")
	}
}

func TestIaCScanSeverityFilter(t *testing.T) {
	out := runOK(t, "scan-iac", testdataDir(), "--format", "json", "--severity", "high")

	var result struct {
		Vulnerabilities []struct {
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, v := range result.Vulnerabilities {
		sev := strings.ToUpper(v.Severity)
		if sev != "HIGH" && sev != "CRITICAL" {
			t.Errorf("with --severity high, found IaC vuln with severity %s", v.Severity)
		}
	}
}

func TestIaCScanSARIF(t *testing.T) {
	out := runOK(t, "scan-iac", testdataDir(), "--format", "sarif")
	var sarif map[string]interface{}
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("IaC scan SARIF should be valid JSON: %v", err)
	}
	if v, _ := sarif["version"].(string); v != "2.1.0" {
		t.Errorf("SARIF version should be 2.1.0, got %v", sarif["version"])
	}
}

func TestIaCScanInvalidPath(t *testing.T) {
	_, _, err := run(t, "scan-iac", "/nonexistent/path")
	if err == nil {
		t.Error("scan-iac with invalid path should fail")
	}
}

func TestIaCJSONStructure(t *testing.T) {
	out := runOK(t, "scan-iac", testdataDir(), "--format", "json")

	var result struct {
		Vulnerabilities []struct {
			ID        string `json:"id"`
			Severity  string `json:"severity"`
			Summary   string `json:"summary"`
			FilePath  string `json:"file_path"`
			StartLine int    `json:"start_line"`
			Source    string `json:"source"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, v := range result.Vulnerabilities {
		if v.Source != "iac" {
			t.Errorf("IaC vuln %s should have source 'iac', got %q", v.ID, v.Source)
		}
		if v.FilePath == "" {
			t.Errorf("IaC vuln %s should have a file_path", v.ID)
		}
		if v.StartLine == 0 {
			t.Errorf("IaC vuln %s should have a start_line", v.ID)
		}
	}
}

// ── 8. License scanning ────────────────────────────────────────────────────

func TestLicenseScanBasic(t *testing.T) {
	out := runOK(t, "scan-license", testdataDir(), "--format", "json")

	var result struct {
		LicenseOnly   bool `json:"license_only"`
		TotalPackages int  `json:"total_packages"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !result.LicenseOnly {
		t.Error("scan-license should set license_only=true")
	}
	if result.TotalPackages == 0 {
		t.Error("scan-license should discover packages")
	}
}

// ── 9. Config commands ──────────────────────────────────────────────────────

func TestConfigSetAndGet(t *testing.T) {
	runOK(t, "config", "set", "openai-model", "gpt-4-turbo-test")
	out := runOK(t, "config", "get", "openai-model")
	if !strings.Contains(out, "gpt-4-turbo-test") {
		t.Errorf("config get should return 'gpt-4-turbo-test', got: %s", out)
	}
	runOK(t, "config", "set", "openai-model", "gpt-4")
}

func TestConfigInvalidKey(t *testing.T) {
	_, _, err := run(t, "config", "set", "nonexistent-key", "value")
	if err == nil {
		t.Error("config set with invalid key should fail")
	}
}

func TestConfigGetInvalidKey(t *testing.T) {
	_, _, err := run(t, "config", "get", "nonexistent-key")
	if err == nil {
		t.Error("config get with invalid key should fail")
	}
}

// ── 10. PURL generation ────────────────────────────────────────────────────

func TestPURLsInJSON(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		Packages []struct {
			Name string `json:"name"`
			PURL string `json:"purl"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Packages) == 0 {
		t.Skip("no packages in output to check PURLs")
	}
	for _, pkg := range result.Packages {
		if pkg.PURL == "" {
			t.Errorf("package %q should have a PURL", pkg.Name)
		}
		if !strings.HasPrefix(pkg.PURL, "pkg:") {
			t.Errorf("PURL for %q should start with 'pkg:', got %q", pkg.Name, pkg.PURL)
		}
	}
}

// ── 11. Transitive dependency detection ─────────────────────────────────────

func TestTransitiveDepsInJSON(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		Packages []struct {
			Name     string `json:"name"`
			Indirect bool   `json:"indirect"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	directCount, transitiveCount := 0, 0
	for _, pkg := range result.Packages {
		if pkg.Indirect {
			transitiveCount++
		} else {
			directCount++
		}
	}
	if directCount == 0 {
		t.Error("expected at least some direct dependencies")
	}
	if transitiveCount == 0 {
		t.Error("expected at least some transitive dependencies")
	}
}

// ── 12. Vulnerability source tracking ───────────────────────────────────────

func TestVulnerabilitySourceField(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		Vulnerabilities []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(result.Vulnerabilities) == 0 {
		t.Skip("no vulnerabilities found to check source field")
	}
	validSources := map[string]bool{"osv": true, "nvd": true, "github-advisory": true}
	for _, v := range result.Vulnerabilities {
		if !validSources[v.Source] {
			t.Errorf("vulnerability %s has unexpected source %q", v.ID, v.Source)
		}
	}
}

// ── 13. Verbose mode ────────────────────────────────────────────────────────

func TestVerboseOutput(t *testing.T) {
	_, stderr, err := run(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "-v", "--no-cache")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, want := range []string{"Detecting", "Parsing", "packages"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("verbose stderr should contain %q", want)
		}
	}
}

// ── 14. Cache behaviour ────────────────────────────────────────────────────

func TestNoCacheFlag(t *testing.T) {
	out1 := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json")
	out2 := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var r1, r2 map[string]interface{}
	if err := json.Unmarshal([]byte(out1), &r1); err != nil {
		t.Fatalf("run 1 invalid JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(out2), &r2); err != nil {
		t.Fatalf("run 2 invalid JSON: %v", err)
	}
	if r1["total_packages"] != r2["total_packages"] {
		t.Errorf("cache vs no-cache should return same package count: %v vs %v",
			r1["total_packages"], r2["total_packages"])
	}
}

// ── 15. Deterministic output ────────────────────────────────────────────────

func TestDeterministicOutput(t *testing.T) {
	out1 := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")
	out2 := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var r1, r2 struct {
		TotalPackages int      `json:"total_packages"`
		Ecosystems    []string `json:"ecosystems"`
	}
	json.Unmarshal([]byte(out1), &r1)
	json.Unmarshal([]byte(out2), &r2)

	if r1.TotalPackages != r2.TotalPackages {
		t.Errorf("two scans should yield same package count: %d vs %d",
			r1.TotalPackages, r2.TotalPackages)
	}
	if len(r1.Ecosystems) != len(r2.Ecosystems) {
		t.Errorf("two scans should yield same ecosystem count: %d vs %d",
			len(r1.Ecosystems), len(r2.Ecosystems))
	}
}

// ── 16. JSON output structural completeness ─────────────────────────────────

func TestJSONOutputStructure(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		ProjectPath     string `json:"project_path"`
		TotalPackages   int    `json:"total_packages"`
		ScannedAt       string `json:"scanned_at"`
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Source  string `json:"source"`
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.ProjectPath == "" {
		t.Error("project_path should not be empty")
	}
	if result.ScannedAt == "" {
		t.Error("scanned_at should not be empty")
	}
	if result.TotalPackages == 0 {
		t.Error("total_packages should be > 0")
	}
	for _, v := range result.Vulnerabilities {
		if v.ID == "" {
			t.Error("vulnerability ID should not be empty")
		}
		if v.Package.Name == "" {
			t.Error("vulnerability package name should not be empty")
		}
		if v.Source == "" {
			t.Error("vulnerability source should not be empty")
		}
	}
}

// ── 17. Integrity hash parsing ──────────────────────────────────────────────

func TestNpmIntegrityInPackages(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		Packages []struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	integrityCount := 0
	for _, pkg := range result.Packages {
		if pkg.Ecosystem == "npm" && pkg.Integrity != "" {
			integrityCount++
		}
	}
	if integrityCount < 2 {
		t.Errorf("expected at least 2 npm packages with integrity hashes, got %d", integrityCount)
	}
}

func TestCargoChecksumInPackages(t *testing.T) {
	out := runOK(t, "scan", testdataDir(),
		"--skip-ai", "--skip-semgrep", "--format", "json", "--no-cache")

	var result struct {
		Packages []struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	checksumCount := 0
	for _, pkg := range result.Packages {
		if pkg.Ecosystem == "crates.io" && strings.HasPrefix(pkg.Integrity, "sha256-") {
			checksumCount++
		}
	}
	if checksumCount < 2 {
		t.Errorf("expected at least 2 crates.io packages with sha256- checksums, got %d", checksumCount)
	}
}
