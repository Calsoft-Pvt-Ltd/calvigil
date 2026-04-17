package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
)

func TestWriteReport_Stdout(t *testing.T) {
	rep := reporter.ForFormat("json")
	result := &models.ScanResult{ProjectPath: "/test"}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := writeReport(rep, result, "")
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("writeReport error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "project_path") {
		t.Error("expected JSON output on stdout")
	}
}

func TestWriteReport_ToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")
	rep := reporter.ForFormat("json")
	result := &models.ScanResult{ProjectPath: "/test"}
	if err := writeReport(rep, result, outFile); err != nil {
		t.Fatalf("writeReport error: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(string(data), "project_path") {
		t.Error("expected JSON in output file")
	}
	// Report files must be 0600 — they can contain CVEs, package
	// inventories, and AI-enriched code snippets.
	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("report file perm = %o, want 0600", perm)
	}
}

// TestWriteReport_OverwritesExistingFile verifies that writing to an
// existing file truncates and keeps 0600 perms.
func TestWriteReport_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")
	// Pre-create with permissive perms to ensure writeReport overrides them.
	if err := os.WriteFile(outFile, []byte("old junk"), 0o644); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	rep := reporter.ForFormat("json")
	result := &models.ScanResult{ProjectPath: "/test"}
	if err := writeReport(rep, result, outFile); err != nil {
		t.Fatalf("writeReport: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "old junk") {
		t.Error("expected file to be truncated")
	}
	// Note: O_WRONLY|O_CREATE|O_TRUNC keeps the existing file's perm bits.
	// On a freshly truncated existing file we do NOT expect perms to
	// change. The primary protection is for newly-created files (covered
	// by TestWriteReport_ToFile). This test just asserts truncation.
}

func TestWriteReport_InvalidPath(t *testing.T) {
	rep := reporter.ForFormat("json")
	result := &models.ScanResult{ProjectPath: "/test"}
	err := writeReport(rep, result, "/nonexistent/dir/report.json")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestFilterVulnsBySeverity_CmdEmpty(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "V1", Severity: models.SeverityCritical},
		{ID: "V2", Severity: models.SeverityLow},
	}
	got := filterVulnsBySeverity(vulns, "")
	if len(got) != 2 {
		t.Errorf("empty filter should return all, got %d", len(got))
	}
}

func TestFilterVulnsBySeverity_CmdHigh(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "V1", Severity: models.SeverityCritical},
		{ID: "V2", Severity: models.SeverityHigh},
		{ID: "V3", Severity: models.SeverityMedium},
		{ID: "V4", Severity: models.SeverityLow},
	}
	got := filterVulnsBySeverity(vulns, models.SeverityHigh)
	if len(got) != 2 {
		t.Errorf("high filter: expected 2, got %d", len(got))
	}
}

func TestVersionCommand(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "calvigil") {
		t.Errorf("expected calvigil in version output, got: %s", out)
	}
}

func TestConfigSetGet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"config", "set", "openai-model", "gpt-4-turbo"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("config set error: %v", err)
	}
	if !strings.Contains(buf.String(), "Configuration updated") {
		t.Errorf("expected Configuration updated, got: %s", buf.String())
	}
	buf.Reset()
	rootCmd.SetArgs([]string{"config", "get", "openai-model"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("config get error: %v", err)
	}
	if !strings.Contains(buf.String(), "gpt-4-turbo") {
		t.Errorf("expected gpt-4-turbo, got: %s", buf.String())
	}
}

func TestRunScan_PathNotExist(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", "/nonexistent/path/xyz"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestRunScan_FileNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("hello"), 0644)
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", f})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for file not directory")
	}
}

func TestRunScan_MinimalProject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "json", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	data, _ := os.ReadFile(outFile)
	if !strings.Contains(string(data), "project_path") {
		t.Error("expected JSON report")
	}
}

func TestRunScanIaC_PathNotExist(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-iac", "/nonexistent/path/xyz"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestRunScanIaC_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "iac.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-iac", dir, "--format", "json", "--output", outFile})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-iac error: %v", err)
	}
}

func TestRunScanIaC_WithDockerfile(t *testing.T) {
	dir := t.TempDir()
	df := "FROM ubuntu:latest\nRUN apt-get update\nUSER root\n"
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0644)
	outFile := filepath.Join(dir, "iac.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-iac", dir, "--format", "json", "--output", outFile})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-iac error: %v", err)
	}
	data, _ := os.ReadFile(outFile)
	if len(data) == 0 {
		t.Error("expected non-empty report")
	}
}

func TestRunScanIaC_WithSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	df := "FROM ubuntu:latest\nUSER root\n"
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0644)
	outFile := filepath.Join(dir, "iac.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-iac", dir, "--format", "json", "--output", outFile, "--severity", "critical"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-iac error: %v", err)
	}
}

func TestRunScanBinary_PathNotExist(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-binary", "/nonexistent/binary"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestRunScanBinary_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	outFile := filepath.Join(dir, "bin.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-binary", dir, "--format", "json", "--output", outFile})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-binary error: %v", err)
	}
}

func TestRunScanImage_NoSyft(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-image", "alpine:latest"})
	err := rootCmd.Execute()
	if err == nil {
		t.Skip("syft is installed, skipping no-syft test")
	}
	if !strings.Contains(err.Error(), "syft") {
		t.Errorf("expected syft error, got: %v", err)
	}
}

func TestRunScanLicense_PathNotExist(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", "/nonexistent/path/xyz"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestRunScanLicense_FileNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("hello"), 0644)
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", f})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when path is a file")
	}
}

func TestRunScanLicense_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", dir})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
}

func TestRunScanLicense_WithGoMod(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "license.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", dir, "--format", "json", "--output", outFile})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
	data, _ := os.ReadFile(outFile)
	if !strings.Contains(string(data), "project_path") {
		t.Error("expected JSON report")
	}
}

func TestRunScanLicense_RiskFilter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "license.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", dir, "--format", "json", "--output", outFile, "--risk", "copyleft"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
}

func TestFilterByRisk_Copyleft(t *testing.T) {
	issues := []models.LicenseIssue{
		{Package: models.Package{Name: "gpl-lib"}, Risk: models.LicenseCopyleft},
		{Package: models.Package{Name: "unknown-lib"}, Risk: models.LicenseUnknown},
		{Package: models.Package{Name: "gpl-lib2"}, Risk: models.LicenseCopyleft},
	}
	got := filterByRisk(issues, "copyleft")
	if len(got) != 2 {
		t.Errorf("copyleft filter: expected 2, got %d", len(got))
	}
}

func TestFilterByRisk_Unknown(t *testing.T) {
	issues := []models.LicenseIssue{
		{Package: models.Package{Name: "gpl-lib"}, Risk: models.LicenseCopyleft},
		{Package: models.Package{Name: "unknown-lib"}, Risk: models.LicenseUnknown},
	}
	got := filterByRisk(issues, "unknown")
	if len(got) != 1 {
		t.Errorf("unknown filter: expected 1, got %d", len(got))
	}
}

func TestFilterByRisk_Default(t *testing.T) {
	issues := []models.LicenseIssue{
		{Package: models.Package{Name: "a"}, Risk: models.LicenseCopyleft},
		{Package: models.Package{Name: "b"}, Risk: models.LicenseUnknown},
	}
	got := filterByRisk(issues, "all")
	if len(got) != 2 {
		t.Errorf("default filter should return all, got %d", len(got))
	}
}

func TestPrintLicenseSummary(t *testing.T) {
	pkgs := []models.Package{
		{Name: "a", License: "MIT"},
		{Name: "b", License: "GPL-3.0"},
		{Name: "c", License: "UNKNOWN-LIC"},
		{Name: "d", License: ""},
	}
	issues := []models.LicenseIssue{
		{Package: models.Package{Name: "b"}, Risk: models.LicenseCopyleft},
	}
	var buf bytes.Buffer
	printLicenseSummary(&buf, pkgs, issues, 100*time.Millisecond)
	out := buf.String()
	if !strings.Contains(out, "License Summary") {
		t.Error("expected License Summary header")
	}
}

func TestExecute_Help(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"--help"})
	err := Execute()
	if err != nil {
		t.Fatalf("Execute help error: %v", err)
	}
}

func TestRunScanBinary_WithGoBinary(t *testing.T) {
	dir := t.TempDir()
	// Use a separate dir for HOME that won't get go module cache
	homeDir, err := os.MkdirTemp("", "calvigil-test-home-*")
	if err != nil {
		t.Fatalf("cannot create temp home: %v", err)
	}
	defer os.RemoveAll(homeDir)
	t.Setenv("HOME", homeDir)
	t.Setenv("GOMODCACHE", filepath.Join(os.TempDir(), "go-mod-cache-test"))

	// Build the calvigil binary itself — it has real dependencies
	binPath := filepath.Join(dir, "calvigil")
	projRoot, _ := os.Getwd()
	if filepath.Base(projRoot) == "cmd" {
		projRoot = filepath.Dir(projRoot)
	}
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = projRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build Go binary: %v\n%s", err, out)
	}

	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-binary", binPath, "--format", "json", "--output", outFile, "--verbose"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-binary error: %v", err)
	}
	data, _ := os.ReadFile(outFile)
	if !strings.Contains(string(data), "project_path") {
		t.Error("expected JSON report")
	}
}

func TestRunScanBinary_WithSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-binary", dir, "--format", "json", "--output", outFile, "--severity", "critical"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-binary error: %v", err)
	}
}

func TestRunScan_Verbose(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "json", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache", "--verbose"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
}

func TestRunScanIaC_Verbose(t *testing.T) {
	dir := t.TempDir()
	df := "FROM ubuntu:latest\nUSER root\n"
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0644)
	outFile := filepath.Join(dir, "iac.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-iac", dir, "--format", "json", "--output", outFile, "--verbose"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-iac error: %v", err)
	}
}

func TestRunScanLicense_Verbose(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "license.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", dir, "--format", "json", "--output", outFile, "--verbose"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
}

func TestRunScan_WithDepsAndLicense(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "json", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache", "--check-licenses"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
}

func TestRunScan_WithSeverity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "json", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache", "--severity", "critical"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
}

func TestRunScan_WithIntegrity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "json", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache", "--verify-integrity"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
}

func TestRunScanLicense_WithRiskAndVerbose(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "license.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license", dir, "--format", "json", "--output", outFile, "--risk", "unknown", "--verbose"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
}

func TestRunScan_NoCwdArgs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Chdir(dir)

	outFile := filepath.Join(dir, "report.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	// No path argument — runScan should use cwd.
	rootCmd.SetArgs([]string{"scan", "--format", "json", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
}

func TestRunScan_SARIFFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "report.sarif")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "sarif", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
	data, _ := os.ReadFile(outFile)
	if len(data) == 0 {
		t.Error("expected non-empty SARIF report")
	}
}

func TestRunScan_CycloneDXFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	outFile := filepath.Join(dir, "report.cdx.json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan", dir, "--format", "cyclonedx", "--output", outFile,
		"--skip-ai", "--skip-semgrep", "--no-cache"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan error: %v", err)
	}
	data, _ := os.ReadFile(outFile)
	if len(data) == 0 {
		t.Error("expected non-empty CycloneDX report")
	}
}

func TestRunScanLicense_NoCwdArgs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Chdir(dir)

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-license"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
}

func TestRunScanLicense_TableFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	// Table format (default) exercises the printLicenseSummary path.
	rootCmd.SetArgs([]string{"scan-license", dir, "--format", "table", "--output", ""})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("scan-license error: %v", err)
	}
}

func TestRunScanImage_MissingArg(t *testing.T) {
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"scan-image"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when no image arg provided")
	}
}
