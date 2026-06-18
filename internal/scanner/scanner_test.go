package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/config"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/detector"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/license"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/matcher"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
)

func init() {
	license.SetResolverForTesting(func(_ context.Context, pkg models.Package) string {
		if pkg.License != "" {
			return pkg.License
		}
		return "Apache-2.0"
	})
}

func TestFilterBySeverity_Critical(t *testing.T) {
	vulns := makeVulns()
	got := filterBySeverity(vulns, models.SeverityCritical)
	if len(got) != 1 {
		t.Errorf("critical: got %d, want 1", len(got))
	}
}

func TestFilterBySeverity_High(t *testing.T) {
	got := filterBySeverity(makeVulns(), models.SeverityHigh)
	if len(got) != 2 {
		t.Errorf("high: got %d, want 2", len(got))
	}
}

func TestFilterBySeverity_Medium(t *testing.T) {
	got := filterBySeverity(makeVulns(), models.SeverityMedium)
	if len(got) != 3 {
		t.Errorf("medium: got %d, want 3", len(got))
	}
}

func TestFilterBySeverity_Low(t *testing.T) {
	got := filterBySeverity(makeVulns(), models.SeverityLow)
	if len(got) != 4 {
		t.Errorf("low: got %d, want 4", len(got))
	}
}

func TestFilterBySeverity_Unknown(t *testing.T) {
	got := filterBySeverity(makeVulns(), models.SeverityUnknown)
	if len(got) != 5 {
		t.Errorf("unknown: got %d, want 5", len(got))
	}
}

func TestFilterBySeverity_Nil(t *testing.T) {
	got := filterBySeverity(nil, models.SeverityHigh)
	if len(got) != 0 {
		t.Errorf("nil: got %d, want 0", len(got))
	}
}

func TestDependencyMatchersSkipsOSSIndexWithoutCredentials(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{},
		cfg:  &config.Config{},
	}

	got := matcherNames(s.dependencyMatchers())
	if strings.Join(got, ",") != "osv" {
		t.Fatalf("matchers = %v, want only osv", got)
	}
}

func TestDependencyMatchersIncludesOSSIndexWithCredentials(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{},
		cfg:  &config.Config{OSSIndexUser: "user@example.com", OSSIndexToken: "token"},
	}

	got := matcherNames(s.dependencyMatchers())
	if strings.Join(got, ",") != "osv,oss-index" {
		t.Fatalf("matchers = %v, want osv and oss-index", got)
	}
}

func matcherNames(matchers []matcher.Matcher) []string {
	names := make([]string, 0, len(matchers))
	for _, m := range matchers {
		names = append(names, m.Name())
	}
	return names
}

func TestPopulateDepPaths_Basic(t *testing.T) {
	vulns := []models.Vulnerability{{
		ID:      "CVE-1",
		Package: models.Package{Name: "lodash", Version: "4.17", FilePath: "/p/lock.json"},
	}}
	populateDepPaths(vulns, "/p")
	if vulns[0].DepPath == "" {
		t.Error("DepPath should be set")
	}
}

func TestPopulateDepPaths_Transitive(t *testing.T) {
	vulns := []models.Vulnerability{{
		ID:      "CVE-1",
		Package: models.Package{Name: "x", Version: "1", Indirect: true, FilePath: "/p/l.json"},
	}}
	populateDepPaths(vulns, "/p")
	if !strings.Contains(vulns[0].DepPath, "[transitive]") {
		t.Error("should contain [transitive]")
	}
}

func TestPopulateDepPaths_Existing(t *testing.T) {
	vulns := []models.Vulnerability{{
		ID: "CVE-1", DepPath: "keep",
		Package: models.Package{Name: "x", Version: "1"},
	}}
	populateDepPaths(vulns, "/p")
	if vulns[0].DepPath != "keep" {
		t.Error("should not overwrite")
	}
}

func TestPopulateDepPaths_NoName(t *testing.T) {
	vulns := []models.Vulnerability{{ID: "CVE-1"}}
	populateDepPaths(vulns, "/p")
	if vulns[0].DepPath != "" {
		t.Error("no name means no path")
	}
}

func TestBuildImportPatterns(t *testing.T) {
	need := map[string]bool{"a": false, "b": false}
	r := buildImportPatterns(need)
	if len(r) != 2 {
		t.Fatalf("got %d, want 2", len(r))
	}
}

func TestScanFileForImports_Found(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "m.go")
	os.WriteFile(f, []byte("import \"gin\"\n"), 0644)
	p := map[string]bool{"gin": false}
	scanFileForImports(f, p)
	if !p["gin"] {
		t.Error("gin not found")
	}
}

func TestScanFileForImports_NotFound(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "m.go")
	os.WriteFile(f, []byte("package main\n"), 0644)
	p := map[string]bool{"express": false}
	scanFileForImports(f, p)
	if p["express"] {
		t.Error("express should not be found")
	}
}

func TestPopulateReachability_Mixed(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "m.go")
	os.WriteFile(f, []byte("import \"vuln/pkg\"\n"), 0644)
	vulns := []models.Vulnerability{
		{ID: "C1", Source: models.SourcePatternMatch},
		{ID: "C2", Source: models.SourceOSV, Package: models.Package{Name: "vuln/pkg"}},
		{ID: "C3", Source: models.SourceOSV, Package: models.Package{Name: "other"}},
	}
	populateReachability(vulns, d, false, false)
	if vulns[0].Reachable == "" {
		t.Error("pattern should have reachable")
	}
	if vulns[1].Reachable == "" {
		t.Error("imported should have reachable")
	}
	if vulns[2].Reachable == "" {
		t.Error("other should have reachable")
	}
}

func makeVulns() []models.Vulnerability {
	return []models.Vulnerability{
		{ID: "1", Severity: models.SeverityCritical},
		{ID: "2", Severity: models.SeverityHigh},
		{ID: "3", Severity: models.SeverityMedium},
		{ID: "4", Severity: models.SeverityLow},
		{ID: "5", Severity: models.SeverityUnknown},
	}
}

func TestResolveAIProvider_Ollama(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{AIProvider: "ollama"},
		cfg:  &config.Config{},
	}
	got := s.resolveAIProvider()
	if got != "ollama" {
		t.Errorf("resolveAIProvider(ollama) = %q, want ollama", got)
	}
}

func TestResolveAIProvider_OpenAI_WithKey(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{AIProvider: "openai"},
		cfg:  &config.Config{OpenAIKey: "sk-test"},
	}
	got := s.resolveAIProvider()
	if got != "openai" {
		t.Errorf("resolveAIProvider(openai+key) = %q, want openai", got)
	}
}

func TestResolveAIProvider_OpenAI_NoKey(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{AIProvider: "openai"},
		cfg:  &config.Config{},
	}
	got := s.resolveAIProvider()
	if got != "" {
		t.Errorf("resolveAIProvider(openai no key) = %q, want empty", got)
	}
}

func TestResolveAIProvider_Auto_NoProviders(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{AIProvider: "auto"},
		cfg:  &config.Config{},
	}
	got := s.resolveAIProvider()
	if got != "" {
		t.Errorf("resolveAIProvider(auto no providers) = %q, want empty", got)
	}
}

func TestResolveAIProvider_Auto_OpenAIFallback(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{},
		cfg:  &config.Config{OpenAIKey: "sk-test"},
	}
	got := s.resolveAIProvider()
	if got != "openai" {
		t.Errorf("resolveAIProvider(auto+openai key) = %q, want openai", got)
	}
}

func TestOllamaSettings_FromOpts(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{
			OllamaURL:   "http://custom:11434",
			OllamaModel: "llama3",
		},
		cfg: &config.Config{
			OllamaURL:   "http://config:11434",
			OllamaModel: "config-model",
		},
	}
	url, model := s.ollamaSettings()
	if url != "http://custom:11434" {
		t.Errorf("url = %q, want http://custom:11434", url)
	}
	if model != "llama3" {
		t.Errorf("model = %q, want llama3", model)
	}
}

func TestOllamaSettings_FromConfig(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{},
		cfg: &config.Config{
			OllamaURL:   "http://config:11434",
			OllamaModel: "config-model",
		},
	}
	url, model := s.ollamaSettings()
	if url != "http://config:11434" {
		t.Errorf("url = %q, want http://config:11434", url)
	}
	if model != "config-model" {
		t.Errorf("model = %q, want config-model", model)
	}
}

func TestGetAIEnricher_NoProvider(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{},
		cfg:  &config.Config{},
	}
	e := s.getAIEnricher()
	if e != nil {
		t.Error("expected nil enricher when no provider available")
	}
}

func TestGetAIEnricher_OpenAI(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{AIProvider: "openai"},
		cfg:  &config.Config{OpenAIKey: "sk-test", OpenAIModel: "gpt-4"},
	}
	e := s.getAIEnricher()
	if e == nil {
		t.Error("expected non-nil enricher for openai")
	}
}

func TestGetAIEnricher_Ollama(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{AIProvider: "ollama", OllamaURL: "http://localhost:11434", OllamaModel: "llama3"},
		cfg:  &config.Config{},
	}
	e := s.getAIEnricher()
	if e == nil {
		t.Error("expected non-nil enricher for ollama")
	}
}

func TestWriteReport_Stdout(t *testing.T) {
	s := &Scanner{
		opts:     models.ScanOptions{Format: "json"},
		cfg:      &config.Config{},
		reporter: reporter.ForFormat("json"),
	}
	result := &models.ScanResult{
		ProjectPath: "/test",
	}
	// writeReport writes to stdout by default
	// We need to capture it — redirect stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := s.writeReport(result)
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("writeReport error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "project_path") {
		t.Errorf("expected JSON output with project_path, got: %s", buf.String())
	}
}

func TestWriteReport_ToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")
	s := &Scanner{
		opts:     models.ScanOptions{Format: "json", OutputFile: outFile},
		cfg:      &config.Config{},
		reporter: reporter.ForFormat("json"),
	}
	result := &models.ScanResult{
		ProjectPath: "/test",
	}
	err := s.writeReport(result)
	if err != nil {
		t.Fatalf("writeReport error: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), "project_path") {
		t.Errorf("expected JSON with project_path, got: %s", string(data))
	}
}

func TestPopulateDepPaths_NoFilePath(t *testing.T) {
	vulns := []models.Vulnerability{{
		ID:      "CVE-1",
		Package: models.Package{Name: "test", Version: "1.0", Ecosystem: "npm"},
	}}
	populateDepPaths(vulns, "/project")
	if vulns[0].DepPath == "" {
		t.Error("DepPath should be set even without FilePath")
	}
	if !strings.Contains(vulns[0].DepPath, "npm") {
		t.Errorf("DepPath should contain ecosystem name, got: %s", vulns[0].DepPath)
	}
}

func TestPopulateReachability_PatternMatch(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "C1", Source: models.SourcePatternMatch},
	}
	populateReachability(vulns, t.TempDir(), false, false)
	if !strings.Contains(vulns[0].Reachable, "direct") {
		t.Errorf("pattern match should be marked direct, got: %s", vulns[0].Reachable)
	}
}

func TestPopulateReachability_AIAnalysis(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "C1", Source: models.SourceAIAnalysis},
	}
	populateReachability(vulns, t.TempDir(), false, false)
	if !strings.Contains(vulns[0].Reachable, "direct") {
		t.Errorf("AI analysis should be marked direct, got: %s", vulns[0].Reachable)
	}
}

func TestPopulateReachability_Semgrep(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "C1", Source: models.SourceSemgrep},
	}
	populateReachability(vulns, t.TempDir(), false, false)
	if !strings.Contains(vulns[0].Reachable, "direct") {
		t.Errorf("semgrep should be marked direct, got: %s", vulns[0].Reachable)
	}
}

func TestPopulateReachability_AlreadySet(t *testing.T) {
	vulns := []models.Vulnerability{
		{ID: "C1", Source: models.SourceOSV, Reachable: "already-set"},
	}
	populateReachability(vulns, t.TempDir(), false, false)
	if vulns[0].Reachable != "already-set" {
		t.Errorf("should not overwrite, got: %s", vulns[0].Reachable)
	}
}

func TestScanFileForImports_AllFound(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "m.go")
	os.WriteFile(f, []byte("import \"a\"\nimport \"b\"\n"), 0644)
	p := map[string]bool{"a": false, "b": false}
	scanFileForImports(f, p)
	if !p["a"] || !p["b"] {
		t.Error("both packages should be found")
	}
}

func TestScanFileForImports_AlreadyAllFound(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "m.go")
	os.WriteFile(f, []byte("import \"a\"\n"), 0644)
	p := map[string]bool{"a": true} // already found — should skip reading file
	scanFileForImports(f, p)
	// No assertion needed — just verifying it doesn't crash
}

func TestFilterBySeverity_EmptyString(t *testing.T) {
	vulns := makeVulns()
	got := filterBySeverity(vulns, "")
	if len(got) != 5 {
		t.Errorf("empty severity filter should return all, got %d", len(got))
	}
}

// ── New / parsePackages / scanDependencies / scanSourceCode tests ──

func TestNew_Success(t *testing.T) {
	// New relies on config.Load which reads from $HOME/.calvigil/config.yaml
	// Set HOME to temp dir so it loads empty config
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s, err := New(models.ScanOptions{
		Path:    "/tmp/test",
		Format:  "json",
		NoCache: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if s == nil {
		t.Fatal("New() returned nil scanner")
	}
	if s.cache != nil {
		t.Error("cache should be nil when NoCache=true")
	}
}

func TestNew_WithCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s, err := New(models.ScanOptions{
		Path:     "/tmp/test",
		Format:   "table",
		NoCache:  false,
		CacheTTL: "1h",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if s.cache == nil {
		t.Error("cache should be initialized when NoCache=false")
	}
}

func TestNew_InvalidCacheTTL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	s, err := New(models.ScanOptions{
		Path:     "/tmp/test",
		Format:   "json",
		NoCache:  false,
		CacheTTL: "not-a-duration",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	// Should still succeed, just uses default TTL
	if s.cache == nil {
		t.Error("cache should still be initialized with default TTL")
	}
}

func TestParsePackages_ValidGoMod(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/test

go 1.21

require (
	golang.org/x/text v0.14.0
	github.com/pkg/errors v0.9.1
)
`
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	pkgs, errs := s.parsePackages(files)
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(pkgs) < 2 {
		t.Errorf("expected at least 2 packages, got %d", len(pkgs))
	}
	// Check PURLs are generated
	for _, p := range pkgs {
		if p.PURL == "" {
			t.Errorf("package %s missing PURL", p.Name)
		}
	}
}

func TestParsePackages_FileNotFound(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{Path: "/nonexistent"},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: "/nonexistent/go.mod", Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	pkgs, errs := s.parsePackages(files)
	if len(errs) == 0 {
		t.Error("expected error for nonexistent file")
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestParsePackages_UnknownFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "unknown.txt")
	os.WriteFile(f, []byte("content"), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: f, Filename: "unknown.txt", Ecosystem: "unknown"},
	}

	pkgs, errs := s.parsePackages(files)
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for unknown file, got %d", len(pkgs))
	}
	if len(errs) != 0 {
		t.Errorf("unknown files shouldn't produce errors, got %d", len(errs))
	}
}

func TestParsePackages_Verbose(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/test

go 1.21

require golang.org/x/text v0.14.0
`
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir, Verbose: true},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	pkgs, _ := s.parsePackages(files)
	if len(pkgs) == 0 {
		t.Error("expected packages")
	}
}

func TestParsePackages_EmptyManifest(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/test

go 1.21
`
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	pkgs, _ := s.parsePackages(files)
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty go.mod, got %d", len(pkgs))
	}
}

func TestScanDependencies_EmptyPackages(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/test

go 1.21
`
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir, NoCache: true},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	vulns, pkgs, errs := s.scanDependencies(context.Background(), files)
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
	_ = errs
}

func TestScanSourceCode_NoAIProvider(t *testing.T) {
	// Create a project with a pattern-matchable file but no AI provider
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte(`
password = "secret_123"
api_key = "sk_test_abc"
`), 0644)

	s := &Scanner{
		opts: models.ScanOptions{
			Path:       dir,
			AIProvider: "openai", // OpenAI but no key → resolves to ""
			SkipAI:     false,
		},
		cfg: &config.Config{OpenAIKey: ""}, // no key
	}

	vulns, errs := s.scanSourceCode(context.Background())
	// Should fall back to pattern matching
	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	// Pattern matching should find hardcoded secrets
	if len(vulns) == 0 {
		t.Error("expected pattern-match vulnerabilities")
	}
}

func TestScanSourceCode_PatternOnly(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.js"), []byte(`
const password = "hardcoded_password_123";
const apiKey = "AKIA1234567890ABCDEF";
`), 0644)

	s := &Scanner{
		opts: models.ScanOptions{
			Path:       dir,
			AIProvider: "auto",
		},
		cfg: &config.Config{}, // no keys → pattern-only
	}

	vulns, _ := s.scanSourceCode(context.Background())
	if len(vulns) == 0 {
		t.Error("expected pattern-based findings")
	}
}

func TestScanSemgrep_NotInstalled(t *testing.T) {
	// Semgrep is likely not installed in test env
	s := &Scanner{
		opts: models.ScanOptions{
			Path:         t.TempDir(),
			SemgrepRules: "",
		},
		cfg: &config.Config{},
	}

	vulns, errs := s.scanSemgrep(context.Background())
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns when semgrep not installed, got %d", len(vulns))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors (graceful skip), got %d", len(errs))
	}
}

func TestRun_MinimalPipeline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Create a minimal Go project
	gomod := `module example.com/test

go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:        dir,
		Format:      "json",
		OutputFile:  outFile,
		SkipAI:      true,
		SkipSemgrep: true,
		SkipDeps:    true,
		NoCache:     true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	err = s.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "project_path") {
		t.Error("expected JSON report with project_path")
	}
}

func TestRun_WithDeps(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := `module example.com/test

go 1.21

require golang.org/x/text v0.14.0
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:        dir,
		Format:      "json",
		OutputFile:  outFile,
		SkipAI:      true,
		SkipSemgrep: true,
		NoCache:     true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	err = s.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), "project_path") {
		t.Error("expected JSON report")
	}
	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if len(result.Packages) != 1 {
		t.Fatalf("packages = %d, want 1", len(result.Packages))
	}
	if result.Packages[0].License != "Apache-2.0" {
		t.Fatalf("package license = %q, want Apache-2.0", result.Packages[0].License)
	}
	if len(result.LicenseIssues) != 0 {
		t.Fatalf("license issues should require --check-licenses, got %d", len(result.LicenseIssues))
	}
}

func TestRun_Verbose(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:        dir,
		Format:      "json",
		OutputFile:  outFile,
		SkipAI:      true,
		SkipSemgrep: true,
		NoCache:     true,
		Verbose:     true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestRun_WithSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:           dir,
		Format:         "json",
		OutputFile:     outFile,
		SkipAI:         true,
		SkipSemgrep:    true,
		NoCache:        true,
		SeverityFilter: models.SeverityCritical,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestRun_WithLicenseChecking(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:          dir,
		Format:        "json",
		OutputFile:    outFile,
		SkipAI:        true,
		SkipSemgrep:   true,
		NoCache:       true,
		CheckLicenses: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestRun_WithIntegrity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:            dir,
		Format:          "json",
		OutputFile:      outFile,
		SkipAI:          true,
		SkipSemgrep:     true,
		NoCache:         true,
		VerifyIntegrity: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestRun_SkipDepsWithIntegrity(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:            dir,
		Format:          "json",
		OutputFile:      outFile,
		SkipAI:          true,
		SkipSemgrep:     true,
		SkipDeps:        true,
		NoCache:         true,
		VerifyIntegrity: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestRun_WithPatternScanning(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// Create a file with a hardcoded secret to trigger pattern scanning
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("password = \"secret123\"\napi_key = \"AKIA1234567890ABCDEF\"\n"), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:        dir,
		Format:      "json",
		OutputFile:  outFile,
		SkipAI:      false,
		AIProvider:  "openai",
		SkipSemgrep: true,
		SkipDeps:    true,
		NoCache:     true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	// No OpenAI key → falls back to pattern-only code scanning
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestScanDependencies_WithVerbose(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir, Verbose: true, NoCache: true},
		cfg:  &config.Config{},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	vulns, pkgs, _ := s.scanDependencies(context.Background(), files)
	_ = vulns
	if len(pkgs) == 0 {
		t.Error("expected packages")
	}
}

func TestScanDependencies_WithNVDKey(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir, NoCache: true},
		cfg:  &config.Config{NVDKey: "test-nvd-key"},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	_, pkgs, _ := s.scanDependencies(context.Background(), files)
	if len(pkgs) == 0 {
		t.Error("expected packages")
	}
}

func TestScanDependencies_WithGitHubToken(t *testing.T) {
	dir := t.TempDir()
	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir, NoCache: true},
		cfg:  &config.Config{GitHubToken: "ghp_test"},
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	_, pkgs, _ := s.scanDependencies(context.Background(), files)
	if len(pkgs) == 0 {
		t.Error("expected packages")
	}
}

func TestScanSourceCode_VerboseNoProvider(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("password = \"hardcoded\"\n"), 0644)

	s := &Scanner{
		opts: models.ScanOptions{Path: dir, Verbose: true, AIProvider: "openai"},
		cfg:  &config.Config{},
	}

	vulns, _ := s.scanSourceCode(context.Background())
	if len(vulns) == 0 {
		t.Error("expected pattern-match findings")
	}
}

func TestScanSemgrep_Verbose(t *testing.T) {
	s := &Scanner{
		opts: models.ScanOptions{Path: t.TempDir(), Verbose: true},
		cfg:  &config.Config{},
	}
	_, errs := s.scanSemgrep(context.Background())
	if len(errs) != 0 {
		t.Errorf("expected 0 errors when semgrep not installed, got %d", len(errs))
	}
}

func TestRun_VerboseWithLicensesAndPatterns(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)
	os.WriteFile(filepath.Join(dir, "config.js"), []byte("const key = \"AKIA1234567890ABCDEF\";\n"), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:          dir,
		Format:        "json",
		OutputFile:    outFile,
		SkipAI:        false,
		AIProvider:    "openai",
		SkipSemgrep:   true,
		NoCache:       true,
		Verbose:       true,
		CheckLicenses: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}

func TestScanSourceCode_OllamaProvider(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("password = \"secret\"\n"), 0644)

	s := &Scanner{
		opts: models.ScanOptions{
			Path:        dir,
			AIProvider:  "ollama",
			OllamaURL:   "http://localhost:1",
			OllamaModel: "llama3",
			Verbose:     true,
		},
		cfg: &config.Config{},
	}

	vulns, errs := s.scanSourceCode(context.Background())
	_ = vulns
	_ = errs
}

func TestScanSourceCode_OpenAIProvider(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("password = \"test\"\n"), 0644)

	s := &Scanner{
		opts: models.ScanOptions{
			Path:       dir,
			AIProvider: "openai",
			Verbose:    true,
		},
		cfg: &config.Config{OpenAIKey: "sk-invalid", OpenAIModel: "gpt-4"},
	}

	vulns, errs := s.scanSourceCode(context.Background())
	_ = vulns
	_ = errs
}

func TestScanDependencies_WithCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	goModPath := filepath.Join(dir, "go.mod")
	os.WriteFile(goModPath, []byte(gomod), 0644)

	s, err := New(models.ScanOptions{
		Path:    dir,
		Format:  "json",
		NoCache: false,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	files := []detector.DetectedFile{
		{Path: goModPath, Filename: "go.mod", Ecosystem: models.EcosystemGo},
	}

	_, pkgs, _ := s.scanDependencies(context.Background(), files)
	if len(pkgs) == 0 {
		t.Skip("no packages found")
	}

	_, pkgs2, _ := s.scanDependencies(context.Background(), files)
	if len(pkgs2) == 0 {
		t.Error("expected packages from cache")
	}
}

func TestRun_WithSeverityFilterAndDeps(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	gomod := "module example.com/test\n\ngo 1.21\n\nrequire golang.org/x/text v0.14.0\n"
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	outFile := filepath.Join(dir, "report.json")
	s, err := New(models.ScanOptions{
		Path:           dir,
		Format:         "json",
		OutputFile:     outFile,
		SkipAI:         true,
		SkipSemgrep:    true,
		NoCache:        true,
		SeverityFilter: models.SeverityHigh,
		Verbose:        true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
}
