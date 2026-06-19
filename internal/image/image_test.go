package image

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/matcher"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestMapSyftType(t *testing.T) {
	tests := []struct {
		typ      string
		language string
		want     models.Ecosystem
	}{
		{"npm", "", models.EcosystemNpm},
		{"", "javascript", models.EcosystemNpm},
		{"", "typescript", models.EcosystemNpm},
		{"python", "", models.EcosystemPyPI},
		{"pip", "", models.EcosystemPyPI},
		{"wheel", "", models.EcosystemPyPI},
		{"egg", "", models.EcosystemPyPI},
		{"", "python", models.EcosystemPyPI},
		{"go-module", "", models.EcosystemGo},
		{"", "go", models.EcosystemGo},
		{"java-archive", "", models.EcosystemMaven},
		{"maven", "", models.EcosystemMaven},
		{"gradle", "", models.EcosystemMaven},
		{"", "java", models.EcosystemMaven},
		{"gem", "", models.Ecosystem("RubyGems")},
		{"", "ruby", models.Ecosystem("RubyGems")},
		{"rust-crate", "", models.Ecosystem("crates.io")},
		{"", "rust", models.Ecosystem("crates.io")},
		{"deb", "", models.Ecosystem("DEB")},
		{"rpm", "", models.Ecosystem("RPM")},
		{"apk", "", models.Ecosystem("APK")},
		{"unknown", "", models.Ecosystem("")},
		{"", "", models.Ecosystem("")},
	}

	for _, tt := range tests {
		got := mapSyftType(tt.typ, tt.language)
		if got != tt.want {
			t.Errorf("mapSyftType(%q, %q) = %q, want %q", tt.typ, tt.language, got, tt.want)
		}
	}
}

func TestMapSyftType_CaseInsensitive(t *testing.T) {
	if got := mapSyftType("NPM", ""); got != models.EcosystemNpm {
		t.Errorf("mapSyftType(NPM) = %q, want npm", got)
	}
	if got := mapSyftType("", "JavaScript"); got != models.EcosystemNpm {
		t.Errorf("mapSyftType(JavaScript) = %q, want npm", got)
	}
	if got := mapSyftType("PYTHON", ""); got != models.EcosystemPyPI {
		t.Errorf("mapSyftType(PYTHON) = %q, want pypi", got)
	}
}

func TestNewScanner(t *testing.T) {
	s := NewScanner("alpine:latest", true, nil)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.imageRef != "alpine:latest" {
		t.Errorf("imageRef = %q, want alpine:latest", s.imageRef)
	}
	if !s.verbose {
		t.Error("verbose should be true")
	}
}

func TestSyftAvailable(t *testing.T) {
	// Just call it — test that it doesn't panic
	_ = SyftAvailable()
}

func TestScan_NoSyft(t *testing.T) {
	// If syft is not on PATH, Scan should fail with extractPackages error
	if SyftAvailable() {
		t.Skip("syft is installed, skipping no-syft test")
	}
	s := NewScanner("nonexistent:latest", false, nil)
	_, err := s.Scan(context.Background())
	if err == nil {
		t.Error("expected error when syft is not available")
	}
}

func TestScan_VerboseNoSyft(t *testing.T) {
	if SyftAvailable() {
		t.Skip("syft is installed, skipping no-syft test")
	}
	s := NewScanner("nonexistent:latest", true, nil)
	_, err := s.Scan(context.Background())
	if err == nil {
		t.Error("expected error when syft is not available")
	}
}

// TestScan_RejectsMaliciousImageRef verifies that Scan() refuses to hand a
// ref containing shell metacharacters to syft, even when syft is installed.
func TestScan_RejectsMaliciousImageRef(t *testing.T) {
	bad := []string{
		"nginx;rm -rf /",
		"nginx:`whoami`",
		"nginx:$(id)",
		"nginx latest",
		"",
	}
	for _, ref := range bad {
		s := NewScanner(ref, false, nil)
		_, err := s.Scan(context.Background())
		if err == nil {
			t.Errorf("Scan(%q) accepted unsafe ref", ref)
		}
	}
}

func TestScan_WithFakeSyftPipeline(t *testing.T) {
	installFakeSyft(t, []byte(`{
		"artifacts": [
			{
				"name": "lodash",
				"version": "4.17.21",
				"type": "npm",
				"language": "javascript",
				"locations": [{"path": "/app/package-lock.json"}]
			},
			{
				"name": "flask",
				"version": "2.3.2",
				"type": "python",
				"language": "python",
				"purl": "pkg:pypi/flask@2.3.2"
			}
		]
	}`), 0)

	fm := &fakeImageMatcher{}
	s := NewScanner("registry.example.com/team/app:1.2.3", true, []matcher.Matcher{fm})
	result, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if result.ProjectPath != "image:registry.example.com/team/app:1.2.3" {
		t.Fatalf("ProjectPath = %q", result.ProjectPath)
	}
	if result.TotalPackages != 2 {
		t.Fatalf("TotalPackages = %d, want 2", result.TotalPackages)
	}
	if len(result.Ecosystems) != 2 {
		t.Fatalf("ecosystems = %v, want npm and PyPI", result.Ecosystems)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(result.Vulnerabilities))
	}
	if len(fm.packages) != 2 {
		t.Fatalf("matcher saw %d packages, want 2", len(fm.packages))
	}
	if fm.packages[0].PURL == "" {
		t.Fatal("Scan() should generate missing PURLs before matching")
	}
	if result.Vulnerabilities[0].Package.PURL == "" {
		t.Fatal("vulnerability package should carry generated PURL")
	}
}

func TestExtractPackages_SyftFailure(t *testing.T) {
	installFakeSyft(t, nil, 42)

	s := NewScanner("nginx:latest", false, nil)
	_, err := s.extractPackages(context.Background())
	if err == nil {
		t.Fatal("expected syft failure")
	}
	if !strings.Contains(err.Error(), "syft failed") {
		t.Fatalf("error = %v, want syft failed", err)
	}
}

func TestParseSBOM(t *testing.T) {
	input := `{
		"artifacts": [
			{
				"name": "lodash",
				"version": "4.17.21",
				"type": "npm",
				"language": "javascript",
				"purl": "pkg:npm/lodash@4.17.21",
				"locations": [{"path": "/app/node_modules/lodash"}]
			},
			{
				"name": "flask",
				"version": "2.3.2",
				"type": "python",
				"language": "python",
				"purl": "",
				"locations": []
			},
			{
				"name": "stdlib",
				"version": "1.21.0",
				"type": "go-module",
				"language": "go",
				"purl": "pkg:golang/stdlib@1.21.0",
				"locations": [{"path": "/usr/local/go"}, {"path": "/other"}]
			}
		]
	}`

	pkgs, err := parseSBOM([]byte(input))
	if err != nil {
		t.Fatalf("parseSBOM: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}

	// lodash
	if pkgs[0].Name != "lodash" || pkgs[0].Version != "4.17.21" {
		t.Errorf("pkg[0] = %s@%s, want lodash@4.17.21", pkgs[0].Name, pkgs[0].Version)
	}
	if pkgs[0].Ecosystem != models.EcosystemNpm {
		t.Errorf("pkg[0].Ecosystem = %q, want npm", pkgs[0].Ecosystem)
	}
	if pkgs[0].PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("pkg[0].PURL = %q", pkgs[0].PURL)
	}
	if pkgs[0].FilePath != "/app/node_modules/lodash" {
		t.Errorf("pkg[0].FilePath = %q", pkgs[0].FilePath)
	}

	// flask — no PURL, no locations
	if pkgs[1].PURL != "" {
		t.Errorf("pkg[1].PURL = %q, want empty", pkgs[1].PURL)
	}
	if pkgs[1].FilePath != "" {
		t.Errorf("pkg[1].FilePath = %q, want empty", pkgs[1].FilePath)
	}

	// stdlib — first location used
	if pkgs[2].FilePath != "/usr/local/go" {
		t.Errorf("pkg[2].FilePath = %q, want /usr/local/go", pkgs[2].FilePath)
	}
}

func TestParseSBOM_SkipsIncomplete(t *testing.T) {
	input := `{
		"artifacts": [
			{"name": "", "version": "1.0", "type": "npm"},
			{"name": "pkg", "version": "", "type": "npm"},
			{"name": "unknown-thing", "version": "1.0", "type": "unknown-type", "language": ""},
			{"name": "real", "version": "2.0", "type": "npm"}
		]
	}`

	pkgs, err := parseSBOM([]byte(input))
	if err != nil {
		t.Fatalf("parseSBOM: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1 (only 'real')", len(pkgs))
	}
	if pkgs[0].Name != "real" {
		t.Errorf("got %q, want 'real'", pkgs[0].Name)
	}
}

func TestParseSBOM_InvalidJSON(t *testing.T) {
	_, err := parseSBOM([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseSBOM_EmptyArtifacts(t *testing.T) {
	pkgs, err := parseSBOM([]byte(`{"artifacts": []}`))
	if err != nil {
		t.Fatalf("parseSBOM: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("got %d packages, want 0", len(pkgs))
	}
}

type fakeImageMatcher struct {
	packages []models.Package
}

func (m *fakeImageMatcher) Name() string { return "fake-image-matcher" }

func (m *fakeImageMatcher) Match(_ context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	m.packages = append([]models.Package(nil), packages...)
	if len(packages) == 0 {
		return nil, nil
	}
	return []models.Vulnerability{{
		ID:       "CVE-2026-0001",
		Severity: models.SeverityHigh,
		Score:    8.1,
		Package:  packages[0],
		Source:   models.SourceOSV,
	}}, nil
}

func installFakeSyft(t *testing.T, output []byte, exitCode int) {
	t.Helper()

	dir := t.TempDir()
	syftPath := filepath.Join(dir, "syft")
	outPath := filepath.Join(dir, "sbom.json")
	if output != nil {
		if err := os.WriteFile(outPath, output, 0o600); err != nil {
			t.Fatalf("write fake sbom: %v", err)
		}
	}

	script := "#!/bin/sh\n"
	if exitCode != 0 {
		script += "echo syft failed >&2\n"
		script += "exit " + strconv.Itoa(exitCode) + "\n"
	} else {
		script += "exec /bin/cat " + shellQuote(outPath) + "\n"
	}
	if err := os.WriteFile(syftPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake syft: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
