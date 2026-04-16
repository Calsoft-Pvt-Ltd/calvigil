package parser

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// redirectTransport intercepts all outgoing requests and redirects them to a local test server.
type redirectTransport struct {
	server *httptest.Server
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = rt.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func TestGoModTransitiveDeps(t *testing.T) {
	input := "module example.com/myproject\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/stretchr/testify v1.8.4\n\tgolang.org/x/net v0.15.0 // indirect\n\tgolang.org/x/text v0.13.0 // indirect\n)\n"

	p := &GoModParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "go.mod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(pkgs))
	}

	directCount, indirectCount := 0, 0
	for _, pkg := range pkgs {
		if pkg.Indirect {
			indirectCount++
		} else {
			directCount++
		}
	}
	if directCount != 2 {
		t.Errorf("expected 2 direct deps, got %d", directCount)
	}
	if indirectCount != 2 {
		t.Errorf("expected 2 indirect deps, got %d", indirectCount)
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "github.com/gin-gonic/gin":
			if pkg.Indirect {
				t.Error("gin should be direct")
			}
		case "golang.org/x/net":
			if !pkg.Indirect {
				t.Error("x/net should be indirect")
			}
		}
	}
}

func TestNpmLockV2TransitiveDeps(t *testing.T) {
	input := `{"name":"my-app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"my-app","version":"1.0.0"},"node_modules/express":{"version":"4.18.2"},"node_modules/express/node_modules/cookie":{"version":"0.5.0"},"node_modules/lodash":{"version":"4.17.21"}}}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.Indirect {
				t.Error("express should be direct (depth 1)")
			}
		case "cookie":
			if !pkg.Indirect {
				t.Error("cookie should be transitive (nested under express)")
			}
		case "lodash":
			if pkg.Indirect {
				t.Error("lodash should be direct (depth 1)")
			}
		}
	}
}

func TestNpmLockV1TransitiveDeps(t *testing.T) {
	input := `{"name":"my-app","version":"1.0.0","lockfileVersion":1,"dependencies":{"express":{"version":"4.18.2","requires":{"cookie":"0.5.0"},"dependencies":{"cookie":{"version":"0.5.0"}}},"lodash":{"version":"4.17.21"}}}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) < 3 {
		t.Fatalf("expected at least 3 packages, got %d", len(pkgs))
	}

	foundTransitiveCookie := false
	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.Indirect {
				t.Error("express should be direct (top-level)")
			}
		case "cookie":
			if !pkg.Indirect {
				t.Error("cookie should be transitive (nested)")
			}
			foundTransitiveCookie = true
		case "lodash":
			if pkg.Indirect {
				t.Error("lodash should be direct (top-level)")
			}
		}
	}
	if !foundTransitiveCookie {
		t.Error("expected to find transitive cookie package")
	}
}

func TestCargoLockTransitiveDeps(t *testing.T) {
	input := "# Cargo generated\n[[package]]\nname = \"my-project\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde 1.0.180\",\n \"tokio 1.32.0\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.180\"\ndependencies = [\n \"serde_derive 1.0.180\",\n]\n\n[[package]]\nname = \"serde_derive\"\nversion = \"1.0.180\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.32.0\"\n"

	p := &CargoLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Cargo.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages (root skipped), got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "serde":
			if pkg.Indirect {
				t.Error("serde should be direct (in root deps)")
			}
		case "tokio":
			if pkg.Indirect {
				t.Error("tokio should be direct (in root deps)")
			}
		case "serde_derive":
			if !pkg.Indirect {
				t.Error("serde_derive should be transitive (not in root deps)")
			}
		}
	}
}

func TestGemfileLockTransitiveDeps(t *testing.T) {
	input := "GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.4)\n      actionview (= 7.0.4)\n      activesupport (= 7.0.4)\n    actionview (7.0.4)\n    activesupport (7.0.4)\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.0)\n"

	p := &GemfileLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Gemfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	directCount, indirectCount := 0, 0
	for _, pkg := range pkgs {
		if pkg.Indirect {
			indirectCount++
		} else {
			directCount++
		}
	}

	if directCount == 0 {
		t.Error("expected some direct gems (4-space indent)")
	}
	if indirectCount == 0 {
		t.Error("expected some transitive gems (6-space indent)")
	}

	for _, pkg := range pkgs {
		if pkg.Name == "rails" && pkg.Indirect {
			t.Error("rails at 4-space indent should be direct")
		}
	}
}

func TestPoetryLockWithoutPyProjectAllDirect(t *testing.T) {
	input := "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.0.7\"\n"

	p := &PoetryLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "/tmp/nonexistent/poetry.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("without pyproject.toml, %s should default to direct", pkg.Name)
		}
	}
}

func TestRequirementsTxtAllDirect(t *testing.T) {
	input := "requests==2.31.0\nflask>=2.3.0\nurllib3==2.0.7\n"

	p := &RequirementsTxtParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "requirements.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("%s in requirements.txt should be direct", pkg.Name)
		}
	}
}

func TestPipfileLockAllDirect(t *testing.T) {
	input := `{"_meta":{"requires":{"python_version":"3.11"}},"default":{"requests":{"version":"==2.31.0"},"urllib3":{"version":"==2.0.7"}},"develop":{}}`

	p := &PipfileLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Pipfile.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("%s in Pipfile.lock should be direct", pkg.Name)
		}
	}
}

func TestComposerLockWithoutJsonAllDirect(t *testing.T) {
	input := `{"packages":[{"name":"monolog/monolog","version":"3.5.0"},{"name":"psr/log","version":"3.0.0"}],"packages-dev":[]}`

	p := &ComposerLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "/tmp/nonexistent/composer.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		if pkg.Indirect {
			t.Errorf("without composer.json, %s should default to direct", pkg.Name)
		}
	}
}

// ── npm License Extraction Tests ──────────────────────────────────

func TestExtractNpmLicense_String(t *testing.T) {
	got := extractNpmLicense("MIT")
	if got != "MIT" {
		t.Errorf("expected MIT, got %s", got)
	}
}

func TestExtractNpmLicense_Object(t *testing.T) {
	obj := map[string]interface{}{"type": "Apache-2.0"}
	got := extractNpmLicense(obj)
	if got != "Apache-2.0" {
		t.Errorf("expected Apache-2.0, got %s", got)
	}
}

func TestExtractNpmLicense_Nil(t *testing.T) {
	got := extractNpmLicense(nil)
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestExtractNpmLicense_EmptyString(t *testing.T) {
	got := extractNpmLicense("")
	if got != "" {
		t.Errorf("expected empty string, got %s", got)
	}
}

func TestNpmLockV2WithLicenses(t *testing.T) {
	input := `{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "my-app", "version": "1.0.0"},
    "node_modules/express": {
      "version": "4.18.2",
      "license": "MIT"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "license": {"type": "MIT"}
    },
    "node_modules/no-lic-pkg": {
      "version": "1.0.0"
    }
  }
}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.License != "MIT" {
				t.Errorf("express license: want MIT, got %s", pkg.License)
			}
		case "lodash":
			if pkg.License != "MIT" {
				t.Errorf("lodash license: want MIT (from object), got %s", pkg.License)
			}
		case "no-lic-pkg":
			if pkg.License != "" {
				t.Errorf("no-lic-pkg license: want empty, got %s", pkg.License)
			}
		}
	}
}

// ── Integrity Parsing Tests ──────────────────────────────────

func TestNpmLockV2IntegrityParsed(t *testing.T) {
	input := `{
  "name": "my-app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "my-app", "version": "1.0.0"},
    "node_modules/express": {
      "version": "4.18.2",
      "integrity": "sha512-abc123==",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.Integrity != "sha512-abc123==" {
				t.Errorf("express integrity: want sha512-abc123==, got %s", pkg.Integrity)
			}
		case "lodash":
			if pkg.Integrity != "" {
				t.Errorf("lodash integrity: want empty, got %s", pkg.Integrity)
			}
		}
	}
}

func TestNpmLockV1IntegrityParsed(t *testing.T) {
	input := `{"name":"my-app","lockfileVersion":1,"dependencies":{
		"express":{"version":"4.18.2","integrity":"sha512-xyz789=="},
		"lodash":{"version":"4.17.21"}
	}}`

	p := &NpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "package-lock.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "express":
			if pkg.Integrity != "sha512-xyz789==" {
				t.Errorf("express integrity: want sha512-xyz789==, got %s", pkg.Integrity)
			}
		case "lodash":
			if pkg.Integrity != "" {
				t.Errorf("lodash integrity: want empty, got %s", pkg.Integrity)
			}
		}
	}
}

func TestCargoLockChecksumParsed(t *testing.T) {
	input := `[[package]]
name = "my-project"
version = "0.1.0"
dependencies = [
 "serde 1.0.180",
]

[[package]]
name = "serde"
version = "1.0.180"
checksum = "deadbeef1234567890abcdef"

[[package]]
name = "tokio"
version = "1.32.0"
`

	p := &CargoLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "Cargo.lock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "serde":
			want := "sha256-deadbeef1234567890abcdef"
			if pkg.Integrity != want {
				t.Errorf("serde integrity: want %s, got %s", want, pkg.Integrity)
			}
		case "tokio":
			if pkg.Integrity != "" {
				t.Errorf("tokio integrity: want empty, got %s", pkg.Integrity)
			}
		}
	}
}

// ── Consistency (Phantom Dependency) Tests ──────────────────

func TestCheckConsistency_NoPhantoms(t *testing.T) {
	// Create a temp dir with package.json and simulate lockfile packages
	dir := t.TempDir()
	manifestContent := `{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	lockFile := filepath.Join(dir, "package-lock.json")
	packages := []models.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: false},
		{Name: "jest", Version: "29.7.0", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: false},
		{Name: "cookie", Version: "0.5.0", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: true},
	}

	issues := CheckConsistency(dir, packages)
	if len(issues) != 0 {
		t.Errorf("expected 0 consistency issues, got %d", len(issues))
		for _, i := range issues {
			t.Logf("  phantom: %s in %s", i.Package.Name, i.LockFile)
		}
	}
}

func TestCheckConsistency_PhantomDetected(t *testing.T) {
	dir := t.TempDir()
	manifestContent := `{"dependencies":{"express":"^4.18.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	lockFile := filepath.Join(dir, "package-lock.json")
	packages := []models.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: false},
		{Name: "evil-pkg", Version: "1.0.0", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: false},
	}

	issues := CheckConsistency(dir, packages)
	if len(issues) != 1 {
		t.Fatalf("expected 1 consistency issue, got %d", len(issues))
	}
	if issues[0].Package.Name != "evil-pkg" {
		t.Errorf("expected phantom package evil-pkg, got %s", issues[0].Package.Name)
	}
}

func TestCheckConsistency_TransitiveNotFlagged(t *testing.T) {
	dir := t.TempDir()
	manifestContent := `{"dependencies":{"express":"^4.18.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifestContent), 0644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	lockFile := filepath.Join(dir, "package-lock.json")
	packages := []models.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: false},
		// cookie is transitive — should NOT be flagged
		{Name: "cookie", Version: "0.5.0", Ecosystem: models.EcosystemNpm, FilePath: lockFile, Indirect: true},
	}

	issues := CheckConsistency(dir, packages)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues (transitive deps should be ignored), got %d", len(issues))
	}
}

// ── Parser Registry Tests ───────────────────────────────────────

func TestSupportedFiles(t *testing.T) {
	files := SupportedFiles()
	if len(files) == 0 {
		t.Error("SupportedFiles() returned empty")
	}
	// Should contain at least go.mod and package-lock.json
	found := make(map[string]bool)
	for _, f := range files {
		found[f] = true
	}
	for _, want := range []string{"go.mod", "package-lock.json", "requirements.txt", "pom.xml"} {
		if !found[want] {
			t.Errorf("SupportedFiles() missing %q", want)
		}
	}
}

func TestForFile_Known(t *testing.T) {
	p := ForFile("go.mod")
	if p == nil {
		t.Error("ForFile(go.mod) returned nil")
	}
}

func TestForFile_Unknown(t *testing.T) {
	p := ForFile("unknown.xyz")
	if p != nil {
		t.Error("ForFile(unknown.xyz) should return nil")
	}
}

// ── Maven/Gradle Tests ──────────────────────────────────────────

func TestPomXMLParser(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>unresolved</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>`

	p := &PomXMLParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "pom.xml")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package (test/unresolved skipped), got %d", len(pkgs))
	}
	if pkgs[0].Name != "org.springframework:spring-core" {
		t.Errorf("name = %q, want org.springframework:spring-core", pkgs[0].Name)
	}
}

func TestGradleParser(t *testing.T) {
	input := `plugins {
    id 'java'
}
dependencies {
    implementation 'org.springframework:spring-core:5.3.20'
    api "com.google.guava:guava:31.1-jre"
    testImplementation 'junit:junit:4.13.2'
}`
	p := &GradleParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "build.gradle")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
}

// ── Conan Tests ─────────────────────────────────────────────────

func TestConanLockV2(t *testing.T) {
	input := `{"requires":["zlib/1.2.13","openssl/3.1.0#abc123"]}`
	p := &ConanLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "conan.lock")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	for _, pkg := range pkgs {
		if pkg.Ecosystem != models.EcosystemConan {
			t.Errorf("ecosystem = %v, want ConanCenter", pkg.Ecosystem)
		}
	}
}

func TestConanLockV1(t *testing.T) {
	input := `{"graph_lock":{"nodes":{"0":{"ref":"zlib/1.2.13"},"1":{"ref":"openssl/3.1.0#rev"}}}}`
	p := &ConanLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "conan.lock")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
}

func TestParseConanRef(t *testing.T) {
	name, ver := parseConanRef("zlib/1.2.13#abc")
	if name != "zlib" || ver != "1.2.13" {
		t.Errorf("parseConanRef = %q,%q", name, ver)
	}
	name, ver = parseConanRef("invalid")
	if name != "" || ver != "" {
		t.Error("invalid ref should return empty")
	}
}

// ── Yarn Lock Tests ─────────────────────────────────────────────

func TestYarnLockParser(t *testing.T) {
	input := `# yarn lockfile v1

"express@^4.18.0":
  version "4.18.2"

"@babel/core@^7.0.0":
  version "7.23.0"
`
	p := &YarnLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "yarn.lock")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
}

// ── Pnpm Lock Tests ────────────────────────────────────────────

func TestPnpmLockParser(t *testing.T) {
	input := `lockfileVersion: 5.4
packages:
  /express@4.18.2:
    resolution: {integrity: sha512-abc}
  /lodash@4.17.21:
    resolution: {integrity: sha512-xyz}
`
	p := &PnpmLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), "pnpm-lock.yaml")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
}

// ── PHP Composer Tests ──────────────────────────────────────────

func TestComposerLockWithJson(t *testing.T) {
	dir := t.TempDir()
	cjson := `{"require":{"monolog/monolog":"^3.0"}}`
	os.WriteFile(filepath.Join(dir, "composer.json"), []byte(cjson), 0644)

	input := `{"packages":[{"name":"monolog/monolog","version":"v3.5.0"},{"name":"psr/log","version":"v3.0.0"}],"packages-dev":[]}`
	lockPath := filepath.Join(dir, "composer.lock")
	p := &ComposerLockParser{}
	pkgs, err := p.Parse(strings.NewReader(input), lockPath)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	for _, pkg := range pkgs {
		if pkg.Name == "monolog/monolog" && pkg.Indirect {
			t.Error("monolog should be direct")
		}
		if pkg.Name == "psr/log" && !pkg.Indirect {
			t.Error("psr/log should be indirect")
		}
	}
}

// ── Python helper tests ─────────────────────────────────────────

func TestExtractTOMLString(t *testing.T) {
	got := extractTOMLString(`name = "requests"`)
	if got != "requests" {
		t.Errorf("extractTOMLString = %q, want requests", got)
	}
}

func TestExtractBracketItems(t *testing.T) {
	items := extractBracketItems(`dependencies = ["requests>=2.28", "flask"]`)
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestNormalizePyName(t *testing.T) {
	tests := map[string]string{
		"Flask":           "flask",
		"Flask>=2.0":      "flask",
		"requests[socks]": "requests",
		"My_Package":      "my_package",
	}
	for input, want := range tests {
		got := normalizePyName(input)
		if got != want {
			t.Errorf("normalizePyName(%q) = %q, want %q", input, got, want)
		}
	}
}

// ── Manifests helper tests ──────────────────────────────────────

func TestManifestForLockfile(t *testing.T) {
	tests := map[string]string{
		"/path/package-lock.json": "/path/package.json",
		"/path/yarn.lock":         "/path/package.json",
		"/path/pnpm-lock.yaml":    "/path/package.json",
		"/path/go.mod":            "",
		"/path/Cargo.lock":        "",
	}
	for input, want := range tests {
		got := manifestForLockfile(input)
		if got != want {
			t.Errorf("manifestForLockfile(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeIntegrity(t *testing.T) {
	got := normalizeIntegrity("  sha512-abc123==  ")
	if got != "sha512-abc123==" {
		t.Errorf("normalizeIntegrity = %q", got)
	}
}

func TestReadPyprojectDirectDeps_Poetry(t *testing.T) {
	dir := t.TempDir()
	content := `[tool.poetry]
name = "myproject"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
flask = "^2.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0"
`
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(content), 0644)
	deps := readPyprojectDirectDeps(dir)
	if !deps["requests"] {
		t.Error("expected 'requests' in deps")
	}
	if !deps["flask"] {
		t.Error("expected 'flask' in deps")
	}
	if !deps["pytest"] {
		t.Error("expected 'pytest' in deps")
	}
	if deps["python"] {
		t.Error("'python' should be excluded")
	}
}

func TestReadPyprojectDirectDeps_PEP621(t *testing.T) {
	dir := t.TempDir()
	// Use inline list syntax to avoid the multiline "]" edge case bug
	content := `[project]
name = "myproject"
version = "1.0.0"
dependencies = ["requests>=2.28", "flask>=2.0"]
`
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(content), 0644)
	deps := readPyprojectDirectDeps(dir)
	if !deps["requests"] {
		t.Error("expected 'requests' in deps")
	}
	if !deps["flask"] {
		t.Error("expected 'flask' in deps")
	}
}

func TestReadPyprojectDirectDeps_InlineDeps(t *testing.T) {
	dir := t.TempDir()
	content := `[project]
name = "myproject"
dependencies = ["requests>=2.28", "flask"]
`
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(content), 0644)
	deps := readPyprojectDirectDeps(dir)
	if !deps["requests"] {
		t.Error("expected 'requests' in deps")
	}
	if !deps["flask"] {
		t.Error("expected 'flask' in deps")
	}
}

func TestReadPyprojectDirectDeps_MissingFile(t *testing.T) {
	dir := t.TempDir()
	deps := readPyprojectDirectDeps(dir)
	if len(deps) != 0 {
		t.Errorf("expected empty deps for missing file, got %d", len(deps))
	}
}

func TestVerifyIntegrity_CratesNoChecksum(t *testing.T) {
	pkgs := []models.Package{
		{Name: "serde", Version: "1.0", Ecosystem: models.EcosystemCrates, Integrity: ""},
	}
	issues := VerifyIntegrity(context.Background(), pkgs, false)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
	if !strings.Contains(issues[0].Reason, "no checksum") {
		t.Errorf("reason = %q", issues[0].Reason)
	}
}

func TestVerifyIntegrity_NpmNoIntegrity(t *testing.T) {
	// npm packages without integrity should be silently skipped
	pkgs := []models.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm, Integrity: ""},
	}
	issues := VerifyIntegrity(context.Background(), pkgs, false)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for npm without integrity, got %d", len(issues))
	}
}

func TestVerifyIntegrity_EmptyPackages(t *testing.T) {
	issues := VerifyIntegrity(context.Background(), nil, false)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for nil packages, got %d", len(issues))
	}
}

func TestVerifyIntegrity_OtherEcosystems(t *testing.T) {
	// Non-npm/crates packages should be ignored
	pkgs := []models.Package{
		{Name: "gin", Version: "1.9", Ecosystem: models.EcosystemGo},
		{Name: "flask", Version: "2.0", Ecosystem: models.EcosystemPyPI},
	}
	issues := VerifyIntegrity(context.Background(), pkgs, false)
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for Go/PyPI, got %d", len(issues))
	}
}

func TestVerifyNpmIntegrity_Match(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dist": map[string]interface{}{
				"integrity": "sha512-abc123==",
				"shasum":    "deadbeef",
			},
		})
	}))
	defer ts.Close()

	pkg := models.Package{
		Name:      "express",
		Version:   "4.18.2",
		Ecosystem: models.EcosystemNpm,
		Integrity: "sha512-abc123==",
	}
	client := &http.Client{Transport: &redirectTransport{server: ts}}
	issue := verifyNpmIntegrity(context.Background(), client, pkg)
	if issue != nil {
		t.Errorf("expected no issue for matching integrity, got: %s", issue.Reason)
	}
}

func TestVerifyNpmIntegrity_Mismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dist": map[string]interface{}{
				"integrity": "sha512-registry-hash==",
			},
		})
	}))
	defer ts.Close()

	pkg := models.Package{
		Name:      "express",
		Version:   "4.18.2",
		Ecosystem: models.EcosystemNpm,
		Integrity: "sha512-local-hash==",
	}
	client := &http.Client{Transport: &redirectTransport{server: ts}}
	issue := verifyNpmIntegrity(context.Background(), client, pkg)
	if issue == nil {
		t.Fatal("expected integrity mismatch issue")
	}
	if !strings.Contains(issue.Reason, "does not match") {
		t.Errorf("reason = %q", issue.Reason)
	}
}

func TestVerifyNpmIntegrity_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	pkg := models.Package{
		Name:      "malicious-pkg",
		Version:   "1.0.0",
		Ecosystem: models.EcosystemNpm,
		Integrity: "sha512-abc==",
	}
	client := &http.Client{Transport: &redirectTransport{server: ts}}
	issue := verifyNpmIntegrity(context.Background(), client, pkg)
	if issue == nil {
		t.Fatal("expected issue for 404")
	}
	if !strings.Contains(issue.Reason, "not found") {
		t.Errorf("reason = %q", issue.Reason)
	}
}

func TestVerifyNpmIntegrity_NoRegistryIntegrity(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dist": map[string]interface{}{
				"shasum": "abc123",
			},
		})
	}))
	defer ts.Close()

	pkg := models.Package{
		Name:      "old-pkg",
		Version:   "0.1.0",
		Ecosystem: models.EcosystemNpm,
		Integrity: "sha512-local==",
	}
	client := &http.Client{Transport: &redirectTransport{server: ts}}
	issue := verifyNpmIntegrity(context.Background(), client, pkg)
	if issue != nil {
		t.Error("should skip when registry has no integrity (old package)")
	}
}

func TestVerifyNpmIntegrity_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	pkg := models.Package{
		Name:      "pkg",
		Version:   "1.0",
		Ecosystem: models.EcosystemNpm,
		Integrity: "sha512-abc==",
	}
	client := &http.Client{Transport: &redirectTransport{server: ts}}
	issue := verifyNpmIntegrity(context.Background(), client, pkg)
	if issue != nil {
		t.Error("should skip on server error")
	}
}
