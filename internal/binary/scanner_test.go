package binary

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanGoBinary(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "testbin")
	moduleRoot, err := filepath.Abs("../../")
	if err != nil {
		t.Fatalf("cannot resolve module root: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cannot build test binary: %v\n%s", err, out)
	}
	pkgs := scanGoBinary(binPath)
	if len(pkgs) == 0 {
		t.Fatal("expected to find embedded Go packages in binary")
	}
	for _, p := range pkgs {
		if p.Name == "" {
			t.Error("package Name should not be empty")
		}
		if p.Version == "" {
			t.Error("package Version should not be empty")
		}
		if p.Ecosystem != "Go" {
			t.Errorf("expected Go ecosystem, got %s", p.Ecosystem)
		}
		if !p.Indirect {
			t.Errorf("binary deps should be marked indirect: %s", p.Name)
		}
	}
}

func TestScanGoBinaryNotGoBinary(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "not-a-binary")
	os.WriteFile(f, []byte("hello world"), 0644)
	pkgs := scanGoBinary(f)
	if pkgs != nil {
		t.Errorf("expected nil for non-Go binary, got %d packages", len(pkgs))
	}
}

func TestScanJARWithPomProperties(t *testing.T) {
	dir := t.TempDir()
	jarPath := filepath.Join(dir, "test.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	pomProps, err := w.Create("META-INF/maven/org.example/mylib/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	pomProps.Write([]byte("groupId=org.example\nartifactId=mylib\nversion=1.2.3\n"))
	w.Close()
	f.Close()

	pkgs := scanJAR(jarPath)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "org.example:mylib" {
		t.Errorf("expected org.example:mylib, got %s", pkgs[0].Name)
	}
	if pkgs[0].Version != "1.2.3" {
		t.Errorf("expected 1.2.3, got %s", pkgs[0].Version)
	}
}

func TestScanJARWithManifest(t *testing.T) {
	dir := t.TempDir()
	jarPath := filepath.Join(dir, "test.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	mf, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	mf.Write([]byte("Manifest-Version: 1.0\nImplementation-Title: commons-lang\nImplementation-Version: 3.14.0\n"))
	w.Close()
	f.Close()

	pkgs := scanJAR(jarPath)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "commons-lang" {
		t.Errorf("expected commons-lang, got %s", pkgs[0].Name)
	}
	if pkgs[0].Version != "3.14.0" {
		t.Errorf("expected 3.14.0, got %s", pkgs[0].Version)
	}
}

func TestScanWheel(t *testing.T) {
	dir := t.TempDir()
	whlPath := filepath.Join(dir, "requests-2.31.0-py3-none-any.whl")
	f, err := os.Create(whlPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	metadata, err := w.Create("requests-2.31.0.dist-info/METADATA")
	if err != nil {
		t.Fatal(err)
	}
	metadata.Write([]byte("Metadata-Version: 2.1\nName: Requests\nVersion: 2.31.0\n\nLong description.\n"))
	w.Close()
	f.Close()

	pkgs := scanWheel(whlPath)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "requests" {
		t.Errorf("expected requests, got %s", pkgs[0].Name)
	}
	if pkgs[0].Version != "2.31.0" {
		t.Errorf("expected 2.31.0, got %s", pkgs[0].Version)
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected 0 packages in empty dir, got %d", len(result.Packages))
	}
}

func TestParseJARFilename(t *testing.T) {
	tests := []struct {
		entry   string
		wantNil bool
		name    string
		version string
	}{
		{"BOOT-INF/lib/spring-core-5.3.21.jar", false, "spring-core", "5.3.21"},
		{"BOOT-INF/lib/commons-lang3-3.14.0.jar", false, "commons-lang3", "3.14.0"},
		{"BOOT-INF/lib/not-a-version.jar", true, "", ""},
		{"META-INF/MANIFEST.MF", true, "", ""},
		{"simple.jar", true, "", ""},
	}

	for _, tt := range tests {
		pkg := parseJARFilename(tt.entry, "/test/app.jar")
		if tt.wantNil {
			if pkg != nil {
				t.Errorf("parseJARFilename(%q) should be nil, got %+v", tt.entry, pkg)
			}
			continue
		}
		if pkg == nil {
			t.Errorf("parseJARFilename(%q) = nil, want name=%s", tt.entry, tt.name)
			continue
		}
		if pkg.Name != tt.name {
			t.Errorf("parseJARFilename(%q).Name = %q, want %q", tt.entry, pkg.Name, tt.name)
		}
		if pkg.Version != tt.version {
			t.Errorf("parseJARFilename(%q).Version = %q, want %q", tt.entry, pkg.Version, tt.version)
		}
		if !pkg.Indirect {
			t.Errorf("parseJARFilename should mark packages as indirect")
		}
	}
}

func TestShouldSkipDir(t *testing.T) {
	skip := []string{"node_modules", ".git", "vendor", "__pycache__", ".idea", ".vscode", ".venv", "venv", ".env", ".cache", ".tox", ".nox"}
	for _, name := range skip {
		if !shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) = false, want true", name)
		}
	}

	noSkip := []string{"src", "lib", "internal", "cmd", "main"}
	for _, name := range noSkip {
		if shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) = true, want false", name)
		}
	}
}

func TestExtractRegex(t *testing.T) {
	got := extractRegex(pomPropsGroupRe, "groupId=org.example\nartifactId=mylib\n")
	if got != "org.example" {
		t.Errorf("extractRegex groupId = %q, want org.example", got)
	}

	got = extractRegex(pomPropsArtifactRe, "groupId=org.example\nartifactId=mylib\n")
	if got != "mylib" {
		t.Errorf("extractRegex artifactId = %q, want mylib", got)
	}

	got = extractRegex(pomPropsVersionRe, "version=1.2.3\n")
	if got != "1.2.3" {
		t.Errorf("extractRegex version = %q, want 1.2.3", got)
	}

	got = extractRegex(pomPropsGroupRe, "no match here")
	if got != "" {
		t.Errorf("extractRegex no match = %q, want empty", got)
	}
}

func TestParsePythonMetadata(t *testing.T) {
	content := "Metadata-Version: 2.1\nName: Flask\nVersion: 3.0.0\n\nLong description here.\n"
	r := strings.NewReader(content)
	pkg := parsePythonMetadata(r, "/test/flask.whl")
	if pkg == nil {
		t.Fatal("parsePythonMetadata returned nil")
	}
	if pkg.Name != "flask" {
		t.Errorf("Name = %q, want flask (lowercase)", pkg.Name)
	}
	if pkg.Version != "3.0.0" {
		t.Errorf("Version = %q, want 3.0.0", pkg.Version)
	}
	if pkg.Ecosystem != "PyPI" {
		t.Errorf("Ecosystem = %q, want PyPI", pkg.Ecosystem)
	}
}

func TestParsePythonMetadata_MissingFields(t *testing.T) {
	r := strings.NewReader("Name: OnlyName\n\n")
	pkg := parsePythonMetadata(r, "/test/pkg.whl")
	if pkg != nil {
		t.Errorf("expected nil for missing version, got %+v", pkg)
	}
}

func TestParseManifest(t *testing.T) {
	content := "Manifest-Version: 1.0\nBundle-SymbolicName: org.apache.commons.io\nBundle-Version: 2.15.1\n"
	r := strings.NewReader(content)
	pkg := parseManifest(r, "/test/commons-io.jar")
	if pkg == nil {
		t.Fatal("parseManifest returned nil")
	}
	if pkg.Name != "org.apache.commons.io" {
		t.Errorf("Name = %q, want org.apache.commons.io", pkg.Name)
	}
	if pkg.Version != "2.15.1" {
		t.Errorf("Version = %q, want 2.15.1", pkg.Version)
	}
}

func TestParseManifest_ImplementationOverridesBundle(t *testing.T) {
	content := "Bundle-SymbolicName: bundle.name\nImplementation-Title: impl.name\nImplementation-Version: 1.0.0\n"
	r := strings.NewReader(content)
	pkg := parseManifest(r, "/test/lib.jar")
	if pkg == nil {
		t.Fatal("parseManifest returned nil")
	}
	if pkg.Name != "impl.name" {
		t.Errorf("Name = %q, want impl.name (Implementation-Title overrides Bundle)", pkg.Name)
	}
}

func TestParseManifest_MissingFields(t *testing.T) {
	r := strings.NewReader("Manifest-Version: 1.0\n")
	pkg := parseManifest(r, "/test/empty.jar")
	if pkg != nil {
		t.Errorf("expected nil for manifest with no title/version, got %+v", pkg)
	}
}

func TestScanFile_NonBinary(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "readme.txt")
	os.WriteFile(f, []byte("just text"), 0644)
	pkgs, sf := scanFile(f, false)
	if len(pkgs) != 0 {
		t.Errorf("expected no packages from text file, got %d", len(pkgs))
	}
	if sf != nil {
		t.Errorf("expected nil ScannedFile for text, got %+v", sf)
	}
}

func TestScanSingleFile(t *testing.T) {
	dir := t.TempDir()
	whlPath := filepath.Join(dir, "test-1.0-py3-none-any.whl")
	f, err := os.Create(whlPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	meta, _ := w.Create("test-1.0.dist-info/METADATA")
	meta.Write([]byte("Name: TestPkg\nVersion: 1.0\n\n"))
	w.Close()
	f.Close()

	result, err := Scan(whlPath, false)
	if err != nil {
		t.Fatalf("Scan single file error: %v", err)
	}
	if len(result.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result.Packages))
	}
	if result.Packages[0].Name != "testpkg" {
		t.Errorf("Name = %q, want testpkg", result.Packages[0].Name)
	}
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 scanned file, got %d", len(result.Files))
	}
	if result.Files[0].Type != "python-wheel" {
		t.Errorf("Type = %q, want python-wheel", result.Files[0].Type)
	}
}

func TestScan_SkipsIgnoredDirs(t *testing.T) {
	dir := t.TempDir()
	// Create a node_modules dir with a .whl file — should be skipped
	nmDir := filepath.Join(dir, "node_modules")
	os.MkdirAll(nmDir, 0755)
	whlPath := filepath.Join(nmDir, "test-1.0-py3-none-any.whl")
	f, err := os.Create(whlPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	meta, _ := w.Create("test-1.0.dist-info/METADATA")
	meta.Write([]byte("Name: TestPkg\nVersion: 1.0\n\n"))
	w.Close()
	f.Close()

	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(result.Packages) != 0 {
		t.Errorf("expected 0 packages (node_modules skipped), got %d", len(result.Packages))
	}
}

func TestScan_DeduplicatesPackages(t *testing.T) {
	dir := t.TempDir()
	// Create two identical .whl files in different subdirs
	for _, sub := range []string{"a", "b"} {
		subDir := filepath.Join(dir, sub)
		os.MkdirAll(subDir, 0755)
		whlPath := filepath.Join(subDir, "test-1.0-py3-none-any.whl")
		f, _ := os.Create(whlPath)
		w := zip.NewWriter(f)
		meta, _ := w.Create("test-1.0.dist-info/METADATA")
		meta.Write([]byte("Name: SamePkg\nVersion: 1.0\n\n"))
		w.Close()
		f.Close()
	}

	result, err := Scan(dir, false)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(result.Packages) != 1 {
		t.Errorf("expected 1 deduplicated package, got %d", len(result.Packages))
	}
}

func TestScanJAR_EmbeddedJARs(t *testing.T) {
	dir := t.TempDir()
	jarPath := filepath.Join(dir, "spring-boot-app.jar")
	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)

	// Add embedded JARs in BOOT-INF/lib/
	j1, _ := w.Create("BOOT-INF/lib/spring-core-5.3.21.jar")
	j1.Write([]byte("fake jar content"))
	j2, _ := w.Create("BOOT-INF/lib/jackson-databind-2.15.0.jar")
	j2.Write([]byte("fake jar content"))

	w.Close()
	f.Close()

	pkgs := scanJAR(jarPath)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages from embedded JARs, got %d", len(pkgs))
	}
}

func TestScanJAR_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "notajar.jar")
	os.WriteFile(f, []byte("not a zip file"), 0644)
	pkgs := scanJAR(f)
	if pkgs != nil {
		t.Errorf("expected nil for invalid jar, got %d packages", len(pkgs))
	}
}

func TestScanWheel_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.whl")
	os.WriteFile(f, []byte("not a zip"), 0644)
	pkgs := scanWheel(f)
	if pkgs != nil {
		t.Errorf("expected nil for invalid wheel, got %d packages", len(pkgs))
	}
}

func TestScanFile_EggFile(t *testing.T) {
	dir := t.TempDir()
	eggPath := filepath.Join(dir, "test-1.0.egg")
	f, err := os.Create(eggPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	meta, _ := w.Create("EGG-INFO/PKG-INFO")
	meta.Write([]byte("Name: TestEgg\nVersion: 2.0\n\n"))
	w.Close()
	f.Close()

	pkgs, sf := scanFile(eggPath, false)
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package from egg, got %d", len(pkgs))
	}
	if pkgs[0].Name != "testegg" {
		t.Errorf("Name = %q, want testegg", pkgs[0].Name)
	}
	if sf == nil || sf.Type != "python-egg" {
		t.Errorf("expected python-egg type, got %v", sf)
	}
}

func TestScan_NonexistentPath(t *testing.T) {
	_, err := Scan("/nonexistent/path", false)
	if err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}

func TestScanFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.jar")
	os.WriteFile(f, []byte{}, 0644)
	// Empty file should not crash
	pkgs, sf := scanFile(f, false)
	if len(pkgs) != 0 {
		t.Errorf("expected no packages from empty file, got %d", len(pkgs))
	}
	if sf != nil {
		t.Errorf("expected nil ScannedFile for empty, got %+v", sf)
	}
}
