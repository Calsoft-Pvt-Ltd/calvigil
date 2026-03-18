package binary

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
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
