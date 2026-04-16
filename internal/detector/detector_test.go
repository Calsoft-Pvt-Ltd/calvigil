package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestDetect_GoMod(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0644); err != nil {
		t.Fatal(err)
	}

	files, ecosystems, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if files[0].Ecosystem != models.EcosystemGo {
		t.Errorf("ecosystem = %v, want Go", files[0].Ecosystem)
	}
	if len(ecosystems) != 1 {
		t.Errorf("expected 1 ecosystem, got %d", len(ecosystems))
	}
}

func TestDetect_MultipleEcosystems(t *testing.T) {
	dir := t.TempDir()
	markers := []string{"go.mod", "package-lock.json", "requirements.txt", "pom.xml", "Cargo.lock"}
	for _, m := range markers {
		if err := os.WriteFile(filepath.Join(dir, m), []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}

	files, ecosystems, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 5 {
		t.Errorf("expected 5 files, got %d", len(files))
	}
	if len(ecosystems) < 4 {
		t.Errorf("expected at least 4 ecosystems, got %d", len(ecosystems))
	}
}

func TestDetect_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nmDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files (node_modules skipped), got %d", len(files))
	}
}

func TestDetect_SkipsGitDir(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "go.mod"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files (.git skipped), got %d", len(files))
	}
}

func TestDetect_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	files, ecosystems, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
	if len(ecosystems) != 0 {
		t.Errorf("expected 0 ecosystems, got %d", len(ecosystems))
	}
}

func TestDetect_NestedManifests(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subproject")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "package-lock.json"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}
}

func TestDetect_AllKnownMarkers(t *testing.T) {
	dir := t.TempDir()
	for _, marker := range knownMarkers {
		if err := os.WriteFile(filepath.Join(dir, marker.Name), []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}

	files, _, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != len(knownMarkers) {
		t.Errorf("expected %d files, got %d", len(knownMarkers), len(files))
	}
}

func TestDetect_SkipsVendorDir(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "go.mod"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files (vendor skipped), got %d", len(files))
	}
}

func TestDetectedFile_Fields(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module test"), 0644); err != nil {
		t.Fatal(err)
	}

	files, _, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}

	df := files[0]
	if df.Filename != "go.mod" {
		t.Errorf("Filename = %q, want go.mod", df.Filename)
	}
	if df.Path != gomod {
		t.Errorf("Path = %q, want %q", df.Path, gomod)
	}
}
