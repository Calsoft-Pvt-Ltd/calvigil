package image

import (
	"context"
	"testing"

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
