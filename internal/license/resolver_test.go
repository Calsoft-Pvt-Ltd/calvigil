package license

import (
	"context"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

func TestResolveGo_WellKnownPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lic := resolveGo(ctx, "github.com/gin-gonic/gin", "v1.9.1")
	if lic == "" {
		t.Skip("deps.dev API unreachable, skipping")
	}
	// gin is MIT licensed
	if lic != "MIT" {
		t.Errorf("expected MIT for gin, got %q", lic)
	}
}

func TestResolvePyPI_WellKnownPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lic := resolvePyPI(ctx, "requests")
	if lic == "" {
		t.Skip("PyPI API unreachable, skipping")
	}
	// requests is Apache-2.0
	if lic != "Apache-2.0" && lic != "Apache 2.0" {
		t.Logf("requests license: %q (may vary)", lic)
	}
}

func TestResolveNpm_WellKnownPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lic := resolveNpm(ctx, "express", "4.18.2")
	if lic == "" {
		t.Skip("npm registry unreachable, skipping")
	}
	if lic != "MIT" {
		t.Errorf("expected MIT for express, got %q", lic)
	}
}

func TestResolveRubyGem_WellKnownPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lic := resolveRubyGem(ctx, "rails")
	if lic == "" {
		t.Skip("RubyGems API unreachable, skipping")
	}
	if lic != "MIT" {
		t.Errorf("expected MIT for rails, got %q", lic)
	}
}

func TestResolvePackages_FillsMissingLicenses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	packages := []models.Package{
		{Name: "express", Version: "4.18.2", Ecosystem: models.EcosystemNpm},
		{Name: "already-has-license", Version: "1.0.0", Ecosystem: models.EcosystemNpm, License: "MIT"},
	}

	ResolvePackages(ctx, packages, false)

	// express should now have a license
	if packages[0].License == "" {
		t.Skip("npm registry unreachable, skipping")
	}
	if packages[0].License != "MIT" {
		t.Errorf("expected MIT for express, got %q", packages[0].License)
	}

	// already-has-license should be unchanged
	if packages[1].License != "MIT" {
		t.Errorf("should not overwrite existing license, got %q", packages[1].License)
	}
}

func TestResolvePackages_NoMissingLicenses(t *testing.T) {
	packages := []models.Package{
		{Name: "a", Version: "1.0", License: "MIT"},
		{Name: "b", Version: "2.0", License: "Apache-2.0"},
	}

	// Should be a no-op
	ResolvePackages(context.Background(), packages, false)

	if packages[0].License != "MIT" {
		t.Errorf("unexpected change: %q", packages[0].License)
	}
}

func TestResolveOne_UnknownEcosystem(t *testing.T) {
	pkg := models.Package{Name: "unknown-pkg", Version: "1.0", Ecosystem: "UnknownEcosystem"}
	lic := resolveOne(context.Background(), pkg)
	if lic != "" {
		t.Errorf("expected empty for unknown ecosystem, got %q", lic)
	}
}

func TestUrlPathEscape(t *testing.T) {
	tests := map[string]string{
		"github.com/gin-gonic/gin": "github.com%2Fgin-gonic%2Fgin",
		"simple":                   "simple",
		"has space":                "has%20space",
		"has@at":                   "has%40at",
		"group:artifact":           "group%3Aartifact",
	}
	for input, want := range tests {
		got := urlPathEscape(input)
		if got != want {
			t.Errorf("urlPathEscape(%q) = %q, want %q", input, got, want)
		}
	}
}
