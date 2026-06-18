package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// redirectTransport intercepts HTTP requests and redirects to a test server.
type redirectTransport struct {
	server *httptest.Server
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = rt.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func withMockClient(ts *httptest.Server, fn func()) {
	orig := httpClient
	httpClient = &http.Client{Transport: &redirectTransport{server: ts}}
	defer func() { httpClient = orig }()
	fn()
}

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

func TestResolvePyPI_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]interface{}{
				"license": "MIT",
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolvePyPI(context.Background(), "requests")
		if lic != "MIT" {
			t.Errorf("resolvePyPI = %q, want MIT", lic)
		}
	})
}

func TestResolvePyPI_Mock_LongLicense(t *testing.T) {
	// PyPI sometimes returns very long license text — should be ignored
	longLic := "Apache Software License, Version 2.0 and something else that makes this way too long for an SPDX ID"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]interface{}{
				"license": longLic,
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolvePyPI(context.Background(), "somepkg")
		if lic != "" {
			t.Errorf("long license should be ignored, got %q", lic)
		}
	})
}

func TestResolvePyPI_Mock_Unknown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]interface{}{
				"license": "UNKNOWN",
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolvePyPI(context.Background(), "somepkg")
		if lic != "" {
			t.Errorf("UNKNOWN should be ignored, got %q", lic)
		}
	})
}

func TestResolveNpm_Mock_StringLicense(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"license": "ISC",
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveNpm(context.Background(), "express", "4.18.2")
		if lic != "ISC" {
			t.Errorf("resolveNpm = %q, want ISC", lic)
		}
	})
}

func TestResolveNpm_Mock_ObjectLicense(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"license": map[string]interface{}{
				"type": "Apache-2.0",
				"url":  "https://opensource.org/licenses/Apache-2.0",
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveNpm(context.Background(), "somepkg", "1.0")
		if lic != "Apache-2.0" {
			t.Errorf("resolveNpm object = %q, want Apache-2.0", lic)
		}
	})
}

func TestResolveNpm_Mock_LegacyLicenses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []interface{}{
				map[string]interface{}{
					"type": "BSD-3-Clause",
					"url":  "https://opensource.org/licenses/BSD-3-Clause",
				},
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveNpm(context.Background(), "oldpkg", "0.1")
		if lic != "BSD-3-Clause" {
			t.Errorf("resolveNpm legacy = %q, want BSD-3-Clause", lic)
		}
	})
}

func TestResolveNpm_Mock_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveNpm(context.Background(), "nonexistent", "1.0")
		if lic != "" {
			t.Errorf("expected empty for 404, got %q", lic)
		}
	})
}

func TestResolveRubyGem_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"MIT"},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveRubyGem(context.Background(), "rails")
		if lic != "MIT" {
			t.Errorf("resolveRubyGem = %q, want MIT", lic)
		}
	})
}

func TestResolveRubyGem_Mock_NoLicenses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveRubyGem(context.Background(), "nolic")
		if lic != "" {
			t.Errorf("expected empty for no licenses, got %q", lic)
		}
	})
}

func TestQueryDepsDevLicense_Mock_VersionLevel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"Apache-2.0"},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := queryDepsDevLicense(context.Background(), "http://mock/v3alpha/test")
		if lic != "Apache-2.0" {
			t.Errorf("queryDepsDevLicense version = %q, want Apache-2.0", lic)
		}
	})
}

func TestQueryDepsDevLicense_Mock_PackageLevel(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"defaultVersion": "1.0.0",
			"versions": []interface{}{
				map[string]interface{}{
					"versionKey": map[string]interface{}{
						"version": "1.0.0",
					},
					"licenses": []string{"MIT"},
				},
				map[string]interface{}{
					"versionKey": map[string]interface{}{
						"version": "0.9.0",
					},
					"licenses": []string{"BSD-2-Clause"},
				},
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := queryDepsDevLicense(context.Background(), "http://mock/v3alpha/test")
		if lic != "MIT" {
			t.Errorf("queryDepsDevLicense package = %q, want MIT (defaultVersion match)", lic)
		}
	})
}

func TestQueryDepsDevLicense_Mock_FallbackFirstVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"defaultVersion": "2.0.0", // doesn't match any version
			"versions": []interface{}{
				map[string]interface{}{
					"versionKey": map[string]interface{}{
						"version": "1.0.0",
					},
					"licenses": []string{"GPL-3.0"},
				},
			},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := queryDepsDevLicense(context.Background(), "http://mock/v3alpha/test")
		if lic != "GPL-3.0" {
			t.Errorf("queryDepsDevLicense fallback = %q, want GPL-3.0", lic)
		}
	})
}

func TestQueryDepsDevLicense_Mock_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := queryDepsDevLicense(context.Background(), "http://mock/error")
		if lic != "" {
			t.Errorf("expected empty for server error, got %q", lic)
		}
	})
}

func TestResolveGo_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"BSD-3-Clause"},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveGo(context.Background(), "golang.org/x/net", "v0.19.0")
		if lic != "BSD-3-Clause" {
			t.Errorf("resolveGo = %q, want BSD-3-Clause", lic)
		}
	})
}

func TestResolvePackages_GoReportedModules(t *testing.T) {
	seen := map[string]bool{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedPath := r.URL.EscapedPath()
		switch {
		case strings.Contains(escapedPath, "github.com%2Fmodern-go%2Freflect2"):
			seen["reflect2"] = true
		case strings.Contains(escapedPath, "gopkg.in%2Fini.v1"):
			seen["ini"] = true
		default:
			t.Fatalf("unexpected deps.dev path: %s", escapedPath)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"Apache-2.0"},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		packages := []models.Package{
			{Name: "github.com/modern-go/reflect2", Version: "v1.0.2", Ecosystem: models.EcosystemGo},
			{Name: "gopkg.in/ini.v1", Version: "v1.67.0", Ecosystem: models.EcosystemGo},
		}
		ResolvePackages(context.Background(), packages, false)
		for _, pkg := range packages {
			if pkg.License != "Apache-2.0" {
				t.Fatalf("%s license = %q, want Apache-2.0", pkg.Name, pkg.License)
			}
		}
	})

	if !seen["reflect2"] || !seen["ini"] {
		t.Fatalf("expected both reported Go module paths to be queried, seen=%v", seen)
	}
}

func TestResolveMaven_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"Apache-2.0"},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveMaven(context.Background(), "org.springframework:spring-core")
		if lic != "Apache-2.0" {
			t.Errorf("resolveMaven = %q, want Apache-2.0", lic)
		}
	})
}

func TestResolveCrates_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"MIT OR Apache-2.0"},
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		lic := resolveCrates(context.Background(), "serde")
		if lic != "MIT OR Apache-2.0" {
			t.Errorf("resolveCrates = %q, want MIT OR Apache-2.0", lic)
		}
	})
}

func TestResolveOne_AllEcosystems(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"licenses": []string{"MIT"},
			"info":     map[string]interface{}{"license": "MIT"},
			"license":  "MIT",
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		ecosystems := []models.Ecosystem{
			models.EcosystemGo,
			models.EcosystemPyPI,
			models.EcosystemNpm,
			models.EcosystemMaven,
			models.EcosystemCrates,
			models.EcosystemRubyGem,
		}
		for _, eco := range ecosystems {
			pkg := models.Package{Name: "test", Version: "1.0", Ecosystem: eco}
			lic := resolveOne(context.Background(), pkg)
			if lic == "" {
				t.Errorf("resolveOne(%s) = empty, expected a license", eco)
			}
		}
	})
}

func TestResolvePackages_Mock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"license": "MIT",
		})
	}))
	defer ts.Close()

	withMockClient(ts, func() {
		packages := []models.Package{
			{Name: "testpkg", Version: "1.0", Ecosystem: models.EcosystemNpm},
			{Name: "already", Version: "1.0", Ecosystem: models.EcosystemNpm, License: "Apache-2.0"},
		}
		ResolvePackages(context.Background(), packages, false)
		if packages[0].License != "MIT" {
			t.Errorf("expected MIT, got %q", packages[0].License)
		}
		if packages[1].License != "Apache-2.0" {
			t.Errorf("should not overwrite, got %q", packages[1].License)
		}
	})
}
