package license

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// httpClient is a shared HTTP client with reasonable timeouts for license lookups.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// ResolvePackages enriches packages that are missing license information
// by querying the appropriate package registry for each ecosystem.
// It modifies the packages slice in place.
func ResolvePackages(ctx context.Context, packages []models.Package, verbose bool) {
	// Collect indices of packages missing license info
	var missing []int
	for i, pkg := range packages {
		if pkg.License == "" {
			missing = append(missing, i)
		}
	}

	if len(missing) == 0 {
		return
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "   Resolving licenses for %d packages from registries...\n", len(missing))
	}

	// Resolve in parallel with bounded concurrency
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	resolved := 0
	for _, idx := range missing {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lic := resolveOne(ctx, packages[i])
			if lic != "" {
				mu.Lock()
				packages[i].License = lic
				resolved++
				mu.Unlock()
			}
		}(idx)
	}

	wg.Wait()
}

// resolveOne queries the appropriate registry for a single package's license.
func resolveOne(ctx context.Context, pkg models.Package) string {
	switch pkg.Ecosystem {
	case models.EcosystemGo:
		return resolveGo(ctx, pkg.Name, pkg.Version)
	case models.EcosystemPyPI:
		return resolvePyPI(ctx, pkg.Name)
	case models.EcosystemNpm:
		return resolveNpm(ctx, pkg.Name, pkg.Version)
	case models.EcosystemMaven:
		return resolveMaven(ctx, pkg.Name)
	case models.EcosystemCrates:
		return resolveCrates(ctx, pkg.Name)
	case models.EcosystemRubyGem:
		return resolveRubyGem(ctx, pkg.Name)
	default:
		return ""
	}
}

// resolveGo queries the Go module proxy for license information.
// The Go proxy doesn't directly expose license data, so we use the
// pkg.go.dev license API.
func resolveGo(ctx context.Context, name, version string) string {
	// pkg.go.dev exposes license info via its frontend API
	url := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/go/packages/%s/versions/%s",
		urlPathEscape(name), urlPathEscape(version))

	lic := queryDepsDevLicense(ctx, url)
	if lic != "" {
		return lic
	}

	// Fallback: try without version
	url = fmt.Sprintf("https://api.deps.dev/v3alpha/systems/go/packages/%s",
		urlPathEscape(name))
	return queryDepsDevLicense(ctx, url)
}

// resolvePyPI queries the PyPI JSON API for license info.
func resolvePyPI(ctx context.Context, name string) string {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", urlPathEscape(name))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var result struct {
		Info struct {
			License string `json:"license"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	lic := strings.TrimSpace(result.Info.License)
	// PyPI sometimes returns long license text instead of SPDX ID; skip those
	if len(lic) > 60 || lic == "" || lic == "UNKNOWN" {
		return ""
	}
	return lic
}

// resolveNpm queries the npm registry for license info.
// This is a fallback for cases where the lockfile didn't include it.
func resolveNpm(ctx context.Context, name, version string) string {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", urlPathEscape(name), urlPathEscape(version))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var result struct {
		License  interface{} `json:"license"`
		Licenses interface{} `json:"licenses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	// Try "license" field first (modern npm format)
	switch lic := result.License.(type) {
	case string:
		return lic
	case map[string]interface{}:
		if t, ok := lic["type"].(string); ok {
			return t
		}
	}

	// Fallback: "licenses" field (legacy npm format, array of {type, url} objects)
	if arr, ok := result.Licenses.([]interface{}); ok && len(arr) > 0 {
		if obj, ok := arr[0].(map[string]interface{}); ok {
			if t, ok := obj["type"].(string); ok {
				return t
			}
		}
	}

	return ""
}

// resolveMaven tries to resolve license from deps.dev for Maven artifacts.
func resolveMaven(ctx context.Context, name string) string {
	// Maven names are "group:artifact"
	url := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/maven/packages/%s",
		urlPathEscape(name))
	return queryDepsDevLicense(ctx, url)
}

// resolveCrates queries deps.dev for Rust crate license info.
func resolveCrates(ctx context.Context, name string) string {
	url := fmt.Sprintf("https://api.deps.dev/v3alpha/systems/cargo/packages/%s",
		urlPathEscape(name))
	return queryDepsDevLicense(ctx, url)
}

// resolveRubyGem queries the RubyGems API for license info.
func resolveRubyGem(ctx context.Context, name string) string {
	url := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", urlPathEscape(name))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var result struct {
		Licenses []string `json:"licenses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	if len(result.Licenses) > 0 {
		return result.Licenses[0]
	}
	return ""
}

// queryDepsDevLicense queries the deps.dev API (Google's open source dependency
// insights) for license information. This covers Go, Maven, Cargo, npm, and PyPI.
func queryDepsDevLicense(ctx context.Context, url string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var result struct {
		// deps.dev v3alpha package-level response
		DefaultVersion string `json:"defaultVersion"`
		Versions       []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
			Licenses []string `json:"licenses"`
		} `json:"versions"`
		// deps.dev v3alpha version-level response
		Licenses []string `json:"licenses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	// Version-specific response
	if len(result.Licenses) > 0 {
		return result.Licenses[0]
	}

	// Package-level response — use default version's license
	for _, v := range result.Versions {
		if v.VersionKey.Version == result.DefaultVersion && len(v.Licenses) > 0 {
			return v.Licenses[0]
		}
	}

	// Fallback: first version with license info
	for _, v := range result.Versions {
		if len(v.Licenses) > 0 {
			return v.Licenses[0]
		}
	}

	return ""
}

// urlPathEscape escapes a string for use in a URL path segment.
// It replaces / with %2F and other special characters.
func urlPathEscape(s string) string {
	// Use strings.ReplaceAll for the common case (Go module paths with /)
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '/':
			b.WriteString("%2F")
		case ' ':
			b.WriteString("%20")
		case '@':
			b.WriteString("%40")
		case ':':
			b.WriteString("%3A")
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
