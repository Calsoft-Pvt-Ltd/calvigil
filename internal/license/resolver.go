package license

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// httpClient is a shared HTTP client with reasonable timeouts for license lookups.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

var resolveOneFunc = resolveOne

// SetResolverForTesting replaces the per-package resolver and returns a restore
// function. It keeps command/scanner tests hermetic without changing production
// behavior.
func SetResolverForTesting(fn func(context.Context, models.Package) string) func() {
	previous := resolveOneFunc
	if fn == nil {
		resolveOneFunc = resolveOne
	} else {
		resolveOneFunc = fn
	}
	return func() {
		resolveOneFunc = previous
	}
}

// ResolvePackages enriches packages that are missing license information
// by querying the appropriate package registry for each ecosystem.
// It modifies the packages slice in place.
func ResolvePackages(ctx context.Context, packages []models.Package, verbose bool) {
	NormalizePackages(packages)

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

			lic := cleanRegistryLicense(resolveOneFunc(ctx, packages[i]))
			if lic != "" {
				mu.Lock()
				packages[i].License = lic
				resolved++
				mu.Unlock()
			}
		}(idx)
	}

	wg.Wait()

	if verbose {
		fmt.Fprintf(os.Stderr, "   Resolved %d/%d missing package licenses\n", resolved, len(missing))
	}
}

// NormalizePackages canonicalizes license strings already present in parsed
// manifests and lockfiles. It does not perform network calls.
func NormalizePackages(packages []models.Package) {
	for i := range packages {
		packages[i].License = cleanRegistryLicense(packages[i].License)
	}
}

// resolveOne queries the appropriate registry for a single package's license.
func resolveOne(ctx context.Context, pkg models.Package) string {
	switch pkg.Ecosystem {
	case models.EcosystemGo:
		return resolveGo(ctx, pkg.Name, pkg.Version)
	case models.EcosystemPyPI:
		return resolvePyPI(ctx, pkg.Name, pkg.Version)
	case models.EcosystemNpm:
		return resolveNpm(ctx, pkg.Name, pkg.Version)
	case models.EcosystemMaven:
		return resolveMaven(ctx, pkg.Name)
	case models.EcosystemCrates:
		return resolveCrates(ctx, pkg.Name)
	case models.EcosystemRubyGem:
		return resolveRubyGem(ctx, pkg.Name)
	case models.EcosystemConan:
		return resolveConan(ctx, pkg.Name)
	default:
		return ""
	}
}

// resolveGo queries deps.dev for Go module license information.
func resolveGo(ctx context.Context, name, version string) string {
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
func resolvePyPI(ctx context.Context, name, version string) string {
	if name == "" {
		return ""
	}
	if version != "" {
		url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", urlPathEscape(name), urlPathEscape(version))
		if lic := queryPyPILicense(ctx, url); lic != "" {
			return lic
		}
	}

	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", urlPathEscape(name))
	return queryPyPILicense(ctx, url)
}

func queryPyPILicense(ctx context.Context, url string) string {
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
			License           string   `json:"license"`
			LicenseExpression string   `json:"license_expression"`
			Classifiers       []string `json:"classifiers"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	if lic := cleanPyPILicenseExpression(result.Info.LicenseExpression); lic != "" {
		return lic
	}
	if lic := cleanRegistryLicense(result.Info.License); lic != "" {
		return lic
	}
	return licenseFromPyPIClassifiers(result.Info.Classifiers)
}

func cleanPyPILicenseExpression(lic string) string {
	lic = strings.TrimSpace(lic)
	if isUnknownLicenseValue(lic) {
		return ""
	}
	return lic
}

func cleanRegistryLicense(lic string) string {
	lic = strings.TrimSpace(lic)
	if isUnknownLicenseValue(lic) {
		return ""
	}
	if known := licenseFromKnownText(lic); known != "" {
		return known
	}
	if normalized := normalizeID(lic); normalized != "" && Classify(normalized) != models.LicenseUnknown {
		return normalized
	}
	// PyPI's legacy license field sometimes contains full license text instead
	// of an SPDX identifier. Keep that out of compliance classification and
	// prefer structured license_expression/classifiers instead unless the text
	// matches a known canonical license.
	if len(lic) > 60 {
		return ""
	}
	return lic
}

func isUnknownLicenseValue(lic string) bool {
	switch strings.ToUpper(strings.TrimSpace(lic)) {
	case "", "UNKNOWN", "UNKNOWN LICENSE", "N/A", "NONE":
		return true
	default:
		return false
	}
}

func licenseFromPyPIClassifiers(classifiers []string) string {
	for _, classifier := range classifiers {
		parts := strings.Split(classifier, "::")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) != "License" {
			continue
		}
		lic := strings.TrimSpace(parts[len(parts)-1])
		if isUnknownLicenseValue(lic) ||
			strings.EqualFold(lic, "Other/Proprietary License") ||
			strings.EqualFold(lic, "Public Domain") {
			continue
		}
		normalized := normalizeID(lic)
		if Classify(normalized) != models.LicenseUnknown {
			return normalized
		}
	}
	return ""
}

func licenseFromKnownText(text string) string {
	normalized := strings.ToLower(strings.Join(strings.Fields(text), " "))
	isBSD := strings.Contains(normalized, "redistribution and use in source and binary forms") &&
		strings.Contains(normalized, "are permitted provided that the following conditions are met")
	switch {
	case strings.Contains(normalized, "permission is hereby granted, free of charge, to any person obtaining a copy") &&
		strings.Contains(normalized, `the software is provided "as is"`):
		return "MIT"
	case strings.Contains(normalized, "apache license version 2.0") &&
		strings.Contains(normalized, "http://www.apache.org/licenses/license-2.0"):
		return "Apache-2.0"
	case isBSD && strings.Contains(normalized, "advertising materials"):
		return ""
	case isBSD && strings.Contains(normalized, "neither the name of"):
		return "BSD-3-Clause"
	case isBSD:
		return "BSD-2-Clause"
	default:
		return ""
	}
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
		return cleanRegistryLicense(lic)
	case map[string]interface{}:
		if t, ok := lic["type"].(string); ok {
			return cleanRegistryLicense(t)
		}
	}

	// Fallback: "licenses" field (legacy npm format, array of {type, url} objects)
	if arr, ok := result.Licenses.([]interface{}); ok && len(arr) > 0 {
		if obj, ok := arr[0].(map[string]interface{}); ok {
			if t, ok := obj["type"].(string); ok {
				return cleanRegistryLicense(t)
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
		return cleanRegistryLicense(result.Licenses[0])
	}
	return ""
}

var conanLicenseRe = regexp.MustCompile(`(?m)^\s*license\s*=\s*(?:"([^"]+)"|'([^']+)')`)

// resolveConan queries ConanCenter recipe metadata for C/C++ package licenses.
// Conan lockfiles do not include license data, so this reads the public recipe
// conanfile.py and extracts the recipe's static license field when present.
func resolveConan(ctx context.Context, name string) string {
	if name == "" {
		return ""
	}
	url := fmt.Sprintf("https://raw.githubusercontent.com/conan-io/conan-center-index/master/recipes/%s/all/conanfile.py",
		urlPathEscape(strings.ToLower(name)))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	matches := conanLicenseRe.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return ""
	}
	for _, match := range matches[1:] {
		if lic := cleanRegistryLicense(match); lic != "" {
			return lic
		}
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
		return cleanRegistryLicense(result.Licenses[0])
	}

	// Package-level response — use default version's license
	for _, v := range result.Versions {
		if v.VersionKey.Version == result.DefaultVersion && len(v.Licenses) > 0 {
			return cleanRegistryLicense(v.Licenses[0])
		}
	}

	// Fallback: first version with license info
	for _, v := range result.Versions {
		if len(v.Licenses) > 0 {
			return cleanRegistryLicense(v.Licenses[0])
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
