package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// VerifyIntegrity checks lockfile-recorded integrity hashes against the
// corresponding package registry for npm packages. Packages whose lockfile
// hash does not match the registry hash are returned as IntegrityIssues.
//
// Only packages that have a non-empty Integrity field are checked. Cargo
// checksums use a different scheme (sha256 of .crate) and are flagged if
// the checksum field is unexpectedly empty for a non-root package.
func VerifyIntegrity(ctx context.Context, packages []models.Package, verbose bool) []models.IntegrityIssue {
	client := &http.Client{Timeout: 10 * time.Second}

	// Separate npm packages (need network verification) from others.
	var npmPkgs []models.Package
	var localIssues []models.IntegrityIssue

	for _, pkg := range packages {
		switch pkg.Ecosystem {
		case models.EcosystemNpm:
			if pkg.Integrity == "" {
				// npm v1 lockfiles often lack integrity hashes — skip silently.
				continue
			}
			npmPkgs = append(npmPkgs, pkg)

		case models.EcosystemCrates:
			if pkg.Integrity == "" {
				localIssues = append(localIssues, models.IntegrityIssue{
					Package: pkg,
					Reason:  "no checksum recorded in Cargo.lock",
				})
			}
		}
	}

	// Verify npm packages concurrently (bounded to 10 goroutines).
	const maxWorkers = 10
	sem := make(chan struct{}, maxWorkers)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, pkg := range npmPkgs {
		wg.Add(1)
		sem <- struct{}{}
		go func(p models.Package) {
			defer wg.Done()
			defer func() { <-sem }()
			if issue := verifyNpmIntegrity(ctx, client, p); issue != nil {
				mu.Lock()
				localIssues = append(localIssues, *issue)
				mu.Unlock()
			}
		}(pkg)
	}
	wg.Wait()

	return localIssues
}

// npmRegistryVersion is the minimum info we need from the npm registry.
type npmRegistryVersion struct {
	Dist struct {
		Integrity string `json:"integrity"`
		Shasum    string `json:"shasum"`
	} `json:"dist"`
}

func verifyNpmIntegrity(ctx context.Context, client *http.Client, pkg models.Package) *models.IntegrityIssue {
	// Query the npm registry for the specific version
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg.Name, pkg.Version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil // network error — skip, don't flag
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return &models.IntegrityIssue{
				Package: pkg,
				Reason:  "package not found on npm registry — possible supply chain injection",
			}
		}
		return nil // other registry error — skip
	}

	var version npmRegistryVersion
	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return nil
	}

	registryIntegrity := version.Dist.Integrity
	if registryIntegrity == "" {
		// Older packages only have shasum
		return nil
	}

	// Normalise: both should be "sha512-<base64>"
	lockHash := normalizeIntegrity(pkg.Integrity)
	regHash := normalizeIntegrity(registryIntegrity)

	if lockHash != regHash {
		return &models.IntegrityIssue{
			Package:  pkg,
			Expected: regHash,
			Actual:   lockHash,
			Reason:   "integrity hash in lockfile does not match npm registry",
		}
	}
	return nil
}

// normalizeIntegrity trims whitespace and standardises the SRI format.
func normalizeIntegrity(s string) string {
	return strings.TrimSpace(s)
}
