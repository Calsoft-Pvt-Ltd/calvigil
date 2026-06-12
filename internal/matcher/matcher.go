package matcher

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

// Matcher queries a vulnerability database for known CVEs affecting given packages.
type Matcher interface {
	// Name returns the name of this vulnerability source.
	Name() string

	// Match checks a list of packages against the vulnerability database
	// and returns any known vulnerabilities.
	Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error)
}

// matcherResult collects the output of a single matcher goroutine.
type matcherResult struct {
	name    string
	vulns   []models.Vulnerability
	elapsed time.Duration
	err     error
}

// AggregatedMatcher combines results from multiple matchers and deduplicates by CVE ID.
// All matchers execute concurrently for maximum throughput.
type AggregatedMatcher struct {
	matchers []Matcher
	verbose  bool
}

// NewAggregatedMatcher creates a matcher that queries multiple sources.
func NewAggregatedMatcher(matchers ...Matcher) *AggregatedMatcher {
	return &AggregatedMatcher{matchers: matchers}
}

// SetVerbose enables verbose logging of per-database query progress.
func (a *AggregatedMatcher) SetVerbose(v bool) {
	a.verbose = v
}

// Match runs all matchers concurrently and returns deduplicated results.
func (a *AggregatedMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	var sources []string
	for _, m := range a.matchers {
		sources = append(sources, strings.ToUpper(m.Name()))
	}
	if a.verbose {
		fmt.Fprintf(os.Stderr, "   Databases: %s (querying in parallel)\n", strings.Join(sources, ", "))
		fmt.Fprintf(os.Stderr, "   Packages to query: %d\n", len(packages))
	}

	// Launch all matchers concurrently.
	results := make([]matcherResult, len(a.matchers))
	var wg sync.WaitGroup

	for i, m := range a.matchers {
		wg.Add(1)
		go func(idx int, mat Matcher) {
			defer wg.Done()
			start := time.Now()
			vulns, err := mat.Match(ctx, packages)
			results[idx] = matcherResult{
				name:    mat.Name(),
				vulns:   vulns,
				elapsed: time.Since(start),
				err:     err,
			}
		}(i, m)
	}
	wg.Wait()

	// Merge results in matcher order for deterministic output. Duplicate
	// records (same CVE/alias from multiple sources) are merged via the
	// Canonical Data Model so the best available data wins — a record with
	// severity UNKNOWN from one source gets filled in from a duplicate that
	// carries a real severity or CVSS score.
	seen := make(map[string]int) // ID or alias -> index in `all`
	var all []models.Vulnerability

	for _, r := range results {
		if r.err != nil {
			if a.verbose {
				fmt.Fprintf(os.Stderr, "   %s: error after %s — %v\n",
					strings.ToUpper(r.name), r.elapsed.Round(time.Millisecond), r.err)
			}
			continue
		}

		newCount := 0
		dupCount := 0
		for _, v := range r.vulns {
			Normalize(&v)

			// Check primary ID and all aliases for an existing record.
			existingIdx := -1
			if idx, ok := seen[v.ID]; ok {
				existingIdx = idx
			} else {
				for _, alias := range v.Aliases {
					if idx, ok := seen[alias]; ok {
						existingIdx = idx
						break
					}
				}
			}

			if existingIdx >= 0 {
				// Merge the duplicate into the existing record so missing
				// fields (severity, score, fix version, ...) get filled.
				Merge(&all[existingIdx], v)
				seen[all[existingIdx].ID] = existingIdx
				for _, alias := range all[existingIdx].Aliases {
					seen[alias] = existingIdx
				}
				dupCount++
				continue
			}

			idx := len(all)
			all = append(all, v)
			seen[v.ID] = idx
			for _, alias := range v.Aliases {
				seen[alias] = idx
			}
			newCount++
		}

		if a.verbose {
			if dupCount > 0 {
				fmt.Fprintf(os.Stderr, "   %s: %d vulnerabilities found (%d new, %d merged) [%s]\n",
					strings.ToUpper(r.name), len(r.vulns), newCount, dupCount, r.elapsed.Round(time.Millisecond))
			} else {
				fmt.Fprintf(os.Stderr, "   %s: %d vulnerabilities found [%s]\n",
					strings.ToUpper(r.name), len(r.vulns), r.elapsed.Round(time.Millisecond))
			}
		}
	}

	if a.verbose {
		fmt.Fprintf(os.Stderr, "   Total unique vulnerabilities: %d\n", len(all))
	}

	return all, nil
}
