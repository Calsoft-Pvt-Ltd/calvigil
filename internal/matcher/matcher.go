package matcher

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// AggregatedMatcher combines results from multiple matchers and deduplicates by CVE ID.
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

// Match runs all matchers and returns deduplicated results.
func (a *AggregatedMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	seen := make(map[string]bool)
	var all []models.Vulnerability

	var sources []string
	for _, m := range a.matchers {
		sources = append(sources, strings.ToUpper(m.Name()))
	}
	if a.verbose {
		fmt.Fprintf(os.Stderr, "   Databases: %s\n", strings.Join(sources, ", "))
		fmt.Fprintf(os.Stderr, "   Packages to query: %d\n", len(packages))
	}

	for _, m := range a.matchers {
		if a.verbose {
			fmt.Fprintf(os.Stderr, "   Querying %s...\n", strings.ToUpper(m.Name()))
		}
		start := time.Now()
		vulns, err := m.Match(ctx, packages)
		elapsed := time.Since(start)
		if err != nil {
			if a.verbose {
				fmt.Fprintf(os.Stderr, "   %s: error after %s — %v\n", strings.ToUpper(m.Name()), elapsed.Round(time.Millisecond), err)
			}
			// Log but continue with other sources
			all = append(all, models.Vulnerability{
				ID:      "SCAN-ERR-" + m.Name(),
				Summary: "Error querying " + m.Name() + ": " + err.Error(),
			})
			continue
		}

		newCount := 0
		dupCount := 0
		for _, v := range vulns {
			if !seen[v.ID] {
				seen[v.ID] = true
				all = append(all, v)
				newCount++
			} else {
				dupCount++
			}
			// Also deduplicate by aliases
			for _, alias := range v.Aliases {
				seen[alias] = true
			}
		}

		if a.verbose {
			if dupCount > 0 {
				fmt.Fprintf(os.Stderr, "   %s: %d vulnerabilities found (%d new, %d duplicates) [%s]\n",
					strings.ToUpper(m.Name()), len(vulns), newCount, dupCount, elapsed.Round(time.Millisecond))
			} else {
				fmt.Fprintf(os.Stderr, "   %s: %d vulnerabilities found [%s]\n",
					strings.ToUpper(m.Name()), len(vulns), elapsed.Round(time.Millisecond))
			}
		}
	}

	if a.verbose {
		fmt.Fprintf(os.Stderr, "   Total unique vulnerabilities: %d\n", len(all))
	}

	return all, nil
}
