package matcher

import (
	"context"

	"github.com/chavakula/calvigil/internal/models"
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
}

// NewAggregatedMatcher creates a matcher that queries multiple sources.
func NewAggregatedMatcher(matchers ...Matcher) *AggregatedMatcher {
	return &AggregatedMatcher{matchers: matchers}
}

// Match runs all matchers and returns deduplicated results.
func (a *AggregatedMatcher) Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error) {
	seen := make(map[string]bool)
	var all []models.Vulnerability

	for _, m := range a.matchers {
		vulns, err := m.Match(ctx, packages)
		if err != nil {
			// Log but continue with other sources
			all = append(all, models.Vulnerability{
				ID:      "SCAN-ERR-" + m.Name(),
				Summary: "Error querying " + m.Name() + ": " + err.Error(),
			})
			continue
		}

		for _, v := range vulns {
			if !seen[v.ID] {
				seen[v.ID] = true
				all = append(all, v)
			}
			// Also deduplicate by aliases
			for _, alias := range v.Aliases {
				seen[alias] = true
			}
		}
	}

	return all, nil
}
