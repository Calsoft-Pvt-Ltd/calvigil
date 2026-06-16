package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/config"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/matcher"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
)

// writeReport writes scan results using the given reporter to the specified
// output file, or stdout if outputFile is empty.
//
// Output files are created with mode 0600 because scan reports may contain
// sensitive information (full package inventories, CVEs, AI-enriched code
// snippets). Using os.Create would honor the process umask and could yield
// world-readable files on systems with a permissive umask.
func writeReport(rep reporter.Reporter, result *models.ScanResult, outputFile string) error {
	if outputFile != "" {
		f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		return rep.Report(result, f)
	}
	return rep.Report(result, os.Stdout)
}

// filterVulnsBySeverity filters vulnerabilities to only include those at or above
// the given minimum severity. Returns the original slice if min is empty.
func filterVulnsBySeverity(vulns []models.Vulnerability, min models.Severity) []models.Vulnerability {
	if min == "" {
		return vulns
	}
	minRank := min.Rank()
	var filtered []models.Vulnerability
	for _, v := range vulns {
		if v.Severity.Rank() >= minRank {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func enrichDependencyCVSS(ctx context.Context, cfg *config.Config, vulns []models.Vulnerability, verbose bool) {
	if len(vulns) == 0 {
		return
	}
	nvd := matcher.NewNVDMatcher(cfg.NVDKey)
	result, err := nvd.EnrichCVSSByCVE(ctx, vulns)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment skipped: %v\n", err)
		}
		return
	}
	if !verbose {
		return
	}
	switch {
	case result.Enriched > 0:
		if result.Batches > 1 {
			fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: filled %d finding(s) across %d batch request(s)\n",
				result.Enriched, result.Batches)
		} else {
			fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: filled %d finding(s)\n", result.Enriched)
		}
	case result.Requested > 0:
		fmt.Fprintf(os.Stderr, "   NVD CVSS enrichment: no additional scores found\n")
	}
}
