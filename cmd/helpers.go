package cmd

import (
	"fmt"
	"os"

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
