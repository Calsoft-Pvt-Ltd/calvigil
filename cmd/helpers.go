package cmd

import (
	"fmt"
	"os"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
)

// writeReport writes scan results using the given reporter to the specified
// output file, or stdout if outputFile is empty.
func writeReport(rep reporter.Reporter, result *models.ScanResult, outputFile string) error {
	if outputFile != "" {
		f, err := os.Create(outputFile)
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
