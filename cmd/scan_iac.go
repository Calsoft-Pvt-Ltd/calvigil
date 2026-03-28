package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/iac"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
	"github.com/spf13/cobra"
)

var scanIaCOpts struct {
	Format   string
	Output   string
	Severity string
}

var scanIaCCmd = &cobra.Command{
	Use:   "scan-iac <path>",
	Short: "Scan Infrastructure-as-Code files for security misconfigurations",
	Long: `Scan Infrastructure-as-Code files for security misconfigurations using
built-in rules. No external tools required.

Supported IaC types:
  - Terraform      — .tf, .tfvars files (AWS security groups, S3, IAM, RDS, CloudTrail)
  - Kubernetes     — YAML manifests (privileged containers, root, resource limits, hostNetwork)
  - Dockerfile     — Dockerfile (root user, latest tag, ADD vs COPY, curl-pipe-bash)
  - CloudFormation — YAML/JSON templates (public S3, open security groups)
  - Docker Compose — docker-compose.yml (privileged mode)

The path can be a single file or a directory that will be walked recursively.`,
	Example: `  # Scan a Terraform directory
  calvigil scan-iac ./infra/

  # Scan a single Kubernetes manifest
  calvigil scan-iac k8s/deployment.yaml

  # Scan with JSON output
  calvigil scan-iac ./terraform/ --format json

  # Only report high and critical
  calvigil scan-iac ./infra/ --severity high

  # Write SARIF report for CI integration
  calvigil scan-iac . --format sarif --output iac-results.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runScanIaC,
}

func init() {
	rootCmd.AddCommand(scanIaCCmd)

	scanIaCCmd.Flags().StringVarP(&scanIaCOpts.Format, "format", "f", "table", "output format: table, json, sarif, cyclonedx, openvex, html, pdf")
	scanIaCCmd.Flags().StringVarP(&scanIaCOpts.Output, "output", "o", "", "write output to file (default: stdout)")
	scanIaCCmd.Flags().StringVarP(&scanIaCOpts.Severity, "severity", "s", "", "minimum severity to report: critical, high, medium, low")
}

func runScanIaC(cmd *cobra.Command, args []string) error {
	target := args[0]
	absPath, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("path does not exist: %s", absPath)
	}

	isVerbose := verbose
	start := time.Now()

	if isVerbose {
		fmt.Fprintf(os.Stderr, "🔍 IaC Scanning: %s\n\n", absPath)
	}

	// Step 1: Scan IaC files
	scanResult, err := iac.Scan(absPath, isVerbose)
	if err != nil {
		return fmt.Errorf("IaC scan failed: %w", err)
	}

	if isVerbose {
		totalFiles := len(scanResult.Files)
		cats := iac.Categories(scanResult.Files)
		fmt.Fprintf(os.Stderr, "\n   Scanned %d IaC files (%s)\n", totalFiles, strings.Join(cats, ", "))
		fmt.Fprintf(os.Stderr, "   Found %d misconfigurations\n\n", len(scanResult.Findings))
	}

	// Step 2: Convert to vulnerabilities
	vulns := iac.ToVulnerabilities(scanResult.Findings, absPath)

	// Step 3: Filter by severity
	if scanIaCOpts.Severity != "" {
		minSev := models.Severity(strings.ToUpper(scanIaCOpts.Severity))
		vulns = filterVulnsBySeverity(vulns, minSev)
	}

	result := &models.ScanResult{
		ProjectPath:     absPath,
		TotalPackages:   len(scanResult.Files),
		Vulnerabilities: vulns,
		ScannedAt:       start,
		Duration:        time.Since(start),
	}

	rep := reporter.ForFormat(scanIaCOpts.Format)
	return writeReport(rep, result, scanIaCOpts.Output)
}
