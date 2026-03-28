package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/binary"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/config"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/matcher"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
	"github.com/spf13/cobra"
)

var scanBinaryOpts struct {
	Format   string
	Output   string
	Severity string
}

var scanBinaryCmd = &cobra.Command{
	Use:   "scan-binary <path>",
	Short: "Scan compiled binaries and archives for embedded dependency vulnerabilities",
	Long: `Scan compiled binaries, JAR archives, and Python wheels for embedded
dependency vulnerabilities.

Supported binary types:
  - Go binaries       — reads embedded Go module build info
  - Java JARs/WARs    — extracts Maven coordinates from pom.properties / MANIFEST.MF
  - Python wheels/eggs — reads METADATA / PKG-INFO from .whl and .egg files

The path can be a single file (e.g., a Go binary or a JAR) or a directory
that will be walked recursively to discover scannable files.`,
	Example: `  # Scan a single Go binary
  calvigil scan-binary ./bin/myapp

  # Scan a directory of JARs
  calvigil scan-binary ./lib/

  # Scan a Spring Boot uber-JAR with JSON output
  calvigil scan-binary app.jar --format json

  # Only report high and critical
  calvigil scan-binary ./bin/ --severity high

  # Write HTML report
  calvigil scan-binary ./dist/ --format html --output report.html`,
	Args: cobra.ExactArgs(1),
	RunE: runScanBinary,
}

func init() {
	rootCmd.AddCommand(scanBinaryCmd)

	scanBinaryCmd.Flags().StringVarP(&scanBinaryOpts.Format, "format", "f", "table", "output format: table, json, sarif, cyclonedx, openvex, html, pdf")
	scanBinaryCmd.Flags().StringVarP(&scanBinaryOpts.Output, "output", "o", "", "write output to file (default: stdout)")
	scanBinaryCmd.Flags().StringVarP(&scanBinaryOpts.Severity, "severity", "s", "", "minimum severity to report: critical, high, medium, low")
}

func runScanBinary(cmd *cobra.Command, args []string) error {
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
		fmt.Fprintf(os.Stderr, "Scanning binaries in %s ...\n\n", absPath)
	}

	// Step 1: Extract packages from binaries
	scanResult, err := binary.Scan(absPath, isVerbose)
	if err != nil {
		return fmt.Errorf("binary scan failed: %w", err)
	}

	if isVerbose {
		fmt.Fprintf(os.Stderr, "Binary/SCA scan results:\n")
		for _, sf := range scanResult.Files {
			fmt.Fprintf(os.Stderr, "   %s (%s) — %d packages\n", filepath.Base(sf.Path), sf.Type, sf.PkgCount)
		}
		fmt.Fprintf(os.Stderr, "   Total: %d unique packages extracted\n\n", len(scanResult.Packages))
	}

	if len(scanResult.Packages) == 0 {
		if isVerbose {
			fmt.Fprintf(os.Stderr, "No embedded packages found to scan\n")
		}
		// Still produce an output with 0 vulns
		result := &models.ScanResult{
			ProjectPath: absPath,
			ScannedAt:   start,
			Duration:    time.Since(start),
		}
		rep := reporter.ForFormat(scanBinaryOpts.Format)
		return writeReport(rep, result, scanBinaryOpts.Output)
	}

	// Generate PURLs
	for i := range scanResult.Packages {
		scanResult.Packages[i].EnsurePURL()
	}

	// Step 2: Build matchers
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	matchers := []matcher.Matcher{
		matcher.NewOSVMatcher(),
	}
	if cfg.NVDKey != "" {
		matchers = append(matchers, matcher.NewNVDMatcher(cfg.NVDKey))
	} else if isVerbose {
		fmt.Fprintf(os.Stderr, "   Skipping NVD (no API key configured)\n")
	}
	if cfg.GitHubToken != "" {
		matchers = append(matchers, matcher.NewGitHubAdvisoryMatcher(cfg.GitHubToken))
	} else if isVerbose {
		fmt.Fprintf(os.Stderr, "   Skipping GitHub Advisory (no token configured)\n")
	}

	if isVerbose {
		fmt.Fprintf(os.Stderr, "Querying vulnerability databases...\n")
	}

	ctx := context.Background()
	agg := matcher.NewAggregatedMatcher(matchers...)
	agg.SetVerbose(isVerbose)
	vulns, err := agg.Match(ctx, scanResult.Packages)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: matcher error: %v\n", err)
	}

	if isVerbose {
		fmt.Fprintf(os.Stderr, "   Found %d vulnerabilities\n\n", len(vulns))
	}

	// Set DepPath for each vuln
	for i := range vulns {
		pkg := vulns[i].Package
		if vulns[i].DepPath == "" && pkg.Name != "" {
			vulns[i].DepPath = filepath.Base(absPath) + " → " +
				filepath.Base(pkg.FilePath) + " → " + pkg.Name + "@" + pkg.Version
		}
	}

	// Filter by severity
	if scanBinaryOpts.Severity != "" {
		vulns = filterVulnsBySeverity(vulns, models.Severity(strings.ToUpper(scanBinaryOpts.Severity)))
	}

	// Collect unique ecosystems
	ecoSet := make(map[models.Ecosystem]bool)
	for _, p := range scanResult.Packages {
		ecoSet[p.Ecosystem] = true
	}
	var ecosystems []models.Ecosystem
	for e := range ecoSet {
		ecosystems = append(ecosystems, e)
	}

	result := &models.ScanResult{
		ProjectPath:     absPath,
		Ecosystems:      ecosystems,
		TotalPackages:   len(scanResult.Packages),
		Vulnerabilities: vulns,
		ScannedAt:       start,
		Duration:        time.Since(start),
	}

	rep := reporter.ForFormat(scanBinaryOpts.Format)
	return writeReport(rep, result, scanBinaryOpts.Output)
}
