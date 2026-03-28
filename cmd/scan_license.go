package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/detector"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/license"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/parser"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
	"github.com/spf13/cobra"
)

var licenseOpts struct {
	format     string
	outputFile string
	risk       string // filter: copyleft, unknown, all
}

var scanLicenseCmd = &cobra.Command{
	Use:   "scan-license [path]",
	Short: "Scan project dependencies for license compliance",
	Long: `Scan a project directory for license compliance issues.

This is a lightweight, focused command that:
  1. Detects project ecosystems and parses dependency manifests
  2. Resolves license information from package registries
     (deps.dev, PyPI, npm, RubyGems)
  3. Classifies each license as permissive, copyleft, or unknown
  4. Reports issues for copyleft and unknown licenses

No API keys are required. No vulnerability databases are queried.
Use this when you only need to audit your dependency licenses.`,
	Example: `  # Scan current directory
  calvigil scan-license

  # Scan a specific project
  calvigil scan-license /path/to/project

  # Output as JSON
  calvigil scan-license --format json

  # Show only copyleft issues
  calvigil scan-license --risk copyleft

  # Show only unknown/unresolved licenses
  calvigil scan-license --risk unknown

  # Write report to file
  calvigil scan-license --format json --output licenses.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScanLicense,
}

func init() {
	rootCmd.AddCommand(scanLicenseCmd)

	scanLicenseCmd.Flags().StringVarP(&licenseOpts.format, "format", "f", "table", "output format: table, json, html, pdf")
	scanLicenseCmd.Flags().StringVarP(&licenseOpts.outputFile, "output", "o", "", "write output to file (default: stdout)")
	scanLicenseCmd.Flags().StringVar(&licenseOpts.risk, "risk", "", "filter by risk level: copyleft, unknown (default: show all issues)")
}

func runScanLicense(cmd *cobra.Command, args []string) error {
	// Determine scan path
	var scanPath string
	if len(args) > 0 {
		scanPath = args[0]
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine current directory: %w", err)
		}
		scanPath = cwd
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %s", absPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}

	start := time.Now()
	ctx := cmd.Context()

	if verbose {
		fmt.Fprintf(os.Stderr, "Scanning %s for license compliance...\n\n", absPath)
	}

	// Step 1: Detect ecosystems
	files, ecosystems, err := detector.Detect(absPath)
	if err != nil {
		return fmt.Errorf("ecosystem detection failed: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Detecting project ecosystems...\n")
		fmt.Fprintf(os.Stderr, "   Found %d manifest files across %d ecosystems\n", len(files), len(ecosystems))
		for _, f := range files {
			fmt.Fprintf(os.Stderr, "   - %s (%s)\n", f.Filename, f.Ecosystem)
		}
		fmt.Fprintln(os.Stderr)
	}

	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "No supported manifest files found.")
		return nil
	}

	// Step 2: Parse all dependencies
	var allPackages []models.Package
	var scanErrors []string

	for _, mf := range files {
		p := parser.ForFile(mf.Filename)
		if p == nil {
			continue
		}
		file, err := os.Open(mf.Path)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("cannot open %s: %s", mf.Filename, err))
			continue
		}
		pkgs, err := p.Parse(file, mf.Path)
		file.Close()
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("parse %s: %s", mf.Filename, err))
			continue
		}
		allPackages = append(allPackages, pkgs...)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Parsed %d packages\n\n", len(allPackages))
	}

	if len(allPackages) == 0 {
		fmt.Fprintln(os.Stderr, "No packages found in manifest files.")
		return nil
	}

	// Step 3: Resolve licenses from package registries
	if verbose {
		fmt.Fprintf(os.Stderr, "Resolving licenses from package registries...\n")
	}
	license.ResolvePackages(ctx, allPackages, verbose)

	// Step 4: Check license compliance
	issues := license.CheckPackages(allPackages)

	// Filter by risk level if requested
	if licenseOpts.risk != "" {
		issues = filterByRisk(issues, licenseOpts.risk)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "   Found %d license issues\n\n", len(issues))
	}

	// Build result
	duration := time.Since(start)
	result := &models.ScanResult{
		ProjectPath:   absPath,
		Ecosystems:    ecosystems,
		TotalPackages: len(allPackages),
		Packages:      allPackages,
		LicenseIssues: issues,
		ScannedAt:     start,
		Duration:      duration,
		Errors:        scanErrors,
		LicenseOnly:   true,
	}

	// Output
	rep := reporter.ForFormat(licenseOpts.format)
	if err := writeReport(rep, result, licenseOpts.outputFile); err != nil {
		return err
	}

	// Print license summary to stderr for table format
	if licenseOpts.format == "table" {
		printLicenseSummary(os.Stderr, allPackages, issues, duration)
	}

	return nil
}

func filterByRisk(issues []models.LicenseIssue, risk string) []models.LicenseIssue {
	var filtered []models.LicenseIssue
	for _, iss := range issues {
		switch risk {
		case "copyleft":
			if iss.Risk == models.LicenseCopyleft {
				filtered = append(filtered, iss)
			}
		case "unknown":
			if iss.Risk == models.LicenseUnknown {
				filtered = append(filtered, iss)
			}
		default:
			filtered = append(filtered, iss)
		}
	}
	return filtered
}

func printLicenseSummary(w io.Writer, pkgs []models.Package, issues []models.LicenseIssue, d time.Duration) {
	permissive := 0
	copyleft := 0
	unknown := 0
	noLicense := 0

	for _, pkg := range pkgs {
		if pkg.License == "" {
			noLicense++
			continue
		}
		risk := license.Classify(pkg.License)
		switch risk {
		case models.LicensePermissive:
			permissive++
		case models.LicenseCopyleft:
			copyleft++
		default:
			unknown++
		}
	}

	fmt.Fprintf(w, "\n📋 License Summary\n")
	fmt.Fprintf(w, "   Total packages:  %d\n", len(pkgs))
	fmt.Fprintf(w, "   ✅ Permissive:    %d\n", permissive)
	fmt.Fprintf(w, "   ⚠️  Copyleft:      %d\n", copyleft)
	fmt.Fprintf(w, "   ❓ Unknown:       %d\n", unknown)
	fmt.Fprintf(w, "   🔍 No license:    %d\n", noLicense)
	fmt.Fprintf(w, "   ⏱  Duration:      %s\n\n", d.Round(time.Millisecond))
}

// ensure context is used (resolver needs it)
var _ = context.Background
