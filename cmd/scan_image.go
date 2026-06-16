package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/config"
	imgscanner "github.com/Calsoft-Pvt-Ltd/calvigil/internal/image"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/matcher"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/reporter"
	"github.com/spf13/cobra"
)

var imageOpts struct {
	format     string
	outputFile string
	severity   string
}

var scanImageCmd = &cobra.Command{
	Use:   "scan-image <image>",
	Short: "Scan a container image for vulnerabilities",
	Long: `Scan a container image for security vulnerabilities.

This command uses syft to extract an SBOM from the image and then queries
vulnerability databases (OSV, NVD, GitHub Advisory) for known CVEs.

Requires: syft (https://github.com/anchore/syft)

The image argument can be:
  - A Docker/OCI image reference: nginx:latest, ubuntu:22.04
  - A local archive: docker-archive:image.tar
  - A directory:      dir:/path/to/rootfs`,
	Example: `  # Scan a Docker image
  calvigil scan-image nginx:latest

  # Scan with JSON output
  calvigil scan-image python:3.12-slim --format json

  # Scan and write SARIF report
  calvigil scan-image node:20 --format sarif --output results.sarif

  # Only report high and critical
  calvigil scan-image alpine:3.18 --severity high`,
	Args: cobra.ExactArgs(1),
	RunE: runScanImage,
}

func init() {
	rootCmd.AddCommand(scanImageCmd)

	scanImageCmd.Flags().StringVarP(&imageOpts.format, "format", "f", "table", "output format: table, json, sarif, cyclonedx, openvex, html, pdf")
	scanImageCmd.Flags().StringVarP(&imageOpts.outputFile, "output", "o", "", "write output to file (default: stdout)")
	scanImageCmd.Flags().StringVarP(&imageOpts.severity, "severity", "s", "", "minimum severity to report: critical, high, medium, low")
}

func runScanImage(cmd *cobra.Command, args []string) error {
	imageRef := args[0]

	if !imgscanner.SyftAvailable() {
		return fmt.Errorf("syft is not installed; install it from https://github.com/anchore/syft\n\n  brew install syft          # macOS\n  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh  # Linux")
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Build matchers
	matchers := []matcher.Matcher{
		matcher.NewOSVMatcher(),
	}
	if cfg.NVDKey != "" {
		matchers = append(matchers, matcher.NewNVDMatcher(cfg.NVDKey))
	}
	if cfg.GitHubToken != "" {
		matchers = append(matchers, matcher.NewGitHubAdvisoryMatcher(cfg.GitHubToken))
	}

	s := imgscanner.NewScanner(imageRef, verbose, matchers)
	result, err := s.Scan(cmd.Context())
	if err != nil {
		return err
	}
	enrichDependencyCVSS(cmd.Context(), cfg, result.Vulnerabilities, verbose)

	// Filter by severity (shared helper keeps validation consistent across commands)
	if imageOpts.severity != "" {
		result.Vulnerabilities = filterVulnsBySeverity(result.Vulnerabilities,
			models.Severity(strings.ToUpper(imageOpts.severity)))
	}

	// Report
	var w io.Writer = os.Stdout
	if imageOpts.outputFile != "" {
		// 0600: reports may contain sensitive data (CVEs, package inventories).
		f, err := os.OpenFile(imageOpts.outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("cannot create output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	rep := reporter.ForFormat(imageOpts.format)
	return rep.Report(result, w)
}
