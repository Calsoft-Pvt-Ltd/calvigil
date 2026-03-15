package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/chavakula/calvigil/internal/models"
	"github.com/chavakula/calvigil/internal/scanner"
	"github.com/spf13/cobra"
)

var scanOpts models.ScanOptions

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for security vulnerabilities",
	Long: `Scan a project directory for security vulnerabilities.

This command performs two types of analysis:
  - Dependency scanning: checks your lock files against CVE databases (OSV, NVD, GitHub Advisory)
  - AI code analysis: uses OpenAI GPT-4 or a local Ollama model to detect OWASP Top 10 patterns

Use --provider to choose the AI backend: openai, ollama, or auto (default).
In auto mode the scanner picks Ollama when it is reachable, otherwise OpenAI.

Use --skip-ai to run dependency scanning only (no API key required).
Use --skip-deps to run AI analysis only.`,
	Example: `  # Scan current directory
  calvigil scan

  # Scan a specific project
  calvigil scan /path/to/project

  # Output as JSON
  calvigil scan --format json

  # Output as SARIF
  calvigil scan --format sarif --output results.sarif

  # Dependencies only (no OpenAI key needed)
  calvigil scan --skip-ai

  # Only report high and critical vulnerabilities
  calvigil scan --severity high

  # Use local Ollama model
  calvigil scan --provider ollama --ollama-model llama3

  # Use a remote Ollama server
  calvigil scan --provider ollama --ollama-url http://gpu-server:11434 --ollama-model codellama`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOpts.Format, "format", "f", "table", "output format: table, json, sarif, cyclonedx, openvex, html, pdf")
	scanCmd.Flags().StringVarP(&scanOpts.OutputFile, "output", "o", "", "write output to file (default: stdout)")
	scanCmd.Flags().StringVarP((*string)(&scanOpts.SeverityFilter), "severity", "s", "", "minimum severity to report: critical, high, medium, low")
	scanCmd.Flags().BoolVar(&scanOpts.SkipAI, "skip-ai", false, "skip AI-powered code analysis")
	scanCmd.Flags().BoolVar(&scanOpts.SkipDeps, "skip-deps", false, "skip dependency vulnerability scanning")
	scanCmd.Flags().BoolVar(&scanOpts.SkipSemgrep, "skip-semgrep", false, "skip Semgrep SAST analysis")
	scanCmd.Flags().StringVar(&scanOpts.SemgrepRules, "semgrep-rules", "", "path to custom Semgrep rule directory")
	scanCmd.Flags().StringVar(&scanOpts.AIProvider, "provider", "auto", "AI provider: openai, ollama, or auto")
	scanCmd.Flags().StringVar(&scanOpts.OllamaURL, "ollama-url", "", "Ollama server URL (default: http://localhost:11434)")
	scanCmd.Flags().StringVar(&scanOpts.OllamaModel, "ollama-model", "", "Ollama model name (e.g. llama3, codellama, mistral)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Determine scan path
	if len(args) > 0 {
		scanOpts.Path = args[0]
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine current directory: %w", err)
		}
		scanOpts.Path = cwd
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(scanOpts.Path)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}
	scanOpts.Path = absPath
	scanOpts.Verbose = verbose

	// Validate path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path does not exist: %s", absPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}

	// Run the scanner
	s, err := scanner.New(scanOpts)
	if err != nil {
		return err
	}

	return s.Run(cmd.Context())
}
