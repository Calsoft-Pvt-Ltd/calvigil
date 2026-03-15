package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "calvigil",
	Short: "AI-powered vulnerability scanner for Go, Java, Python & Node.js projects",
	Long: "calvigil is an open-source CLI tool that scans your projects for\n" +
		"security vulnerabilities using two complementary engines:\n\n" +
		"  1. Dependency scanning - checks your dependencies against CVE databases\n" +
		"     (OSV, NVD, GitHub Advisory)\n" +
		"  2. AI-powered code analysis - uses OpenAI GPT-4 to detect OWASP Top 10\n" +
		"     vulnerabilities in your source code\n\n" +
		"Supported ecosystems: Go, Java (Maven/Gradle), Python (pip/poetry/pipenv), Node.js (npm/yarn/pnpm)",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
}
