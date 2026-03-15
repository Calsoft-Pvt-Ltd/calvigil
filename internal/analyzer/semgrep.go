package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chavakula/calvigil/internal/models"
)

// SemgrepAnalyzer runs Semgrep CE with custom rule packs for SAST scanning.
type SemgrepAnalyzer struct {
	RulesDir string // directory containing custom .yaml rule files
	Verbose  bool
}

// NewSemgrepAnalyzer creates a new Semgrep-based analyzer.
// rulesDir is the path to custom rule packs; if empty, uses built-in rules.
func NewSemgrepAnalyzer(rulesDir string, verbose bool) *SemgrepAnalyzer {
	return &SemgrepAnalyzer{
		RulesDir: rulesDir,
		Verbose:  verbose,
	}
}

// semgrepOutput represents the top-level Semgrep JSON output.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string                 `json:"message"`
	Severity string                 `json:"severity"`
	Metadata map[string]interface{} `json:"metadata"`
	Lines    string                 `json:"lines"`
}

type semgrepError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

// Available checks if semgrep is installed and accessible.
func (s *SemgrepAnalyzer) Available() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

// Analyze runs Semgrep on the given project path and returns vulnerabilities.
func (s *SemgrepAnalyzer) Analyze(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error) {
	if !s.Available() {
		return nil, fmt.Errorf("semgrep not found in PATH (install: pip install semgrep)")
	}

	args := []string{
		"--json",
		"--no-git-ignore",
		"--metrics", "off",
	}

	// Determine rules source
	rulesConfigured := false
	if s.RulesDir != "" {
		// Use custom rule packs directory
		info, err := os.Stat(s.RulesDir)
		if err == nil && info.IsDir() {
			args = append(args, "--config", s.RulesDir)
			rulesConfigured = true
		}
	}

	// Also check for project-local .semgrep/ or .semgrep.yml
	localRulesDir := filepath.Join(projectPath, ".semgrep")
	if info, err := os.Stat(localRulesDir); err == nil && info.IsDir() {
		args = append(args, "--config", localRulesDir)
		rulesConfigured = true
	}
	localRulesFile := filepath.Join(projectPath, ".semgrep.yml")
	if _, err := os.Stat(localRulesFile); err == nil {
		args = append(args, "--config", localRulesFile)
		rulesConfigured = true
	}

	// Fall back to bundled rules if available
	if !rulesConfigured {
		bundledRules := getBundledRulesDir()
		if bundledRules != "" {
			args = append(args, "--config", bundledRules)
		} else {
			// Use Semgrep's auto config as last resort
			args = append(args, "--config", "auto")
		}
	}

	args = append(args, projectPath)

	if verbose {
		fmt.Fprintf(os.Stderr, "  Running: semgrep %s\n", strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, "semgrep", args...)
	output, err := cmd.Output()
	if err != nil {
		// Semgrep returns exit code 1 if findings exist — that's fine
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 && len(output) > 0 {
				// Has findings, continue parsing
			} else {
				stderr := string(exitErr.Stderr)
				return nil, fmt.Errorf("semgrep failed (exit %d): %s", exitErr.ExitCode(), truncateStr(stderr, 500))
			}
		} else {
			return nil, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	return parseSemgrepOutput(output, projectPath)
}

func parseSemgrepOutput(data []byte, projectPath string) ([]models.Vulnerability, error) {
	var result semgrepOutput
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("cannot parse semgrep output: %w", err)
	}

	var vulns []models.Vulnerability
	for _, r := range result.Results {
		severity := semgrepSeverityToSeverity(r.Extra.Severity)

		// Extract snippet — use the matched lines
		snippet := r.Extra.Lines
		if snippet == "" {
			snippet = readSnippet(r.Path, r.Start.Line, r.End.Line)
		}

		// Build a descriptive ID
		ruleID := r.CheckID

		vuln := models.Vulnerability{
			ID:          "SG-" + ruleID,
			Summary:     r.Extra.Message,
			Details:     formatSemgrepDetails(r),
			Severity:    severity,
			Source:      models.SourceSemgrep,
			FilePath:    r.Path,
			StartLine:   r.Start.Line,
			EndLine:     r.End.Line,
			Snippet:     snippet,
			MatchedRule: ruleID,
		}

		// Extract CWE from metadata if available
		if cwe, ok := r.Extra.Metadata["cwe"].(string); ok {
			vuln.Details += "\nCWE: " + cwe
		} else if cweList, ok := r.Extra.Metadata["cwe"].([]interface{}); ok {
			for _, c := range cweList {
				if cs, ok := c.(string); ok {
					vuln.Details += "\nCWE: " + cs
				}
			}
		}

		// Extract OWASP category from metadata
		if owasp, ok := r.Extra.Metadata["owasp"].(string); ok {
			vuln.Details += "\nOWASP: " + owasp
		} else if owaspList, ok := r.Extra.Metadata["owasp"].([]interface{}); ok {
			for _, o := range owaspList {
				if os, ok := o.(string); ok {
					vuln.Details += "\nOWASP: " + os
				}
			}
		}

		// Extract references from metadata
		if refs, ok := r.Extra.Metadata["references"].([]interface{}); ok {
			for _, ref := range refs {
				if refStr, ok := ref.(string); ok {
					vuln.References = append(vuln.References, refStr)
				}
			}
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func semgrepSeverityToSeverity(s string) models.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return models.SeverityHigh
	case "WARNING":
		return models.SeverityMedium
	case "INFO":
		return models.SeverityLow
	default:
		return models.SeverityMedium
	}
}

func formatSemgrepDetails(r semgrepResult) string {
	var sb strings.Builder
	sb.WriteString(r.Extra.Message)
	sb.WriteString("\n\nRule: ")
	sb.WriteString(r.CheckID)
	return sb.String()
}

func readSnippet(filePath string, startLine, endLine int) string {
	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum >= startLine && lineNum <= endLine {
			lines = append(lines, scanner.Text())
		}
		if lineNum > endLine {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// getBundledRulesDir returns the path to bundled rule packs shipped with the scanner.
func getBundledRulesDir() string {
	// Check relative to the executable
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exeDir := filepath.Dir(exe)

	// Look for rules/ directory next to the binary
	rulesDir := filepath.Join(exeDir, "rules", "semgrep")
	if info, err := os.Stat(rulesDir); err == nil && info.IsDir() {
		return rulesDir
	}

	// Look in the working directory
	if info, err := os.Stat(filepath.Join("rules", "semgrep")); err == nil && info.IsDir() {
		return filepath.Join("rules", "semgrep")
	}

	return ""
}
