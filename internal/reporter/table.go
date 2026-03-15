package reporter

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/chavakula/calvigil/internal/models"
)

// TableReporter outputs scan results as a formatted terminal table.
type TableReporter struct{}

func (r *TableReporter) Report(result *models.ScanResult, w io.Writer) error {
	if len(result.Vulnerabilities) == 0 {
		fmt.Fprintf(w, "\n✅ No vulnerabilities found in %s\n", result.ProjectPath)
		fmt.Fprintf(w, "   Scanned %d packages across %d ecosystems in %s\n\n",
			result.TotalPackages, len(result.Ecosystems), result.Duration.Round(1e8))
		return nil
	}

	// Sort by severity (critical first)
	vulns := make([]models.Vulnerability, len(result.Vulnerabilities))
	copy(vulns, result.Vulnerabilities)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].Severity.Rank() > vulns[j].Severity.Rank()
	})

	// Print header
	fmt.Fprintf(w, "\n🔍 Calvigil Scan Results for %s\n", result.ProjectPath)
	fmt.Fprintf(w, "   Scanned %d packages across %d ecosystems in %s\n\n",
		result.TotalPackages, len(result.Ecosystems), result.Duration.Round(1e8))

	// Dependency vulnerabilities table
	depVulns := filterBySource(vulns, models.SourceOSV, models.SourceNVD, models.SourceGitHubAdv)
	if len(depVulns) > 0 {
		fmt.Fprintf(w, "📦 Dependency Vulnerabilities (%d found)\n", len(depVulns))

		// Group by ecosystem and print separate tables
		ecoGroups := groupByEcosystem(depVulns)
		ecoOrder := []models.Ecosystem{models.EcosystemGo, models.EcosystemNpm, models.EcosystemPyPI, models.EcosystemMaven}
		for _, eco := range ecoOrder {
			group := ecoGroups[eco]
			if len(group) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n  %s %s (%d)\n\n", ecosystemIcon(eco), eco, len(group))
			printDepTable(w, group)
		}
		// Any remaining ecosystems not in the predefined order
		for eco, group := range ecoGroups {
			if eco == models.EcosystemGo || eco == models.EcosystemNpm || eco == models.EcosystemPyPI || eco == models.EcosystemMaven {
				continue
			}
			if len(group) > 0 {
				fmt.Fprintf(w, "\n  📦 %s (%d)\n\n", eco, len(group))
				printDepTable(w, group)
			}
		}
		printEnrichmentDetails(w, depVulns)
	}

	// Code analysis vulnerabilities table
	codeVulns := filterBySource(vulns, models.SourcePatternMatch, models.SourceAIAnalysis)
	if len(codeVulns) > 0 {
		fmt.Fprintf(w, "\n🔬 Code Analysis Findings (%d found)\n\n", len(codeVulns))
		printCodeTable(w, codeVulns, result.ProjectPath)
		printEnrichmentDetails(w, codeVulns)
	}

	// Semgrep SAST findings
	semgrepVulns := filterBySource(vulns, models.SourceSemgrep)
	if len(semgrepVulns) > 0 {
		fmt.Fprintf(w, "\n🛡️  Semgrep SAST Findings (%d found)\n\n", len(semgrepVulns))
		printCodeTable(w, semgrepVulns, result.ProjectPath)
		printEnrichmentDetails(w, semgrepVulns)
	}

	// Summary
	fmt.Fprintln(w)
	printSummary(w, vulns)
	fmt.Fprintln(w)

	// Errors
	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "⚠️  Scan completed with %d warnings:\n", len(result.Errors))
		for _, e := range result.Errors {
			fmt.Fprintf(w, "   - %s\n", e)
		}
		fmt.Fprintln(w)
	}

	return nil
}

func printDepTable(w io.Writer, vulns []models.Vulnerability) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"Severity", "ID", "Package", "Version", "Fixed In", "Summary"})

	for _, v := range vulns {
		t.AppendRow(table.Row{
			colorSeverity(v.Severity),
			v.ID,
			v.Package.Name,
			v.Package.Version,
			orDash(v.FixedIn),
			truncate(v.Summary, 60),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 6, WidthMax: 60},
	})

	t.Render()
}

func printCodeTable(w io.Writer, vulns []models.Vulnerability, projectPath string) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"Severity", "ID", "File", "Line", "Finding"})

	for _, v := range vulns {
		relPath, _ := filepath.Rel(projectPath, v.FilePath)
		if relPath == "" {
			relPath = v.FilePath
		}

		t.AppendRow(table.Row{
			colorSeverity(v.Severity),
			v.ID,
			relPath,
			v.StartLine,
			truncate(v.Summary, 50),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 3, WidthMax: 40},
		{Number: 5, WidthMax: 50},
	})

	t.Render()
}

func printSummary(w io.Writer, vulns []models.Vulnerability) {
	counts := map[models.Severity]int{}
	ecoCounts := map[models.Ecosystem]int{}
	for _, v := range vulns {
		counts[v.Severity]++
		if v.Package.Ecosystem != "" {
			ecoCounts[v.Package.Ecosystem]++
		}
	}

	fmt.Fprintf(w, "Summary: %d total vulnerabilities\n", len(vulns))
	if c := counts[models.SeverityCritical]; c > 0 {
		fmt.Fprintf(w, "  🔴 Critical: %d\n", c)
	}
	if c := counts[models.SeverityHigh]; c > 0 {
		fmt.Fprintf(w, "  🟠 High:     %d\n", c)
	}
	if c := counts[models.SeverityMedium]; c > 0 {
		fmt.Fprintf(w, "  🟡 Medium:   %d\n", c)
	}
	if c := counts[models.SeverityLow]; c > 0 {
		fmt.Fprintf(w, "  🔵 Low:      %d\n", c)
	}
	if c := counts[models.SeverityUnknown]; c > 0 {
		fmt.Fprintf(w, "  ⚪ Unknown:  %d\n", c)
	}

	if len(ecoCounts) > 1 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "By ecosystem:\n")
		ecoOrder := []models.Ecosystem{models.EcosystemGo, models.EcosystemNpm, models.EcosystemPyPI, models.EcosystemMaven}
		for _, eco := range ecoOrder {
			if c := ecoCounts[eco]; c > 0 {
				fmt.Fprintf(w, "  %s %s: %d\n", ecosystemIcon(eco), eco, c)
			}
		}
		for eco, c := range ecoCounts {
			if eco == models.EcosystemGo || eco == models.EcosystemNpm || eco == models.EcosystemPyPI || eco == models.EcosystemMaven {
				continue
			}
			fmt.Fprintf(w, "  📦 %s: %d\n", eco, c)
		}
	}
}

func printEnrichmentDetails(w io.Writer, vulns []models.Vulnerability) {
	hasEnrichment := false
	for _, v := range vulns {
		if v.AIEnrichment != nil {
			hasEnrichment = true
			break
		}
	}
	if !hasEnrichment {
		return
	}

	fmt.Fprintf(w, "\n  🤖 AI Enrichment Details:\n")
	for _, v := range vulns {
		if v.AIEnrichment == nil {
			continue
		}
		e := v.AIEnrichment
		fmt.Fprintf(w, "\n  ── %s (%s) [Confidence: %s] ──\n", v.ID, colorSeverity(v.Severity), e.Confidence)
		if e.Summary != "" {
			for _, line := range strings.Split(e.Summary, "\n") {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
		if e.LikelyImpact != "" {
			fmt.Fprintf(w, "     Impact: %s\n", e.LikelyImpact)
		}
		if e.MinimalRemediation != "" {
			fmt.Fprintf(w, "     Fix: %s\n", e.MinimalRemediation)
		}
		if e.SuppressionRationale != "" {
			fmt.Fprintf(w, "     Suppress: %s\n", e.SuppressionRationale)
		}
	}
	fmt.Fprintln(w)
}

func groupByEcosystem(vulns []models.Vulnerability) map[models.Ecosystem][]models.Vulnerability {
	groups := make(map[models.Ecosystem][]models.Vulnerability)
	for _, v := range vulns {
		groups[v.Package.Ecosystem] = append(groups[v.Package.Ecosystem], v)
	}
	return groups
}

func ecosystemIcon(eco models.Ecosystem) string {
	switch eco {
	case models.EcosystemGo:
		return "🐹"
	case models.EcosystemNpm:
		return "📗"
	case models.EcosystemPyPI:
		return "🐍"
	case models.EcosystemMaven:
		return "☕"
	default:
		return "📦"
	}
}

func filterBySource(vulns []models.Vulnerability, sources ...models.VulnerabilitySource) []models.Vulnerability {
	sourceSet := make(map[models.VulnerabilitySource]bool)
	for _, s := range sources {
		sourceSet[s] = true
	}

	var filtered []models.Vulnerability
	for _, v := range vulns {
		if sourceSet[v.Source] {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func colorSeverity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return text.FgHiRed.Sprint(string(s))
	case models.SeverityHigh:
		return text.FgRed.Sprint(string(s))
	case models.SeverityMedium:
		return text.FgYellow.Sprint(string(s))
	case models.SeverityLow:
		return text.FgBlue.Sprint(string(s))
	default:
		return string(s)
	}
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
