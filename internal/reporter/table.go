package reporter

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// TableReporter outputs scan results as a formatted terminal table.
type TableReporter struct{}

// allEcosystems defines the canonical display order for all supported ecosystems.
var allEcosystems = []models.Ecosystem{
	models.EcosystemGo,
	models.EcosystemNpm,
	models.EcosystemPyPI,
	models.EcosystemMaven,
	models.EcosystemCrates,
	models.EcosystemRubyGem,
	models.EcosystemPHP,
	models.EcosystemConan,
}

func init() {
	Register("table", func() Reporter { return &TableReporter{} })
}

func (r *TableReporter) Report(result *models.ScanResult, w io.Writer) error {
	if result.LicenseOnly {
		return r.reportLicenseOnly(result, w)
	}

	hasSupplyChainFindings := result.SupplyChainRisk != nil && result.SupplyChainRisk.FindingCount > 0
	if len(result.Vulnerabilities) == 0 && len(result.IntegrityIssues) == 0 && len(result.ConsistencyIssues) == 0 && !hasSupplyChainFindings {
		fmt.Fprintf(w, "\n✅ No vulnerabilities found in %s\n", result.ProjectPath)
		fmt.Fprintf(w, "   Scanned %d packages across %d ecosystems in %s\n\n",
			result.TotalPackages, len(result.Ecosystems), result.Duration.Round(1e8))
		if result.SupplyChainRisk != nil {
			printSupplyChainRisk(w, result.SupplyChainRisk)
		}
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

	// Malicious package alerts (MAL- prefixed IDs from OSV)
	depVulns := filterBySource(vulns, models.SourceOSV, models.SourceNVD, models.SourceGitHubAdv)
	malVulns, cleanDepVulns := splitMalicious(depVulns)
	if len(malVulns) > 0 {
		fmt.Fprintf(w, "☠️  Malicious Packages Detected (%d found)\n\n", len(malVulns))
		printMaliciousTable(w, malVulns)
		fmt.Fprintln(w)
	}

	// Dependency vulnerabilities table
	depVulns = cleanDepVulns
	if len(depVulns) > 0 {
		fmt.Fprintf(w, "📦 Dependency Vulnerabilities (%d found)\n", len(depVulns))

		// Group by ecosystem and print separate tables
		ecoGroups := groupByEcosystem(depVulns)
		for _, eco := range allEcosystems {
			group := ecoGroups[eco]
			if len(group) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n  %s %s (%d)\n\n", ecosystemIcon(eco), eco, len(group))
			printDepTable(w, group)
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

	// IaC misconfiguration findings
	iacVulns := filterBySource(vulns, models.SourceIaC)
	if len(iacVulns) > 0 {
		fmt.Fprintf(w, "\n🏗️  IaC Misconfigurations (%d found)\n\n", len(iacVulns))
		printCodeTable(w, iacVulns, result.ProjectPath)
	}

	// License compliance issues
	if len(result.LicenseIssues) > 0 {
		fmt.Fprintf(w, "\n📜 License Compliance Issues (%d found)\n\n", len(result.LicenseIssues))
		printLicenseTable(w, result.LicenseIssues)
	}

	// Integrity verification issues
	if len(result.IntegrityIssues) > 0 {
		fmt.Fprintf(w, "\n🔐 Lockfile Integrity Issues (%d found)\n\n", len(result.IntegrityIssues))
		printIntegrityTable(w, result.IntegrityIssues)
	}

	// Phantom dependency issues
	if len(result.ConsistencyIssues) > 0 {
		fmt.Fprintf(w, "\n👻 Phantom Dependencies (%d found)\n\n", len(result.ConsistencyIssues))
		printConsistencyTable(w, result.ConsistencyIssues)
	}

	if result.SupplyChainRisk != nil {
		printSupplyChainRisk(w, result.SupplyChainRisk)
	}

	if result.SlopCodeSmells != nil {
		printSlopCodeSmellSummary(w, result.SlopCodeSmells)
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

func printSupplyChainRisk(w io.Writer, risk *models.SupplyChainRisk) {
	if risk == nil {
		return
	}

	fmt.Fprintf(w, "\n🧭 Supply Chain Guard\n\n")
	fmt.Fprintf(w, "  Score: %d/100  Level: %s  Decision: %s  Findings: %d\n",
		risk.Score, colorSupplyChainLevel(risk.Level), risk.Decision, risk.FindingCount)
	if risk.NewDependencies > 0 || risk.InstallScripts > 0 || risk.PhantomDependencies > 0 {
		fmt.Fprintf(w, "  New deps: %d  Install scripts: %d  Phantom deps: %d\n",
			risk.NewDependencies, risk.InstallScripts, risk.PhantomDependencies)
	}
	for _, guidance := range risk.Guidance {
		fmt.Fprintf(w, "  - %s\n", guidance)
	}
	if len(risk.Findings) == 0 {
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintln(w)
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"Severity", "Signal", "Package", "Evidence", "Recommendation"})
	limit := len(risk.Findings)
	if limit > 12 {
		limit = 12
	}
	for _, finding := range risk.Findings[:limit] {
		pkg := finding.Package.Name
		if finding.Package.Version != "" {
			pkg += "@" + finding.Package.Version
		}
		t.AppendRow(table.Row{
			colorSeverity(finding.Severity),
			finding.ID + " " + finding.Title,
			orDash(pkg),
			truncate(finding.Evidence, 76),
			truncate(finding.Recommendation, 76),
		})
	}
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 2, WidthMax: 42},
		{Number: 4, WidthMax: 76},
		{Number: 5, WidthMax: 76},
	})
	t.Render()
	if len(risk.Findings) > limit {
		fmt.Fprintf(w, "  ... %d more supply-chain finding(s) omitted from table output. Use --format json for full detail.\n", len(risk.Findings)-limit)
	}
}

func colorSupplyChainLevel(level string) string {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return text.FgHiRed.Sprintf("%s", level)
	case "HIGH":
		return text.FgRed.Sprintf("%s", level)
	case "MEDIUM":
		return text.FgYellow.Sprintf("%s", level)
	case "LOW":
		return text.FgGreen.Sprintf("%s", level)
	default:
		return text.FgGreen.Sprintf("%s", level)
	}
}

func printSlopCodeSmellSummary(w io.Writer, summary *models.SlopCodeSmellSummary) {
	if summary == nil || summary.SignalCount == 0 {
		return
	}

	fmt.Fprintf(w, "\n🧠 AI Slop Code Smells\n\n")
	fmt.Fprintf(w, "  Score: %d/100  Level: %s  Signals: %d  Confidence: %s\n",
		summary.Score, colorSlopLevel(summary.Level), summary.SignalCount, summary.Confidence)
	if summary.GeneratedCodeSignal != "" {
		fmt.Fprintf(w, "  Generated-code signal: %s\n", summary.GeneratedCodeSignal)
	}
	fmt.Fprintf(w, "  Note: %s\n\n", summary.AuthorshipDisclaimer)

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)
	t.AppendHeader(table.Row{"Category", "Count", "Weight", "Why it matters"})
	for _, category := range summary.Categories {
		t.AppendRow(table.Row{
			category.Name,
			category.Count,
			category.Weight,
			truncate(category.Description, 70),
		})
	}
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 4, WidthMax: 70},
	})
	t.Render()

	if len(summary.TopSignals) > 0 {
		fmt.Fprintf(w, "\n  Top smell signals:\n")
		limit := len(summary.TopSignals)
		if limit > 5 {
			limit = 5
		}
		for _, signal := range summary.TopSignals[:limit] {
			location := ""
			if signal.FilePath != "" {
				location = fmt.Sprintf(" (%s:%d)", signal.FilePath, signal.StartLine)
			}
			fmt.Fprintf(w, "   - %s [%s/%s]%s: %s\n",
				signal.FindingID, signal.CategoryID, signal.Confidence, location, truncate(signal.Title, 90))
		}
	}
}

func printDepTable(w io.Writer, vulns []models.Vulnerability) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"Severity", "ID", "Package", "Version", "Type", "Fixed In", "Summary"})

	for _, v := range vulns {
		depType := "Direct"
		if v.Package.Indirect {
			depType = "Transitive"
		}
		id := v.ID
		if v.KnownExploited {
			id += " ⚠ KEV"
		}
		t.AppendRow(table.Row{
			colorSeverity(v.Severity),
			id,
			v.Package.Name,
			v.Package.Version,
			depType,
			orDash(v.FixedIn),
			truncate(v.Summary, 60),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 7, WidthMax: 60},
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

	// Count malicious packages separately
	malCount := 0
	for _, v := range vulns {
		if strings.HasPrefix(v.ID, "MAL-") || hasMalAlias(v.Aliases) {
			malCount++
		}
	}
	if malCount > 0 {
		fmt.Fprintf(w, "  ☠️  Malicious: %d\n", malCount)
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

	// Highlight findings listed in the CISA Known Exploited Vulnerabilities catalog.
	kevCount := 0
	for _, v := range vulns {
		if v.KnownExploited {
			kevCount++
		}
	}
	if kevCount > 0 {
		fmt.Fprintf(w, "  ⚠️  Known exploited (CISA KEV): %d — prioritize these fixes\n", kevCount)
	}

	if len(ecoCounts) > 1 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "By ecosystem:\n")
		for _, eco := range allEcosystems {
			if c := ecoCounts[eco]; c > 0 {
				fmt.Fprintf(w, "  %s %s: %d\n", ecosystemIcon(eco), eco, c)
			}
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
		aiTag := ""
		if e.AICodeIndicator != "" && e.AICodeIndicator != "UNLIKELY_AI" {
			aiTag = fmt.Sprintf(" [AI-Generated: %s]", e.AICodeIndicator)
		}
		fmt.Fprintf(w, "\n  ── %s (%s) [Confidence: %s]%s ──\n", v.ID, colorSeverity(v.Severity), e.Confidence, aiTag)
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
	case models.EcosystemCrates:
		return "🦀"
	case models.EcosystemRubyGem:
		return "💎"
	case models.EcosystemPHP:
		return "🐘"
	case models.EcosystemConan:
		return "⚙️"
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

func colorSlopLevel(level string) string {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return text.FgHiRed.Sprint(level)
	case "HIGH":
		return text.FgRed.Sprint(level)
	case "MODERATE":
		return text.FgYellow.Sprint(level)
	case "LOW":
		return text.FgBlue.Sprint(level)
	default:
		return level
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

// splitMalicious separates MAL- prefixed vulnerabilities from regular CVEs.
func splitMalicious(vulns []models.Vulnerability) (malicious, clean []models.Vulnerability) {
	for _, v := range vulns {
		if strings.HasPrefix(v.ID, "MAL-") || hasMalAlias(v.Aliases) {
			malicious = append(malicious, v)
		} else {
			clean = append(clean, v)
		}
	}
	return
}

// hasMalAlias returns true if any alias starts with "MAL-".
func hasMalAlias(aliases []string) bool {
	for _, a := range aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return false
}

func printMaliciousTable(w io.Writer, vulns []models.Vulnerability) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"ID", "Package", "Version", "Ecosystem", "Summary"})

	for _, v := range vulns {
		t.AppendRow(table.Row{
			text.FgHiRed.Sprint(v.ID),
			text.FgHiRed.Sprint(v.Package.Name),
			v.Package.Version,
			v.Package.Ecosystem,
			truncate(v.Summary, 60),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 5, WidthMax: 60},
	})

	t.Render()
}

func printIntegrityTable(w io.Writer, issues []models.IntegrityIssue) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"Package", "Version", "Ecosystem", "Reason"})

	for _, issue := range issues {
		t.AppendRow(table.Row{
			text.FgHiRed.Sprint(issue.Package.Name),
			issue.Package.Version,
			issue.Package.Ecosystem,
			truncate(issue.Reason, 60),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 4, WidthMax: 60},
	})

	t.Render()
}

func printConsistencyTable(w io.Writer, issues []models.ConsistencyIssue) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"Package", "Version", "Lock File", "Manifest", "Reason"})

	for _, issue := range issues {
		t.AppendRow(table.Row{
			text.FgYellow.Sprint(issue.Package.Name),
			issue.Package.Version,
			filepath.Base(issue.LockFile),
			filepath.Base(issue.Manifest),
			truncate(issue.Reason, 50),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 5, WidthMax: 50},
	})

	t.Render()
}

func printLicenseTable(w io.Writer, issues []models.LicenseIssue) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)

	t.AppendHeader(table.Row{"Risk", "Package", "Version", "License", "Reason"})

	for _, issue := range issues {
		risk := string(issue.Risk)
		switch issue.Risk {
		case models.LicenseCopyleft:
			risk = text.FgRed.Sprint("copyleft")
		case models.LicenseUnknown:
			risk = text.FgYellow.Sprint("unknown")
		default:
			risk = text.FgGreen.Sprint("permissive")
		}
		lic := issue.License
		if lic == "" {
			lic = "-"
		}
		t.AppendRow(table.Row{
			risk,
			issue.Package.Name,
			issue.Package.Version,
			lic,
			truncate(issue.Reason, 50),
		})
	}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 5, WidthMax: 50},
	})

	t.Render()
}

func (r *TableReporter) reportLicenseOnly(result *models.ScanResult, w io.Writer) error {
	fmt.Fprintf(w, "\n📜 Calvigil License Compliance Report for %s\n", result.ProjectPath)
	fmt.Fprintf(w, "   Scanned %d packages across %d ecosystems in %s\n\n",
		result.TotalPackages, len(result.Ecosystems), result.Duration.Round(1e8))

	if len(result.LicenseIssues) > 0 {
		fmt.Fprintf(w, "License Issues (%d found)\n\n", len(result.LicenseIssues))
		printLicenseTable(w, result.LicenseIssues)
	} else {
		fmt.Fprintf(w, "✅ All %d packages have permissive licenses.\n", result.TotalPackages)
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "\n⚠️  Completed with %d warnings:\n", len(result.Errors))
		for _, e := range result.Errors {
			fmt.Fprintf(w, "   - %s\n", e)
		}
	}

	fmt.Fprintln(w)
	return nil
}
