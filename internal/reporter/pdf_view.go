package reporter

import (
	"fmt"
	"html/template"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

const (
	pdfMaxSupplySignals = 20
	pdfMaxSlopSignals   = 20
	pdfMaxDepsPerEco    = 24
	pdfMaxCodeFindings  = 24
)

type pdfReportData struct {
	Title        string
	ProjectPath  string
	ProjectName  string
	GeneratedAt  string
	ScannedAt    string
	Duration     string
	PackageMeta  string
	Ecosystems   []string
	LogoDataURL  template.URL
	Summary      pdfSummary
	Gate         pdfReleaseGate
	TOC          []pdfTOCItem
	Supply       pdfSupplySection
	Slop         pdfSlopSection
	Dependencies pdfDependencySection
	Code         pdfCodeSection
	Warnings     []string
}

type pdfSummary struct {
	TotalFindings     int
	Critical          int
	High              int
	Medium            int
	Low               int
	Unknown           int
	TotalPackages     int
	KnownExploited    int
	LicenseIssues     int
	IntegrityIssues   int
	ConsistencyIssues int
	SeveritySlices    []pdfSeveritySlice
}

type pdfSeveritySlice struct {
	Label   string
	Count   int
	Class   string
	Percent float64
	Width   template.CSS
}

type pdfReleaseGate struct {
	Status  string
	Label   string
	Badge   string
	Body    string
	Actions []string
	Class   string
}

type pdfTOCItem struct {
	Number      string
	Title       string
	Description string
	Page        string
}

type pdfSupplySection struct {
	Score          int
	Level          string
	LevelClass     string
	Decision       string
	DecisionTitle  string
	Recommendation string
	SignalCount    int
	Metrics        []pdfMetric
	Findings       []pdfSupplyFinding
	Guidance       []string
}

type pdfMetric struct {
	Label string
	Value string
	Icon  string
	Class string
}

type pdfSupplyFinding struct {
	ID            string
	Severity      string
	SeverityClass string
	Title         string
	Description   string
	Package       string
	Ecosystem     string
	FilePath      string
	Evidence      string
	Action        string
	Confidence    string
}

type pdfSlopSection struct {
	Score           int
	Level           string
	LevelClass      string
	SignalCount     int
	Confidence      string
	GeneratedSignal string
	MeaningTitle    string
	MeaningBody     string
	Categories      []pdfSlopCategory
	Signals         []pdfSlopSignal
	Guidance        []string
}

type pdfSlopCategory struct {
	Name        string
	Description string
	Count       int
	Weight      int
}

type pdfSlopSignal struct {
	RuleID        string
	Title         string
	Severity      string
	SeverityClass string
	Confidence    string
	File          string
	Reason        string
	Weight        int
}

type pdfDependencySection struct {
	Count  int
	Groups []pdfDependencyGroup
}

type pdfDependencyGroup struct {
	Ecosystem string
	Count     int
	Findings  []pdfDependencyFinding
}

type pdfDependencyFinding struct {
	ID             string
	Severity       string
	SeverityClass  string
	Summary        string
	Package        string
	Scope          string
	CVSS           string
	FixedIn        string
	Reachable      string
	KnownExploited bool
}

type pdfCodeSection struct {
	Count  int
	Groups []pdfCodeGroup
}

type pdfCodeGroup struct {
	Source   string
	Count    int
	Findings []pdfCodeFinding
}

type pdfCodeFinding struct {
	ID            string
	Severity      string
	SeverityClass string
	Title         string
	File          string
	Rule          string
	Confidence    string
	Snippet       string
}

func buildPDFReportData(result *models.ScanResult) pdfReportData {
	now := time.Now()
	projectPath := strings.TrimSpace(result.ProjectPath)
	projectName := filepath.Base(projectPath)
	if projectName == "." || projectName == "/" || projectName == "" {
		projectName = "Calvigil scan"
	}

	summary := buildPDFSummary(result)
	gate := buildPDFGate(summary)
	supply := buildPDFSupply(result)
	slop := buildPDFSlop(result)
	deps := buildPDFDependencies(result)
	code := buildPDFCode(result)

	return pdfReportData{
		Title:       "Calvigil Security Report",
		ProjectPath: projectPath,
		ProjectName: projectName,
		GeneratedAt: now.Format("Mon, 02 Jan 2006 15:04:05 MST"),
		ScannedAt:   pdfTime(result.ScannedAt),
		Duration:    pdfDuration(result.Duration),
		PackageMeta: fmt.Sprintf("%d packages", result.TotalPackages),
		Ecosystems:  pdfEcosystems(result.Ecosystems),
		LogoDataURL: logoDataURL(logoPNG),
		Summary:     summary,
		Gate:        gate,
		TOC: []pdfTOCItem{
			{Number: "01", Title: "Executive overview", Description: "Release posture, severity mix, scan facts, and immediate actions.", Page: "3"},
			{Number: "02", Title: "Supply chain guard", Description: "Dependency provenance, install behavior, and lockfile consistency signals.", Page: "4"},
			{Number: "03", Title: "AI code smells", Description: "Quality and security symptoms for reviewer prioritization.", Page: "5"},
			{Number: "04", Title: "Dependency vulnerabilities", Description: "Known CVEs grouped by ecosystem with remediation context.", Page: "6+"},
			{Number: "05", Title: "Code analysis findings", Description: "Semgrep, pattern, IaC, and AI-assisted static analysis results.", Page: "7+"},
			{Number: "06", Title: "Scanner warnings", Description: "Operational warnings that may affect completeness.", Page: "8+"},
		},
		Supply:       supply,
		Slop:         slop,
		Dependencies: deps,
		Code:         code,
		Warnings:     append([]string(nil), result.Errors...),
	}
}

func buildPDFSummary(result *models.ScanResult) pdfSummary {
	var s pdfSummary
	s.TotalFindings = len(result.Vulnerabilities)
	s.TotalPackages = result.TotalPackages
	s.LicenseIssues = len(result.LicenseIssues)
	s.IntegrityIssues = len(result.IntegrityIssues)
	s.ConsistencyIssues = len(result.ConsistencyIssues)
	for _, v := range result.Vulnerabilities {
		if v.KnownExploited {
			s.KnownExploited++
		}
		switch v.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityLow:
			s.Low++
		default:
			s.Unknown++
		}
	}
	total := s.Critical + s.High + s.Medium + s.Low
	if total == 0 {
		total = 1
	}
	s.SeveritySlices = []pdfSeveritySlice{
		pdfSeveritySliceFor("Critical", s.Critical, "critical", total),
		pdfSeveritySliceFor("High", s.High, "high", total),
		pdfSeveritySliceFor("Medium", s.Medium, "medium", total),
		pdfSeveritySliceFor("Low", s.Low, "low", total),
	}
	return s
}

func pdfSeveritySliceFor(label string, count int, class string, total int) pdfSeveritySlice {
	pct := (float64(count) / float64(total)) * 100
	width := fmt.Sprintf("%.2f%%", pct)
	if count == 0 {
		width = "0"
	}
	return pdfSeveritySlice{Label: label, Count: count, Class: class, Percent: pct, Width: template.CSS(width)}
}

func buildPDFGate(summary pdfSummary) pdfReleaseGate {
	switch {
	case summary.Critical > 0 || summary.KnownExploited > 0:
		return pdfReleaseGate{
			Status: "Release blocked",
			Label:  "RELEASE GATE",
			Badge:  "block_release",
			Body:   "Critical or known-exploited vulnerabilities are present. Do not promote this build until findings are fixed or formally risk accepted.",
			Actions: []string{
				"Patch critical and known-exploited dependencies before release.",
				"Create an accountable, time-boxed risk acceptance only when compensating controls are proven.",
			},
			Class: "critical",
		}
	case summary.High > 0:
		return pdfReleaseGate{
			Status: "Prioritize before release",
			Label:  "RELEASE GATE",
			Badge:  "prioritize",
			Body:   "High severity vulnerabilities exist. Plan remediation before release and verify no exploitability or exposure increase.",
			Actions: []string{
				"Prioritize high-severity fixes in the current release window.",
				"Document deferrals with owners, due dates, and compensating controls.",
			},
			Class: "high",
		}
	default:
		return pdfReleaseGate{
			Status: "Release review clear",
			Label:  "RELEASE GATE",
			Badge:  "monitor",
			Body:   "No critical or high release-blocking findings were detected in this scan. Continue routine monitoring.",
			Actions: []string{
				"Keep dependency intelligence refreshed before release.",
				"Review scanner warnings and unknown severity rows before final approval.",
			},
			Class: "ok",
		}
	}
}

func buildPDFSupply(result *models.ScanResult) pdfSupplySection {
	sc := result.SupplyChainRisk
	if sc == nil {
		return pdfSupplySection{
			Score: 0, Level: "CLEAN", LevelClass: "ok", Decision: "monitor", DecisionTitle: "Monitor",
			Recommendation: "No supply-chain guard summary was present in this scan.",
			Metrics: []pdfMetric{
				{Label: "Findings", Value: "0", Icon: "flag", Class: "neutral"},
				{Label: "New deps", Value: "0", Icon: "package", Class: "neutral"},
				{Label: "Install scripts", Value: "0", Icon: "code", Class: "neutral"},
				{Label: "Phantom deps", Value: "0", Icon: "layers", Class: "neutral"},
			},
			Guidance: []string{"Enable supply-chain guard scanning to evaluate dependency provenance and lockfile consistency."},
		}
	}
	findings := make([]pdfSupplyFinding, 0, min(len(sc.Findings), pdfMaxSupplySignals))
	for _, f := range sc.Findings {
		if len(findings) >= pdfMaxSupplySignals {
			break
		}
		findings = append(findings, pdfSupplyFinding{
			ID:            f.ID,
			Severity:      string(f.Severity),
			SeverityClass: pdfSeverityClass(f.Severity),
			Title:         f.Title,
			Description:   f.Description,
			Package:       pdfPackageLabel(f.Package),
			Ecosystem:     string(f.Package.Ecosystem),
			FilePath:      firstNonEmpty(f.FilePath, f.Package.FilePath),
			Evidence:      f.Evidence,
			Action:        f.Recommendation,
			Confidence:    f.Confidence,
		})
	}
	return pdfSupplySection{
		Score:          sc.Score,
		Level:          firstNonEmpty(strings.ToUpper(sc.Level), "LOW"),
		LevelClass:     pdfLevelClass(sc.Level),
		Decision:       firstNonEmpty(sc.Decision, "monitor"),
		DecisionTitle:  pdfDecisionTitle(sc.Decision),
		Recommendation: pdfSupplyRecommendation(sc.Decision),
		SignalCount:    sc.FindingCount,
		Metrics: []pdfMetric{
			{Label: "Findings", Value: fmt.Sprint(sc.FindingCount), Icon: "flag", Class: "neutral"},
			{Label: "New deps", Value: fmt.Sprint(sc.NewDependencies), Icon: "package", Class: "ok"},
			{Label: "Install scripts", Value: fmt.Sprint(sc.InstallScripts), Icon: "code", Class: "high"},
			{Label: "Phantom deps", Value: fmt.Sprint(sc.PhantomDependencies), Icon: "layers", Class: "med"},
		},
		Findings: findings,
		Guidance: sc.Guidance,
	}
}

func buildPDFSlop(result *models.ScanResult) pdfSlopSection {
	sl := result.SlopCodeSmells
	if sl == nil {
		return pdfSlopSection{
			Score: 0, Level: "CLEAN", LevelClass: "ok", SignalCount: 0, Confidence: "LOW",
			MeaningTitle: "No AI-code-smell summary was present.",
			MeaningBody:  "Calvigil did not receive a slop-code-smell summary for this scan.",
			Guidance:     []string{"Run code-quality and AI-slop smell checks to prioritize reviewer attention."},
		}
	}
	categories := make([]pdfSlopCategory, 0, len(sl.Categories))
	for _, c := range sl.Categories {
		categories = append(categories, pdfSlopCategory{Name: c.Name, Description: c.Description, Count: c.Count, Weight: c.Weight})
	}
	sort.SliceStable(categories, func(i, j int) bool {
		if categories[i].Weight == categories[j].Weight {
			return categories[i].Name < categories[j].Name
		}
		return categories[i].Weight > categories[j].Weight
	})
	if len(categories) > 6 {
		categories = categories[:6]
	}

	signals := make([]pdfSlopSignal, 0, min(len(sl.TopSignals), pdfMaxSlopSignals))
	for _, sig := range sl.TopSignals {
		if len(signals) >= pdfMaxSlopSignals {
			break
		}
		signals = append(signals, pdfSlopSignal{
			RuleID:        firstNonEmpty(sig.RuleID, sig.FindingID),
			Title:         sig.Title,
			Severity:      string(sig.Severity),
			SeverityClass: pdfSeverityClass(sig.Severity),
			Confidence:    firstNonEmpty(sig.Confidence, "MEDIUM") + " confidence",
			File:          pdfFileRef(sig.FilePath, sig.StartLine),
			Reason:        sig.Reason,
			Weight:        sig.Weight,
		})
	}
	return pdfSlopSection{
		Score:           sl.Score,
		Level:           firstNonEmpty(strings.ToUpper(sl.Level), "LOW"),
		LevelClass:      pdfLevelClass(sl.Level),
		SignalCount:     sl.SignalCount,
		Confidence:      firstNonEmpty(sl.Confidence, "MEDIUM"),
		GeneratedSignal: firstNonEmpty(sl.GeneratedCodeSignal, "REVIEW_SIGNAL"),
		MeaningTitle:    "Review generated, copied, or hurried-code risk",
		MeaningBody:     firstNonEmpty(sl.AuthorshipDisclaimer, "Slop code smells are quality and security symptoms, not proof that code was AI-generated."),
		Categories:      categories,
		Signals:         signals,
		Guidance:        sl.Guidance,
	}
}

func buildPDFDependencies(result *models.ScanResult) pdfDependencySection {
	groups := map[string][]pdfDependencyFinding{}
	for _, v := range result.Vulnerabilities {
		if pdfIsCodeFinding(v) {
			continue
		}
		eco := firstNonEmpty(string(v.Package.Ecosystem), "Unknown")
		groups[eco] = append(groups[eco], pdfDependencyFinding{
			ID:             v.ID,
			Severity:       string(v.Severity),
			SeverityClass:  pdfSeverityClass(v.Severity),
			Summary:        firstNonEmpty(v.Summary, v.Details, "No summary reported"),
			Package:        pdfPackageLabel(v.Package),
			Scope:          pdfScope(v.Package),
			CVSS:           pdfScore(v.Score),
			FixedIn:        firstNonEmpty(v.FixedIn, "No fixed version reported"),
			Reachable:      v.Reachable,
			KnownExploited: v.KnownExploited,
		})
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []pdfDependencyGroup
	total := 0
	for _, k := range keys {
		items := groups[k]
		sortPDFDependencyFindings(items)
		total += len(items)
		if len(items) > pdfMaxDepsPerEco {
			items = items[:pdfMaxDepsPerEco]
		}
		out = append(out, pdfDependencyGroup{Ecosystem: k, Count: len(groups[k]), Findings: items})
	}
	return pdfDependencySection{Count: total, Groups: out}
}

func buildPDFCode(result *models.ScanResult) pdfCodeSection {
	groups := map[string][]pdfCodeFinding{}
	for _, v := range result.Vulnerabilities {
		if !pdfIsCodeFinding(v) {
			continue
		}
		source := pdfSourceLabel(v.Source)
		groups[source] = append(groups[source], pdfCodeFinding{
			ID:            v.ID,
			Severity:      string(v.Severity),
			SeverityClass: pdfSeverityClass(v.Severity),
			Title:         firstNonEmpty(v.Summary, v.Details, "Code analysis finding"),
			File:          pdfFileRef(v.FilePath, v.StartLine),
			Rule:          firstNonEmpty(v.MatchedRule, string(v.Source)),
			Confidence:    pdfAIConfidence(v),
			Snippet:       strings.TrimSpace(v.Snippet),
		})
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []pdfCodeGroup
	total := 0
	for _, k := range keys {
		items := groups[k]
		sort.SliceStable(items, func(i, j int) bool {
			return models.ParseSeverity(items[i].Severity).Rank() > models.ParseSeverity(items[j].Severity).Rank()
		})
		total += len(items)
		if len(items) > pdfMaxCodeFindings {
			items = items[:pdfMaxCodeFindings]
		}
		out = append(out, pdfCodeGroup{Source: k, Count: len(groups[k]), Findings: items})
	}
	return pdfCodeSection{Count: total, Groups: out}
}

func sortPDFDependencyFindings(items []pdfDependencyFinding) {
	sort.SliceStable(items, func(i, j int) bool {
		si, sj := models.ParseSeverity(items[i].Severity), models.ParseSeverity(items[j].Severity)
		if si.Rank() == sj.Rank() {
			return items[i].ID < items[j].ID
		}
		return si.Rank() > sj.Rank()
	})
}

func pdfIsCodeFinding(v models.Vulnerability) bool {
	switch v.Source {
	case models.SourceSemgrep, models.SourcePatternMatch, models.SourceAIAnalysis, models.SourceIaC:
		return true
	default:
		return v.FilePath != "" || v.StartLine > 0 || v.Snippet != "" || v.MatchedRule != ""
	}
}

func pdfEcosystems(ecosystems []models.Ecosystem) []string {
	seen := map[string]bool{}
	var out []string
	for _, eco := range ecosystems {
		s := string(eco)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func pdfTime(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.Format("Mon, 02 Jan 2006 15:04:05 MST")
}

func pdfDuration(d time.Duration) string {
	if d <= 0 {
		return "not recorded"
	}
	if d >= time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.String()
}

func pdfSeverityClass(sev models.Severity) string {
	switch sev {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "medium"
	case models.SeverityLow:
		return "low"
	default:
		return "neutral"
	}
}

func pdfLevelClass(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM", "MODERATE":
		return "medium"
	case "LOW":
		return "low"
	case "CLEAN", "OK":
		return "ok"
	default:
		return "neutral"
	}
}

func pdfDecisionTitle(decision string) string {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "block_release":
		return "Block release"
	case "review_before_merge":
		return "Review before merge"
	case "verify_provenance":
		return "Verify provenance"
	case "allow":
		return "Allow"
	default:
		return "Monitor"
	}
}

func pdfSupplyRecommendation(decision string) string {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "block_release":
		return "Block release until highlighted dependency or install-time behavior is reviewed and remediated."
	case "review_before_merge":
		return "Review dependency trust drift before merging this change."
	case "verify_provenance":
		return "Verify package provenance, license, and resolver behavior before release."
	case "allow":
		return "No blocking supply-chain guard signal was detected."
	default:
		return "Review package provenance, license, and resolver behavior before release."
	}
}

func pdfPackageLabel(pkg models.Package) string {
	if pkg.Name == "" {
		return "unknown package"
	}
	if pkg.Version == "" {
		return pkg.Name
	}
	return pkg.Name + "@" + pkg.Version
}

func pdfFileRef(path string, line int) string {
	if path == "" {
		return "no file recorded"
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}

func pdfScope(pkg models.Package) string {
	if pkg.Indirect {
		return "transitive"
	}
	return "direct"
}

func pdfScore(score float64) string {
	if score <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", score)
}

func pdfSourceLabel(src models.VulnerabilitySource) string {
	switch src {
	case models.SourceSemgrep:
		return "Semgrep"
	case models.SourcePatternMatch:
		return "Pattern rules"
	case models.SourceAIAnalysis:
		return "AI analysis"
	case models.SourceIaC:
		return "IaC"
	default:
		return string(src)
	}
}

func pdfAIConfidence(v models.Vulnerability) string {
	if v.AIEnrichment != nil && v.AIEnrichment.Confidence != "" {
		return v.AIEnrichment.Confidence + " confidence"
	}
	return "Review required"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
