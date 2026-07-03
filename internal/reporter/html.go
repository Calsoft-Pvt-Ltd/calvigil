package reporter

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/license"
	"github.com/Calsoft-Pvt-Ltd/calvigil/internal/models"
)

//go:embed assets/calvigil2.png
var logoPNG []byte

// HTMLReporter generates the interactive Calvigil security report.
type HTMLReporter struct{}

func init() {
	Register("html", func() Reporter { return &HTMLReporter{} })
}

type htmlData struct {
	ProjectPath         string
	ProjectName         string
	GeneratedAt         string
	Duration            string
	TotalPackages       int
	Ecosystems          []string
	TotalVulns          int
	CriticalCount       int
	HighCount           int
	MediumCount         int
	LowCount            int
	UnknownCount        int
	KnownExploitedCount int
	DepGroups           []htmlEcoGroup
	CodeVulns           []htmlVuln
	SemgrepVulns        []htmlVuln
	LicenseIssues       []htmlLicense
	LicenseSummary      *htmlLicenseSummary
	Errors              []string
	HasEnrichment       bool
	TotalDepVulns       int
	LogoDataURL         template.URL
	LicenseOnly         bool
	ReleaseGate         htmlReleaseGate
	SlopCodeSmells      *models.SlopCodeSmellSummary
	SupplyChainRisk     *models.SupplyChainRisk
	SupplyChainFindings []models.SupplyChainFinding
	SupplyChainMore     int
}

type htmlReleaseGate struct {
	Class           string
	Title           string
	Badge           string
	Decision        string
	SidebarStatus   string
	Message         string
	Drivers         []string
	Recommendations []string
}

type htmlEcoGroup struct {
	Ecosystem string
	Icon      string
	Vulns     []htmlVuln
}

type htmlVuln struct {
	ID            string
	Summary       string
	Details       string
	Severity      string
	SeverityClass string
	Score         string
	PackageName   string
	PackageVer    string
	Ecosystem     string
	FixedIn       string
	FilePath      string
	StartLine     int
	DepPath       string
	Reachable     string
	Source        string
	PURL          string
	IsTransitive  bool
	Enrichment    *htmlEnrichment
}

type htmlLicense struct {
	PackageName string
	PackageVer  string
	Ecosystem   string
	License     string
	Risk        string
	RiskClass   string
	Reason      string
}

type htmlLicenseSummary struct {
	Total      int
	Permissive int
	Copyleft   int
	Unknown    int
	NoLicense  int
}

type htmlEnrichment struct {
	Summary              string
	LikelyImpact         string
	Confidence           string
	ConfidenceClass      string
	AICodeIndicator      string
	MinimalRemediation   string
	SuppressionRationale string
}

func (r *HTMLReporter) Report(result *models.ScanResult, w io.Writer) error {
	vulns := make([]models.Vulnerability, len(result.Vulnerabilities))
	copy(vulns, result.Vulnerabilities)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].Severity.Rank() > vulns[j].Severity.Rank()
	})

	data := htmlData{
		ProjectPath:     result.ProjectPath,
		ProjectName:     htmlProjectName(result.ProjectPath),
		GeneratedAt:     result.ScannedAt.Format(time.RFC1123),
		Duration:        result.Duration.Round(time.Millisecond).String(),
		TotalPackages:   result.TotalPackages,
		TotalVulns:      len(vulns),
		LogoDataURL:     template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(logoPNG)),
		LicenseOnly:     result.LicenseOnly,
		SlopCodeSmells:  result.SlopCodeSmells,
		SupplyChainRisk: result.SupplyChainRisk,
	}
	if data.ProjectName == "" {
		data.ProjectName = "scanned project"
	}
	if result.SupplyChainRisk != nil {
		limit := len(result.SupplyChainRisk.Findings)
		if limit > 20 {
			limit = 20
			data.SupplyChainMore = len(result.SupplyChainRisk.Findings) - limit
		}
		data.SupplyChainFindings = result.SupplyChainRisk.Findings[:limit]
	}

	for _, e := range result.Ecosystems {
		data.Ecosystems = append(data.Ecosystems, string(e))
	}

	for _, v := range vulns {
		if v.KnownExploited {
			data.KnownExploitedCount++
		}
		switch v.Severity {
		case models.SeverityCritical:
			data.CriticalCount++
		case models.SeverityHigh:
			data.HighCount++
		case models.SeverityMedium:
			data.MediumCount++
		case models.SeverityLow:
			data.LowCount++
		default:
			data.UnknownCount++
		}
	}

	depVulnsByEco := make(map[string][]htmlVuln)
	for _, v := range vulns {
		hv := toHTMLVuln(v, result.ProjectPath)
		if hv.Enrichment != nil {
			data.HasEnrichment = true
		}
		switch v.Source {
		case models.SourceOSV, models.SourceNVD, models.SourceGitHubAdv:
			eco := hv.Ecosystem
			if eco == "" {
				eco = "Other"
			}
			depVulnsByEco[eco] = append(depVulnsByEco[eco], hv)
			data.TotalDepVulns++
		case models.SourceSemgrep:
			data.SemgrepVulns = append(data.SemgrepVulns, hv)
		default:
			data.CodeVulns = append(data.CodeVulns, hv)
		}
	}

	ecoOrder := []string{"Go", "npm", "PyPI", "Maven", "crates.io", "RubyGems", "Packagist", "ConanCenter"}
	seen := make(map[string]bool)
	for _, e := range ecoOrder {
		seen[e] = true
	}
	for e := range depVulnsByEco {
		if !seen[e] {
			ecoOrder = append(ecoOrder, e)
		}
	}
	for _, eco := range ecoOrder {
		if vlist, ok := depVulnsByEco[eco]; ok {
			data.DepGroups = append(data.DepGroups, htmlEcoGroup{
				Ecosystem: eco,
				Icon:      htmlEcoIcon(eco),
				Vulns:     vlist,
			})
		}
	}

	if len(result.LicenseIssues) > 0 {
		for _, iss := range result.LicenseIssues {
			riskStr := "Unknown"
			riskClass := "unknown"
			switch iss.Risk {
			case models.LicenseCopyleft:
				riskStr = "Copyleft"
				riskClass = "high"
			case models.LicenseUnknown:
				riskStr = "Unknown"
				riskClass = "medium"
			}
			lic := iss.License
			if lic == "" {
				lic = "(none)"
			}
			data.LicenseIssues = append(data.LicenseIssues, htmlLicense{
				PackageName: iss.Package.Name,
				PackageVer:  iss.Package.Version,
				Ecosystem:   string(iss.Package.Ecosystem),
				License:     lic,
				Risk:        riskStr,
				RiskClass:   riskClass,
				Reason:      iss.Reason,
			})
		}
	}

	if result.LicenseOnly || len(result.LicenseIssues) > 0 {
		ls := &htmlLicenseSummary{Total: result.TotalPackages}
		for _, pkg := range result.Packages {
			if pkg.License == "" {
				ls.NoLicense++
				continue
			}
			switch license.Classify(pkg.License) {
			case models.LicensePermissive:
				ls.Permissive++
			case models.LicenseCopyleft:
				ls.Copyleft++
			default:
				ls.Unknown++
			}
		}
		data.LicenseSummary = ls
	}

	data.Errors = result.Errors
	data.ReleaseGate = buildHTMLReleaseGate(data)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"pct": func(count, total int) string {
			if total == 0 {
				return "0"
			}
			return fmt.Sprintf("%.1f", float64(count)*100/float64(total))
		},
		"pctSum": func(a, b, total int) string {
			if total == 0 {
				return "0"
			}
			return fmt.Sprintf("%.1f", float64(a+b)*100/float64(total))
		},
		"pctSum3": func(a, b, c, total int) string {
			if total == 0 {
				return "0"
			}
			return fmt.Sprintf("%.1f", float64(a+b+c)*100/float64(total))
		},
		"lower": func(v interface{}) string {
			return strings.ToLower(fmt.Sprint(v))
		},
		"add": func(a, b int) int {
			return a + b
		},
		"pkgLabel":       htmlPackageLabel,
		"vulnSearchText": htmlVulnSearchText,
		"lineRef":        htmlLineRef,
		"safeScore": func(score string) string {
			if score == "" {
				return "-"
			}
			return score
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("HTML template error: %w", err)
	}
	return tmpl.Execute(w, data)
}

func toHTMLVuln(v models.Vulnerability, projectPath string) htmlVuln {
	relPath := v.FilePath
	if relPath != "" && projectPath != "" {
		if r, err := filepath.Rel(projectPath, v.FilePath); err == nil && r != "" {
			relPath = r
		}
	}
	if relPath == "" && v.Package.FilePath != "" {
		if r, err := filepath.Rel(projectPath, v.Package.FilePath); err == nil && r != "" {
			relPath = r
		}
	}

	hv := htmlVuln{
		ID:            v.ID,
		Summary:       v.Summary,
		Details:       v.Details,
		Severity:      string(v.Severity),
		SeverityClass: severityCSS(v.Severity),
		Score:         fmtScore(v.Score),
		PackageName:   v.Package.Name,
		PackageVer:    v.Package.Version,
		Ecosystem:     string(v.Package.Ecosystem),
		FixedIn:       v.FixedIn,
		FilePath:      relPath,
		StartLine:     v.StartLine,
		DepPath:       v.DepPath,
		Reachable:     v.Reachable,
		Source:        string(v.Source),
		PURL:          v.Package.PURL,
		IsTransitive:  v.Package.Indirect,
	}

	if v.AIEnrichment != nil {
		hv.Enrichment = &htmlEnrichment{
			Summary:              v.AIEnrichment.Summary,
			LikelyImpact:         v.AIEnrichment.LikelyImpact,
			Confidence:           v.AIEnrichment.Confidence,
			ConfidenceClass:      strings.ToLower(v.AIEnrichment.Confidence),
			AICodeIndicator:      v.AIEnrichment.AICodeIndicator,
			MinimalRemediation:   v.AIEnrichment.MinimalRemediation,
			SuppressionRationale: v.AIEnrichment.SuppressionRationale,
		}
	}
	return hv
}

func severityCSS(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "medium"
	case models.SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

func fmtScore(s float64) string {
	if s == 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", s)
}

func htmlEcoIcon(eco string) string {
	switch eco {
	case "Go":
		return "Go"
	case "npm":
		return "npm"
	case "PyPI":
		return "Py"
	case "Maven":
		return "Mv"
	case "crates.io":
		return "Cr"
	case "RubyGems":
		return "Rb"
	case "Packagist":
		return "Pk"
	case "ConanCenter":
		return "Co"
	default:
		return "pkg"
	}
}

func htmlProjectName(path string) string {
	if path == "" {
		return ""
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return path
	}
	return base
}

func htmlPackageLabel(name, version string) string {
	if name == "" {
		return "not reported"
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

func htmlLineRef(path string, line int) string {
	if path == "" {
		return "not reported"
	}
	if line <= 0 {
		return path
	}
	return fmt.Sprintf("%s:%d", path, line)
}

func htmlVulnSearchText(v htmlVuln) string {
	parts := []string{
		v.ID, v.Severity, v.Summary, v.Details, v.PackageName, v.PackageVer,
		v.Ecosystem, v.FixedIn, v.FilePath, v.DepPath, v.Reachable, v.Source, v.PURL,
	}
	if v.Enrichment != nil {
		parts = append(parts,
			v.Enrichment.Summary,
			v.Enrichment.LikelyImpact,
			v.Enrichment.MinimalRemediation,
			v.Enrichment.SuppressionRationale,
		)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func buildHTMLReleaseGate(data htmlData) htmlReleaseGate {
	gate := htmlReleaseGate{
		Class:         "pass",
		Title:         "Release ready",
		Badge:         "READY",
		Decision:      "ready_to_release",
		SidebarStatus: "READY TO RELEASE",
		Message:       "No critical or known-exploited vulnerabilities were detected in this scan.",
		Drivers: []string{
			fmt.Sprintf("%d total findings", data.TotalVulns),
			fmt.Sprintf("%d packages", data.TotalPackages),
		},
		Recommendations: []string{"Continue normal release validation and keep dependency monitoring enabled."},
	}
	if data.CriticalCount > 0 || data.KnownExploitedCount > 0 {
		gate.Class = "block"
		gate.Title = "Release blocked"
		gate.Badge = "BLOCKED"
		gate.Decision = "block_release"
		gate.SidebarStatus = "BLOCK RELEASE"
		gate.Message = "Critical or known-exploited vulnerabilities are present. Do not promote this build until fixed or formally risk-accepted."
		gate.Drivers = []string{
			fmt.Sprintf("%d critical finding(s)", data.CriticalCount),
			fmt.Sprintf("%d known-exploited finding(s)", data.KnownExploitedCount),
		}
		gate.Recommendations = []string{
			"Upgrade affected packages or apply the vendor fix.",
			"Open a time-boxed risk acceptance only with compensating controls and an accountable owner.",
		}
		return gate
	}
	if data.HighCount > 0 || (data.SupplyChainRisk != nil && data.SupplyChainRisk.Score >= 50) {
		gate.Class = "review"
		gate.Title = "Release review required"
		gate.Badge = "REVIEW"
		gate.Decision = "review_before_release"
		gate.SidebarStatus = "REVIEW REQUIRED"
		gate.Message = "High-impact findings or supply-chain signals need owner review before release approval."
		gate.Drivers = []string{
			fmt.Sprintf("%d high finding(s)", data.HighCount),
			fmt.Sprintf("%d supply-chain signal(s)", supplyFindingCount(data.SupplyChainRisk)),
		}
		gate.Recommendations = []string{
			"Review reachable high findings and supply-chain guard evidence.",
			"Document acceptance decisions before promotion.",
		}
	}
	return gate
}

func supplyFindingCount(risk *models.SupplyChainRisk) int {
	if risk == nil {
		return 0
	}
	return risk.FindingCount
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Calvigil {{if .LicenseOnly}}License Compliance{{else}}Security{{end}} Report - {{.ProjectName}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0b1220;--ink-2:#111c31;--surface:#eef1f6;--panel:#fff;--panel-2:#f7f9fc;
  --line:#dde3ec;--line-2:#e9edf3;--text:#182234;--text-2:#3f4c60;--muted:#6b7787;--faint:#93a0b1;
  --brand:#2563eb;--brand-ink:#1d4ed8;--brand-soft:#e9f0fe;
  --crit:#c02a37;--crit-bg:#fcecee;--crit-bd:#f0ccd1;
  --high:#c85a12;--high-bg:#fcf1e6;--high-bd:#f2d8bc;
  --med:#a97a05;--med-bg:#fbf5e2;--med-bd:#ecdcac;
  --low:#1f6feb;--low-bg:#eaf2fe;--low-bd:#cadcfb;
  --ok:#127a52;--ok-bg:#e7f4ee;--ok-bd:#bfe2d1;
  --neutral:#3a4658;--neutral-bg:#eef1f6;--neutral-bd:#dbe2ec;
  --radius:14px;--radius-sm:10px;--nav-w:256px;
  --shadow:0 1px 2px rgba(16,28,48,.05),0 8px 24px -14px rgba(16,28,48,.18);
  --shadow-sm:0 1px 2px rgba(16,28,48,.06);
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--surface);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased;font-feature-settings:"cv02","cv03","cv04","ss01"}
a{color:inherit;text-decoration:none}.mono{font-family:var(--mono);font-variant-ligatures:none}.ic{width:18px;height:18px;flex:0 0 auto}
.shell{display:grid;grid-template-columns:var(--nav-w) 1fr;min-height:100vh}.sidebar{background:var(--ink);color:#c3cede;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;border-right:1px solid #05070d}.brand{display:flex;align-items:center;gap:11px;padding:20px 20px 18px}.brand img{width:34px;height:34px;border-radius:8px;background:#fff;padding:3px;object-fit:contain}.brand strong{display:block;color:#fff;font-size:15px;line-height:1.1;letter-spacing:-.01em}.brand span{display:block;color:#7d8ba1;font-size:11px;letter-spacing:.02em;margin-top:2px}
.gate-mini{margin:2px 16px 14px;border-radius:10px;padding:12px 13px;border:1px solid;background:rgba(255,255,255,.04)}.gate-mini.block{background:rgba(192,42,55,.14);border-color:rgba(192,42,55,.4)}.gate-mini.pass{background:rgba(18,122,82,.14);border-color:rgba(18,122,82,.4)}.gate-mini.review{background:rgba(200,90,18,.14);border-color:rgba(200,90,18,.4)}.gm-title{display:flex;align-items:center;gap:8px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#8a97ab;font-weight:700}.gm-value{margin-top:5px;font-weight:800;font-size:15px;color:#fff;display:flex;align-items:center;gap:7px}.gm-sub{font-size:12px;color:#8a97ab;margin-top:5px}
.navlist{padding:4px 12px;overflow-y:auto;flex:1}.navlist .nl-h{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:#66748b;padding:12px 10px 6px;font-weight:700}.navlink{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:8px;color:#aeb9ca;font-size:13px;font-weight:600;position:relative;transition:background .12s,color .12s}.navlink .ic{width:17px;height:17px;color:#7f8da2;transition:color .12s}.navlink:hover{background:rgba(255,255,255,.05);color:#e7ecf3}.navlink:hover .ic{color:#c3cede}.navlink.active{background:rgba(37,99,235,.16);color:#fff}.navlink.active .ic{color:#7aa7ff}.navlink.active:before{content:"";position:absolute;left:-12px;top:8px;bottom:8px;width:3px;background:var(--brand);border-radius:0 3px 3px 0}.nl-count{margin-left:auto;font-size:11px;font-family:var(--mono);color:#7f8da2;background:rgba(255,255,255,.06);padding:1px 7px;border-radius:20px}.sidefoot{padding:12px 20px 16px;border-top:1px solid #141d2e;font-size:11px;color:#67748a;line-height:1.5}
.main{min-width:0}.topbar{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.86);backdrop-filter:saturate(160%) blur(10px);border-bottom:1px solid var(--line);padding:14px 34px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}.crumb{font-family:var(--mono);font-size:12.5px;color:var(--text-2);display:flex;align-items:center;gap:8px;min-width:0}.crumb span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-2);font-weight:500}.scanmeta{margin-left:auto;display:flex;gap:18px;flex-wrap:wrap}.scanmeta span{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}.scanmeta b{color:var(--text);font-weight:700}.content{max-width:1120px;margin:0 auto;padding:28px 34px 60px}
.sec{scroll-margin-top:76px;margin-bottom:34px}.sec-head{display:flex;align-items:center;gap:12px;margin-bottom:16px}.sec-icon{width:38px;height:38px;border-radius:10px;display:grid;place-items:center;background:var(--panel);border:1px solid var(--line);color:var(--brand-ink);box-shadow:var(--shadow-sm)}.sec-icon .ic{width:20px;height:20px}.sec-title{font-size:17px;font-weight:800;letter-spacing:-.01em}.sec-sub{font-size:12.5px;color:var(--muted);margin-top:1px}.sec-count{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--muted);background:var(--panel);border:1px solid var(--line);padding:4px 11px;border-radius:20px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
.gate{border-radius:16px;padding:22px 24px;display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:22px;align-items:start;border:1px solid;box-shadow:var(--shadow);margin-bottom:26px;position:relative;overflow:hidden}.gate.block{background:linear-gradient(120deg,#fff 0%,#fdf1f2 100%);border-color:var(--crit-bd)}.gate.pass{background:linear-gradient(120deg,#fff 0%,#eef7f1 100%);border-color:var(--ok-bd)}.gate.review{background:linear-gradient(120deg,#fff 0%,#fff7ed 100%);border-color:var(--high-bd)}.gate-main{display:flex;gap:22px}.gate-ico{width:74px;height:74px;border-radius:16px;display:grid;place-items:center;color:#fff;flex:0 0 auto}.gate.block .gate-ico{background:linear-gradient(150deg,#d23948,#a3202d);border:0}.gate.pass .gate-ico{background:linear-gradient(150deg,#1a9e6b,#0e6b47);border:0}.gate.review .gate-ico{background:linear-gradient(150deg,#db6b1f,#a8480d);border:0}.gate-ico .ic{width:38px;height:38px}.gate h1{font-size:26px;line-height:1.2;letter-spacing:-.02em;margin:3px 0 2px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}.gate.block h1{color:#9e1f2b}.gate.pass h1{color:#0e6b47}.gate.review h1{color:#9a3412}.gate p{margin:7px 0 0;color:var(--text-2);font-weight:600}.gate-kicker{font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:800;color:var(--muted)}.pill{font-family:var(--mono);font-size:12px;font-weight:700;padding:3px 9px;border-radius:6px;letter-spacing:.02em;border:1px solid var(--line);background:#fff}.pill.block{background:var(--crit-bg);color:var(--crit);border-color:var(--crit-bd)}.pill.pass{background:var(--ok-bg);color:var(--ok);border-color:var(--ok-bd)}.pill.review{background:var(--high-bg);color:var(--high);border-color:var(--high-bd)}.gate-side{display:grid;gap:8px}.driver{display:flex;align-items:center;gap:7px;font-size:12.5px;font-weight:700;color:var(--text-2);background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:7px 11px}.rec-list{margin-top:12px;padding-top:13px;border-top:1px dashed var(--line);display:grid;gap:6px}.rec-list li{display:flex;gap:9px;font-size:13px;color:var(--text-2);font-weight:600;list-style:none}.rec-list li:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--crit);margin-top:7px;flex:0 0 auto}.gate.pass .rec-list li:before{background:var(--ok)}.gate.review .rec-list li:before{background:var(--high)}
.overview{display:grid;grid-template-columns:1.15fr 1fr;gap:18px;margin-bottom:26px}.tiles{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-sm);padding:15px 16px;box-shadow:var(--shadow-sm);position:relative;overflow:hidden}.tile:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px}.tile.total:before{background:var(--neutral)}.tile.critical:before{background:var(--crit)}.tile.high:before{background:var(--high)}.tile.medium:before{background:var(--med)}.tile.low:before{background:var(--low)}.tile .tv{font-family:var(--mono);font-size:30px;font-weight:800;letter-spacing:-.03em;line-height:1;margin-top:0}.tile .tl{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:700;margin-top:8px}.tile .tsub{font-size:11px;color:var(--faint);margin-top:2px}.tile.total .tv{color:var(--neutral)}.tile.critical .tv{color:var(--crit)}.tile.high .tv{color:var(--high)}.tile.medium .tv{color:var(--med)}.tile.low .tv{color:var(--low)}
.dist{padding:17px 18px;display:flex;flex-direction:column}.dist h3{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:800;margin-bottom:14px;display:flex;align-items:center;gap:8px}.track{height:30px;border-radius:8px;overflow:hidden;display:flex;background:var(--line-2)}.seg.critical{background:var(--crit)}.seg.high{background:var(--high)}.seg.medium{background:var(--med)}.seg.low{background:var(--low)}.seg.unknown{background:var(--neutral)}.legend{display:grid;grid-template-columns:1fr 1fr;gap:9px 16px;margin-top:15px}.dot{width:9px;height:9px;border-radius:3px;display:inline-block}.legend span{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--text-2);font-weight:600}
.scorewrap{padding:20px 22px 22px}.scorehead{display:grid;grid-template-columns:180px minmax(0,1fr);gap:20px;align-items:stretch}.scorecard{border-radius:12px;padding:18px 20px;min-width:0;min-height:156px;border:1px solid;display:flex;flex-direction:column;justify-content:center;background:var(--low-bg);border-color:var(--low-bd)}.scorecard.critical{background:var(--crit-bg);border-color:var(--crit-bd)}.scorecard.high{background:var(--high-bg);border-color:var(--high-bd)}.scorecard.medium,.scorecard.moderate{background:var(--med-bg);border-color:var(--med-bd)}.scorecard.low{background:var(--low-bg);border-color:var(--low-bd)}.scorecard.unknown{background:var(--neutral-bg);border-color:var(--neutral-bd)}.scorecard .label,.decision-box .label{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;font-weight:800;color:var(--muted)}.scorecard .score{font-family:var(--mono);font-size:42px;font-weight:800;letter-spacing:-.04em;line-height:1;margin:9px 0 8px;color:var(--brand)}.scorecard .score small{font-size:20px;color:#64748b;letter-spacing:-.04em}.scorecard.critical .score{color:var(--crit)}.scorecard.high .score{color:var(--high)}.scorecard.medium .score,.scorecard.moderate .score{color:var(--med)}.scorecard.low .score{color:var(--low)}.scorecard.unknown .score{color:var(--neutral)}.decision-box{background:var(--panel-2);border:1px solid var(--line);border-radius:12px;padding:17px 18px;display:flex;flex-direction:column;justify-content:flex-start;min-height:156px}.decision-box .decision{font-family:var(--mono);font-size:17px;font-weight:800;margin-top:5px;color:var(--crit);letter-spacing:-.02em}.decision-box .guidance-list{margin:10px 0 0;padding-left:18px;color:var(--text-2);font-size:13px}.metricrow{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0 4px}.decision-box>.metricrow{margin:18px 0 0}.metric{background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.decision-box .metric{background:#fff}.metric span{font-size:11px;color:var(--muted);font-weight:700;letter-spacing:.07em;text-transform:uppercase}.metric b{font-family:var(--mono);font-size:22px;font-weight:800;color:var(--text);letter-spacing:-.02em;margin-top:3px;display:block}.guidance{margin-top:16px;background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.guidance b{display:block;margin-bottom:7px}.guidance ul{display:grid;gap:7px;margin:0;padding-left:18px;color:var(--text-2)}
.slop-review-grid{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);gap:16px;margin-top:18px}.slop-board{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow-sm);overflow:hidden;min-width:0}.slop-board-head{display:flex;align-items:center;gap:10px;background:var(--panel-2);border-bottom:1px solid var(--line);padding:12px 16px;font-size:11px;letter-spacing:.09em;text-transform:uppercase;font-weight:800;color:var(--text-2)}.slop-board-head .ic{width:16px;height:16px;color:#91a0b5}.slop-review-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:16px;align-items:center;padding:15px 16px;border-bottom:1px solid var(--line-2)}.slop-review-row:last-child{border-bottom:0}.slop-review-row:hover{background:var(--panel-2)}.slop-row-title{font-size:14px;font-weight:800;color:var(--text);letter-spacing:-.01em}.slop-row-title .mono{font-size:13px}.slop-row-desc{font-size:13px;color:var(--muted);line-height:1.45;margin-top:4px;overflow-wrap:anywhere}.slop-row-score{font-family:var(--mono);font-size:18px;font-weight:800;color:var(--brand-ink);background:var(--brand-soft);border-radius:9px;padding:6px 12px;min-width:48px;text-align:center}.slop-signal-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.slop-signal-title .vid{font-size:13px}.slop-signal-title .sf-title{font-size:13.5px}
.sf-section-title{display:flex;align-items:center;gap:8px;margin:21px 0 12px;font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);font-weight:800}.sf-section-title .ic{width:16px;height:16px;color:#91a0b5}.sf-list{display:grid;gap:11px}.sf{border:1px solid var(--line);border-radius:12px;padding:16px 18px;background:var(--panel);box-shadow:var(--shadow-sm)}.sf-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}.sf-title{font-weight:800;font-size:14px;letter-spacing:-.01em}.sf p{font-size:13.5px;color:var(--text-2);margin-bottom:10px;line-height:1.45}.sf-chips{display:flex;gap:8px;flex-wrap:wrap;margin:9px 0 12px}.sf-chips .tag{font-family:var(--mono);font-size:11.5px;padding:5px 9px;max-width:100%;overflow-wrap:anywhere}.sf-chips .tag .ic{width:14px;height:14px;color:#91a0b5}.sf-chips .tag b{font-family:var(--sans);font-size:11px;text-transform:lowercase;color:var(--muted);letter-spacing:.02em;margin-right:1px}.sf-lines{display:grid;gap:5px}.sf-line{display:grid;grid-template-columns:84px minmax(0,1fr);gap:12px;font-size:13px;color:var(--text-2);line-height:1.45}.sf-line b{color:var(--muted);font-weight:800}.sf-line span{overflow-wrap:anywhere}.sf-grid{display:flex;gap:8px;flex-wrap:wrap}.sf-grid span{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--line);border-radius:7px;background:var(--panel-2);padding:5px 8px;font-size:11.5px;color:var(--text-2);overflow-wrap:anywhere}.sf-grid b{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.06em;margin-right:2px}
.toolbar{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow-sm);padding:12px 14px;margin-bottom:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;position:sticky;top:60px;z-index:10}.searchbox{display:flex;align-items:center;gap:8px;flex:1;min-width:220px;background:var(--panel-2);border:1px solid var(--line);border-radius:9px;padding:8px 12px}.searchbox .ic{color:var(--faint)}.searchbox input{border:0;background:transparent;outline:none;font:inherit;font-size:13px;width:100%;color:var(--text)}.filters{display:flex;gap:6px;flex-wrap:wrap}.chip{font-size:12px;font-weight:700;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--text-2);cursor:pointer;display:flex;align-items:center;gap:6px}.chip:hover{border-color:#c4cedb}.chip[aria-pressed=true]{background:var(--ink);color:#fff;border-color:var(--ink)}.tool-actions{display:flex;gap:8px;align-items:center;margin-left:auto}.txtbtn{font-size:12px;font-weight:700;color:var(--brand-ink);cursor:pointer;background:none;border:0;padding:6px 8px;border-radius:7px}.txtbtn:hover{background:var(--brand-soft)}.result-note{font-size:12px;color:var(--muted);font-family:var(--mono)}
.eco-group{margin:24px 0 12px;display:flex;align-items:center;gap:10px;padding:0;font-weight:800;color:var(--text)}.eco-badge{width:32px;height:32px;border-radius:10px;border:1px solid #bfdbfe;background:#eff6ff;color:var(--brand);display:grid;place-items:center;font-family:var(--mono);font-size:11px}.eco-group .sec-count{margin-left:0}.eco-group .rule{flex:1;height:1px;background:var(--line)}
.vcard{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;box-shadow:var(--shadow-sm);overflow:hidden;transition:border-color .12s}.vcard.sev-critical{border-left:4px solid var(--crit)}.vcard.sev-high{border-left:4px solid var(--high)}.vcard.sev-medium{border-left:4px solid var(--med)}.vcard.sev-low{border-left:4px solid var(--low)}.vcard.sev-unknown{border-left:4px solid var(--neutral)}.vhead{display:flex;align-items:center;gap:12px;padding:14px 17px;cursor:pointer;user-select:none}.vhead:hover{background:var(--panel-2)}.vid{font-family:var(--mono);font-size:13px;font-weight:800;color:var(--text);flex:0 0 auto;overflow-wrap:anywhere}.vsum{font-size:14px;color:var(--text-2);font-weight:650;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.vcvss{font-family:var(--mono);font-size:12px;color:var(--muted);background:var(--panel-2);border:1px solid var(--line);border-radius:7px;padding:3px 9px;flex:0 0 auto}.reach-chip{font-family:var(--mono);font-size:11.5px;padding:4px 9px;flex:0 0 auto}.reach-chip .ic{width:14px;height:14px;color:#91a0b5}.vbody{display:none;padding:2px 15px 15px;border-top:1px solid var(--line-2)}.vcard.open .vbody{display:block}.chev{color:var(--faint);transition:transform .2s}.vcard.open .chev{transform:rotate(180deg)}
.badge{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:800;letter-spacing:.03em;padding:3px 9px;border-radius:6px;text-transform:uppercase;line-height:1;border:1px solid}.badge.critical{color:var(--crit);background:var(--crit-bg);border-color:var(--crit-bd)}.badge.high{color:var(--high);background:var(--high-bg);border-color:var(--high-bd)}.badge.medium,.badge.moderate{color:var(--med);background:var(--med-bg);border-color:var(--med-bd)}.badge.low{color:var(--low);background:var(--low-bg);border-color:var(--low-bd)}.badge.unknown,.badge.clean{color:var(--neutral);background:var(--neutral-bg);border-color:var(--neutral-bd)}.badge .dot{width:7px;height:7px;border-radius:2px}.badge.critical .dot{background:var(--crit)}.badge.high .dot{background:var(--high)}.badge.medium .dot,.badge.moderate .dot{background:var(--med)}.badge.low .dot{background:var(--low)}.tag{display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;padding:3px 8px;border-radius:6px;background:var(--panel-2);border:1px solid var(--line);color:var(--text-2)}
.fields{display:grid;grid-template-columns:1fr 1fr;gap:9px 16px;margin:13px 0}.field{display:flex;flex-direction:column;gap:2px;min-width:0;border:0;border-radius:0;background:transparent;padding:0}.field.wide{grid-column:1/-1}.fl{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:700;display:flex;align-items:center;gap:6px}.fl .ic{width:13px;height:13px;color:var(--faint)}.fv{font-size:13px;color:var(--text);word-break:break-word;font-weight:600}.fv.mono{font-family:var(--mono);font-size:12px;color:var(--text-2)}.enr{background:var(--panel-2);border:1px solid var(--line);border-radius:10px;padding:13px 15px;margin-top:4px}.eh{display:flex;align-items:center;gap:8px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;font-weight:800;color:var(--text-2);margin-bottom:10px}.eh .ic{width:16px;height:16px;color:#7c3aed}.conf{font-size:10.5px;font-weight:800;letter-spacing:.04em;text-transform:uppercase;padding:2px 7px;border-radius:5px;border:1px solid}.conf.high{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}.conf.medium{color:var(--med);background:var(--med-bg);border-color:var(--med-bd)}.conf.low{color:var(--muted);background:var(--panel-2);border-color:var(--line)}.enr-field{margin-bottom:9px}.enr-field:last-child{margin-bottom:0}.el{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:700;margin-bottom:2px}.ev{font-size:13px;color:var(--text-2);white-space:pre-line;overflow-wrap:anywhere}.suppression{margin-top:10px;padding:10px 12px;border-radius:8px;background:#fbfbe9;border:1px solid #ece6b8}
.license-grid{display:grid;grid-template-columns:170px minmax(0,1fr);gap:18px;padding:18px}.donut{position:relative;width:150px;height:150px}.donut svg{width:100%;height:100%;transform:rotate(-90deg)}.donut-center{position:absolute;inset:0;display:grid;place-items:center;text-align:center}.lic-table{width:100%;border-collapse:collapse;font-size:13px}.lic-table th{background:var(--panel-2);color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-size:11px;text-align:left;padding:10px;border-bottom:1px solid var(--line)}.lic-table td{padding:10px;border-bottom:1px solid var(--line-2)}
.warn-panel{padding:16px 18px;border-left:3px solid var(--med)}.warn-item{display:flex;gap:11px;align-items:flex-start;font-size:13px;color:var(--text-2);padding:9px 0;font-weight:650}.warn-item .ic{width:17px;height:17px;color:var(--high);margin-top:2px}.footer{text-align:center;font-size:12px;color:var(--muted);padding:26px 0 8px;border-top:1px solid var(--line);margin-top:8px}.footer b{color:var(--text-2)}
@media(max-width:960px){:root{--nav-w:0px}.shell{grid-template-columns:1fr}.sidebar{display:none}.gate,.overview,.scorehead,.license-grid,.slop-review-grid{grid-template-columns:1fr}.metricrow{grid-template-columns:repeat(2,1fr)}.content{padding:22px 18px 50px}.topbar{padding:12px 18px}.vhead{align-items:flex-start}.vsum{white-space:normal}}
@media(max-width:560px){.tiles{grid-template-columns:1fr 1fr}.fields{grid-template-columns:1fr}.legend{grid-template-columns:1fr}.toolbar{position:static}}
@media print{.sidebar,.toolbar{display:none!important}.shell{grid-template-columns:1fr}body{background:#fff}.vbody{display:block!important}.vcard .chev{display:none}.panel,.vcard,.gate,.tile,.dist{box-shadow:none}.sec{break-inside:avoid}}
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <img src="{{.LogoDataURL}}" alt="Calvigil">
      <div><strong>Calvigil</strong><span>Security Report</span></div>
    </div>
    <div class="gate-mini {{.ReleaseGate.Class}}">
      <div class="gm-title">{{template "icon-shield" .}} Release gate</div>
      <div class="gm-value">{{if eq .ReleaseGate.Class "pass"}}{{template "icon-check" .}}{{else}}{{template "icon-alert" .}}{{end}}{{.ReleaseGate.SidebarStatus}}</div>
      <div class="gm-sub">{{.TotalVulns}} findings &middot; {{.TotalPackages}} packages</div>
    </div>
    <nav class="navlist">
      <div class="nl-h">Report</div>
      <a class="navlink active" href="#overview" data-target="overview">{{template "icon-shield" .}} <span>Overview</span></a>
      {{if .SupplyChainRisk}}<a class="navlink" href="#supply" data-target="supply">{{template "icon-network" .}} <span>Supply chain</span><span class="nl-count">{{.SupplyChainRisk.Score}}</span></a>{{end}}
      {{if .SlopCodeSmells}}<a class="navlink" href="#slop" data-target="slop">{{template "icon-spark" .}} <span>AI code smells</span><span class="nl-count">{{.SlopCodeSmells.Score}}</span></a>{{end}}
      {{if .DepGroups}}<a class="navlink" href="#deps" data-target="deps">{{template "icon-package" .}} <span>Dependencies</span><span class="nl-count">{{.TotalDepVulns}}</span></a>{{end}}
      {{if or .CodeVulns .SemgrepVulns}}<a class="navlink" href="#code" data-target="code">{{template "icon-code" .}} <span>Code analysis</span><span class="nl-count">{{add (len .CodeVulns) (len .SemgrepVulns)}}</span></a>{{end}}
      {{if or .LicenseIssues .LicenseSummary}}<a class="navlink" href="#licenses" data-target="licenses">{{template "icon-file" .}} <span>Licenses</span><span class="nl-count">{{len .LicenseIssues}}</span></a>{{end}}
      {{if .Errors}}<a class="navlink" href="#warnings" data-target="warnings">{{template "icon-alert" .}} <span>Warnings</span><span class="nl-count">{{len .Errors}}</span></a>{{end}}
    </nav>
    <div class="sidefoot">Generated by Calvigil<br>{{.GeneratedAt}}</div>
  </aside>

  <main class="main">
    <header class="topbar">
      <div class="crumb">{{template "icon-folder" .}}<span>{{.ProjectPath}}</span></div>
      <div class="scanmeta">
        <span>{{template "icon-clock" .}}Scanned <b>{{.GeneratedAt}}</b></span>
        <span>{{template "icon-target" .}}Duration <b>{{.Duration}}</b></span>
        <span>{{template "icon-layers" .}}<b>{{.TotalPackages}} packages</b> &middot; {{len .Ecosystems}} ecosystems</span>
      </div>
    </header>

    <div class="content">
      <section id="overview" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-shield" .}}</div>
          <div>
            <div class="sec-title">Calvigil {{if .LicenseOnly}}License Compliance{{else}}Security{{end}} Report</div>
            <div class="sec-sub">{{.ProjectPath}}</div>
          </div>
          <span class="sec-count">{{.TotalPackages}} packages</span>
        </div>

        {{if not .LicenseOnly}}
        <div class="gate {{.ReleaseGate.Class}}">
          <div class="gate-main">
            <div class="gate-ico">{{if eq .ReleaseGate.Class "pass"}}{{template "icon-check" .}}{{else}}{{template "icon-bolt" .}}{{end}}</div>
            <div>
              <div class="gate-kicker">Release gate</div>
              <h1>{{.ReleaseGate.Title}} <span class="pill {{.ReleaseGate.Class}}">{{.ReleaseGate.Decision}}</span></h1>
              <p>{{.ReleaseGate.Message}}</p>
              {{if .ReleaseGate.Recommendations}}
              <ul class="rec-list">
                {{range .ReleaseGate.Recommendations}}<li>{{.}}</li>{{end}}
              </ul>
              {{end}}
            </div>
          </div>
          <div class="gate-side">
            {{range .ReleaseGate.Drivers}}<div class="driver">{{.}}</div>{{end}}
          </div>
        </div>

        <div class="overview">
          <div class="tiles">
            <div class="tile total"><div class="tl">Total findings</div><div class="tv">{{.TotalVulns}}</div><div class="tsub">across all scanners</div></div>
            <div class="tile critical"><div class="tl">Critical</div><div class="tv">{{.CriticalCount}}</div></div>
            <div class="tile high"><div class="tl">High</div><div class="tv">{{.HighCount}}</div></div>
            <div class="tile medium"><div class="tl">Medium</div><div class="tv">{{.MediumCount}}</div></div>
            <div class="tile low"><div class="tl">Low</div><div class="tv">{{.LowCount}}</div></div>
            <div class="tile"><div class="tl">Known exploited</div><div class="tv">{{.KnownExploitedCount}}</div></div>
          </div>
          <div class="panel dist">
            <h3>Severity distribution</h3>
            <div class="track">
              {{if gt .CriticalCount 0}}<div class="seg critical" style="width:{{pct .CriticalCount .TotalVulns}}%"></div>{{end}}
              {{if gt .HighCount 0}}<div class="seg high" style="width:{{pct .HighCount .TotalVulns}}%"></div>{{end}}
              {{if gt .MediumCount 0}}<div class="seg medium" style="width:{{pct .MediumCount .TotalVulns}}%"></div>{{end}}
              {{if gt .LowCount 0}}<div class="seg low" style="width:{{pct .LowCount .TotalVulns}}%"></div>{{end}}
              {{if gt .UnknownCount 0}}<div class="seg unknown" style="width:{{pct .UnknownCount .TotalVulns}}%"></div>{{end}}
            </div>
            <div class="legend">
              <span><i class="dot" style="background:var(--crit)"></i>Critical ({{.CriticalCount}})</span>
              <span><i class="dot" style="background:var(--high)"></i>High ({{.HighCount}})</span>
              <span><i class="dot" style="background:#f59e0b"></i>Medium ({{.MediumCount}})</span>
              <span><i class="dot" style="background:#2563eb"></i>Low ({{.LowCount}})</span>
              {{if gt .UnknownCount 0}}<span><i class="dot" style="background:var(--neutral)"></i>Unknown ({{.UnknownCount}})</span>{{end}}
            </div>
          </div>
        </div>
        {{end}}
      </section>

      {{with .SupplyChainRisk}}
      <section id="supply" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-network" .}}</div>
          <div><div class="sec-title">Supply chain guard</div><div class="sec-sub">Install-time behavior, lockfile integrity and dependency provenance</div></div>
          <span class="sec-count">{{.Score}} /100 risk</span>
        </div>
        <div class="panel scorewrap">
          <div class="scorehead">
            <div class="scorecard {{lower .Level}}"><div class="label">Risk score</div><div class="score">{{.Score}}<small>/100</small></div><span class="badge {{lower .Level}}">{{.Level}}</span></div>
            <div class="decision-box">
              <div class="label">Recommended decision</div>
              <div class="decision">{{.Decision}}</div>
              <div class="metricrow">
                <div class="metric"><span>Findings</span><b>{{.FindingCount}}</b></div>
                <div class="metric"><span>New deps</span><b>{{.NewDependencies}}</b></div>
                <div class="metric"><span>Install scripts</span><b>{{.InstallScripts}}</b></div>
                <div class="metric"><span>Phantom deps</span><b>{{.PhantomDependencies}}</b></div>
              </div>
            </div>
          </div>
          {{if $.SupplyChainFindings}}
          <div class="sf-section-title">{{template "icon-list" .}}<span>Signals to review</span><span>({{.FindingCount}})</span></div>
          <div class="sf-list">
            {{range $.SupplyChainFindings}}
            <div class="sf">
              <div class="sf-head"><span class="badge {{lower .Severity}}"><span class="dot"></span>{{.Severity}}</span><span class="vid">{{.ID}}</span><span class="sf-title">{{.Title}}</span></div>
              <p>{{.Description}}</p>
              <div class="sf-chips">
                {{if .Package.Name}}<span class="tag">{{template "icon-package" .}}<b>pkg</b> {{.Package.Name}}{{if .Package.Version}}@{{.Package.Version}}{{end}}</span>{{end}}
                {{if .Package.Ecosystem}}<span class="tag">{{template "icon-layers" .}}<b>eco</b> {{.Package.Ecosystem}}</span>{{end}}
                {{if .FilePath}}<span class="tag">{{template "icon-file" .}}<b>file</b> {{.FilePath}}{{if .StartLine}}:{{.StartLine}}{{end}}</span>{{end}}
                {{if .BaselineVersion}}<span class="tag"><b>base</b> {{.BaselineVersion}}</span>{{end}}
                {{if .TargetVersion}}<span class="tag"><b>target</b> {{.TargetVersion}}</span>{{end}}
                {{if .TargetSource}}<span class="tag"><b>source</b> {{.TargetSource}}</span>{{end}}
              </div>
              <div class="sf-lines">
                {{if .Evidence}}<div class="sf-line"><b>Evidence</b><span>{{.Evidence}}</span></div>{{end}}
                {{if .Recommendation}}<div class="sf-line"><b>Action</b><span>{{.Recommendation}}</span></div>{{end}}
              </div>
            </div>
            {{end}}
          </div>
          {{if gt $.SupplyChainMore 0}}<p style="color:#64748b;margin:12px 0 0">{{$.SupplyChainMore}} more supply-chain signal(s) omitted from HTML/PDF output. Use JSON output for full detail.</p>{{end}}
          {{end}}
        </div>
      </section>
      {{end}}

      {{with .SlopCodeSmells}}
      <section id="slop" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-spark" .}}</div>
          <div><div class="sec-title">AI Slop Code Smells</div><div class="sec-sub">Concrete quality and security symptoms, not authorship attribution.</div></div>
          <span class="sec-count">{{.SignalCount}} signals</span>
        </div>
        <div class="panel scorewrap">
          <div class="scorehead">
            <div class="scorecard {{lower .Level}}"><div class="label">Smell score</div><div class="score">{{.Score}}<small>/100</small></div><span class="badge {{lower .Level}}">{{.Level}}</span></div>
            <div class="decision-box">
              <div class="label">What this means</div>
              <p style="margin:4px 0 8px;color:#475569;font-weight:650">Calvigil found concrete review signals often seen in low-trust generated, copied, or hurried code.</p>
              <p style="margin:0;color:#64748b">{{.AuthorshipDisclaimer}}</p>
              <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px"><span class="pill">{{.SignalCount}} signal(s)</span><span class="pill">{{.Confidence}} confidence</span>{{if .GeneratedCodeSignal}}<span class="pill">{{.GeneratedCodeSignal}}</span>{{end}}</div>
            </div>
          </div>
          {{if or .Categories .TopSignals}}
          <div class="slop-review-grid">
            {{if .Categories}}
            <div class="slop-board">
              <div class="slop-board-head">{{template "icon-layers" .}}<span>Top categories</span></div>
              {{range .Categories}}
              <div class="slop-review-row">
                <div>
                  <div class="slop-row-title">{{.Name}} ({{.Count}})</div>
                  <div class="slop-row-desc">{{.Description}}</div>
                </div>
                <div class="slop-row-score">{{if gt .Weight 0}}{{.Weight}}{{else}}{{.Count}}{{end}}</div>
              </div>
              {{end}}
            </div>
            {{end}}
            {{if .TopSignals}}
            <div class="slop-board">
              <div class="slop-board-head">{{template "icon-list" .}}<span>Top signals to review</span></div>
              {{range .TopSignals}}
              <div class="slop-review-row">
                <div>
                  <div class="slop-signal-title"><span class="vid">{{.FindingID}}</span><span class="sf-title">{{.Title}}</span></div>
                  <div class="slop-row-desc">{{if .FilePath}}{{.FilePath}}{{if gt .StartLine 0}}:{{.StartLine}}{{end}}{{else}}{{.Reason}}{{end}}</div>
                </div>
                <div class="slop-row-score">{{.Weight}}</div>
              </div>
              {{end}}
            </div>
            {{end}}
          </div>
          {{end}}
          {{if .Guidance}}<div class="guidance"><b>Review guidance</b><ul>{{range .Guidance}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
        </div>
      </section>
      {{end}}

      {{if .DepGroups}}
      <section id="deps" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-package" .}}</div>
          <div><div class="sec-title">Dependency vulnerabilities</div><div class="sec-sub">Known CVEs in direct and transitive packages, enriched with AI reachability analysis.</div></div>
          <span class="sec-count">{{.TotalDepVulns}} findings</span>
        </div>
        <div class="panel">
          {{template "finding-toolbar" .}}
          <div id="veco">
            {{range .DepGroups}}
            <div class="eco-group" data-eco="{{lower .Ecosystem}}"><span class="eco-badge">{{.Icon}}</span><span>{{.Ecosystem}}</span><span class="sec-count">{{len .Vulns}}</span><span class="rule"></span></div>
            <div class="eco-cards">
              {{range .Vulns}}{{template "vuln-card" .}}{{end}}
            </div>
            {{end}}
          </div>
          <div id="vempty" style="display:none;padding:22px;color:#64748b;font-weight:700">No findings match the current filters.</div>
        </div>
      </section>
      {{end}}

      {{if or .CodeVulns .SemgrepVulns}}
      <section id="code" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-code" .}}</div>
          <div><div class="sec-title">Code analysis findings</div><div class="sec-sub">Pattern-match and Semgrep SAST findings with file-level evidence.</div></div>
          <span class="sec-count">{{add (len .CodeVulns) (len .SemgrepVulns)}} findings</span>
        </div>
        <div class="panel">
          {{range .CodeVulns}}{{template "code-card" .}}{{end}}
          {{range .SemgrepVulns}}{{template "code-card" .}}{{end}}
        </div>
      </section>
      {{end}}

      {{if or .LicenseIssues .LicenseSummary}}
      <section id="licenses" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-file" .}}</div>
          <div><div class="sec-title">License Compliance</div><div class="sec-sub">SPDX posture and dependency license findings captured during this scan.</div></div>
          <span class="sec-count">{{len .LicenseIssues}} review rows</span>
        </div>
        <div class="panel">
          {{if .LicenseSummary}}
          <div class="license-grid">
            <div class="donut">
              <svg viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#e8edf5" stroke-width="3"/>
                {{if gt .LicenseSummary.Total 0}}
                <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#22c55e" stroke-width="3" stroke-dasharray="{{pct .LicenseSummary.Permissive .LicenseSummary.Total}} 100" stroke-dashoffset="0"/>
                <circle cx="18" cy="18" r="15.9155" fill="none" stroke="var(--high)" stroke-width="3" stroke-dasharray="{{pct .LicenseSummary.Copyleft .LicenseSummary.Total}} 100" stroke-dashoffset="-{{pct .LicenseSummary.Permissive .LicenseSummary.Total}}"/>
                <circle cx="18" cy="18" r="15.9155" fill="none" stroke="var(--med)" stroke-width="3" stroke-dasharray="{{pct .LicenseSummary.Unknown .LicenseSummary.Total}} 100" stroke-dashoffset="-{{pctSum .LicenseSummary.Permissive .LicenseSummary.Copyleft .LicenseSummary.Total}}"/>
                <circle cx="18" cy="18" r="15.9155" fill="none" stroke="var(--neutral)" stroke-width="3" stroke-dasharray="{{pct .LicenseSummary.NoLicense .LicenseSummary.Total}} 100" stroke-dashoffset="-{{pctSum3 .LicenseSummary.Permissive .LicenseSummary.Copyleft .LicenseSummary.Unknown .LicenseSummary.Total}}"/>
                {{end}}
              </svg>
              <div class="donut-center"><div><div style="font-size:28px;font-weight:800">{{.LicenseSummary.Total}}</div><div style="font-size:11px;color:#64748b;font-weight:800;text-transform:uppercase">Packages</div></div></div>
            </div>
            <div class="tiles">
              <div class="tile low"><div class="tl">Permissive</div><div class="tv">{{.LicenseSummary.Permissive}}</div></div>
              <div class="tile high"><div class="tl">Copyleft</div><div class="tv">{{.LicenseSummary.Copyleft}}</div></div>
              <div class="tile medium"><div class="tl">Unknown</div><div class="tv">{{.LicenseSummary.Unknown}}</div></div>
              <div class="tile"><div class="tl">No license</div><div class="tv">{{.LicenseSummary.NoLicense}}</div></div>
            </div>
          </div>
          {{end}}
          {{if .LicenseIssues}}
          <table class="lic-table">
            <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>License</th><th>Risk</th><th>Reason</th></tr></thead>
            <tbody>
            {{range .LicenseIssues}}
              <tr><td><b>{{.PackageName}}</b></td><td>{{.PackageVer}}</td><td>{{.Ecosystem}}</td><td class="mono">{{.License}}</td><td><span class="badge {{.RiskClass}}">{{.Risk}}</span></td><td>{{.Reason}}</td></tr>
            {{end}}
            </tbody>
          </table>
          {{end}}
        </div>
      </section>
      {{end}}

      {{if .Errors}}
      <section id="warnings" class="sec">
        <div class="sec-head">
          <div class="sec-icon">{{template "icon-alert" .}}</div>
          <div><div class="sec-title">Scanner warnings</div><div class="sec-sub">Non-fatal issues encountered during the scan.</div></div>
          <span class="sec-count">{{len .Errors}}</span>
        </div>
        <div class="panel warn-panel">{{range .Errors}}<div class="warn-item">{{template "icon-alert" .}}<span>{{.}}</span></div>{{end}}</div>
      </section>
      {{end}}

      <div class="footer">Generated by <b>Calvigil</b> - {{.GeneratedAt}}</div>
    </div>
  </main>
</div>

{{define "finding-toolbar"}}
<div class="toolbar">
  <div class="searchbox">{{template "icon-search" .}}<input id="vsearch" type="search" placeholder="Search CVE, package, summary..." autocomplete="off"></div>
  <div class="filters" id="vfilters">
    <button class="chip" data-sev="all" aria-pressed="true">All</button>
    <button class="chip" data-sev="critical" aria-pressed="false"><span class="dot" style="background:var(--crit)"></span>Critical</button>
    <button class="chip" data-sev="high" aria-pressed="false"><span class="dot" style="background:var(--high)"></span>High</button>
    <button class="chip" data-sev="medium" aria-pressed="false"><span class="dot" style="background:#f59e0b"></span>Medium</button>
    <button class="chip" data-sev="low" aria-pressed="false"><span class="dot" style="background:var(--low)"></span>Low</button>
  </div>
  <div class="tool-actions"><span class="result-note" id="vcount"></span><button class="txtbtn" id="vexpand">Expand all</button><button class="txtbtn" id="vcollapse">Collapse all</button></div>
</div>
{{end}}

{{define "vuln-card"}}
<div class="vcard sev-{{.SeverityClass}}" data-sev="{{.SeverityClass}}" data-text="{{vulnSearchText .}}">
  <div class="vhead" onclick="this.parentNode.classList.toggle('open')">
    <span class="badge {{.SeverityClass}}"><span class="dot"></span>{{.Severity}}</span>
    <span class="vid">{{.ID}}</span>
    {{if .IsTransitive}}<span class="tag reach-chip">{{template "icon-network" .}}transitive</span>{{end}}
    <span class="vsum">{{.Summary}}</span>
    <span class="vcvss">CVSS {{safeScore .Score}}</span>
    {{template "icon-chevron" .}}
  </div>
  <div class="vbody">
    <div class="fields">
      <div class="field"><div class="fl">{{template "icon-package" .}}Package</div><div class="fv mono">{{pkgLabel .PackageName .PackageVer}}</div></div>
      {{if .FixedIn}}<div class="field"><div class="fl">{{template "icon-tool" .}}Fixed in</div><div class="fv mono">{{.FixedIn}}</div></div>{{end}}
      <div class="field wide"><div class="fl">{{template "icon-info" .}}Summary</div><div class="fv">{{.Summary}}</div></div>
      {{if .DepPath}}<div class="field wide"><div class="fl">{{template "icon-network" .}}Dependency path</div><div class="fv mono">{{.DepPath}}</div></div>{{end}}
      {{if .Reachable}}<div class="field"><div class="fl">{{template "icon-eye" .}}Reachability</div><div class="fv">{{.Reachable}}</div></div>{{end}}
      {{if .PURL}}<div class="field"><div class="fl">{{template "icon-hash" .}}PURL</div><div class="fv mono">{{.PURL}}</div></div>{{end}}
    </div>
    {{template "enrichment" .}}
  </div>
</div>
{{end}}

{{define "code-card"}}
<div class="vcard sev-{{.SeverityClass}}" data-sev="{{.SeverityClass}}">
  <div class="vhead" onclick="this.parentNode.classList.toggle('open')">
    <span class="badge {{.SeverityClass}}"><span class="dot"></span>{{.Severity}}</span>
    <span class="vid">{{.ID}}</span>
    <span class="vsum">{{.Summary}}</span>
    <span class="vcvss">{{.Source}}</span>
    {{template "icon-chevron" .}}
  </div>
  <div class="vbody">
    <div class="fields">
      <div class="field wide"><div class="fl">{{template "icon-file" .}}File</div><div class="fv mono">{{lineRef .FilePath .StartLine}}</div></div>
      <div class="field wide"><div class="fl">{{template "icon-flag" .}}Finding</div><div class="fv">{{.Summary}}</div></div>
    </div>
    {{template "enrichment" .}}
  </div>
</div>
{{end}}

{{define "enrichment"}}
{{with .Enrichment}}
<div class="enr">
  <div class="eh">{{template "icon-spark" .}}AI analysis{{if .Confidence}}<span class="conf {{.ConfidenceClass}}" style="margin-left:auto">{{.Confidence}} confidence</span>{{end}}</div>
  {{if .Summary}}<div class="enr-field"><div class="el">Assessment</div><div class="ev">{{.Summary}}</div></div>{{end}}
  {{if .LikelyImpact}}<div class="enr-field"><div class="el">Impact</div><div class="ev">{{.LikelyImpact}}</div></div>{{end}}
  {{if .MinimalRemediation}}<div class="enr-field"><div class="el">Remediation</div><div class="ev">{{.MinimalRemediation}}</div></div>{{end}}
  {{if .SuppressionRationale}}<div class="suppression"><div class="el">Suppression rationale</div><div class="ev">{{.SuppressionRationale}}</div></div>{{end}}
</div>
{{end}}
{{end}}

{{define "icon-shield"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6l7-3z"/><path d="M9 12l2 2 4-5"/></svg>{{end}}
{{define "icon-package"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M4 7.5l8 4.5 8-4.5M12 21v-9"/></svg>{{end}}
{{define "icon-network"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="6" r="2.2"/><circle cx="6" cy="6" r="2.2"/><path d="M8 6h8M8 18h4a6 6 0 006-6V8"/></svg>{{end}}
{{define "icon-spark"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l1.6 4.4L18 10l-4.4 1.6L12 16l-1.6-4.4L6 10l4.4-1.6L12 4z"/><path d="M18 15l.7 1.8 1.8.2-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.2.7-1.8z"/></svg>{{end}}
{{define "icon-code"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 9l-4 3 4 3M16 9l4 3-4 3M13 5l-2 14"/></svg>{{end}}
{{define "icon-file"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 3h7l4 4v14a1 1 0 01-1 1H7a1 1 0 01-1-1V4a1 1 0 011-1z"/><path d="M14 3v4h4"/></svg>{{end}}
{{define "icon-alert"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l9 15H3l9-15z"/><path d="M12 10v4M12 17.5v.5"/></svg>{{end}}
{{define "icon-bolt"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L4 14h7l-1 8 10-13h-7l0-7z"/></svg>{{end}}
{{define "icon-check"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M8 12l2.5 2.5L16 9"/></svg>{{end}}
{{define "icon-search"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/></svg>{{end}}
{{define "icon-chevron"}}<svg class="ic chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 10l4 4 4-4"/></svg>{{end}}
{{define "icon-tool"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 6.5a3.5 3.5 0 01-4.6 4.6L5 16v3h3l4.9-4.9a3.5 3.5 0 004.6-4.6l-2.3 2.3-2-2 2.3-2.3z"/></svg>{{end}}
{{define "icon-info"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.5"/></svg>{{end}}
{{define "icon-eye"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.5"/></svg>{{end}}
{{define "icon-hash"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 9h14M5 15h14M10 4L8 20M16 4l-2 16"/></svg>{{end}}
{{define "icon-flag"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 21V4M6 4h11l-2 3 2 3H6"/></svg>{{end}}
{{define "icon-folder"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 012-2h5l2 2h7a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/></svg>{{end}}
{{define "icon-clock"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg>{{end}}
{{define "icon-target"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>{{end}}
{{define "icon-layers"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 4-8 4-8-4 8-4z"/><path d="M4 12l8 4 8-4M4 17l8 4 8-4"/></svg>{{end}}
{{define "icon-list"}}<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h12M8 12h12M8 18h12"/><path d="M4 6h.01M4 12h.01M4 18h.01"/></svg>{{end}}

<script>
(function(){
  var links=[].slice.call(document.querySelectorAll('.navlink'));
  var map={}; links.forEach(function(l){map[l.dataset.target]=l;});
  var secs=[].slice.call(document.querySelectorAll('section[id]'));
  if('IntersectionObserver' in window){
    var obs=new IntersectionObserver(function(es){
      es.forEach(function(e){
        if(e.isIntersecting){
          links.forEach(function(l){l.classList.remove('active');});
          var id=e.target.id; if(map[id])map[id].classList.add('active');
        }
      });
    },{rootMargin:'-45% 0px -50% 0px',threshold:0});
    secs.forEach(function(s){obs.observe(s);});
  }

  var search=document.getElementById('vsearch');
  var filters=document.getElementById('vfilters');
  var cards=[].slice.call(document.querySelectorAll('#veco .vcard'));
  var groups=[].slice.call(document.querySelectorAll('#veco .eco-group'));
  var ecoCards=[].slice.call(document.querySelectorAll('#veco .eco-cards'));
  var empty=document.getElementById('vempty');
  var countEl=document.getElementById('vcount');
  var activeSev='all', q='';
  function apply(){
    var shown=0;
    cards.forEach(function(c){
      var okSev=activeSev==='all'||c.dataset.sev===activeSev;
      var okQ=!q||(c.dataset.text||'').indexOf(q)>-1;
      var vis=okSev&&okQ;
      c.style.display=vis?'':'none';
      if(vis)shown++;
    });
    ecoCards.forEach(function(ec,i){
      var any=[].slice.call(ec.querySelectorAll('.vcard')).some(function(c){return c.style.display!=='none';});
      ec.style.display=any?'':'none';
      if(groups[i])groups[i].style.display=any?'':'none';
    });
    if(empty)empty.style.display=shown?'none':'block';
    if(countEl)countEl.textContent=shown+' shown';
  }
  if(search)search.addEventListener('input',function(){q=this.value.trim().toLowerCase();apply();});
  if(filters)filters.addEventListener('click',function(e){
    var b=e.target.closest('.chip'); if(!b)return;
    activeSev=b.dataset.sev;
    [].slice.call(filters.querySelectorAll('.chip')).forEach(function(c){c.setAttribute('aria-pressed',c===b?'true':'false');});
    apply();
  });
  var ex=document.getElementById('vexpand'), co=document.getElementById('vcollapse');
  if(ex)ex.addEventListener('click',function(){cards.forEach(function(c){if(c.style.display!=='none')c.classList.add('open');});});
  if(co)co.addEventListener('click',function(){cards.forEach(function(c){c.classList.remove('open');});});
  apply();
})();
</script>
</body>
</html>`
