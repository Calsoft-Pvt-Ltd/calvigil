package reporter

import (
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chavakula/calvigil/internal/models"
)

// HTMLReporter generates a self-contained HTML report suitable for
// executive / MIS audiences with charts, severity badges, and clear layout.
type HTMLReporter struct{}

// htmlData is the top-level data passed into the HTML template.
type htmlData struct {
	ProjectPath   string
	GeneratedAt   string
	Duration      string
	TotalPackages int
	Ecosystems    []string
	TotalVulns    int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	UnknownCount  int
	DepGroups     []htmlEcoGroup
	CodeVulns     []htmlVuln
	SemgrepVulns  []htmlVuln
	Errors        []string
	HasEnrichment bool
	TotalDepVulns int
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
	Enrichment    *htmlEnrichment
}

type htmlEnrichment struct {
	Summary              string
	LikelyImpact         string
	Confidence           string
	ConfidenceClass      string
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
		ProjectPath:   result.ProjectPath,
		GeneratedAt:   result.ScannedAt.Format(time.RFC1123),
		Duration:      result.Duration.Round(time.Millisecond).String(),
		TotalPackages: result.TotalPackages,
		TotalVulns:    len(vulns),
	}

	for _, e := range result.Ecosystems {
		data.Ecosystems = append(data.Ecosystems, string(e))
	}

	// Count severities
	for _, v := range vulns {
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

	// Categorise vulns
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

	// Build ordered ecosystem groups
	ecoOrder := []string{"Go", "npm", "PyPI", "Maven"}
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

	data.Errors = result.Errors

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"pct": func(count, total int) string {
			if total == 0 {
				return "0"
			}
			return fmt.Sprintf("%.1f", float64(count)*100/float64(total))
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
	}

	if v.AIEnrichment != nil {
		hv.Enrichment = &htmlEnrichment{
			Summary:              v.AIEnrichment.Summary,
			LikelyImpact:         v.AIEnrichment.LikelyImpact,
			Confidence:           v.AIEnrichment.Confidence,
			ConfidenceClass:      strings.ToLower(v.AIEnrichment.Confidence),
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
		return "🐹"
	case "npm":
		return "📗"
	case "PyPI":
		return "🐍"
	case "Maven":
		return "☕"
	default:
		return "📦"
	}
}

// ---------------------------------------------------------------------------
// Embedded HTML template — self-contained with CSS, no external resources.
// ---------------------------------------------------------------------------

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Calvigil Security Report — {{.ProjectPath}}</title>
<style>
  :root {
    --critical: #d32f2f;
    --high:     #e64a19;
    --medium:   #f9a825;
    --low:      #1976d2;
    --unknown:  #9e9e9e;
    --bg:       #f5f7fa;
    --card:     #ffffff;
    --border:   #e0e4e8;
    --text:     #212529;
    --muted:    #6c757d;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 0;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }

  /* Header */
  .header {
    background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
    color: #fff;
    padding: 32px 0;
    margin-bottom: 32px;
  }
  .header .container { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; }
  .header h1 { font-size: 1.6rem; font-weight: 700; }
  .header .meta { font-size: 0.85rem; opacity: 0.85; text-align: right; }
  .header .meta span { display: block; }

  /* Severity cards */
  .severity-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }
  .sev-card {
    background: var(--card);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    border-top: 4px solid var(--border);
  }
  .sev-card.critical { border-top-color: var(--critical); }
  .sev-card.high     { border-top-color: var(--high); }
  .sev-card.medium   { border-top-color: var(--medium); }
  .sev-card.low      { border-top-color: var(--low); }
  .sev-card.total    { border-top-color: #333; }
  .sev-card .count { font-size: 2rem; font-weight: 800; }
  .sev-card.critical .count { color: var(--critical); }
  .sev-card.high     .count { color: var(--high); }
  .sev-card.medium   .count { color: var(--medium); }
  .sev-card.low      .count { color: var(--low); }
  .sev-card.total    .count { color: #333; }
  .sev-card .label   { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }

  /* Executive summary bar */
  .exec-bar {
    background: var(--card);
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 32px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }
  .exec-bar h2 { font-size: 1rem; margin-bottom: 12px; }
  .bar-track { height: 24px; border-radius: 12px; background: #e9ecef; overflow: hidden; display: flex; }
  .bar-segment { height: 100%; transition: width 0.3s; min-width: 0; }
  .bar-segment.critical { background: var(--critical); }
  .bar-segment.high     { background: var(--high); }
  .bar-segment.medium   { background: var(--medium); }
  .bar-segment.low      { background: var(--low); }
  .bar-segment.unknown  { background: var(--unknown); }
  .bar-legend { display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; }
  .bar-legend span { font-size: 0.78rem; display: flex; align-items: center; gap: 4px; }
  .bar-legend .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }

  /* Section */
  .section {
    background: var(--card);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
  }
  .section h2 { font-size: 1.15rem; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid var(--bg); }

  /* Vuln card */
  .vuln-card {
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 14px;
    overflow: hidden;
  }
  .vuln-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 18px;
    background: #fafbfc;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .vuln-card-header .vuln-id {
    font-weight: 700;
    font-size: 0.9rem;
    word-break: break-all;
  }
  .vuln-card-body {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2px 24px;
    padding: 14px 18px;
    font-size: 0.85rem;
  }
  .vuln-field {
    display: flex;
    padding: 4px 0;
  }
  .vuln-field.wide {
    grid-column: 1 / -1;
  }
  .vuln-field-label {
    min-width: 100px;
    font-weight: 600;
    color: var(--muted);
    flex-shrink: 0;
  }
  .vuln-field-value {
    flex: 1;
    word-break: break-word;
  }
  .vuln-card.sev-critical { border-left: 4px solid var(--critical); }
  .vuln-card.sev-high     { border-left: 4px solid var(--high); }
  .vuln-card.sev-medium   { border-left: 4px solid var(--medium); }
  .vuln-card.sev-low      { border-left: 4px solid var(--low); }
  .vuln-card.sev-unknown  { border-left: 4px solid var(--unknown); }

  /* Badge */
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.72rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    white-space: nowrap;
  }
  .badge.critical { background: var(--critical); }
  .badge.high     { background: var(--high); }
  .badge.medium   { background: var(--medium); color: #333; }
  .badge.low      { background: var(--low); }
  .badge.unknown  { background: var(--unknown); }

  /* AI Enrichment inside card */
  .enrichment {
    background: #f0f4ff;
    border-top: 1px solid #d0d8f0;
    padding: 14px 18px;
    font-size: 0.82rem;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2px 24px;
  }
  .enrichment-title {
    grid-column: 1 / -1;
    font-weight: 700;
    color: #3949ab;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .enrichment .vuln-field-label { color: #3949ab; }
  .enrichment .wide { grid-column: 1 / -1; }
  .conf-badge { padding: 1px 8px; border-radius: 8px; font-size: 0.7rem; font-weight: 600; }
  .conf-badge.high   { background: #c8e6c9; color: #2e7d32; }
  .conf-badge.medium { background: #fff9c4; color: #f57f17; }
  .conf-badge.low    { background: #ffcdd2; color: #c62828; }

  /* Eco group header */
  .eco-group-header {
    font-size: 1.05rem;
    font-weight: 700;
    margin: 20px 0 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
  }
  .eco-group-header:first-child { margin-top: 0; }

  /* Footer */
  .footer {
    text-align: center;
    font-size: 0.78rem;
    color: var(--muted);
    padding: 32px 0;
  }

  /* Print */
  @media print {
    body { background: #fff; }
    .header { background: #1a237e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .sev-card, .section, .exec-bar { box-shadow: none; border: 1px solid var(--border); }
    .bar-segment { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .vuln-card { break-inside: avoid; }
  }

  /* Responsive */
  @media (max-width: 768px) {
    .container { padding: 12px; }
    .severity-cards { grid-template-columns: repeat(2, 1fr); }
    .vuln-card-header { flex-direction: column; align-items: flex-start; gap: 6px; }
    .vuln-card-body, .enrichment { grid-template-columns: 1fr; }
    .vuln-field-label { min-width: 90px; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="container">
    <div>
      <h1>&#x1F6E1; Calvigil Security Report</h1>
      <div style="margin-top:6px;opacity:0.85">{{.ProjectPath}}</div>
    </div>
    <div class="meta">
      <span>{{.GeneratedAt}}</span>
      <span>Duration: {{.Duration}}</span>
      <span>{{.TotalPackages}} packages &middot; {{len .Ecosystems}} ecosystems</span>
    </div>
  </div>
</div>

<div class="container">

  <!-- Severity cards -->
  <div class="severity-cards">
    <div class="sev-card total">
      <div class="count">{{.TotalVulns}}</div>
      <div class="label">Total</div>
    </div>
    <div class="sev-card critical">
      <div class="count">{{.CriticalCount}}</div>
      <div class="label">Critical</div>
    </div>
    <div class="sev-card high">
      <div class="count">{{.HighCount}}</div>
      <div class="label">High</div>
    </div>
    <div class="sev-card medium">
      <div class="count">{{.MediumCount}}</div>
      <div class="label">Medium</div>
    </div>
    <div class="sev-card low">
      <div class="count">{{.LowCount}}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <!-- Severity distribution bar -->
  {{if gt .TotalVulns 0}}
  <div class="exec-bar">
    <h2>Severity Distribution</h2>
    <div class="bar-track">
      {{if gt .CriticalCount 0}}<div class="bar-segment critical" style="width:{{pct .CriticalCount .TotalVulns}}%"></div>{{end}}
      {{if gt .HighCount 0}}<div class="bar-segment high" style="width:{{pct .HighCount .TotalVulns}}%"></div>{{end}}
      {{if gt .MediumCount 0}}<div class="bar-segment medium" style="width:{{pct .MediumCount .TotalVulns}}%"></div>{{end}}
      {{if gt .LowCount 0}}<div class="bar-segment low" style="width:{{pct .LowCount .TotalVulns}}%"></div>{{end}}
      {{if gt .UnknownCount 0}}<div class="bar-segment unknown" style="width:{{pct .UnknownCount .TotalVulns}}%"></div>{{end}}
    </div>
    <div class="bar-legend">
      {{if gt .CriticalCount 0}}<span><span class="dot" style="background:var(--critical)"></span> Critical ({{.CriticalCount}})</span>{{end}}
      {{if gt .HighCount 0}}<span><span class="dot" style="background:var(--high)"></span> High ({{.HighCount}})</span>{{end}}
      {{if gt .MediumCount 0}}<span><span class="dot" style="background:var(--medium)"></span> Medium ({{.MediumCount}})</span>{{end}}
      {{if gt .LowCount 0}}<span><span class="dot" style="background:var(--low)"></span> Low ({{.LowCount}})</span>{{end}}
      {{if gt .UnknownCount 0}}<span><span class="dot" style="background:var(--unknown)"></span> Unknown ({{.UnknownCount}})</span>{{end}}
    </div>
  </div>
  {{end}}

  <!-- Dependency Vulnerabilities grouped by ecosystem -->
  {{if .DepGroups}}
  <div class="section">
    <h2>&#x1F4E6; Dependency Vulnerabilities ({{.TotalDepVulns}})</h2>
    {{range .DepGroups}}
    <div class="eco-group-header">{{.Icon}} {{.Ecosystem}} ({{len .Vulns}})</div>
    {{range .Vulns}}
    <div class="vuln-card sev-{{.SeverityClass}}">
      <div class="vuln-card-header">
        <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
        <span class="vuln-id">{{.ID}}</span>
        {{if .Score}}<span style="font-size:0.8rem;color:var(--muted)">CVSS {{.Score}}</span>{{end}}
      </div>
      <div class="vuln-card-body">
        <div class="vuln-field"><span class="vuln-field-label">Package</span><span class="vuln-field-value">{{.PackageName}}@{{.PackageVer}}</span></div>
        {{if .FixedIn}}<div class="vuln-field"><span class="vuln-field-label">Fixed In</span><span class="vuln-field-value">{{.FixedIn}}</span></div>{{end}}
        <div class="vuln-field wide"><span class="vuln-field-label">Summary</span><span class="vuln-field-value">{{.Summary}}</span></div>
        {{if .DepPath}}<div class="vuln-field"><span class="vuln-field-label">Dep Path</span><span class="vuln-field-value">{{.DepPath}}</span></div>{{end}}
        {{if .Reachable}}<div class="vuln-field"><span class="vuln-field-label">Reachable</span><span class="vuln-field-value">{{.Reachable}}</span></div>{{end}}
        {{if .PURL}}<div class="vuln-field wide"><span class="vuln-field-label">PURL</span><span class="vuln-field-value" style="font-size:0.78rem">{{.PURL}}</span></div>{{end}}
      </div>
      {{if .Enrichment}}
      <div class="enrichment">
        <div class="enrichment-title">&#x1F916; AI Analysis <span class="conf-badge {{.Enrichment.ConfidenceClass}}">{{.Enrichment.Confidence}}</span></div>
        {{if .Enrichment.Summary}}<div class="vuln-field wide"><span class="vuln-field-label">Assessment</span><span class="vuln-field-value">{{.Enrichment.Summary}}</span></div>{{end}}
        {{if .Enrichment.LikelyImpact}}<div class="vuln-field"><span class="vuln-field-label">Impact</span><span class="vuln-field-value">{{.Enrichment.LikelyImpact}}</span></div>{{end}}
        {{if .Enrichment.MinimalRemediation}}<div class="vuln-field"><span class="vuln-field-label">Remediation</span><span class="vuln-field-value">{{.Enrichment.MinimalRemediation}}</span></div>{{end}}
        {{if .Enrichment.SuppressionRationale}}
        <div class="vuln-field wide suppression"><span class="vuln-field-label">Suppression</span><span class="vuln-field-value">{{.Enrichment.SuppressionRationale}}</span></div>
        {{end}}
      </div>
      {{end}}
    </div>
    {{end}}
    {{end}}
  </div>
  {{end}}

  <!-- Code Analysis Findings -->
  {{if .CodeVulns}}
  <div class="section">
    <h2>&#x1F52C; Code Analysis Findings ({{len .CodeVulns}})</h2>
    {{range .CodeVulns}}
    <div class="vuln-card sev-{{.SeverityClass}}">
      <div class="vuln-card-header">
        <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
        <span class="vuln-id">{{.ID}}</span>
      </div>
      <div class="vuln-card-body">
        <div class="vuln-field"><span class="vuln-field-label">File</span><span class="vuln-field-value">{{.FilePath}}{{if gt .StartLine 0}}:{{.StartLine}}{{end}}</span></div>
        <div class="vuln-field wide"><span class="vuln-field-label">Finding</span><span class="vuln-field-value">{{.Summary}}</span></div>
      </div>
      {{if .Enrichment}}
      <div class="enrichment">
        <div class="enrichment-title">&#x1F916; AI Analysis <span class="conf-badge {{.Enrichment.ConfidenceClass}}">{{.Enrichment.Confidence}}</span></div>
        {{if .Enrichment.Summary}}<div class="vuln-field wide"><span class="vuln-field-label">Assessment</span><span class="vuln-field-value">{{.Enrichment.Summary}}</span></div>{{end}}
        {{if .Enrichment.LikelyImpact}}<div class="vuln-field"><span class="vuln-field-label">Impact</span><span class="vuln-field-value">{{.Enrichment.LikelyImpact}}</span></div>{{end}}
        {{if .Enrichment.MinimalRemediation}}<div class="vuln-field"><span class="vuln-field-label">Remediation</span><span class="vuln-field-value">{{.Enrichment.MinimalRemediation}}</span></div>{{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- Semgrep SAST Findings -->
  {{if .SemgrepVulns}}
  <div class="section">
    <h2>&#x1F6E1; Semgrep SAST Findings ({{len .SemgrepVulns}})</h2>
    {{range .SemgrepVulns}}
    <div class="vuln-card sev-{{.SeverityClass}}">
      <div class="vuln-card-header">
        <span class="badge {{.SeverityClass}}">{{.Severity}}</span>
        <span class="vuln-id">{{.ID}}</span>
      </div>
      <div class="vuln-card-body">
        <div class="vuln-field"><span class="vuln-field-label">File</span><span class="vuln-field-value">{{.FilePath}}{{if gt .StartLine 0}}:{{.StartLine}}{{end}}</span></div>
        <div class="vuln-field wide"><span class="vuln-field-label">Finding</span><span class="vuln-field-value">{{.Summary}}</span></div>
      </div>
      {{if .Enrichment}}
      <div class="enrichment">
        <div class="enrichment-title">&#x1F916; AI Analysis <span class="conf-badge {{.Enrichment.ConfidenceClass}}">{{.Enrichment.Confidence}}</span></div>
        {{if .Enrichment.Summary}}<div class="vuln-field wide"><span class="vuln-field-label">Assessment</span><span class="vuln-field-value">{{.Enrichment.Summary}}</span></div>{{end}}
        {{if .Enrichment.LikelyImpact}}<div class="vuln-field"><span class="vuln-field-label">Impact</span><span class="vuln-field-value">{{.Enrichment.LikelyImpact}}</span></div>{{end}}
        {{if .Enrichment.MinimalRemediation}}<div class="vuln-field"><span class="vuln-field-label">Remediation</span><span class="vuln-field-value">{{.Enrichment.MinimalRemediation}}</span></div>{{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- No vulnerabilities -->
  {{if eq .TotalVulns 0}}
  <div class="section" style="text-align:center;padding:48px;">
    <div style="font-size:3rem;">&#x2705;</div>
    <h2 style="border:none;margin-top:12px;">No Vulnerabilities Found</h2>
    <p style="color:var(--muted);margin-top:8px;">Scanned {{.TotalPackages}} packages across {{len .Ecosystems}} ecosystems.</p>
  </div>
  {{end}}

  <!-- Errors -->
  {{if .Errors}}
  <div class="section" style="border-left:4px solid var(--medium);">
    <h2>&#x26A0;&#xFE0F; Warnings ({{len .Errors}})</h2>
    <ul style="padding-left:20px;font-size:0.85rem;">
    {{range .Errors}}
      <li>{{.}}</li>
    {{end}}
    </ul>
  </div>
  {{end}}

  <div class="footer">
    Generated by <strong>calvigil</strong> &mdash; {{.GeneratedAt}}
  </div>

</div>
</body>
</html>`
