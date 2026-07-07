package reporter

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
)

var pdfIconPaths = map[string]string{
	"shield":       `<path d="M12 3l7 3v5c0 5-3.4 8.8-7 10-3.6-1.2-7-5-7-10V6l7-3z"/><path d="M9 12l2 2 4-5"/>`,
	"gate":         `<path d="M4 7h16"/><path d="M6 7v12"/><path d="M18 7v12"/><path d="M9 19v-7h6v7"/>`,
	"gate-x":       `<path d="M4 7h16"/><path d="M6 7v12"/><path d="M18 7v12"/><path d="M9 19v-7h6v7"/><path d="M9 4l6 6"/><path d="M15 4l-6 6"/>`,
	"link":         `<path d="M10 13a5 5 0 0 0 7.1 0l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.1 0l-2 2A5 5 0 0 0 12 20.1l1.1-1.1"/>`,
	"cpu":          `<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v3"/><path d="M15 2v3"/><path d="M9 19v3"/><path d="M15 19v3"/><path d="M2 9h3"/><path d="M2 15h3"/><path d="M19 9h3"/><path d="M19 15h3"/>`,
	"package":      `<path d="M21 8l-9-5-9 5 9 5 9-5z"/><path d="M3 8v8l9 5 9-5V8"/><path d="M12 13v8"/>`,
	"code":         `<path d="M8 9l-4 3 4 3"/><path d="M16 9l4 3-4 3"/><path d="M13 5l-2 14"/>`,
	"alert":        `<path d="M10.3 3h3.4l8.3 15H2L10.3 3z"/><path d="M12 9v4"/><path d="M12 17h.01"/>`,
	"clock":        `<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>`,
	"layers":       `<path d="M12 2l9 5-9 5-9-5 9-5z"/><path d="M3 12l9 5 9-5"/><path d="M3 17l9 5 9-5"/>`,
	"folder":       `<path d="M3 7h6l2 2h10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>`,
	"file":         `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>`,
	"flag":         `<path d="M5 22V4"/><path d="M5 4h12l-2 5 2 5H5"/>`,
	"route":        `<circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M9 6h3a4 4 0 0 1 0 8H9"/>`,
	"hash":         `<path d="M4 9h16"/><path d="M4 15h16"/><path d="M10 3L8 21"/><path d="M16 3l-2 18"/>`,
	"target":       `<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>`,
	"shield-alert": `<path d="M12 3l7 3v5c0 5-3.4 8.8-7 10-3.6-1.2-7-5-7-10V6l7-3z"/><path d="M12 8v5"/><path d="M12 16h.01"/>`,
	"sparkles":     `<path d="M12 3l1.6 4.8L18 9l-4.4 1.2L12 15l-1.6-4.8L6 9l4.4-1.2L12 3z"/><path d="M19 14l.8 2.2L22 17l-2.2.8L19 20l-.8-2.2L16 17l2.2-.8L19 14z"/><path d="M5 14l.8 2.2L8 17l-2.2.8L5 20l-.8-2.2L2 17l2.2-.8L5 14z"/>`,
	"list":         `<path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>`,
	"wrench":       `<path d="M14.7 6.3a4 4 0 0 0-5 5L3 18l3 3 6.7-6.7a4 4 0 0 0 5-5l-2.4 2.4-3-3 2.4-2.4z"/>`,
	"eye":          `<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>`,
	"info":         `<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>`,
	"arrow-right":  `<path d="M5 12h14"/><path d="M13 5l7 7-7 7"/>`,
}

func logoDataURL(data []byte) template.URL {
	if len(data) == 0 {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(data))
}

func renderPDFSourceHTML(data pdfReportData) (string, error) {
	tpl, err := template.New("pdf-report").Funcs(template.FuncMap{
		"icon": pdfIcon,
	}).Parse(pdfReportTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func pdfIcon(name string) template.HTML {
	path := pdfIconPaths[name]
	if path == "" {
		path = pdfIconPaths["info"]
	}
	return template.HTML(fmt.Sprintf(`<svg class="pdf-icon" width="16" height="16" viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">%s</svg>`, path))
}

const pdfReportTemplate = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
@font-face{font-family:Inter;src:url("fonts/Inter-Regular.ttf") format("truetype");font-weight:400;font-style:normal;font-display:swap}
@font-face{font-family:JetBrainsMono;src:url("fonts/JetBrainsMono-Regular.ttf") format("truetype");font-weight:400;font-style:normal;font-display:swap}
:root{
  --ink:#0b1220; --text:#182234; --text-2:#3f4c60; --muted:#6b7787; --faint:#93a0b1;
  --line:#dde3ec; --line-2:#e9edf3; --panel:#ffffff; --panel-2:#f7f9fc; --surface:#f3f5f9;
  --brand:#2563eb; --brand-ink:#1d4ed8; --brand-soft:#e9f0fe;
  --crit:#c02a37; --crit-bg:#fcecee; --crit-bd:#f0ccd1;
  --high:#c85a12; --high-bg:#fcf1e6; --high-bd:#f2d8bc;
  --med:#a97a05; --med-bg:#fbf5e2; --med-bd:#ecdcac;
  --low:#1f6feb; --low-bg:#eaf2fe; --low-bd:#cadcfb;
  --ok:#127a52; --ok-bg:#e7f4ee; --ok-bd:#bfe2d1;
  --neutral:#3a4658; --neutral-bg:#eef1f6; --neutral-bd:#dbe2ec;
}
@page{ size:A4; margin:20mm 16mm 16mm 16mm; }
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:#fff;color:var(--text);font-family:Inter,Arial,sans-serif;font-size:9.6px;line-height:1.45}
body{print-color-adjust:exact;-webkit-print-color-adjust:exact}
svg{width:1em;height:1em;max-width:100%;max-height:100%;flex:none;overflow:hidden}
.pdf-icon{display:inline-block;width:1em;height:1em;vertical-align:-0.14em}
h1,h2,h3,p{margin:0}
h1{font-size:30px;line-height:1.05;letter-spacing:-.02em;color:var(--ink)}
h2{font-size:14px;line-height:1.2;color:var(--ink)}
h3{font-size:10.5px;color:var(--ink)}
.mono{font-family:JetBrainsMono,Menlo,monospace}
.page{position:relative;break-after:page;page-break-after:always;min-height:257mm;background:#fff}
.page.flow{min-height:auto}
.topbar{height:22mm;background:#113665;color:#fff;margin:-20mm -16mm 13mm -16mm;padding:6mm 16mm;display:flex;align-items:center;gap:4mm}
.logo{width:12mm;height:12mm;border-radius:3mm;background:#fff;display:flex;align-items:center;justify-content:center;overflow:hidden}
.logo img{width:100%;height:100%;object-fit:cover}
.logo svg{width:7mm;height:7mm}
.brand .name{font-size:14px;font-weight:800;letter-spacing:.02em}
.brand .sub{font-size:8px;opacity:.8;letter-spacing:.12em;text-transform:uppercase}
.cover-title{margin-top:9mm}
.cover-subtitle{margin-top:4mm;color:var(--muted);font-size:13px;max-width:150mm}
.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:4mm;margin-top:12mm}
.metric-card{border:0.75px solid var(--line);background:var(--panel-2);border-radius:8px;padding:4.5mm;min-height:24mm}
.metric-card .label{color:var(--muted);font-size:7.8px;font-weight:800;letter-spacing:.09em;text-transform:uppercase}
.metric-card .value{margin-top:2mm;font-size:20px;font-weight:900;color:var(--ink)}
.metric-card.critical{border-color:var(--crit-bd);background:var(--crit-bg)}
.metric-card.high{border-color:var(--high-bd);background:var(--high-bg)}
.metric-card.medium{border-color:var(--med-bd);background:var(--med-bg)}
.metric-card.low{border-color:var(--low-bd);background:var(--low-bg)}
.metric-card.ok{border-color:var(--ok-bd);background:var(--ok-bg)}
.notice{margin-top:12mm;border:1px solid var(--brand);background:var(--brand-soft);border-radius:8px;padding:5mm 6mm}
.notice h2{margin-bottom:2mm}
.review-list{display:grid;gap:4mm;margin-top:10mm}
.review-row{display:grid;grid-template-columns:10mm 1fr;gap:4mm;align-items:start}
.review-row .q{width:8mm;height:8mm;border-radius:50%;background:var(--brand-soft);color:var(--brand);display:flex;align-items:center;justify-content:center;font-weight:900}
.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:6mm}
.section-title{display:flex;align-items:center;gap:4mm}
.section-icon{width:12mm;height:12mm;border:0.75px solid var(--line);border-radius:4px;background:#fff;color:var(--brand);display:flex;align-items:center;justify-content:center}
.section-icon svg{width:5mm;height:5mm}
.section-copy .subtitle{color:var(--muted);font-size:10px;margin-top:1mm}
.pill{display:inline-flex;align-items:center;gap:1.4mm;border:0.75px solid var(--line);background:#fff;border-radius:999px;padding:1.3mm 3mm;color:var(--text-2);font-size:8.4px;font-weight:700;white-space:nowrap}
.pill svg{width:3mm;height:3mm}
.panel{border:0.75px solid var(--line);border-radius:8px;background:var(--panel);box-shadow:0 2px 8px rgba(11,18,32,.04)}
.panel-pad{padding:6mm}
.toc-row{display:grid;grid-template-columns:12mm 1fr 14mm;gap:4mm;padding:4mm 0;border-bottom:0.75px solid var(--line-2);align-items:center}
.toc-row:last-child{border-bottom:0}
.toc-no{font-family:JetBrainsMono,Menlo,monospace;color:var(--brand);font-weight:800}
.toc-title{font-size:11px;font-weight:800;color:var(--ink)}
.toc-desc{color:var(--muted);font-size:9px;margin-top:1mm}
.toc-page{text-align:right;color:var(--muted);font-family:JetBrainsMono,Menlo,monospace}
.gate-card{display:grid;grid-template-columns:20mm 1fr;gap:6mm;border:0.75px solid var(--crit-bd);border-radius:10px;background:linear-gradient(110deg,#fff 0%,var(--crit-bg) 100%);padding:7mm}
.gate-card.ok{border-color:var(--ok-bd);background:linear-gradient(110deg,#fff 0%,var(--ok-bg) 100%)}
.gate-card.high{border-color:var(--high-bd);background:linear-gradient(110deg,#fff 0%,var(--high-bg) 100%)}
.gate-icon{width:18mm;height:18mm;border-radius:6px;background:linear-gradient(135deg,#e3364a,#a81e2d);color:#fff;display:flex;align-items:center;justify-content:center}
.gate-card.ok .gate-icon{background:linear-gradient(135deg,#18a66d,#0f6746)}
.gate-card.high .gate-icon{background:linear-gradient(135deg,#e67824,#b64c0e)}
.gate-icon svg{width:8mm;height:8mm}
.eyebrow{font-size:7.8px;letter-spacing:.13em;text-transform:uppercase;color:var(--muted);font-weight:900}
.gate-title{display:flex;align-items:center;gap:3mm;margin-top:1.5mm;font-size:18px;font-weight:900;color:var(--crit)}
.gate-card.ok .gate-title{color:var(--ok)}
.gate-card.high .gate-title{color:var(--high)}
.gate-body{margin-top:3mm;color:var(--text-2);font-size:10px}
.gate-actions{margin-top:5mm;border-top:0.75px dashed var(--line);padding-top:4mm}
.gate-actions li{margin:1.5mm 0;color:var(--text-2)}
.badge{display:inline-flex;align-items:center;gap:1.2mm;border-radius:4px;border:0.75px solid var(--neutral-bd);background:var(--neutral-bg);color:var(--neutral);font-size:8px;font-weight:900;text-transform:uppercase;padding:1mm 2.4mm}
.badge.critical{background:var(--crit-bg);border-color:var(--crit-bd);color:var(--crit)}
.badge.high{background:var(--high-bg);border-color:var(--high-bd);color:var(--high)}
.badge.medium{background:var(--med-bg);border-color:var(--med-bd);color:var(--med)}
.badge.low{background:var(--low-bg);border-color:var(--low-bd);color:var(--low)}
.badge.ok{background:var(--ok-bg);border-color:var(--ok-bd);color:var(--ok)}
.overview-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:6mm;margin-top:7mm}
.stat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:4mm}
.stat{border:0.75px solid var(--line);border-left:2.5px solid var(--neutral);border-radius:7px;background:#fff;padding:5mm}
.stat.critical{border-left-color:var(--crit)}
.stat.high{border-left-color:var(--high)}
.stat.medium{border-left-color:var(--med)}
.stat.low{border-left-color:var(--low)}
.stat .num{font-size:22px;font-weight:900;line-height:1;color:var(--ink)}
.stat.critical .num{color:var(--crit)}
.stat.high .num{color:var(--high)}
.stat.medium .num{color:var(--med)}
.stat.low .num{color:var(--low)}
.stat .txt{margin-top:1.5mm;color:var(--muted);font-size:8px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}
.dist-bar{height:8mm;border-radius:999px;background:var(--line-2);overflow:hidden;display:flex;margin:5mm 0}
.dist-bar span.critical{background:var(--crit)}
.dist-bar span.high{background:var(--high)}
.dist-bar span.medium{background:var(--med)}
.dist-bar span.low{background:var(--low)}
.dist-row{display:grid;grid-template-columns:20mm 1fr 15mm 15mm;gap:3mm;align-items:center;margin:2mm 0;color:var(--text-2)}
.dot{width:3mm;height:3mm;border-radius:50%;display:inline-block;margin-right:1.5mm}
.dot.critical{background:var(--crit)}.dot.high{background:var(--high)}.dot.medium{background:var(--med)}.dot.low{background:var(--low)}
.facts{display:grid;grid-template-columns:repeat(2,1fr);gap:3mm;margin-top:4mm}
.fact{border:0.75px solid var(--line);border-radius:7px;padding:4mm;background:#fff}
.fact .label{font-size:7.6px;color:var(--muted);font-weight:900;text-transform:uppercase;letter-spacing:.1em}
.fact .value{font-weight:800;margin-top:1.5mm;color:var(--ink);overflow-wrap:anywhere}
.hero-grid{display:grid;grid-template-columns:36mm 1fr;gap:5mm;margin-bottom:5mm}
.score-card{border:0.75px solid var(--low-bd);background:var(--low-bg);border-radius:8px;padding:6mm}
.score-card.critical{background:var(--crit-bg);border-color:var(--crit-bd)}
.score-card.high{background:var(--high-bg);border-color:var(--high-bd)}
.score-card.medium{background:var(--med-bg);border-color:var(--med-bd)}
.score-card.ok{background:var(--ok-bg);border-color:var(--ok-bd)}
.score-card .label{font-size:7.6px;color:var(--muted);font-weight:900;text-transform:uppercase;letter-spacing:.13em}
.score-card .score{font-size:26px;font-weight:950;line-height:1;color:var(--brand);margin-top:4mm}
.score-card.critical .score{color:var(--crit)}.score-card.high .score{color:var(--high)}.score-card.medium .score{color:var(--med)}.score-card.ok .score{color:var(--ok)}
.score-card .denom{font-size:11px;color:var(--muted)}
.decision{border:0.75px solid var(--line);background:var(--panel-2);border-radius:8px;padding:6mm}
.decision .mono{font-size:12px;color:var(--crit);font-weight:800;margin-top:2mm}
.decision p{margin-top:3mm;color:var(--text-2);font-size:9.6px}
.metric-row{display:grid;grid-template-columns:repeat(4,1fr);gap:3mm;margin-bottom:5mm}
.small-metric{border:0.75px solid var(--line);border-radius:7px;background:var(--panel-2);padding:4mm}
.small-metric .ico{width:7mm;height:7mm;border-radius:3px;display:flex;align-items:center;justify-content:center;margin-bottom:4mm}
.small-metric .ico svg{width:4mm;height:4mm}
.small-metric.neutral .ico{background:var(--neutral-bg);color:var(--neutral)}
.small-metric.ok .ico{background:var(--ok-bg);color:var(--ok)}
.small-metric.high .ico{background:var(--high-bg);color:var(--high)}
.small-metric.med .ico{background:var(--med-bg);color:var(--med)}
.small-metric .label{font-size:7.8px;color:var(--muted);font-weight:900;text-transform:uppercase;letter-spacing:.12em}
.small-metric .value{font-size:16px;font-weight:900;color:var(--ink);margin-top:2mm}
.subhead{display:flex;align-items:center;justify-content:space-between;margin:6mm 0 3mm}
.subhead h3{display:flex;align-items:center;gap:1.8mm;font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--text-2)}
.subhead h3 svg{width:3mm;height:3mm;color:var(--faint)}
.signal-card{border:0.75px solid var(--line);border-left:2.5px solid var(--neutral);border-radius:8px;padding:4mm 5mm;margin-bottom:3mm;background:#fff;break-inside:avoid;page-break-inside:avoid}
.signal-card.critical{border-left-color:var(--crit)}.signal-card.high{border-left-color:var(--high)}.signal-card.medium{border-left-color:var(--med)}.signal-card.low{border-left-color:var(--low)}
.signal-title{display:flex;align-items:center;gap:3mm;font-size:10.5px;font-weight:900;color:var(--ink)}
.signal-desc{margin-top:2mm;color:var(--text-2);font-size:9.2px}
.chips{display:flex;flex-wrap:wrap;gap:2mm;margin-top:3mm}
.chip{display:inline-flex;align-items:center;gap:1.5mm;max-width:100%;border:0.75px solid var(--line);border-radius:4px;background:var(--panel-2);padding:1.2mm 2.4mm;color:var(--text-2);font-size:8px;overflow-wrap:anywhere}
.chip svg{width:3mm;height:3mm;flex:none;color:var(--faint)}
.kv{display:grid;grid-template-columns:22mm 1fr;gap:3mm;margin-top:3mm;color:var(--text-2)}
.kv .k{font-weight:900;color:var(--muted)}
.cards-2{display:grid;grid-template-columns:1fr 1fr;gap:4mm;margin-top:5mm}
.category-card{border:0.75px solid var(--line);background:var(--panel-2);border-radius:7px;padding:4mm;break-inside:avoid}
.category-card .count{float:right;border-radius:5px;background:var(--brand-soft);color:var(--brand);font-weight:900;padding:1.5mm 3mm}
.category-card p{color:var(--muted);margin-top:1.5mm}
.vuln-toolbar{border:0.75px solid var(--line);background:#fff;border-radius:8px;padding:4mm;margin-bottom:5mm;display:flex;align-items:center;gap:3mm;color:var(--muted)}
.vuln-toolbar svg{width:4mm;height:4mm;color:var(--brand)}
.eco-head{display:flex;align-items:center;gap:3mm;margin:6mm 0 3mm;color:var(--ink);font-weight:900}
.eco-head svg{width:4mm;height:4mm;color:var(--brand)}
.eco-head .count{border:0.75px solid var(--line);border-radius:999px;padding:1mm 3mm;color:var(--muted);font-family:JetBrainsMono,Menlo,monospace}
.finding-row{display:grid;grid-template-columns:30mm 1fr 20mm 22mm;gap:3mm;align-items:center;border:0.75px solid var(--line);border-left:2.5px solid var(--neutral);border-radius:7px;padding:3mm 4mm;margin-bottom:2mm;background:#fff;break-inside:avoid}
.finding-row.critical{border-left-color:var(--crit)}.finding-row.high{border-left-color:var(--high)}.finding-row.medium{border-left-color:var(--med)}.finding-row.low{border-left-color:var(--low)}
.finding-row .title{font-weight:900;color:var(--text);overflow-wrap:anywhere}
.finding-row .sub{color:var(--muted);font-size:8.2px;margin-top:1mm;overflow-wrap:anywhere}
.finding-row .right{text-align:right}
.code-row{border:0.75px solid var(--line);border-left:2.5px solid var(--neutral);border-radius:7px;background:#fff;padding:4mm;margin-bottom:3mm;break-inside:avoid}
.code-row.critical{border-left-color:var(--crit)}.code-row.high{border-left-color:var(--high)}.code-row.medium{border-left-color:var(--med)}.code-row.low{border-left-color:var(--low)}
.code-head{display:flex;align-items:center;justify-content:space-between;gap:3mm}
.code-title{display:flex;align-items:center;gap:3mm;font-weight:900;color:var(--ink)}
pre{font-family:JetBrainsMono,Menlo,monospace;font-size:7.2px;background:var(--neutral-bg);border:0.75px solid var(--neutral-bd);border-radius:5px;padding:3mm;white-space:pre-wrap;overflow-wrap:anywhere;margin:3mm 0 0;color:var(--text-2)}
.empty{border:0.75px dashed var(--line);border-radius:8px;padding:7mm;text-align:center;color:var(--muted);background:var(--panel-2)}
.muted{color:var(--muted)}
</style>
</head>
<body>
<main>
<section class="page cover">
  <div class="topbar">
    <div class="logo">{{if .LogoDataURL}}<img src="{{.LogoDataURL}}" alt="Calvigil">{{else}}{{icon "shield"}}{{end}}</div>
    <div class="brand"><div class="name">Calvigil</div><div class="sub">Security Report</div></div>
  </div>
  <div class="cover-title">
    <div class="eyebrow">CALVIGIL ENTERPRISE</div>
    <h1>{{.ProjectName}}<br>Security Report</h1>
    <p class="cover-subtitle">Release-focused software supply-chain, dependency, code-quality, and scanner-evidence report generated from Calvigil OSS scan data.</p>
  </div>
  <div class="meta-grid">
    <div class="metric-card"><div class="label">Total findings</div><div class="value">{{.Summary.TotalFindings}}</div></div>
    <div class="metric-card critical"><div class="label">Critical</div><div class="value">{{.Summary.Critical}}</div></div>
    <div class="metric-card high"><div class="label">High</div><div class="value">{{.Summary.High}}</div></div>
    <div class="metric-card low"><div class="label">Packages</div><div class="value">{{.Summary.TotalPackages}}</div></div>
    <div class="metric-card medium"><div class="label">License issues</div><div class="value">{{.Summary.LicenseIssues}}</div></div>
    <div class="metric-card"><div class="label">Integrity issues</div><div class="value">{{.Summary.IntegrityIssues}}</div></div>
    <div class="metric-card"><div class="label">Consistency issues</div><div class="value">{{.Summary.ConsistencyIssues}}</div></div>
    <div class="metric-card ok"><div class="label">Known exploited</div><div class="value">{{.Summary.KnownExploited}}</div></div>
  </div>
  <div class="notice">
    <h2>Manual review still required</h2>
    <p>Calvigil automates inventory, CVE, license, supply-chain, and evidence collection. Intended use, safety impact, legal interpretation, mitigation, and release approval still require accountable human review.</p>
  </div>
  <div class="review-list">
    <div class="review-row"><div class="q">E</div><p><strong>Engineering:</strong> confirm intended use, dependency reachability, remediation path, and owner.</p></div>
    <div class="review-row"><div class="q">S</div><p><strong>Security:</strong> assess CVE exposure, KEV signals, exploitability, and residual risk.</p></div>
    <div class="review-row"><div class="q">L</div><p><strong>Legal/compliance:</strong> review license obligations, exceptions, and audit evidence.</p></div>
  </div>
</section>

<section class="page">
  <div class="section-head">
    <div class="section-title"><div class="section-icon">{{icon "list"}}</div><div class="section-copy"><h2>Table of contents</h2><p class="subtitle">Numbered sections and PDF bookmarks are included for reviewer navigation.</p></div></div>
  </div>
  <div class="panel panel-pad">
    {{range .TOC}}
    <div class="toc-row">
      <div class="toc-no">{{.Number}}</div>
      <div><div class="toc-title">{{.Title}}</div><div class="toc-desc">{{.Description}}</div></div>
      <div class="toc-page">{{.Page}}</div>
    </div>
    {{end}}
  </div>
</section>

<section class="page" id="overview">
  <div class="section-head">
    <div class="section-title"><div class="section-icon">{{icon "shield"}}</div><div class="section-copy"><h2>Executive overview</h2><p class="subtitle">Release posture, severity mix, scan metadata, and operational signals.</p></div></div>
    <span class="pill">{{icon "folder"}} {{.ProjectName}}</span>
  </div>
  <div class="gate-card {{.Gate.Class}}">
    <div class="gate-icon">{{if eq .Gate.Class "ok"}}{{icon "shield"}}{{else}}{{icon "gate-x"}}{{end}}</div>
    <div>
      <div class="eyebrow">{{.Gate.Label}}</div>
      <div class="gate-title">{{.Gate.Status}} <span class="badge {{.Gate.Class}} mono">{{.Gate.Badge}}</span></div>
      <p class="gate-body">{{.Gate.Body}}</p>
      <div class="gate-actions"><div class="eyebrow">Required before release</div><ul>{{range .Gate.Actions}}<li>{{.}}</li>{{end}}</ul></div>
    </div>
  </div>
  <div class="overview-grid">
    <div class="stat-grid">
      <div class="stat"><div class="num">{{.Summary.TotalFindings}}</div><div class="txt">Total findings</div></div>
      <div class="stat critical"><div class="num">{{.Summary.Critical}}</div><div class="txt">Critical</div></div>
      <div class="stat high"><div class="num">{{.Summary.High}}</div><div class="txt">High</div></div>
      <div class="stat medium"><div class="num">{{.Summary.Medium}}</div><div class="txt">Medium</div></div>
      <div class="stat low"><div class="num">{{.Summary.Low}}</div><div class="txt">Low</div></div>
      <div class="stat"><div class="num">{{.Summary.Unknown}}</div><div class="txt">Unknown</div></div>
    </div>
    <div class="panel panel-pad">
      <div class="eyebrow">{{icon "target"}} Severity distribution</div>
      <div class="dist-bar">{{range .Summary.SeveritySlices}}<span class="{{.Class}}" style="width:{{.Width}}"></span>{{end}}</div>
      {{range .Summary.SeveritySlices}}
      <div class="dist-row"><div><span class="dot {{.Class}}"></span>{{.Label}}</div><strong>{{.Count}}</strong><span class="muted">{{printf "%.1f%%" .Percent}}</span><div></div></div>
      {{end}}
      <div class="facts">
        <div class="fact"><div class="label">Scanned</div><div class="value">{{.ScannedAt}}</div></div>
        <div class="fact"><div class="label">Duration</div><div class="value">{{.Duration}}</div></div>
        <div class="fact"><div class="label">Project path</div><div class="value">{{.ProjectPath}}</div></div>
        <div class="fact"><div class="label">Ecosystems</div><div class="value">{{range .Ecosystems}}<span class="pill">{{.}}</span> {{else}}not detected{{end}}</div></div>
      </div>
    </div>
  </div>
</section>

<section class="page flow" id="supply">
  <div class="section-head">
    <div class="section-title"><div class="section-icon">{{icon "link"}}</div><div class="section-copy"><h2>Supply chain guard</h2><p class="subtitle">Dependency trust drift, package metadata, install behavior, and resolver consistency.</p></div></div>
    <span class="pill mono">{{.Supply.SignalCount}} signals</span>
  </div>
  <div class="panel panel-pad">
    <div class="hero-grid">
      <div class="score-card {{.Supply.LevelClass}}"><div class="label">Risk score</div><div class="score">{{.Supply.Score}}<span class="denom">/100</span></div><div class="badge {{.Supply.LevelClass}}">{{.Supply.Level}}</div></div>
      <div class="decision"><div class="eyebrow">Recommended decision</div><div class="mono">{{.Supply.Decision}}</div><p>{{.Supply.Recommendation}}</p></div>
    </div>
    <div class="metric-row">{{range .Supply.Metrics}}<div class="small-metric {{.Class}}"><div class="ico">{{icon .Icon}}</div><div class="label">{{.Label}}</div><div class="value">{{.Value}}</div></div>{{end}}</div>
    <div class="subhead"><h3>{{icon "list"}} Signals to review</h3><span class="pill mono">{{len .Supply.Findings}} shown</span></div>
    {{range .Supply.Findings}}
    <div class="signal-card {{.SeverityClass}}">
      <div class="signal-title"><span class="badge {{.SeverityClass}}">{{.Severity}}</span><span>{{.ID}} {{.Title}}</span></div>
      <p class="signal-desc">{{.Description}}</p>
      <div class="chips">
        {{if .Package}}<span class="chip">{{icon "package"}} pkg {{.Package}}</span>{{end}}
        {{if .Ecosystem}}<span class="chip">{{icon "layers"}} eco {{.Ecosystem}}</span>{{end}}
        {{if .FilePath}}<span class="chip">{{icon "file"}} file {{.FilePath}}</span>{{end}}
        {{if .Confidence}}<span class="chip">{{icon "eye"}} {{.Confidence}} confidence</span>{{end}}
      </div>
      <div class="kv">{{if .Evidence}}<div class="k">Evidence</div><div>{{.Evidence}}</div>{{end}}{{if .Action}}<div class="k">Action</div><div>{{.Action}}</div>{{end}}</div>
    </div>
    {{else}}<div class="empty">No supply-chain guard signals were reported.</div>{{end}}
    {{if .Supply.Guidance}}<div class="notice"><h2>Review guidance</h2><ul>{{range .Supply.Guidance}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
  </div>
</section>

<section class="page flow" id="slop">
  <div class="section-head">
    <div class="section-title"><div class="section-icon">{{icon "sparkles"}}</div><div class="section-copy"><h2>AI code smells</h2><p class="subtitle">Concrete quality and security symptoms for reviewer prioritization, not authorship attribution.</p></div></div>
    <span class="pill mono">{{.Slop.SignalCount}} signals</span>
  </div>
  <div class="panel panel-pad">
    <div class="hero-grid">
      <div class="score-card {{.Slop.LevelClass}}"><div class="label">Smell score</div><div class="score">{{.Slop.Score}}<span class="denom">/100</span></div><div class="badge {{.Slop.LevelClass}}">{{.Slop.Level}}</div></div>
      <div class="decision"><div class="eyebrow">What this means</div><div class="mono">{{.Slop.MeaningTitle}}</div><p>{{.Slop.MeaningBody}}</p><div class="chips"><span class="chip">{{.Slop.SignalCount}} signal(s)</span><span class="chip">{{.Slop.Confidence}} confidence</span><span class="chip mono">{{.Slop.GeneratedSignal}}</span></div></div>
    </div>
    {{if .Slop.Categories}}
    <div class="cards-2">{{range .Slop.Categories}}<div class="category-card"><span class="count">{{.Weight}}</span><h3>{{.Name}} ({{.Count}})</h3><p>{{.Description}}</p></div>{{end}}</div>
    {{end}}
    <div class="subhead"><h3>{{icon "list"}} Top signals to review</h3><span class="pill mono">{{len .Slop.Signals}} shown</span></div>
    {{range .Slop.Signals}}
    <div class="signal-card {{.SeverityClass}}">
      <div class="signal-title"><span class="badge {{.SeverityClass}}">{{.Severity}}</span><span class="mono">{{.RuleID}}</span><span>{{.Title}}</span><span class="pill">{{.Confidence}}</span></div>
      <p class="signal-desc">{{.Reason}}</p>
      <div class="chips"><span class="chip">{{icon "file"}} {{.File}}</span><span class="chip mono">weight {{.Weight}}</span></div>
    </div>
    {{else}}<div class="empty">No AI code smell signals were reported.</div>{{end}}
    {{if .Slop.Guidance}}<div class="notice"><h2>Review guidance</h2><ul>{{range .Slop.Guidance}}<li>{{.}}</li>{{end}}</ul></div>{{end}}
  </div>
</section>

<section class="page flow" id="dependencies">
  <div class="section-head">
    <div class="section-title"><div class="section-icon">{{icon "package"}}</div><div class="section-copy"><h2>Dependency vulnerabilities</h2><p class="subtitle">Known CVEs in direct and transitive packages, enriched with reachability and remediation context.</p></div></div>
    <span class="pill mono">{{.Dependencies.Count}} findings</span>
  </div>
  <div class="vuln-toolbar">{{icon "target"}} Dependency findings are grouped by ecosystem and sorted by normalized severity.</div>
  {{range .Dependencies.Groups}}
  <div class="eco-head">{{icon "package"}} {{.Ecosystem}} <span class="count">{{.Count}}</span></div>
  {{range .Findings}}
  <div class="finding-row {{.SeverityClass}}">
    <div><span class="badge {{.SeverityClass}}">{{.Severity}}</span>{{if .KnownExploited}} <span class="badge critical">KEV</span>{{end}}</div>
    <div><div class="title"><span class="mono">{{.ID}}</span> {{.Summary}}</div><div class="sub">{{.Package}} - {{.Scope}}{{if .Reachable}} - {{.Reachable}}{{end}}</div></div>
    <div><span class="pill mono">CVSS {{.CVSS}}</span></div>
    <div class="right"><div class="muted">Fix</div><strong>{{.FixedIn}}</strong></div>
  </div>
  {{end}}
  {{else}}<div class="empty">No dependency vulnerabilities were reported.</div>{{end}}
</section>

<section class="page flow" id="code">
  <div class="section-head">
    <div class="section-title"><div class="section-icon">{{icon "code"}}</div><div class="section-copy"><h2>Code analysis findings</h2><p class="subtitle">Static analysis, Semgrep, pattern-rule, IaC, and AI-assisted code findings.</p></div></div>
    <span class="pill mono">{{.Code.Count}} findings</span>
  </div>
  {{range .Code.Groups}}
  <div class="eco-head">{{icon "code"}} {{.Source}} <span class="count">{{.Count}}</span></div>
  {{range .Findings}}
  <div class="code-row {{.SeverityClass}}">
    <div class="code-head"><div class="code-title"><span class="badge {{.SeverityClass}}">{{.Severity}}</span><span class="mono">{{.ID}}</span><span>{{.Title}}</span></div><span class="pill">{{.Confidence}}</span></div>
    <div class="chips"><span class="chip">{{icon "file"}} {{.File}}</span><span class="chip mono">rule {{.Rule}}</span></div>
    {{if .Snippet}}<pre>{{.Snippet}}</pre>{{end}}
  </div>
  {{end}}
  {{else}}<div class="empty">No code analysis findings were reported.</div>{{end}}

  <div class="section-head" style="margin-top:10mm">
    <div class="section-title"><div class="section-icon">{{icon "alert"}}</div><div class="section-copy"><h2>Scanner warnings</h2><p class="subtitle">Operational warnings that may affect report completeness.</p></div></div>
    <span class="pill mono">{{len .Warnings}} warnings</span>
  </div>
  {{range .Warnings}}
  <div class="signal-card high"><div class="signal-title"><span class="badge high">Warning</span><span>{{.}}</span></div></div>
  {{else}}<div class="empty">No scanner warnings were reported.</div>{{end}}
</section>
</main>
</body>
</html>`
