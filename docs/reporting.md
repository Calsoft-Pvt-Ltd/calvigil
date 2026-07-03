---
title: Reporting
layout: default
nav_order: 7
---

# Output Formats & Reporting
{: .no_toc }

calvigil supports 8 output formats for different use cases.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Format Overview

| Format | Flag | Use Case | Machine-Readable |
|:-------|:-----|:---------|:----------------:|
| **Table** | `--format table` | Terminal viewing (default) | ❌ |
| **JSON** | `--format json` | Scripting, CI pipelines, custom tooling | ✅ |
| **SARIF** | `--format sarif` | GitHub Code Scanning, VS Code | ✅ |
| **CycloneDX** | `--format cyclonedx` | SBOM standard (v1.5) | ✅ |
| **SPDX** | `--format spdx` | SBOM standard (v2.3) | ✅ |
| **OpenVEX** | `--format openvex` | Vulnerability exploitability (v0.2.0) | ✅ |
| **HTML** | `--format html` | Browser-viewable reports | ❌ |
| **PDF** | `--format pdf` | Printable reports, compliance artifacts | ❌ |

---

## Writing to File

```bash
# Output to file (default: stdout)
calvigil scan --format json --output results.json .
calvigil scan --format html --output report.html .
calvigil scan --format pdf --output report.pdf .
```

{: .note }
> All output files are created with mode `0600` (owner read/write only) since reports may contain sensitive information.

---

## Table (Default)

Human-readable tabular output for terminal use:

```bash
calvigil scan .
```

```
┌───────────────────────┬───────────────┬──────────┬───────────────┬───────────┐
│ ID                    │ Package       │ Severity │ Installed     │ Fixed In  │
├───────────────────────┼───────────────┼──────────┼───────────────┼───────────┤
│ CVE-2024-1234 ⚠ KEV  │ lodash        │ CRITICAL │ 4.17.20       │ 4.17.21   │
│ CVE-2024-5678        │ express       │ HIGH     │ 4.17.1        │ 4.18.2    │
│ GHSA-xxxx-yyyy-zzzz  │ django        │ MEDIUM   │ 4.2.0         │ 4.2.7     │
└───────────────────────┴───────────────┴──────────┴───────────────┴───────────┘

Summary:
  Total: 3 vulnerabilities
  Critical: 1 | High: 1 | Medium: 1 | Low: 0 | Unknown: 0
  ⚠️ Known exploited (CISA KEV): 1 — prioritize these fixes
```

---

## JSON

Structured JSON for programmatic consumption:

```bash
calvigil scan --format json .
```

```json
{
  "scan_info": {
    "path": "/path/to/project",
    "timestamp": "2026-06-12T10:30:00Z",
    "version": "5.0.0"
  },
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "aliases": ["GHSA-abcd-1234-efgh"],
      "package": "lodash",
      "version": "4.17.20",
      "fixed_in": "4.17.21",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "summary": "Prototype pollution in lodash",
      "source": "osv",
      "known_exploited": true,
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
      ]
    }
  ],
  "supply_chain_risk": {
    "score": 74,
    "level": "HIGH",
    "decision": "review_before_merge",
    "finding_count": 3,
    "new_dependencies": 1,
    "install_scripts": 1,
    "phantom_dependencies": 1,
    "guidance": [
      "Review new direct dependencies before release.",
      "Confirm install-time scripts are intentional and pinned."
    ],
    "findings": [
      {
        "id": "SCM-301",
        "category": "install-time-behavior",
        "title": "npm install script present",
        "severity": "HIGH",
        "confidence": "medium",
        "package": {
          "name": "esbuild",
          "version": "0.21.5",
          "ecosystem": "npm"
        },
        "evidence": "package-lock.json reports an install script",
        "recommendation": "Review the package provenance and install hook before release."
      }
    ]
  }
}
```

---

## Supply Chain Risk

When `scan --supply-chain-guard` is enabled, JSON and table reports include `supply_chain_risk`. This section is designed for CI gates and security review workflows that need to understand dependency-risk changes beyond known CVEs.

Key fields:

| Field | Meaning |
|:------|:--------|
| `score` | 0-100 weighted risk score from M1-M3 findings |
| `level` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `decision` | Release posture such as `allow`, `review_before_merge`, `verify_provenance`, or `block_release` |
| `findings` | Detailed `SCM-*` signals with package identity, evidence, and remediation guidance |
| `new_dependencies` | Count of new direct dependencies from report diffing |
| `install_scripts` | Count of install-time execution signals |
| `phantom_dependencies` | Count of lockfile packages not declared in manifests |

Use `calvigil supply-chain diff` to compare a baseline JSON report with a target report and emit the same risk model as table or JSON.

HTML and PDF reports include a compact Supply Chain Guard section with score, decision, guidance, and a capped list of review signals. Each visible signal names the package or project file, evidence, and the action reviewers should take. Use JSON output when you need every `SCM-*` finding for automation.

---

## SARIF

[Static Analysis Results Interchange Format](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning and VS Code:

```bash
calvigil scan --format sarif --output results.sarif .
```

**Upload to GitHub Code Scanning:**

```yaml
# .github/workflows/security.yml
- name: Run calvigil
  run: calvigil scan --format sarif --output results.sarif .

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## CycloneDX (SBOM)

[CycloneDX v1.5](https://cyclonedx.org/) Software Bill of Materials with vulnerability information:

```bash
calvigil scan --format cyclonedx --output sbom.json .
```

Includes:
- Complete component inventory with PURLs
- Vulnerability records linked to components
- License information
- Dependency graph

---

## SPDX (SBOM)

[SPDX v2.3](https://spdx.dev/) Software Package Data Exchange format:

```bash
calvigil scan --format spdx --output sbom.spdx.json .
```

---

## OpenVEX

[OpenVEX v0.2.0](https://openvex.dev/) Vulnerability Exploitability eXchange:

```bash
calvigil scan --format openvex --output vex.json .
```

Useful for communicating which vulnerabilities are actually exploitable in your context.

---

## HTML

Interactive browser-viewable report:

```bash
calvigil scan --format html --output report.html .
open report.html  # macOS
```

Features:
- Sortable vulnerability table
- Severity color coding
- KEV indicators
- AI enrichment details (when available)
- AI code indicator badges

---

## PDF

Printable report for compliance and auditing:

```bash
calvigil scan --format pdf --output report.pdf .
```

---

## Filtering Results

### By Severity

```bash
# Only CRITICAL
calvigil scan --severity critical .

# HIGH and above
calvigil scan --severity high .

# MEDIUM and above
calvigil scan --severity medium .
```

### Combining with Output

```bash
# High+ findings as JSON
calvigil scan --severity high --format json --output high-vulns.json .
```

---

## CI/CD Integration

{: .note }
> For extensive platform-specific guides (GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps, Google Cloud Build, Jenkins, CircleCI), see the dedicated [CI/CD Integration]({% link ci-cd.md %}) page.

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install calvigil
        run: |
          curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
          tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/

      - name: Run scan
        run: calvigil scan --format sarif --output results.sarif .
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: golang:1.22
  script:
    - curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
    - tar xzf calvigil.tar.gz
    - ./calvigil scan --format json --output gl-sast-report.json .
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Exit Codes

| Code | Meaning |
|:-----|:--------|
| `0` | Scan completed successfully |
| `1` | Error occurred (bad path, parse failure, network error, etc.) |

{: .note }
> calvigil exits `0` even when vulnerabilities are found. Use `--format json` and post-process to fail CI on specific conditions.
