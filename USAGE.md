# Calvigil — Complete Usage Guide

A comprehensive reference for all commands, flags, configuration, and usage examples including AI-powered analysis.

---

## Table of Contents

- [Installation](#installation)
- [Configuration & Settings](#configuration--settings)
  - [Config File](#config-file)
  - [Environment Variables](#environment-variables)
  - [Setting API Keys](#setting-api-keys)
  - [Viewing Configuration](#viewing-configuration)
  - [All Config Keys](#all-config-keys)
- [Commands Reference](#commands-reference)
  - [scan](#scan)
  - [scan-image](#scan-image)
  - [config set](#config-set)
  - [config get](#config-get)
  - [version](#version)
- [Scan Examples](#scan-examples)
  - [Basic Dependency Scan (No API Keys Needed)](#1-basic-dependency-scan-no-api-keys-needed)
  - [Verbose Mode](#2-verbose-mode)
  - [JSON Output](#3-json-output)
  - [SARIF Output](#4-sarif-output-for-github-code-scanning--vs-code)
  - [CycloneDX SBOM Output](#5-cyclonedx-sbom-output)
  - [OpenVEX Output](#6-openvex-output)
  - [HTML Report](#7-html-report)
  - [PDF Report](#8-pdf-report)
  - [Filter by Severity](#9-filter-by-severity)
  - [Write to File](#10-write-output-to-file)
  - [AI-Powered Code Analysis](#11-ai-powered-code-analysis)
  - [AI-Only (Skip Dependencies)](#12-ai-only-scan-skip-dependency-checking)
  - [Full Scan (Dependencies + AI)](#13-full-scan-dependencies--ai-code-analysis)
- [Semgrep SAST Engine](#semgrep-sast-engine)
  - [Setup](#setup)
  - [Bundled Rule Packs](#bundled-rule-packs)
  - [Custom Rules](#custom-rules)
  - [Skipping Semgrep](#skipping-semgrep)
- [Standards Support](#standards-support)
  - [PURL (Package URL)](#purl-package-url)
  - [CycloneDX v1.5](#cyclonedx-v15)
  - [OpenVEX v0.2.0](#openvex-v020)
- [AI Use Cases](#ai-use-cases)
  - [Detecting SQL Injection](#detecting-sql-injection)
  - [Finding Hardcoded Secrets](#finding-hardcoded-secrets)
  - [Identifying Command Injection](#identifying-command-injection)
  - [Catching Insecure TLS](#catching-insecure-tls-configuration)
  - [OWASP Top 10 Coverage](#owasp-top-10-coverage)
- [AI Enrichment Layer](#ai-enrichment-layer)
  - [How It Works](#how-it-works)
  - [Enrichment Output Fields](#enrichment-output-fields)
  - [Example Enriched Output](#example-enriched-output)
- [Ollama (Local LLM) Support](#ollama-local-llm-support)
  - [Setup](#ollama-setup)
  - [Provider Selection](#provider-selection)
  - [Configuration](#ollama-configuration)
- [Container Image Scanning](#container-image-scanning)
  - [Prerequisites](#prerequisites)
  - [Usage Examples](#image-scanning-examples)
  - [Supported Ecosystems](#image-supported-ecosystems)
- [Supported Ecosystems & Files](#supported-ecosystems--files)
- [Vulnerability Databases](#vulnerability-databases)
- [Exit Codes](#exit-codes)

---

## Installation

### From Source

```bash
git clone https://github.com/chavakula/calvigil.git
cd calvigil
make build
# binary is at ./bin/calvigil
```

### Go Install

```bash
go install github.com/chavakula/calvigil@latest
```

---

## Configuration & Settings

### Config File

Configuration is stored in `~/.calvigil.json`:

```json
{
  "openai_api_key": "sk-proj-...",
  "openai_model": "gpt-4",
  "nvd_api_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "github_token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "ollama_url": "http://localhost:11434",
  "ollama_model": "llama3"
}
```

### Environment Variables

Environment variables **always take precedence** over config file values:

| Variable | Purpose |
|----------|---------|
| `OPENAI_API_KEY` | OpenAI API key for AI code analysis |
| `OPENAI_MODEL` | OpenAI model name (default: `gpt-4`) |
| `NVD_API_KEY` | NIST NVD API key for vulnerability lookups |
| `GITHUB_TOKEN` | GitHub token for advisory database access |
| `OLLAMA_URL` | Ollama server URL (default: `http://localhost:11434`) |
| `OLLAMA_MODEL` | Ollama model name (e.g. `llama3`, `codellama`, `mistral`) |

**Example — using environment variables:**

```bash
# Set keys via environment (add to ~/.zshrc or ~/.bashrc for persistence)
export OPENAI_API_KEY="sk-proj-abc123..."
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Now run scans — keys are picked up automatically
calvigil scan /path/to/project
```

### Setting API Keys

Use `config set` to persist keys to the config file:

```bash
# Required for AI-powered code analysis
calvigil config set openai-key sk-proj-abc123def456...

# Choose a specific OpenAI model
calvigil config set openai-model gpt-4-turbo

# Optional: NVD key gives higher rate limits (50 req/30s vs 5 req/30s)
# Get one free at: https://nvd.nist.gov/developers/request-an-api-key
calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Optional: GitHub token for advisory database access
# Create at: https://github.com/settings/tokens
calvigil config set github-token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Viewing Configuration

```bash
# View a specific key (secrets are masked)
calvigil config get openai-key
# Output: ****abc1

calvigil config get openai-model
# Output: gpt-4-turbo

calvigil config get nvd-key
# Output: ****xxxx
```

### All Config Keys

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `openai-key` | For AI scan | — | OpenAI API key (`sk-proj-...` or `sk-...`) |
| `openai-model` | No | `gpt-4` | Model to use (`gpt-4`, `gpt-4-turbo`, `gpt-4o`, etc.) |
| `nvd-key` | No | — | NVD API key for higher rate limits |
| `github-token` | No | — | GitHub personal access token |
| `ollama-url` | No | `http://localhost:11434` | Ollama server URL |
| `ollama-model` | No | — | Ollama model name (e.g. `llama3`, `codellama`) |

---

## Commands Reference

### `scan`

Scan a project directory for vulnerabilities.

```
calvigil scan [path] [flags]
```

**Arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | No | `.` (current dir) | Path to the project directory |

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif`, `cyclonedx`, `openvex`, `html`, `pdf` |
| `--output` | `-o` | stdout | Write output to a file |
| `--severity` | `-s` | (all) | Minimum severity filter: `critical`, `high`, `medium`, `low` |
| `--skip-ai` | — | `false` | Skip AI code analysis (dependency scan only) |
| `--skip-deps` | — | `false` | Skip dependency scan (code analysis only) |
| `--skip-semgrep` | — | `false` | Skip Semgrep SAST analysis |
| `--semgrep-rules` | — | (bundled) | Path to custom Semgrep rule directory |
| `--provider` | — | `auto` | AI provider: `openai`, `ollama`, or `auto` |
| `--ollama-url` | — | `http://localhost:11434` | Ollama server URL |
| `--ollama-model` | — | — | Ollama model name (e.g. `llama3`, `codellama`, `mistral`) |
| `--verbose` | `-v` | `false` | Show detailed progress output |

---

### `scan-image`

Scan a container image for vulnerabilities. Requires [syft](https://github.com/anchore/syft).

```
calvigil scan-image <image> [flags]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `image` | Yes | Image reference: `nginx:latest`, `docker-archive:image.tar`, `dir:/path` |

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif`, `cyclonedx`, `openvex`, `html`, `pdf` |
| `--output` | `-o` | stdout | Write output to a file |
| `--severity` | `-s` | (all) | Minimum severity filter: `critical`, `high`, `medium`, `low` |
| `--verbose` | `-v` | `false` | Show detailed progress output |

---

### `config set`

Set a configuration value.

```
calvigil config set <key> <value>
```

**Examples:**

```bash
calvigil config set openai-key sk-proj-abc123...
calvigil config set openai-model gpt-4o
calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
calvigil config set github-token ghp_xxxxxxxxxxxx
calvigil config set ollama-url http://localhost:11434
calvigil config set ollama-model llama3
```

---

### `config get`

Get a configuration value (secrets are masked).

```
calvigil config get <key>
```

**Examples:**

```bash
calvigil config get openai-model
# Output: gpt-4o

calvigil config get openai-key
# Output: ****23...
```

---

### `version`

Print the version.

```bash
calvigil version
# Output: calvigil v0.1.0 (built with go1.26.0)
```

---

## Scan Examples

### 1. Basic Dependency Scan (No API Keys Needed)

Scan a Node.js project's dependencies against the OSV database:

```bash
calvigil scan --skip-ai /path/to/node-project
```

**Example output:**

```
🔍 Calvigil Scan Results for /path/to/node-project
   Scanned 142 packages across 1 ecosystems in 2.3s

📦 Dependency Vulnerabilities (3 found)

╭──────────┬────────────────────┬──────────────┬─────────┬─────────┬────────────────────────────────────────╮
│ SEVERITY │ ID                 │ PACKAGE      │ VERSION │ FIXED   │ SUMMARY                                │
├──────────┼────────────────────┼──────────────┼─────────┼─────────┼────────────────────────────────────────┤
│ CRITICAL │ GHSA-xxxx-xxxx     │ lodash       │ 4.17.15 │ 4.17.21 │ Prototype Pollution in lodash           │
│ HIGH     │ CVE-2023-xxxxx     │ express      │ 4.17.1  │ 4.17.3  │ Open redirect vulnerability             │
│ MEDIUM   │ CVE-2022-xxxxx     │ minimatch    │ 3.0.4   │ 3.1.2   │ ReDoS vulnerability                     │
╰──────────┴────────────────────┴──────────────┴─────────┴─────────┴────────────────────────────────────────╯

Summary: 3 total vulnerabilities
  🔴 Critical: 1
  🟠 High:     1
  🟡 Medium:   1
```

---

### 2. Verbose Mode

See detailed progress during scanning:

```bash
calvigil scan --skip-ai -v /path/to/go-project
```

**Example output:**

```
🔍 Scanning /path/to/go-project ...

📂 Detecting project ecosystems...
   Found 1 manifest files across 1 ecosystems
   - go.mod (Go)

📦 Parsing dependencies...
   Parsed 5 packages from go.mod
   Total: 5 packages

🔎 Querying vulnerability databases...
   Skipping NVD (no API key configured)
   Skipping GitHub Advisory (no token configured)
   Found 0 dependency vulnerabilities

✅ No vulnerabilities found in /path/to/go-project
   Scanned 5 packages across 1 ecosystems in 1s
```

---

### 3. JSON Output

Get machine-readable JSON output for scripting and pipelines:

```bash
calvigil scan --skip-ai --format json /path/to/project
```

**Example output:**

```json
{
  "project_path": "/path/to/project",
  "ecosystems": ["npm"],
  "total_packages": 142,
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-xxxx",
      "aliases": ["CVE-2021-23337"],
      "summary": "Prototype Pollution in lodash",
      "severity": "CRITICAL",
      "score": 9.8,
      "package": {
        "name": "lodash",
        "version": "4.17.15",
        "ecosystem": "npm",
        "file_path": "/path/to/project/package-lock.json"
      },
      "fixed_in": "4.17.21",
      "source": "osv",
      "references": ["https://github.com/advisories/GHSA-xxxx-xxxx"]
    }
  ],
  "scanned_at": "2026-03-12T10:30:00Z",
  "duration": 2300000000
}
```

**Pipe to `jq` for filtering:**

```bash
# Count critical vulnerabilities
calvigil scan --skip-ai --format json . | jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length'

# List all affected packages
calvigil scan --skip-ai --format json . | jq '.vulnerabilities[].package.name'

# Get only package names with fixes available
calvigil scan --skip-ai --format json . | jq '.vulnerabilities[] | select(.fixed_in != "") | {package: .package.name, current: .package.version, fix: .fixed_in}'
```

---

### 4. SARIF Output (for GitHub Code Scanning / VS Code)

Generate SARIF v2.1.0 output for integration with GitHub Code Scanning or VS Code:

```bash
# Write SARIF to file
calvigil scan --format sarif --output results.sarif /path/to/project
```

**Upload to GitHub Code Scanning:**

```bash
# In a GitHub Actions workflow:
- name: Run security scan
  run: calvigil scan --format sarif --output results.sarif --skip-ai .

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Example SARIF output:**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "calvigil",
        "version": "0.1.0",
        "rules": [{
          "id": "SEC-005",
          "shortDescription": { "text": "Hardcoded Secret or API Key" },
          "defaultConfiguration": { "level": "error" }
        }]
      }
    },
    "results": [{
      "ruleId": "SEC-005",
      "level": "error",
      "message": { "text": "Hardcoded Secret or API Key" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/config.py" },
          "region": { "startLine": 15 }
        }
      }]
    }]
  }]
}
```

---

### 5. CycloneDX SBOM Output

Generate a CycloneDX v1.5 Software Bill of Materials with vulnerability data:

```bash
calvigil scan --format cyclonedx --output sbom.json /path/to/project
```

**Example CycloneDX output:**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-13T10:00:00Z",
    "tools": [{ "vendor": "calvigil", "name": "calvigil", "version": "0.1.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.15",
      "purl": "pkg:npm/lodash@4.17.15"
    }
  ],
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-xxxx",
      "ratings": [{ "severity": "high", "score": 7.5 }],
      "description": "Prototype Pollution in lodash",
      "recommendation": "Upgrade to 4.17.21",
      "affects": [{ "ref": "pkg:npm/lodash@4.17.15" }]
    }
  ]
}
```

CycloneDX output includes AI enrichment analysis when available (mapped to CycloneDX analysis states: `exploitable`, `false_positive`, `in_triage`).

---

### 6. OpenVEX Output

Generate an OpenVEX v0.2.0 document for vulnerability exploitability exchange:

```bash
calvigil scan --format openvex --output vex.json /path/to/project
```

**Example OpenVEX output:**

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://calvigil/vex/xxxxxxxx",
  "author": "calvigil",
  "timestamp": "2026-03-13T10:00:00Z",
  "statements": [
    {
      "vulnerability": { "@id": "https://osv.dev/vulnerability/GHSA-xxxx-xxxx", "name": "GHSA-xxxx-xxxx" },
      "products": [{
        "@id": "pkg:npm/lodash@4.17.15",
        "subcomponents": [{ "@id": "pkg:npm/lodash@4.17.15" }]
      }],
      "status": "affected",
      "action_statement": "Upgrade lodash from 4.17.15 to 4.17.21"
    }
  ]
}
```

OpenVEX statuses are determined by AI enrichment confidence:
- **HIGH confidence** → `affected`
- **MEDIUM confidence** → `under_investigation`
- **LOW confidence** → `not_affected` (with justification)
- **No AI enrichment** → `affected` (default)

---

### 7. HTML Report

Generate a professional, self-contained HTML report with severity charts, color-coded badges, and AI enrichment details. Ideal for sharing with management, MIS teams, or non-technical stakeholders:

```bash
calvigil scan --format html --output report.html /path/to/project
```

The HTML report includes:
- **Executive summary cards** — total, critical, high, medium, low counts at a glance
- **Severity distribution bar** — visual breakdown by severity
- **Dependency vulnerability table** — sorted by severity with package info, fix versions
- **Code analysis & Semgrep findings** — file locations, line numbers
- **AI enrichment details** — impact, confidence, remediation, suppression rationale
- **Print-friendly CSS** — looks good when printed from a browser

The report is fully self-contained (all CSS embedded) with no external dependencies.

---

### 8. PDF Report

Generate a print-ready PDF report. This uses headless Chrome/Chromium (`--print-to-pdf`) to convert the HTML report to PDF:

```bash
# Chrome is typically pre-installed; or install it:
brew install --cask google-chrome   # macOS
brew install --cask chromium         # macOS (Chromium)
apt-get install chromium-browser     # Debian/Ubuntu

# Generate PDF
calvigil scan --format pdf --output report.pdf /path/to/project

# Or point to a custom Chrome binary
export CHROME_PATH=/usr/bin/chromium
calvigil scan --format pdf --output report.pdf /path/to/project
```

The PDF uses Chrome's print engine for pixel-perfect rendering of CSS grid, flexbox, and media queries. It contains the same content as the HTML report.

---

### 9. Filter by Severity

Only show vulnerabilities at or above a given severity level:

```bash
# Only critical
calvigil scan --severity critical /path/to/project

# High and above (high + critical)
calvigil scan --severity high /path/to/project

# Medium and above
calvigil scan -s medium /path/to/project
```

---

### 10. Write Output to File

```bash
# Table output to file
calvigil scan --output report.txt /path/to/project

# JSON to file
calvigil scan --format json --output report.json /path/to/project

# SARIF to file
calvigil scan --format sarif --output results.sarif /path/to/project

# CycloneDX SBOM to file
calvigil scan --format cyclonedx --output sbom.json /path/to/project

# OpenVEX to file
calvigil scan --format openvex --output vex.json /path/to/project

# HTML report
calvigil scan --format html --output report.html /path/to/project

# PDF report (requires Chrome or Chromium)
calvigil scan --format pdf --output report.pdf /path/to/project
```

---

### 11. AI-Powered Code Analysis

**Prerequisites:** Set your OpenAI API key first.

```bash
# Set key (one-time)
calvigil config set openai-key sk-proj-abc123def456...

# Or use environment variable
export OPENAI_API_KEY="sk-proj-abc123def456..."
```

**Run a full scan (dependencies + AI):**

```bash
calvigil scan -v /path/to/project
```

**Example output with AI findings:**

```
🔍 Calvigil Scan Results for /path/to/project
   Scanned 28 packages across 2 ecosystems in 12.4s

📦 Dependency Vulnerabilities (1 found)

╭──────────┬────────────────────┬──────────────┬─────────┬─────────┬──────────────────────────────╮
│ SEVERITY │ ID                 │ PACKAGE      │ VERSION │ FIXED   │ SUMMARY                      │
├──────────┼────────────────────┼──────────────┼─────────┼─────────┼──────────────────────────────┤
│ HIGH     │ CVE-2023-xxxxx     │ pyyaml       │ 5.3.1   │ 6.0.1   │ Arbitrary code execution     │
╰──────────┴────────────────────┴──────────────┴─────────┴─────────┴──────────────────────────────╯

🔬 Code Analysis Findings (3 found)

╭──────────┬─────────┬────────────────────┬──────┬──────────────────────────────────────────────────╮
│ SEVERITY │ ID      │ FILE               │ LINE │ FINDING                                          │
├──────────┼─────────┼────────────────────┼──────┼──────────────────────────────────────────────────┤
│ CRITICAL │ SEC-003 │ app/views.py       │   42 │ Potential Command Injection                      │
│ HIGH     │ SEC-005 │ config/settings.py │   15 │ Hardcoded Secret or API Key                      │
│ HIGH     │ AI-001  │ app/views.py       │   67 │ SQL query built from unsanitized user input       │
╰──────────┴─────────┴────────────────────┴──────┴──────────────────────────────────────────────────╯

Summary: 4 total vulnerabilities
  🔴 Critical: 1
  🟠 High:     3
```

---

### 12. AI-Only Scan (Skip Dependency Checking)

Only run code analysis (pattern matching + AI):

```bash
calvigil scan --skip-deps -v /path/to/project
```

---

### 13. Full Scan (Dependencies + AI Code Analysis)

Run everything — dependencies against all CVE databases and AI code analysis:

```bash
# Set up all keys for maximum coverage
calvigil config set openai-key sk-proj-...
calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
calvigil config set github-token ghp_xxxxxxxxxxxx

# Full scan with all databases + AI
calvigil scan -v /path/to/project
```

---

## Semgrep SAST Engine

The scanner integrates with [Semgrep CE](https://semgrep.dev/) (Community Edition) for static application security testing. Semgrep is automatically detected and used when available.

### Setup

```bash
# Install Semgrep
pip install semgrep

# Verify installation
semgrep --version
```

When Semgrep is not installed, the scanner gracefully skips SAST analysis and continues with dependency scanning and AI analysis.

### Bundled Rule Packs

The scanner ships with **30 security rules** in `rules/semgrep/`:

**`owasp-top10.yaml`** — 18 rules covering OWASP Top 10:

| Category | Languages | Rules |
|----------|-----------|-------|
| SQL Injection | Go, Python, Java, JS | Format string + concatenation patterns |
| Command Injection | Go, Python, JS | `exec.Command`, `subprocess`, `child_process` |
| Path Traversal | Go, Python | Unsanitized path joins |
| Hardcoded Secrets | All | API keys, passwords, tokens in source |
| Insecure TLS | Go, Python | `InsecureSkipVerify`, disabled cert checks |
| Weak Crypto | Go, Python | MD5, SHA1, DES for security purposes |
| XSS | Go, JS | Template injection, `innerHTML` |
| Insecure Deserialization | Python, Java | `pickle.loads`, `ObjectInputStream` |
| SSRF | Go, Python | Unvalidated URL from user input |

**`language-specific.yaml`** — 12 language-specific rules:

| Language | Rules |
|----------|-------|
| Go | `unsafe.Pointer`, `http.Client` without timeout, `defer` in loop |
| Python | Flask debug mode, bind to `0.0.0.0`, `assert` for auth checks |
| JavaScript/TypeScript | `eval()`, CORS wildcard `*`, JWT without verification |
| Java | XXE-vulnerable XML parser, ECB mode encryption |

### Custom Rules

Point the scanner at your own Semgrep rule directory:

```bash
# Use only your custom rules
calvigil scan --semgrep-rules ./my-company-rules/ /path/to/project

# Rules are standard Semgrep YAML format
# See: https://semgrep.dev/docs/writing-rules/rule-syntax/
```

The scanner will also pick up any `.semgrep/` directory in the project root automatically.

### Skipping Semgrep

```bash
# Skip Semgrep analysis entirely
calvigil scan --skip-semgrep /path/to/project
```

**Example output with Semgrep findings:**

```
🛡️ Semgrep SAST Findings (2 found)

╭──────────┬─────────────────────┬────────────────┬──────┬────────────────────────────────────────╮
│ SEVERITY │ ID                  │ FILE           │ LINE │ FINDING                                │
├──────────┼─────────────────────┼────────────────┼──────┼────────────────────────────────────────┤
│ CRITICAL │ SG-command-inject   │ handler.go     │   42 │ Command injection via exec.Command     │
│ HIGH     │ SG-sql-injection    │ db/queries.py  │   15 │ SQL injection via string formatting     │
╰──────────┴─────────────────────┴────────────────┴──────┴────────────────────────────────────────╯
```

---

## Standards Support

### PURL (Package URL)

All packages are identified using standard [Package URLs](https://github.com/package-url/purl-spec). PURLs appear in JSON, CycloneDX, and OpenVEX output.

**Format:** `pkg:<type>/<namespace>/<name>@<version>`

| Ecosystem | PURL Type | Example |
|-----------|-----------|---------|
| Go | `golang` | `pkg:golang/github.com/hashicorp/vault@v1.15.2` |
| npm | `npm` | `pkg:npm/@babel/helpers@7.15.4` |
| npm (unscoped) | `npm` | `pkg:npm/ajv@6.12.6` |
| PyPI | `pypi` | `pkg:pypi/requests@2.28.0` |
| Maven | `maven` | `pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0` |

PURLs are auto-generated from package metadata and appear in:
- JSON output: `package.purl` field
- CycloneDX: `components[].purl` and `vulnerabilities[].affects[].ref`
- OpenVEX: `statements[].products[].@id`

### CycloneDX v1.5

The CycloneDX output produces a complete SBOM/VDR (Software Bill of Materials / Vulnerability Disclosure Report):

```bash
calvigil scan --format cyclonedx --output sbom.json /path/to/project
```

**Includes:**
- **Metadata**: scan timestamp, tool information
- **Components**: all detected packages with PURLs
- **Vulnerabilities**: all findings with severity ratings, descriptions, fixed-in versions, advisories, and affected component references
- **AI Analysis**: when enrichment is available, mapped to CycloneDX analysis states (`exploitable`, `false_positive`, `in_triage`)

Compatible with tools that consume CycloneDX: [Dependency-Track](https://dependencytrack.org/), [OWASP DefectDojo](https://defectdojo.com/), [Grype](https://github.com/anchore/grype), etc.

### OpenVEX v0.2.0

The OpenVEX output produces a VEX document for communicating vulnerability exploitability:

```bash
calvigil scan --format openvex --output vex.json /path/to/project
```

**Includes:**
- **Context**: OpenVEX v0.2.0 namespace
- **Statements**: one per vulnerability with product PURLs
- **Status**: `affected`, `not_affected`, or `under_investigation`
- **Justification**: AI-derived rationale for non-affected status
- **Action**: remediation guidance (e.g., upgrade instructions)

VEX status is derived from AI enrichment confidence:

| AI Confidence | VEX Status | Meaning |
|---------------|------------|---------|
| HIGH | `affected` | Confirmed exploitable |
| MEDIUM | `under_investigation` | Needs further review |
| LOW | `not_affected` | Likely not exploitable (with justification) |
| N/A | `affected` | Default when no AI enrichment |

Compatible with the [OpenVEX](https://openvex.dev/) ecosystem and tools like [vexctl](https://github.com/openvex/vexctl).

---

## AI Use Cases

The AI analyzer works in two stages:
1. **Pattern matching** (always runs, no API key needed) — fast regex-based detection of common vulnerability patterns
2. **OpenAI GPT-4 deep analysis** (requires API key) — sends flagged code snippets for semantic analysis, confirms/dismisses false positives, and finds additional issues

### Detecting SQL Injection

**Vulnerable code (`app/db.py`):**

```python
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
```

**Scanner output:**

```
│ HIGH │ SEC-002 │ app/db.py │ 2 │ Potential SQL Injection (string concat) │
```

**AI recommendation (with `--verbose`):**

> SQL query built with string concatenation from user input. Use parameterized queries:
> ```python
> cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
> ```

---

### Finding Hardcoded Secrets

**Vulnerable code (`config.js`):**

```javascript
const API_KEY = "sk-proj-abc123def456ghi789jkl012mno345";
const DB_PASSWORD = "super_secret_password_123";
```

**Scanner output:**

```
│ HIGH     │ SEC-005 │ config.js │  1 │ Hardcoded Secret or API Key │
│ HIGH     │ SEC-005 │ config.js │  2 │ Hardcoded Secret or API Key │
```

---

### Identifying Command Injection

**Vulnerable code (`handler.go`):**

```go
func runCommand(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}
```

**Scanner output:**

```
│ CRITICAL │ SEC-003 │ handler.go │ 3 │ Potential Command Injection │
```

---

### Catching Insecure TLS Configuration

**Vulnerable code (`client.go`):**

```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

**Scanner output:**

```
│ CRITICAL │ SEC-010 │ client.go │ 2 │ TLS Certificate Verification Disabled │
```

---

### OWASP Top 10 Coverage

The scanner detects vulnerabilities mapped to the OWASP Top 10:

| OWASP Category | Detection Rules |
|----------------|----------------|
| A01: Broken Access Control | AI analysis of auth/middleware patterns |
| A02: Cryptographic Failures | SEC-007 (weak MD5/SHA1), SEC-005 (hardcoded secrets), SEC-006 (AWS keys) |
| A03: Injection | SEC-001/SEC-002 (SQL injection), SEC-003 (command injection), SEC-008 (XSS) |
| A04: Insecure Design | AI analysis of architectural patterns |
| A05: Security Misconfiguration | SEC-010 (TLS disabled), SEC-012 (CORS wildcard), SEC-009 (HTTP) |
| A06: Vulnerable Components | Dependency scanning (OSV, NVD, GitHub Advisory) |
| A07: Auth Failures | AI analysis of authentication code |
| A08: Data Integrity | SEC-011 (insecure deserialization) |
| A09: Logging Failures | AI analysis of logging practices |
| A10: SSRF | SEC-004 (path traversal), AI analysis of URL handling |

---

## AI Enrichment Layer

When an OpenAI API key is configured, the scanner automatically enriches **all** vulnerabilities (both dependency and code findings) with structured AI analysis. This provides actionable context beyond raw CVE data.

### How It Works

1. **Evidence collection** — For each finding, the scanner builds a structured evidence block containing: package name/version, advisory text, severity, CVSS score, dependency path, file locations, code snippets, matched pattern rules, reachability hints, and known fix versions.
2. **AI analysis** — Evidence blocks are batched and sent to GPT-4 with a specialized enrichment prompt.
3. **Structured output** — The model returns structured fields (not free-form text) that are attached to each vulnerability.

### Enrichment Output Fields

| Field | Description |
|-------|-------------|
| **Summary** | 3-line summary: (1) what the vuln is, (2) how it's exploited, (3) affected component |
| **Likely Impact** | Realistic impact assessment (e.g., "Remote code execution via crafted YAML payload") |
| **Confidence** | HIGH / MEDIUM / LOW — whether this is a real, exploitable issue in context |
| **Minimal Remediation** | Smallest targeted fix (e.g., "Upgrade lodash from 4.17.15 to 4.17.21") |
| **Suppression Rationale** | Draft rationale for accepting risk (e.g., "Only used in test fixtures") |

### Example Enriched Output

**Table format** (with enrichment details printed below each table):

```
📦 Dependency Vulnerabilities (1 found)

╭──────────┬────────────────┬────────┬────────┬─────────┬──────────────────────────╮
│ Severity │ ID             │ Package│ Version│ Fixed In│ Summary                  │
├──────────┼────────────────┼────────┼────────┼─────────┼──────────────────────────┤
│ HIGH     │ GHSA-xxxx-xxxx │ lodash │ 4.17.15│ 4.17.21 │ Prototype Pollution      │
╰──────────┴────────────────┴────────┴────────┴─────────┴──────────────────────────╯

  🤖 AI Enrichment Details:

  ── GHSA-xxxx-xxxx (HIGH) [Confidence: HIGH] ──
     Prototype pollution in lodash < 4.17.21.
     Attacker can inject properties via mergeWith or zipObjectDeep.
     Affects lodash used in server-side request parsing.
     Impact: Remote DoS or privilege escalation via __proto__ injection
     Fix: Upgrade lodash from 4.17.15 to 4.17.21
     Suppress: Only used in build tooling; not reachable from user input
```

**JSON format** — enrichment fields appear directly on each vulnerability object:

```json
{
  "id": "GHSA-xxxx-xxxx",
  "severity": "HIGH",
  "ai_enrichment": {
    "summary": "Prototype pollution in lodash < 4.17.21.\nAttacker can inject...",
    "likely_impact": "Remote DoS or privilege escalation via __proto__ injection",
    "confidence": "HIGH",
    "minimal_remediation": "Upgrade lodash from 4.17.15 to 4.17.21",
    "suppression_rationale": "Only used in build tooling; not reachable from user input"
  }
}
```

**SARIF format** — enrichment is appended to the result message text for compatibility with code scanning tools.

To skip AI enrichment (e.g., for faster scans), use `--skip-ai`:

```bash
calvigil scan ./my-project --skip-ai
```

---

## Ollama (Local LLM) Support

Run AI-powered code analysis and enrichment entirely offline using [Ollama](https://ollama.ai/).

### Ollama Setup

```bash
# 1. Install Ollama
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# 2. Start the Ollama server
ollama serve

# 3. Pull a model
ollama pull llama3         # general-purpose
ollama pull codellama      # code-focused
ollama pull mistral        # fast and capable

# 4. Configure the scanner
calvigil config set ollama-model llama3
# or via environment variable:
export OLLAMA_MODEL=llama3
```

### Provider Selection

The `--provider` flag controls which AI backend is used:

| Provider | Behavior |
|----------|----------|
| `auto` (default) | Uses Ollama if configured and reachable, otherwise falls back to OpenAI |
| `ollama` | Uses Ollama only; fails if Ollama is not available |
| `openai` | Uses OpenAI only; requires `openai-key` configured |

```bash
# Auto-detect (default) — Ollama first, then OpenAI
calvigil scan

# Force Ollama
calvigil scan --provider ollama --ollama-model llama3

# Force OpenAI
calvigil scan --provider openai

# Use a remote Ollama server
calvigil scan --provider ollama \
  --ollama-url http://gpu-server:11434 \
  --ollama-model codellama
```

### Ollama Configuration

Configuration priority (highest to lowest):
1. CLI flags (`--ollama-url`, `--ollama-model`)
2. Environment variables (`OLLAMA_URL`, `OLLAMA_MODEL`)
3. Config file (`~/.calvigil.json`)

```bash
# Persist Ollama settings
calvigil config set ollama-url http://localhost:11434
calvigil config set ollama-model llama3

# Or use environment variables
export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=llama3
```

The Ollama analyzer supports both OpenAI-compatible (`/v1/chat/completions`) and native Ollama (`/api/chat`) endpoints, with automatic fallback.

---

## Container Image Scanning

Scan Docker/OCI container images for known vulnerabilities.

### Prerequisites

Install [syft](https://github.com/anchore/syft) — an SBOM generator for container images:

```bash
# macOS
brew install syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

### Image Scanning Examples

```bash
# Scan a Docker Hub image
calvigil scan-image nginx:latest

# Scan with verbose output
calvigil scan-image python:3.12-slim -v

# Output as JSON
calvigil scan-image node:20 --format json

# Output as SARIF for CI integration
calvigil scan-image ubuntu:22.04 --format sarif --output results.sarif

# Output as CycloneDX SBOM
calvigil scan-image alpine:3.18 --format cyclonedx --output sbom.json

# Filter by severity
calvigil scan-image python:3.12 --severity high

# Scan a local Docker archive
calvigil scan-image docker-archive:myapp.tar

# Scan an extracted root filesystem
calvigil scan-image dir:/path/to/rootfs
```

### Image Supported Ecosystems

The image scanner maps syft artifact types to vulnerability ecosystems:

| Syft Type | Ecosystem | Database |
|-----------|-----------|----------|
| `npm` | npm | OSV, NVD, GitHub Advisory |
| `python`, `pip`, `wheel` | PyPI | OSV, NVD, GitHub Advisory |
| `go-module` | Go | OSV, NVD, GitHub Advisory |
| `java-archive`, `maven` | Maven | OSV, NVD, GitHub Advisory |
| `gem` | RubyGems | OSV |
| `rust-crate` | crates.io | OSV |
| `deb` | DEB (Debian) | OSV |
| `apk` | APK (Alpine) | OSV |
| `rpm` | RPM (RHEL/CentOS) | OSV |

---

## Supported Ecosystems & Files

| Ecosystem | Icon | PURL Type | Manifest Files Parsed |
|-----------|------|-----------|----------------------|
| **Go** | 🐹 | `golang` | `go.mod` |
| **Python** | 🐍 | `pypi` | `requirements.txt`, `Pipfile.lock`, `poetry.lock` |
| **Node.js** | 📗 | `npm` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Java** | ☕ | `maven` | `pom.xml`, `build.gradle`, `build.gradle.kts` |

Table output groups vulnerabilities by ecosystem with icons for easy identification.

**Source code analysis** scans files with these extensions:
`.go`, `.py`, `.java`, `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.html`, `.yaml`, `.yml`, `.json`, `.env`, `.properties`

**Auto-skipped directories:**
`node_modules`, `.git`, `vendor`, `__pycache__`, `.idea`, `.vscode`, `target`, `build`, `dist`, `.next`, `.nuxt`

---

## Vulnerability Databases

| Database | API Key Required | Rate Limit | Notes |
|----------|-----------------|------------|-------|
| **OSV.dev** | No | Unlimited | Primary source, batch API, always enabled |
| **NVD** | Optional | 5/30s (no key), 50/30s (with key) | Set `nvd-key` for better limits |
| **GitHub Advisory** | Optional | 60/hr (no token), 5000/hr (with token) | Set `github-token` for access |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully |
| `1` | Error occurred (bad path, parse failure, etc.) |
