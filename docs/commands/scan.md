---
title: scan
layout: default
parent: Commands
nav_order: 1
---

# calvigil scan
{: .no_toc }

The primary command for dependency vulnerability scanning and AI code analysis.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Usage

```bash
calvigil scan [flags] <path>
```

## Flags

| Flag | Short | Default | Description |
|:-----|:------|:--------|:------------|
| `--ai` | | `false` | Enable AI-powered code analysis |
| `--ai-only` | | `false` | Skip dependency scanning, only run AI analysis |
| `--provider` | | `auto` | AI provider: `openai`, `ollama`, `lmstudio`, `auto` |
| `--ollama-url` | | from config | Ollama server URL |
| `--ollama-model` | | from config | Ollama model name |
| `--lmstudio-url` | | from config | LM Studio server URL |
| `--lmstudio-model` | | from config | LM Studio model name |
| `--semgrep-rules` | | bundled | Path to custom Semgrep rules YAML |
| `--skip-semgrep` | | `false` | Disable Semgrep SAST engine |
| `--skip-tests` | | `false` | Exclude test files from reachability analysis |
| `--verify-integrity` | | `false` | Verify lockfile integrity (checksums) |
| `--trust-project-rules` | | `false` | Allow Semgrep project-local rules |
| `--format` | `-f` | `table` | Output format |
| `--output` | `-o` | stdout | Output file path |
| `--severity` | `-s` | all | Minimum severity filter |
| `--verbose` | `-v` | `false` | Verbose output |
| `--no-cache` | | `false` | Disable vulnerability cache |
| `--cache-ttl` | | `24h` | Cache TTL duration |
| `--offline` | | `false` | Avoid network calls; parse local inventory and run local checks only |

---

## Examples

### Basic Dependency Scan

```bash
# No API keys needed — uses OSV.dev
calvigil scan .
```

### Verbose Mode

```bash
calvigil scan -v /path/to/project
```

Shows detailed progress including:
- Which databases are being queried
- Number of packages per ecosystem
- Merge/normalization details
- KEV enrichment results

### Offline Inventory Mode

```bash
calvigil scan --offline --skip-ai --skip-semgrep --format json .
```

Use offline mode when you need deterministic local package inventory or report-format validation without calling vulnerability databases, package registries, KEV, CVSS enrichment, or integrity registries.

### Full Scan (Dependencies + AI)

```bash
calvigil scan --ai --provider openai /path/to/project
```

### AI-Only (Skip Dependencies)

```bash
calvigil scan --ai-only /path/to/project
```

### Filter by Severity

```bash
# Only show HIGH and CRITICAL findings
calvigil scan --severity high .
```

### JSON Output to File

```bash
calvigil scan --format json --output results.json .
```

### SARIF for GitHub Code Scanning

```bash
calvigil scan --format sarif --output results.sarif .
```

### With Integrity Verification

```bash
calvigil scan --verify-integrity /path/to/project
```

This additionally checks:
- Lockfile checksums against registry hashes
- Phantom dependencies (in lockfile but not in manifest)
- Consistency between manifest and lockfile versions

---

## What Gets Scanned

1. **Dependency vulnerabilities** — Lock files are parsed, PURLs generated, and all packages checked against configured vulnerability databases
2. **CISA KEV enrichment** — Results are cross-referenced with the Known Exploited Vulnerabilities catalog
3. **Pattern rules** — 47 built-in regex rules (29 SEC + 18 AI-SEC) for common vulnerability patterns
4. **Semgrep SAST** — 77+ semantic rules for deep code analysis (unless `--skip-semgrep`)
5. **AI code analysis** — When `--ai` is enabled, source files are sent to the configured AI provider for OWASP Top 10 detection

---

## How Vulnerability Matching Works

```
Lock files → Parser → Packages (with PURLs)
                          │
                          ▼
              ┌─── AggregatedMatcher ───┐
              │                         │
              │  OSV.dev (batch)        │
              │  OSS Index (batch)      │
              │  NVD (if key)           │
              │  GitHub Advisory (if token) │
              │                         │
              └────────┬────────────────┘
                       │
                       ▼
              Canonical Normalize + Merge
                       │
                       ▼
              CISA KEV Enrichment
                       │
                       ▼
              Final Results (table/json/sarif/...)
```
