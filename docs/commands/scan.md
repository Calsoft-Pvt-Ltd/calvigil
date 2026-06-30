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
| `--pattern-rules` | | none | Path to custom regex pattern rule YAML/JSON file or directory |
| `--disable-builtin-patterns` | | `false` | Run only custom regex pattern rules from `--pattern-rules` |
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
3. **Pattern rules** — 52 built-in regex rules (29 SEC + 23 AI-SEC) for common vulnerability patterns
4. **Semgrep SAST** — 77+ semantic rules for deep code analysis (unless `--skip-semgrep`)
5. **AI code analysis** — When `--ai` is enabled, source files are sent to the configured AI provider for OWASP Top 10 detection
6. **AI slop code-smell scoring** — AI-SEC, Semgrep AI-code-quality, and optional AI enrichment indicators are aggregated into a review-prioritization score

---

## AI Slop Code Smells

The scanner reports an `slop_code_smells` object when source findings show repeated quality and security symptoms that deserve extra human review. This improves the older AI-code detection by merging three signal sources:

- Built-in `AI-SEC-*` regex rules
- Bundled Semgrep `ai-code-quality.yaml` rules
- Optional AI enrichment values such as `ai_code_indicator: LIKELY_AI`

This feature is deliberately conservative: it does **not** prove that a file was AI-generated. It scores concrete symptoms such as resource leaks, concurrency hazards, ignored errors, stale APIs, unbounded work, insecure defaults, validation gaps, and secret exposure.

Example:

```bash
calvigil scan --format json --output results.json .
```

Example JSON excerpt:

```json
{
  "slop_code_smells": {
    "score": 65,
    "level": "HIGH",
    "signal_count": 6,
    "categories": [
      {
        "id": "unbounded_work",
        "name": "Unbounded work",
        "count": 3,
        "weight": 31
      }
    ],
    "top_signals": [
      {
        "finding_id": "AI-SEC-015",
        "rule_id": "AI-SEC-015",
        "category_id": "unbounded_work",
        "title": "HTTP/DB call without timeout",
        "confidence": "HIGH"
      }
    ],
    "authorship_disclaimer": "Slop code smells are quality and security symptoms, not proof that code was AI-generated."
  }
}
```

## Custom Regex Pattern Rules

Use `--pattern-rules` when your team needs project, framework, or company-specific
review signals without forking calvigil:

```bash
calvigil scan . --pattern-rules ./security-rules.yaml
```

Rule packs can be YAML or JSON files, or a directory containing `.yaml`, `.yml`,
or `.json` files:

```yaml
rules:
  - id: CUSTOM-001
    name: Query-string tenant scope
    description: Tenant scope is read from a query string and must be authorized against request context.
    severity: HIGH
    pattern: 'URL\.Query\(\)\.Get\("tenant"\)'
    languages: [".go"]
```

The custom pattern engine uses Go's RE2 regular expressions. Duplicate built-in
rule IDs are rejected unless built-ins are disabled, and project-local rule packs
require `--trust-project-rules`.

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
