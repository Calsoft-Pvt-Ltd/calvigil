---
title: Architecture
layout: default
nav_order: 9
---

# Architecture
{: .no_toc }

High-level design and internal structure of calvigil.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## System Overview

<p align="center">
  <img src="{{ '/assets/images/architecture-calvigil.png' | relative_url }}" alt="Calvigil architecture" >
</p>

---

## Component Responsibilities

| Component | Package | Purpose |
|:----------|:--------|:--------|
| **CLI Layer** | `cmd/` | Command parsing, flag handling, user interaction |
| **Scanner** | `internal/scanner/` | Pipeline orchestration — ties all engines together |
| **Detector** | `internal/detector/` | Filesystem walk to identify project ecosystems |
| **Parser** | `internal/parser/` | Extract dependencies from manifest/lock files; integrity checks |
| **Matcher** | `internal/matcher/` | Query CVE databases; canonical normalize + merge; KEV enrichment |
| **Analyzer** | `internal/analyzer/` | AI code analysis, 47 pattern rules, 77+ Semgrep rules |
| **Reporter** | `internal/reporter/` | Format and emit scan results (8 formats) |
| **Image Scanner** | `internal/image/` | Container image scanning via Syft |
| **IaC Scanner** | `internal/iac/` | Regex-based misconfiguration scanner (25 rules) |
| **Binary Scanner** | `internal/binary/` | SCA on compiled artifacts (Go, JAR, Python wheel) |
| **License** | `internal/license/` | License classification, SPDX parser, registry resolver |
| **Cache** | `internal/cache/` | File-based vulnerability response caching |
| **Config** | `internal/config/` | Credential & preference management; OS keyring + fallback |
| **FS Util** | `internal/fsutil/` | Shared skip-dir rules for all walkers |
| **Models** | `internal/models/` | Shared data structures (Vulnerability, Package, etc.) |

---

## Scan Pipeline Flow

```
1. DETECT      → Find manifest files, identify ecosystems
2. PARSE       → Extract packages from lock files, generate PURLs
3. MATCH       → Query all databases concurrently
4. NORMALIZE   → Apply Canonical Data Model (ID preference, severity fallback)
5. MERGE       → Combine duplicate findings across sources
6. ENRICH      → CISA KEV lookup, mark exploited-in-the-wild
7. ANALYZE     → Pattern rules + Semgrep + AI (if enabled)
8. REPORT      → Format output (table/json/sarif/html/pdf/...)
```

---

## Matcher Architecture

The matcher package uses an interface-based design:

```go
type Matcher interface {
    Name() string
    Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error)
}
```

**Implementations:**
- `OSVMatcher` — batch API, 1000 packages/request
- `OSSIndexMatcher` — PURL-based, 128 coords/batch
- `NVDMatcher` — paced package keyword search plus exact-CVE CVSS enrichment
- `GitHubAdvisoryMatcher` — ecosystem-based advisory lookup

**Aggregation:**
- `AggregatedMatcher` runs all matchers concurrently
- Results are normalized via `Normalize()` (canonical.go)
- Duplicates are merged via `Merge()` (fills missing fields)
- `KEVEnricher` flags exploited CVEs post-aggregation

---

## Extensibility

| Extension Point | Interface / Pattern | How to Add |
|:----------------|:-------------------|:-----------|
| New CVE source | `matcher.Matcher` | Implement `Name()` + `Match()`, add to scanner's matcher list |
| New parser | `parser.Parser` | Implement `Parse()`, register in ecosystem detection |
| New output format | `reporter.Reporter` | Add format handler in reporter package |
| New IaC rule | Rule struct in `iac/` | Add regex pattern + metadata |
| New AI provider | Same interface as OpenAI/Ollama | Implement chat completion handler |

---

## Security Design

| Layer | Protection |
|:------|:-----------|
| **Secrets** | OS keyring (macOS Keychain, Windows CM, Linux SS); file fallback with `0600` permissions |
| **Output** | All report files written with `0600` permissions |
| **Input** | Image references validated against shell metacharacters |
| **Dependencies** | Integrity verification via lockfile checksums |
| **Network** | TLS enforced; rate limiting respected; graceful degradation on API failures |
| **Cache** | Local file-based; keyed by SHA-256 of source + package list |
