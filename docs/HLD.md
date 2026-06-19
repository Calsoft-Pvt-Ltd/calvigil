# Calvigil — High-Level Design (HLD)

**Version:** 1.2
**Date:** May 2026
**Module:** `github.com/Calsoft-Pvt-Ltd/calvigil`

> **Change log**
> - **1.2 (May 2026):** Added 18 AI-generated code anti-pattern rules (AI-SEC-001..018), new Semgrep `ai-code-quality.yaml` rule pack (25+ rules), AI code indicator in enrichment layer, enhanced AI prompts for AI-code detection, CHANGELOG.md.
> - **1.1 (Apr 2026):** Added IaC scanner, binary/SCA scanner, supply-chain integrity & phantom-dependency checks, vulnerability cache, OS keyring secret store, image-reference validation, project-rules trust opt-in, shared filesystem skip helper, CI integration, and SPDX 2.3 reporter sections. Renumbered duplicate "Section 9".
> - **1.0 (Mar 2026):** Initial HLD.

---

## 1. Introduction

### 1.1 Purpose
Calvigil is an open-source, AI-powered vulnerability scanner CLI designed to detect security vulnerabilities in **Go**, **Java (Maven/Gradle)**, **Python (pip/poetry/pipenv/uv)**, **Node.js (npm/yarn/pnpm)**, **Rust**, **Ruby**, **PHP**, and **C/C++** projects. It combines dependency scanning, AI code analysis, static analysis (SAST), IaC scanning, binary/SCA scanning, container image scanning, and license compliance — into a single unified tool.

### 1.2 Scope
This document covers the high-level architecture, major components, data flow, external integrations, and deployment model of the Calvigil system.

### 1.3 Goals
- Detect known CVEs in project dependencies via multiple vulnerability databases
- Identify OWASP Top 10 security issues in source code using AI (GPT-4/Ollama/LM Studio) and pattern matching
- Perform static analysis using Semgrep CE with bundled security rules
- Scan container images for vulnerable packages
- Scan compiled binaries and archives for embedded dependency vulnerabilities
- Scan IaC files (Terraform, Kubernetes, Dockerfile, CloudFormation, Docker Compose, Helm) for misconfigurations
- License compliance scanning with SPDX expression support and registry-based license resolution
- Generate reports in 8 formats: Table, JSON, SARIF, CycloneDX, OpenVEX, SPDX 2.3, HTML, PDF
- Enrich findings with AI-generated impact analysis, remediation, and confidence scores

---

## 2. System Context

```
┌─────────────────────────────────────────────────────────────────┐
│                         Developer                               │
│                                                                 │
│   $ calvigil scan ./myproject --format sarif                    │
│   $ calvigil scan-image nginx:latest                            │
│   $ calvigil scan-license ./myproject --format html              │
│   $ calvigil scan-iac ./infra/ --format json                    │
│   $ calvigil config set openai-key sk-...                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Calvigil CLI (Go binary)                    │
│                                                                 │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Dep Scan │  │ AI Scan   │  │ SAST     │  │ Image Scan    │  │
│  ├──────────┤  ├───────────┤  ├──────────┤  ├───────────────┤  │
│  │ License  │  │ IaC Scan  │  │ Binary   │  │ Cache Layer   │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └──────┬────────┘  │
│       │              │              │               │           │
└───────┼──────────────┼──────────────┼───────────────┼───────────┘
        │              │              │               │
        ▼              ▼              ▼               ▼
┌──────────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────────┐ ┌──────────────────┐
│ CVE Databases│ │ LLM APIs │ │ Semgrep CE│ │ Syft (Anchore)   │ │ License Registries│
│ • OSV.dev    │ │ • OpenAI │ │ (external │ │ (SBOM extraction)│ │ • deps.dev        │
│ • OSS Index  │ │ • Ollama │ │  binary)  │ │                  │ │ • PyPI            │
│ • NVD (NIST) │ │          │ │           │ │                  │ │ • npm registry    │
│ • GitHub Adv │ │          │ │           │ │                  │ │ • RubyGems        │
│ • CISA KEV   │ │          │ │           │ │                  │ │                   │
└──────────────┘ └──────────┘ └───────────┘ └──────────────────┘ └──────────────────┘
```

---

## 3. Architecture Overview

Calvigil follows a **pipeline architecture** with clearly separated stages:

```
     ┌───────────┐
     │  CLI Cmd   │  (cobra commands: scan, scan-image, push, config, version)
     └─────┬─────┘
           │
     ┌─────▼──────┐
     │  Scanner    │  Orchestration engine
     │ (Pipeline)  │
     └─────┬──────┘
           │
  ┌────────┼────────────────────┐
  │        │                    │
  ▼        ▼                    ▼
┌─────┐ ┌──────┐          ┌─────────┐
│Dep  │ │Source│          │ Semgrep │
│Scan │ │Code  │          │ SAST    │
│     │ │AI    │          │         │
└──┬──┘ └──┬───┘          └────┬────┘
   │       │                   │
   ▼       ▼                   ▼
┌────────────────────────────────────┐
│       Unified Vulnerability List   │
│  + Dep Paths + Reachability        │
│  + AI Enrichment                   │
│  + Supply Chain Checks             │
│    (Integrity, Phantom Deps, MAL)  │
└──────────────┬─────────────────────┘
               │
         ┌─────▼─────┐
         │  Reporter  │  (table/json/sarif/cyclonedx/openvex/html/pdf)
         └───────────┘
```

### 3.1 Major Components

| Component | Package | Responsibility |
|-----------|---------|----------------|
| **CLI Layer** | `cmd/` | Command parsing, flag handling, user interaction |
| **Scanner** | `internal/scanner/` | Pipeline orchestration — ties all engines together |
| **Detector** | `internal/detector/` | Filesystem walk to identify project ecosystems |
| **Parser** | `internal/parser/` | Extract dependencies from manifest/lock files; integrity verification; phantom dep detection |
| **Matcher** | `internal/matcher/` | Query CVE databases (OSV, OSS Index, NVD, GHSA); canonical normalization + cross-source merge; CISA KEV enrichment |
| **Analyzer** | `internal/analyzer/` | AI code analysis (OpenAI/Ollama/LM Studio), 47 pattern rules (29 SEC + 18 AI-SEC for AI-generated code), 77+ Semgrep rules across 3 packs |
| **Reporter** | `internal/reporter/` | Format and emit scan results |
| **Image Scanner** | `internal/image/` | Container image scanning via Syft, image-reference validation |
| **IaC Scanner** | `internal/iac/` | Regex-based misconfiguration scanner for Terraform / Kubernetes / Dockerfile / CloudFormation / Docker Compose / Helm (25 built-in rules) |
| **Binary Scanner** | `internal/binary/` | SCA on compiled artifacts: Go binaries (`debug/buildinfo`), JARs (`pom.properties` / MANIFEST.MF / filename), Python wheels (`.dist-info/METADATA`) |
| **License** | `internal/license/` | License classification, SPDX expression parser, registry resolver |
| **Cache** | `internal/cache/` | File-based vulnerability response caching (~/.calvigil/cache/) |
| **Config** | `internal/config/` | Credential and preference management; OS keyring + file-fallback secret store |
| **FS Util** | `internal/fsutil/` | Single source of truth for skip-dir rules shared by all walkers |
| **Models** | `internal/models/` | Shared data structures (Vulnerability, Package, ScanResult, IntegrityIssue, ConsistencyIssue) |

---

## 4. Supported Ecosystems

| Ecosystem | Manifest Files | Parser |
|-----------|---------------|--------|
| **Go** | `go.mod` | `GoModParser` (uses `golang.org/x/mod`) |
| **Python** | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` | `RequirementsTxtParser`, `PipfileLockParser`, `PoetryLockParser`, `UvLockParser` |
| **Node.js** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `NpmLockParser`, `YarnLockParser`, `PnpmLockParser` |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` | `PomXMLParser`, `GradleParser` |
| **Rust** | `Cargo.lock` | `CargoLockParser` (`internal/parser/rust.go`) |
| **Ruby** | `Gemfile.lock` | `GemfileLockParser` (`internal/parser/ruby.go`) |
| **PHP** | `composer.lock` | `ComposerLockParser` (`internal/parser/php.go`) |
| **C/C++** | `conan.lock` | `ConanLockParser` (`internal/parser/conan.go`) |

---

## 5. External Integrations

### 5.1 Vulnerability Databases

| Database | API Endpoint | Auth | Rate Limit | Role |
|----------|-------------|------|------------|------|
| **OSV.dev** | `POST /v1/querybatch` | None | Unrestricted | Primary — batch queries, no API key needed |
| **Sonatype OSS Index** | `POST /api/v3/component-report` | Existing/migrated token | 128 coords/request | Optional — PURL-based, all ecosystems |
| **NVD** | `GET /rest/json/cves/2.0` | Optional API key | 5 req/30s (free), 50 req/30s (keyed) | Secondary — paced package keyword search plus batched exact-CVE CVSS enrichment |
| **GitHub Advisory** | `GET /advisories` | Optional PAT | Standard GitHub limits | Supplementary — GHSA cross-references |
| **CISA KEV** | `GET known_exploited_vulnerabilities.json` | None | Unrestricted | Enrichment — flags actively exploited CVEs (`KnownExploited`) |

All matcher results pass through the **Canonical Data Model** (`internal/matcher/canonical.go`): IDs are normalized (CVE preferred, GHSA/ecosystem IDs become aliases), severity is derived from CVSS vectors/scores when a source omits it, and duplicate findings across databases are merged by ID or alias — missing fields are filled in from whichever source provides them. OSV records are also strengthened by fetching a CVE alias when an ecosystem-specific record such as `GO-*` omits CVSS data. After matching, findings with CVE IDs but missing CVSS data are enriched from NVD using resilient exact `cveIds` requests: up to 100 CVEs per request, a 2-minute per-request timeout, controlled keyed parallelism with six-second request pacing, transient-error backoff, split fallback for timeout/503 responses, partial-result preservation, a bounded 10-minute enrichment budget, a CalVigil User-Agent, source-aware CVSS selection that prefers NVD primary scoring and falls back to contributed sources such as CISA-ADP, and a 24h local CVE cache.

### 5.2 AI Providers

| Provider | Endpoint | Use Case |
|----------|---------|----------|
| **OpenAI** | ChatCompletion API (GPT-4) | Cloud AI analysis (higher quality) |
| **Ollama** | `/v1/chat/completions` (local) | Privacy-first local LLM (llama3, codellama, mistral) |
| **LM Studio** | `/v1/chat/completions` (local) | Desktop-friendly local LLM with GUI model management |

### 5.3 License Registries

| Registry | API Endpoint | Ecosystems |
|----------|-------------|------------|
| **deps.dev** | `GET /v3alpha/systems/{go,maven,cargo}/packages/{name}` and version endpoints | Go, Maven, Rust |
| **PyPI** | `GET /pypi/{name}/{version}/json`, fallback `GET /pypi/{name}/json` | Python |
| **npm** | `GET /{name}/{version}` | Node.js |
| **RubyGems** | `GET /api/v1/gems/{name}.json` | Ruby |

License resolution runs in parallel (bounded at 10 goroutines) and enriches packages missing license metadata from lockfiles. PyPI resolution prefers structured `license_expression` metadata, then short legacy `license` values, normalized license classifiers such as `Mozilla Public License 2.0 (MPL 2.0)`, and canonical full license text for common licenses such as MIT. Regular scan JSON uses this best-effort enrichment for package inventory data; `--check-licenses` and `scan-license` additionally classify licenses and emit compliance issues.

### 5.4 External Tools

| Tool | Purpose | Required For |
|------|---------|-------------|
| **Semgrep CE** | SAST engine | `scan` (unless `--skip-semgrep`) |
| **Syft** (Anchore) | Container SBOM extraction | `scan-image` |
| **Chrome/Chromium** | Headless PDF rendering | `--format pdf` |

---

## 6. Data Flow — Project Scan

```
User runs: calvigil scan ./myproject --format json
                         │
            ┌────────────▼───────────────┐
            │ 1. DETECT ECOSYSTEMS       │
            │    Walk project directory   │
            │    Match known lock files   │
            │    → [go.mod, package.json] │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 2. PARSE DEPENDENCIES      │
            │    Select parser per file   │
            │    Extract (name, version)  │
            │    Generate PURLs           │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 3. MATCH VULNERABILITIES   │
            │    OSV batch query          │
            │    NVD keyword + CVE enrich │
            │    GitHub Advisory lookup   │
            │    Deduplicate by CVE+alias │
            └────────────┬───────────────┘
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
┌──────▼──────┐  ┌───────▼──────┐  ┌───────▼──────┐
│ 4a. PATTERN │  │ 4b. AI CODE  │  │ 4c. SEMGREP  │
│    MATCH    │  │   ANALYSIS   │  │    SAST      │
│ 12 regex    │  │ GPT-4/Ollama │  │ Bundled +    │
│ rules       │  │ source scan  │  │ custom rules │
└──────┬──────┘  └───────┬──────┘  └───────┬──────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 5. POST-PROCESSING         │
            │    • Dependency path mapping│
            │    • Reachability analysis  │
            │    • AI enrichment          │
            │    • Severity filtering     │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 6. REPORT                  │
            │    → JSON/SARIF/Table/etc. │
            └────────────────────────────┘
```

---

## 7. Data Flow — License Scan (`calvigil scan-license`)

```
User runs: calvigil scan-license ./myproject --format html
                         │
            ┌────────────▼───────────────┐
            │ 1. DETECT ECOSYSTEMS       │
            │    Walk project directory   │
            │    Match known lock files   │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 2. PARSE DEPENDENCIES      │
            │    Extract (name, version)  │
            │    from manifest/lock files │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 3. RESOLVE LICENSES        │
            │    Query registries for     │
            │    missing license metadata │
            │    (deps.dev, PyPI, npm,    │
            │     RubyGems) — 10 parallel │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 4. CLASSIFY & CHECK        │
            │    SPDX expression parsing  │
            │    (OR/AND/WITH support)    │
            │    → permissive/copyleft/   │
            │      unknown classification │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 5. REPORT (LicenseOnly)    │
            │    License Compliance Report│
            │    with SVG donut chart     │
            └────────────────────────────┘
```

---

## 8. Data Flow — Supply Chain Checks

Supply chain checks integrate into the main scan pipeline (Step 2a) after dependency parsing. They run regardless of `--skip-deps` when `--verify-integrity` is set.

```
                         │
            ┌────────────▼───────────────┐
            │ 2. PARSE DEPENDENCIES      │
            │    Extract (name, version,  │
            │    integrity, checksum)     │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 2a. SUPPLY CHAIN CHECKS    │
            │                            │
            │ ┌────────────────────────┐  │
            │ │ INTEGRITY VERIFICATION │  │
            │ │ (if --verify-integrity)│  │
            │ │ npm: compare SRI hash  │  │
            │ │   vs registry.npmjs.org│  │
            │ │ Cargo: flag missing    │  │
            │ │   checksums            │  │
            │ └────────────────────────┘  │
            │                            │
            │ ┌────────────────────────┐  │
            │ │ PHANTOM DETECTION      │  │
            │ │ (always-on)            │  │
            │ │ Compare lockfile direct│  │
            │ │ deps vs manifest       │  │
            │ │ (package.json)         │  │
            │ └────────────────────────┘  │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 3. MATCH + REPORT          │
            │    MAL- entries split into  │
            │    dedicated ☠️ section     │
            │    IntegrityIssues → 🔐     │
            │    ConsistencyIssues → 👻   │
            └────────────────────────────┘
```

---

## 10. Data Flow — Container Image Scan

```
User runs: calvigil scan-image nginx:latest
                         │
            ┌────────────▼───────────────┐
            │ 0. VALIDATE IMAGE REFERENCE│
            │    Reject shell metachars   │
            │    (;, |, &, `, $(), \n)   │
            │    Validate scheme prefix   │
            │    or OCI ref pattern       │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 1. SBOM EXTRACTION         │
            │    syft nginx:latest -o json│
            │    → Package list           │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 2. ECOSYSTEM MAPPING       │
            │    Map syft types to        │
            │    ecosystem (npm, pypi...) │
            │    Generate PURLs           │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 3. VULNERABILITY MATCHING  │
            │    Same matchers as scan    │
            │    (OSV, OSS Index,         │
            │     NVD, GHSA)              │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 4. REPORT                  │
            └────────────────────────────┘
```

---

## 11. Output Formats

| Format | Standard/Spec | Primary Use Case |
|--------|--------------|-----------------|
| **Table** | Terminal output | Developer console review |
| **JSON** | Native JSON | CI/CD pipeline consumption, custom tooling |
| **SARIF** | SARIF v2.1.0 | GitHub Code Scanning, VS Code, IDE integration |
| **CycloneDX** | CycloneDX v1.5 | SBOM + VDR for supply chain compliance |
| **OpenVEX** | OpenVEX v0.2.0 | Vulnerability exploitability exchange |
| **SPDX** | SPDX v2.3 | SBOM with packages, licenses, PURLs, and vulnerability annotations |
| **HTML** | Self-contained HTML | Executive reports with severity charts and license donut chart |
| **PDF** | Rendered via Chrome | Formal audit reports |

---

## 12. Configuration & Security

### 12.1 Non-Secret Configuration
- **Location:** `~/.calvigil.yaml` (created with mode `0600`)
- Stores non-sensitive preferences only: model name, Ollama URL, default cache TTL, etc.

### 12.2 Secret Storage (API keys)
API keys are **never written to the YAML config file**. They are stored in a pluggable secret store with auto-fallback:

| Backend | When used | Storage |
|---------|----------|---------|
| OS keyring | Default when available | macOS Keychain / Windows Credential Manager / Linux Secret Service via `go-keyring` |
| Encrypted-file fallback | When keyring probe fails (CI / containers / headless) | `~/.calvigil-secrets.json`, mode `0600` |

The store is selected lazily on first access (`sync.Once` probe). Override with the `CALVIGIL_SECRET_BACKEND` environment variable: `keyring`, `file`, or unset (auto).

**Recognized secrets:** `openai-key`, `nvd-key`, `github-token`, `ossindex-token`. **Recognized env-var overrides:** `OPENAI_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `OSSINDEX_USER`, `OSSINDEX_TOKEN`, `OLLAMA_URL`, `OLLAMA_MODEL`, `LMSTUDIO_URL`, `LMSTUDIO_MODEL`.

`config get` masks secrets as `****<last4>`.

### 12.3 Output File Permissions
All reports written via `--output` are created with mode `0600`. Reports may contain CVE inventories, package lists, and AI-enriched code snippets.

### 12.4 Container Image Reference Validation
`scan-image` validates the reference before invoking syft. Refs containing `;`, `|`, `&`, backticks, `$(...)`, newlines, or NUL bytes are rejected. Scheme-prefixed refs (`docker-archive:`, `dir:`, `oci:`, etc.) and OCI refs (`name[:tag][@sha256:digest]`) are matched against allow-list patterns in `internal/image/validate.go`.

### 12.5 Custom Semgrep Rules — Trust Model
Semgrep rule files execute as code. By default calvigil only loads bundled rules. To load rules from a path inside the scanned project:

```bash
calvigil scan . --semgrep-rules ./.semgrep --trust-project-rules
```

Without `--trust-project-rules`, rule paths inside the scanned project are rejected. Symlinks in `--semgrep-rules` are resolved before the trust check, preventing escape via in-project symlinks.

### 12.6 Skip-Dir Convention
All five filesystem walkers (detector, source analyzer, binary scanner, IaC scanner, license scanner) share `internal/fsutil.SkippedSubDirs`. Directory names such as `testdata`, `test-fixtures`, `node_modules`, `vendor`, `target`, `__pycache__`, `.venv`, `.git`, `.terraform`, `dist`, `build`, `.mypy_cache` are skipped **only when encountered as a subdirectory of the scan root**. A user explicitly running `calvigil scan ./testdata` (e.g. integration tests) still gets it scanned.

This follows the Go convention that `go test` ignores `testdata`. It also prevents the project's CI self-scan from flagging deliberately-vulnerable integration fixtures (log4j, old urllib3, etc.) as real vulnerabilities.

### 12.7 AI Provider Selection
Automatic provider resolution priority:
1. Explicit `--provider` flag → use specified
2. Ollama available locally → prefer Ollama (privacy)
3. LM Studio available locally → use LM Studio
4. OpenAI API key configured → use OpenAI
5. Neither → skip AI analysis

---

## 13. Deployment Model

Calvigil is a **single static Go binary** with no runtime dependencies beyond optional external tools:

```
Required:   Go binary (calvigil)
Optional:   Semgrep CE (pip install semgrep)   — for SAST
            Syft       (brew install syft)      — for image scanning
            Chrome     (system install)         — for PDF reports
            Ollama     (ollama serve)            — for local AI
            LM Studio  (lmstudio.ai)            — for local AI (GUI)
```

### 11.1 Build
```bash
make build          # → bin/calvigil
make install        # → $GOPATH/bin/calvigil
```

Version is embedded at build time via `-ldflags`:
```
-X github.com/Calsoft-Pvt-Ltd/calvigil/cmd.version=$(VERSION)
```

---

## 14. Technology Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Go 1.25 |
| **CLI Framework** | Cobra v1.10.2 |
| **AI Client** | go-openai v1.41.2 |
| **Table Rendering** | go-pretty/v6 v6.7.8 |
| **Module Parsing** | golang.org/x/mod v0.34.0 |
| **YAML Parsing** | gopkg.in/yaml.v3 |
| **SAST Engine** | Semgrep CE (external) |
| **SBOM Tool** | Syft (external) |

---

## 15. Non-Functional Requirements

| Attribute | Design Decision |
|-----------|----------------|
| **Performance** | OSV batch API (up to 1000 packages/request); NVD package keyword search is enabled with a 20-package cap and conservative pacing; NVD CVE enrichment uses exact 100-ID `cveIds` batches, a 2-minute request timeout, a 10-minute budget, six-second request pacing, controlled keyed parallelism, plus 24h CVE cache; AI batches of 20 snippets; vulnerability cache (~/.calvigil/cache/, default 24h TTL); license resolution at 10-way concurrency; integrity verification at 10-way concurrency |
| **Privacy** | Ollama and LM Studio support for fully local AI analysis; secret store prefers OS keyring; no telemetry |
| **Extensibility** | Parser, Matcher, Analyzer, Reporter, IaCRule, PatternRule all implemented as interfaces or rule arrays |
| **Portability** | Single static binary; cross-platform (macOS, Linux, Windows); keyring auto-falls-back to file in headless environments |
| **Graceful degradation** | Missing Semgrep/Syft/AI/Chrome → skip that engine, continue scan |
| **Safe-by-default** | `0600` perms on config + reports + secrets file; image-ref validated against shell metacharacters; project Semgrep rules require explicit opt-in; `testdata/`-style dirs auto-skipped |

---

## 16. Data Flow — IaC Misconfiguration Scan

```
User runs: calvigil scan-iac ./infra --severity high
                         │
            ┌────────────▼───────────────┐
            │ 1. WALK FILESYSTEM         │
            │    fsutil.ShouldSkipSubDir  │
            │    Match by extension or    │
            │    basename:                │
            │    .tf .tfvars .yaml .yml   │
            │    Dockerfile compose.yml   │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 2. APPLY 25 RULES          │
            │    Regex-based, per file:   │
            │    Terraform: SG/S3/IAM/RDS/│
            │      CloudTrail             │
            │    Kubernetes: Privileged,  │
            │      RunAsRoot, HostNet,    │
            │      ResourceLimits         │
            │    Dockerfile: Root, latest,│
            │      ADD, curl|sh           │
            │    CloudFormation, Compose, │
            │      Helm                   │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 3. CONVERT TO VULNS        │
            │    iac.ToVulnerabilities()  │
            │    Source = "iac"           │
            │    Filter by --severity     │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 4. REPORT                  │
            └────────────────────────────┘
```

Files are scanned concurrently with a worker pool. Each rule has explicit
`FileTypes` and `Category`; matches are emitted as `iac.Finding` and then
mapped to `models.Vulnerability` for the standard reporters.

---

## 17. Data Flow — Binary / SCA Scan

```
User runs: calvigil scan-binary ./bin --format json
                         │
            ┌────────────▼───────────────┐
            │ 1. WALK & DISPATCH         │
            │    fsutil.ShouldSkipSubDir  │
            │    By extension or magic:   │
            │      go-binary  → buildinfo │
            │      .jar       → zip+meta  │
            │      .whl/.egg  → wheel meta│
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 2. EXTRACT PACKAGES        │
            │    Go: debug/buildinfo →   │
            │      module + deps with    │
            │      versions              │
            │    JAR: pom.properties →   │
            │      MANIFEST.MF →         │
            │      filename heuristic    │
            │    Wheel: METADATA + name  │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 3. MATCH VULNERABILITIES   │
            │    Same matchers as scan    │
            │    (OSV / OSS Index /       │
            │     NVD / GHSA)             │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 4. REPORT                  │
            └────────────────────────────┘
```

---

## 18. Vulnerability Result Cache

Disk cache for matcher responses keyed by `sha256(source-name + sorted package list)`.

| Property | Value |
|----------|-------|
| Location | `~/.calvigil/cache/` |
| Format | One JSON file per cache key |
| Default TTL | 24h (`--cache-ttl=1h` to override) |
| Disable | `--no-cache` |
| Eviction | Lazy on `Get` (entry past `ExpiresAt` → cache miss) |
| Manual purge | Delete `~/.calvigil/cache/` |

Cache layer stores the merged result of the aggregated matcher (OSV / OSS Index / NVD / GHSA). Used by `scan`, `scan-image`, and `scan-binary`. Not used by `scan-license` (license registries have their own short-lived in-process call sites).

---

## 19. CI/CD Integration

`.github/workflows/security-scan.yml` is the project's own self-scan workflow and a reference recipe for downstream users:

```yaml
- name: Self-scan
  env:
    CALVIGIL_SECRET_BACKEND: file        # skip the keyring probe
  run: |
    calvigil scan . \
      --skip-ai \
      --semgrep-rules rules/semgrep \
      --format sarif --output calvigil.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: calvigil.sarif }
```

Key CI guidance:
- Set `CALVIGIL_SECRET_BACKEND=file` to skip the keyring probe on headless runners.
- Use `--skip-ai` on PR runs to avoid LLM token cost.
- Use `--format sarif` and the official upload action to surface findings in the GitHub Security tab.
- Run from the repository root; `testdata/` and similar directories are skipped automatically (see §12.6).

---

## 20. Roadmap / Extension Points

The following extension points are stable contracts that downstream code (and AI-assisted enhancement work) can target:

| Extension Point | Interface / Pattern | How to extend |
|---|---|---|
| New ecosystem | `parser.Parser` + register in `parser.ForFile()` and `detector.knownMarkers` | Implement `Parse(io.Reader, string) ([]Package, error)`; add manifest filename mapping |
| New CVE source | `matcher.Matcher` + add to scanner's matcher list | Implement `Name()` and `Match(ctx, []Package) ([]Vulnerability, error)` |
| New AI provider | `analyzer.Analyzer` + add provider id to `Scanner.resolveAIProvider()` | Implement `Analyze(ctx, projectPath, verbose)` and optional `EnrichVulnerabilities(...)` |
| New IaC rule | Append to `iacRules` slice in `internal/iac/scanner.go` | Provide ID, Name, Severity, Pattern, FileTypes, Category |
| New pattern rule | Append to `builtInRules` in `internal/analyzer/patterns.go` | Provide ID, Name, Severity, Pattern, Languages |
| New report format | `reporter.Reporter` + add case to `reporter.ForFormat()` | Implement `Report(*ScanResult, io.Writer) error` |
| New skip directory | `fsutil.SkippedSubDirs` map | Add basename; all walkers pick it up automatically |
| New secret backend | `secretStore` interface in `internal/config/secrets.go` | Implement Get/Set/Delete; wire into `getStore()` |
