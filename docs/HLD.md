# Calvigil — High-Level Design (HLD)

**Version:** 1.0  
**Date:** March 2026  
**Module:** `github.com/Calsoft-Pvt-Ltd/calvigil`

---

## 1. Introduction

### 1.1 Purpose
Calvigil is an open-source, AI-powered vulnerability scanner CLI designed to detect security vulnerabilities in **Go**, **Java (Maven/Gradle)**, **Python (pip/poetry/pipenv)**, and **Node.js (npm/yarn/pnpm)** projects. It combines three distinct detection engines — dependency scanning, AI code analysis, and static analysis (SAST) — into a single unified tool.

### 1.2 Scope
This document covers the high-level architecture, major components, data flow, external integrations, and deployment model of the Calvigil system.

### 1.3 Goals
- Detect known CVEs in project dependencies via multiple vulnerability databases
- Identify OWASP Top 10 security issues in source code using AI (GPT-4/Ollama) and pattern matching
- Perform static analysis using Semgrep CE with bundled security rules
- Scan container images for vulnerable packages
- Generate reports in 7 formats: Table, JSON, SARIF, CycloneDX, OpenVEX, HTML, PDF
- Enrich findings with AI-generated impact analysis, remediation, and confidence scores

---

## 2. System Context

```
┌─────────────────────────────────────────────────────────────────┐
│                         Developer                               │
│                                                                 │
│   $ calvigil scan ./myproject --format sarif                    │
│   $ calvigil scan-image nginx:latest                            │
│   $ calvigil config set openai-key sk-...                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Calvigil CLI (Go binary)                    │
│                                                                 │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Dep Scan │  │ AI Scan   │  │ SAST     │  │ Image Scan    │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └──────┬────────┘  │
│       │              │              │               │           │
└───────┼──────────────┼──────────────┼───────────────┼───────────┘
        │              │              │               │
        ▼              ▼              ▼               ▼
┌──────────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────────┐
│ CVE Databases│ │ LLM APIs │ │ Semgrep CE│ │ Syft (Anchore)   │
│ • OSV.dev    │ │ • OpenAI │ │ (external │ │ (SBOM extraction)│
│ • NVD (NIST) │ │ • Ollama │ │  binary)  │ │                  │
│ • GitHub Adv │ │          │ │           │ │                  │
└──────────────┘ └──────────┘ └───────────┘ └──────────────────┘
```

---

## 3. Architecture Overview

Calvigil follows a **pipeline architecture** with clearly separated stages:

```
     ┌───────────┐
     │  CLI Cmd   │  (cobra commands: scan, scan-image, config, version)
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
| **Parser** | `internal/parser/` | Extract dependencies from manifest/lock files |
| **Matcher** | `internal/matcher/` | Query CVE databases (OSV, NVD, GHSA) |
| **Analyzer** | `internal/analyzer/` | AI code analysis (OpenAI/Ollama), pattern matching, Semgrep |
| **Reporter** | `internal/reporter/` | Format and emit scan results |
| **Image Scanner** | `internal/image/` | Container image scanning via Syft |
| **Config** | `internal/config/` | Credential and preference management |
| **Models** | `internal/models/` | Shared data structures (Vulnerability, Package, ScanResult) |

---

## 4. Supported Ecosystems

| Ecosystem | Manifest Files | Parser |
|-----------|---------------|--------|
| **Go** | `go.mod` | `GoModParser` (uses `golang.org/x/mod`) |
| **Python** | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | `RequirementsTxtParser`, `PipfileLockParser`, `PoetryLockParser` |
| **Node.js** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `NpmLockParser`, `YarnLockParser`, `PnpmLockParser` |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` | `PomXMLParser`, `GradleParser` |

---

## 5. External Integrations

### 5.1 Vulnerability Databases

| Database | API Endpoint | Auth | Rate Limit | Role |
|----------|-------------|------|------------|------|
| **OSV.dev** | `POST /v1/querybatch` | None | Unrestricted | Primary — batch queries, no API key needed |
| **NVD** | `GET /rest/json/cves/2.0` | Optional API key | 5 req/30s (free), 50 req/30s (keyed) | Secondary — CVSS enrichment |
| **GitHub Advisory** | `GET /advisories` | Optional PAT | Standard GitHub limits | Supplementary — GHSA cross-references |

### 5.2 AI Providers

| Provider | Endpoint | Use Case |
|----------|---------|----------|
| **OpenAI** | ChatCompletion API (GPT-4) | Cloud AI analysis (higher quality) |
| **Ollama** | `/v1/chat/completions` (local) | Privacy-first local LLM (llama3, codellama, mistral) |

### 5.3 External Tools

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
            │    NVD keyword search       │
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

## 7. Data Flow — Container Image Scan

```
User runs: calvigil scan-image nginx:latest
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
            │    (OSV, NVD, GHSA)         │
            └────────────┬───────────────┘
                         │
            ┌────────────▼───────────────┐
            │ 4. REPORT                  │
            └────────────────────────────┘
```

---

## 8. Output Formats

| Format | Standard/Spec | Primary Use Case |
|--------|--------------|-----------------|
| **Table** | Terminal output | Developer console review |
| **JSON** | Native JSON | CI/CD pipeline consumption, custom tooling |
| **SARIF** | SARIF v2.1.0 | GitHub Code Scanning, VS Code, IDE integration |
| **CycloneDX** | CycloneDX v1.5 | SBOM + VDR for supply chain compliance |
| **OpenVEX** | OpenVEX v0.2.0 | Vulnerability exploitability exchange |
| **HTML** | Self-contained HTML | Executive reports, sharing with stakeholders |
| **PDF** | Rendered via Chrome | Formal audit reports |

---

## 9. Configuration & Security

### 9.1 Configuration Storage
- **Location:** `~/.calvigil.json`
- **Environment overrides:** `OPENAI_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `OLLAMA_URL`, `OLLAMA_MODEL`
- **Secret masking:** API keys displayed as `****<last4>` in `config get`

### 9.2 AI Provider Selection
Automatic provider resolution priority:
1. Explicit `--provider` flag → use specified
2. Ollama available locally → prefer Ollama (privacy)
3. OpenAI API key configured → use OpenAI
4. Neither → skip AI analysis

---

## 10. Deployment Model

Calvigil is a **single static Go binary** with no runtime dependencies beyond optional external tools:

```
Required:   Go binary (calvigil)
Optional:   Semgrep CE (pip install semgrep)   — for SAST
            Syft       (brew install syft)      — for image scanning
            Chrome     (system install)         — for PDF reports
            Ollama     (ollama serve)            — for local AI
```

### 10.1 Build
```bash
make build          # → bin/calvigil
make install        # → $GOPATH/bin/calvigil
```

Version is embedded at build time via `-ldflags`:
```
-X github.com/Calsoft-Pvt-Ltd/calvigil/cmd.version=$(VERSION)
```

---

## 11. Technology Stack

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

## 12. Non-Functional Requirements

| Attribute | Design Decision |
|-----------|----------------|
| **Performance** | OSV batch API (up to 1000 packages/request); NVD capped at 20 queries/scan; AI batches of 20 snippets |
| **Privacy** | Ollama support for fully local AI analysis; no telemetry |
| **Extensibility** | Parser, Matcher, Analyzer, Reporter all implemented as interfaces |
| **Portability** | Single static binary; cross-platform (macOS, Linux, Windows) |
| **Graceful degradation** | Missing Semgrep/Syft/AI → skip that engine, continue scan |
