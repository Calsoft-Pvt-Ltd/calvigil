---
title: Home
layout: home
nav_order: 1
---

<p align="center">
  <img src="{{ '/assets/images/calvigil-logo.png' | relative_url }}" alt="Calvigil Logo" width="200">
</p>

# Calvigil

**AI-Powered Vulnerability Scanner CLI**
{: .fs-6 .fw-300 }

An open-source security scanner for **Go**, **Java**, **Python**, **Node.js**, **Rust**, **Ruby**, **PHP**, and **C/C++** projects. Combines dependency scanning, AI code analysis, SAST, container image scanning, IaC scanning, and license compliance in one tool.
{: .fs-5 .fw-300 }

[Get Started]({% link getting-started.md %}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/Calsoft-Pvt-Ltd/calvigil){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Key Features

| Feature | Description |
|:--------|:------------|
| **Dependency Scanning** | Checks lock files against OSV.dev, Sonatype OSS Index, NVD, and GitHub Advisory databases |
| **Canonical Data Model** | Normalizes all sources — merges duplicates, fills missing severity, eliminates UNKNOWN |
| **CISA KEV Enrichment** | Flags vulnerabilities actively exploited in the wild with `⚠ KEV` |
| **AI Code Analysis** | OpenAI GPT-4, Ollama, or LM Studio detect OWASP Top 10 vulnerabilities in your code |
| **SAST (Semgrep)** | 77+ bundled security rules plus custom rule support |
| **Pattern Detection** | 47 built-in rules (29 SEC + 18 AI-generated code quality) |
| **Container Scanning** | Scan Docker/OCI images via Syft SBOM extraction |
| **Binary/SCA Scanning** | Extract dependencies from Go binaries, JARs, and Python wheels |
| **IaC Scanning** | 25 rules for Terraform, Kubernetes, Dockerfile, CloudFormation, Helm |
| **License Compliance** | SPDX classification with copyleft/permissive/unknown categorization |
| **Supply Chain** | Integrity verification, phantom dependency detection, malicious package checks |
| **Multiple Outputs** | Table, JSON, SARIF, CycloneDX, SPDX, OpenVEX, HTML, PDF |

---

## Quick Example

```bash
# Basic dependency scan (no API keys needed)
calvigil scan /path/to/project

# Full scan with AI analysis
calvigil scan --ai /path/to/project

# Container image scan
calvigil scan-image nginx:latest

# IaC security scan
calvigil scan-iac ./terraform/

# JSON output for CI/CD
calvigil scan --format json --output results.json .
```

---

## Vulnerability Databases

calvigil queries **four** vulnerability databases and enriches results with one more:

| Database | Always On | Notes |
|:---------|:---------:|:------|
| [OSV.dev](https://osv.dev) | ✅ | Batch API, no limits, primary source |
| [Sonatype OSS Index](https://ossindex.sonatype.org/) | ✅ | PURL-based, free, optional account for higher limits |
| [NVD](https://nvd.nist.gov/) | Optional | Requires API key for best rate limits |
| [GitHub Advisory](https://github.com/advisories) | Optional | Requires GitHub token |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | ✅ | Enrichment — flags exploited-in-the-wild CVEs |

All results are normalized through a **Canonical Data Model** that:
- Prefers CVE IDs as canonical identifiers
- Merges findings across databases (fills missing severity, scores, and fix versions)
- Derives severity from CVSS vectors when sources omit a label

---

## Supported Ecosystems

| Language | Manifest Files |
|:---------|:---------------|
| Go | `go.mod` |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| C/C++ | `conan.lock` |

---

## About

calvigil is developed by [Calsoft Pvt Ltd](https://github.com/Calsoft-Pvt-Ltd) and released under the MIT License.

Current version: **5.0.0**
