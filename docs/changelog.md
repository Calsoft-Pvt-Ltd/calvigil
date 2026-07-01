---
title: Changelog
layout: default
nav_order: 10
---

# Changelog
{: .no_toc }

All notable changes to calvigil are documented here.
{: .fs-5 .fw-300 }

---

## [Unreleased]

### Added
- AI slop code-smell scoring for OSS scans. Existing AI-SEC pattern findings, Semgrep AI code-quality findings, and optional AI enrichment indicators now roll up into `slop_code_smells` in JSON plus table and HTML report summaries.
- Documentation and examples explaining that slop code smells are concrete quality/security symptoms, not proof of AI authorship.
- Five new AI-SEC pattern signals for missing request/server timeouts, fail-open error handling, temporary security bypass comments, unbounded Go goroutine fan-out, and Go HTTP servers without timeout configuration.
- Configurable regex pattern rule packs via `--pattern-rules`, with YAML/JSON file or directory support and project-local trust guardrails.
- Community-aligned Semgrep rule pack with 27 original Calvigil rules for framework, JWT, TLS, deserialization, C/C++, PHP/Ruby, Dockerfile, and shell supply-chain patterns.
- Bundled Semgrep rule integrity tests that parse every rule pack, enforce required fields, validate severity values, and prevent duplicate rule IDs.

### Changed
- Built-in regex pattern coverage increased from 47 to 52 rules: 29 general `SEC-*` rules and 23 `AI-SEC-*` code-quality/security signals.
- AI slop code-smell scoring maps additional timeout, fail-open, insecure-default, validation, and secret-exposure rules into summary categories.
- Bundled Semgrep coverage increased from 74 to 101 rules across four packs after comparing Calvigil's gaps with the public `semgrep/semgrep-rules` repository structure.

### Fixed
- Corrected malformed bundled Semgrep YAML in existing packs so all shipped rules parse cleanly in automated tests.

---

## [5.3.0] — 2026-06-24

### Added
- Official Docker image support for Calvigil OSS under `calsoftit/calvigil-oss`, with a non-root container image that includes the `calvigil` binary, CA certificates, `git`, and bundled Semgrep rules.
- Docker build and smoke-test Make targets for local image validation.
- Offline scanning mode for `scan`, `scan-image`, `scan-binary`, and `scan-license`, allowing dependency and package inventory extraction without querying external vulnerability databases.

### Changed
- Docker documentation now points users to `calsoftit/calvigil-oss` and keeps publishing details out of user-facing docs.

### Fixed
- Expanded matcher, image scan, report validation, scanner, and integration test coverage for post-5.2 changes.
- Package license enrichment now resolves and stores licenses before vulnerability matching, preventing package inventory rows from being pushed or reported with empty licenses when later vulnerability sources are slow or fail.
- Registry license strings are normalized before storage across PyPI, npm, RubyGems, ConanCenter, and deps.dev-backed ecosystems such as Go, Maven, and Cargo. This fixes PyPI packages such as `pkg:pypi/plotly@5.24.0` showing as unknown when registry metadata clearly reports `MIT`.

---

## [5.2.0] — 2026-06-19

### Added
- Regular JSON scans now enrich package inventory licenses before reporting or Enterprise push, not only during `scan-license`.

### Changed
- NVD matching and CVSS enrichment are more resilient:
  - Default dependency, image, and binary scans include NVD package keyword search again, capped at 20 unique package names and conservatively paced.
  - Exact-CVE enrichment uses up to 100 `cveIds` per request, a 2-minute request timeout, a 10-minute enrichment budget, controlled keyed parallelism, six-second request pacing, transient-error backoff, and a 24-hour local CVE cache.
  - Timed-out or `503` CVE batches split down to individual CVE lookups so partial successes are preserved.

### Fixed
- Report upload validation now rejects non-JSON and empty scan reports before Enterprise submission.
- NVD CVSS enrichment now falls back to contributed CVSS metrics such as CISA-ADP when NVD/NIST primary scoring is not yet available.
- OSV Go advisories that alias CVEs now receive CVSS score/severity enrichment when the ecosystem-specific OSV record omits CVSS data.
- PyPI license resolution now reads version-specific `license_expression` metadata, normalizes PyPI license classifiers, and recognizes canonical full license text. This fixes packages such as `pkg:pypi/zstandard@0.25.0`, `pkg:pypi/tiktoken@0.12.0`, and `pkg:pypi/pathspec@1.1.1` that previously appeared as unknown.

---

## [5.1.0] — 2026-06-16

### Added

- **`calvigil push`**: Upload an existing JSON scan report to Calvigil Enterprise.
  - Supports Enterprise URL/API key via flags, config, or environment variables.
  - Supports CI metadata: project, ref, commit, environment, CLI version, and idempotency key.
  - `--fail-on-policy` evaluates the Enterprise policy gate before storing and exits non-zero without consuming quota on policy failure.
  - `--evaluate-only` checks policy without storing the scan.
- Enterprise config keys: `enterprise-url`, `enterprise-key`; env vars:
  `CALVIGIL_ENTERPRISE_URL`, `CALVIGIL_API_KEY`, and `CALVIGIL_ENTERPRISE_API_KEY`.
- NVD CVSS enrichment for already-matched CVEs:
  - Uses the NVD `cveIds` batch parameter with up to 100 IDs per request.
  - Fills missing `score` and `severity` on OSV/other-source findings while preserving the original match source.
  - Fixes Go advisory cases where an OSV `GO-*` record aliases a CVE but does not include CVSS data.

---

## [5.0.0] — 2026-06-12

### Added

- **Sonatype OSS Index matcher**: Optional vulnerability database alongside OSV.dev
  - PURL-based component-report API covering all supported ecosystems
  - Enabled when `ossindex-user` and `ossindex-token` are configured
  - Config keys: `ossindex-user`, `ossindex-token`; env vars: `OSSINDEX_USER`, `OSSINDEX_TOKEN`
- **CISA KEV enrichment**: Findings are checked against the CISA Known Exploited
  Vulnerabilities catalog after matching
  - Exploited findings flagged `⚠ KEV` in table output and counted in the scan summary
  - New `known_exploited` field on vulnerability records in JSON/report output
  - Best-effort: feed failures never alter scan results
- **Canonical Data Model** (`internal/matcher/canonical.go`): all sources are
  normalized into one consistent shape before reporting
  - CVE IDs preferred as primary identifier; GHSA/ecosystem IDs demoted to aliases
  - Cross-source merge: duplicate findings (matched by ID **or alias**) are merged
    instead of dropped — missing severity, CVSS score, fix version, summary, and
    references are filled in from whichever source has them
- `--skip-tests` flag: exclude test files from reachability analysis
- **LM Studio Support**: New AI provider for running local LLMs via [LM Studio](https://lmstudio.ai/)
  - OpenAI-compatible `/v1/chat/completions` endpoint (default: `http://localhost:1234`)
  - Full code analysis and vulnerability enrichment support (same capabilities as Ollama)
  - CLI flags: `--provider lmstudio`, `--lmstudio-url`, `--lmstudio-model`
  - Config keys: `lmstudio-url`, `lmstudio-model`
  - Environment variables: `LMSTUDIO_URL`, `LMSTUDIO_MODEL`
  - Auto-detection in `--provider auto` mode (tried after Ollama, before OpenAI)
- **AI-Generated Code Detection**: 18 new pattern rules (AI-SEC-001 through AI-SEC-018)
- **Semgrep AI Code Quality Rule Pack**: 25+ semantic rules for AI-generated code issues
- **AI Code Indicator**: Classifies findings as `LIKELY_AI`, `POSSIBLY_AI`, or `UNLIKELY_AI`

### Changed

- **Vulnerability aggregation now merges duplicate findings** across databases (by ID or alias) instead of keeping only the first occurrence
- Pattern rule count increased from 29 to 47 (29 SEC + 18 AI-SEC)
- Semgrep bundled rule packs increased from 52 to 77+ rules (3 YAML files)

### Fixed

- **`UNKNOWN` severity** eliminated in most cases:
  - OSV: severity now derived from CVSS v3 → v4 → v2 vectors
  - GitHub Advisory: falls back to numeric CVSS score when the label is missing
  - Canonical normalization derives severity from CVSS score as a last resort

---

## [4.3.0] — 2026-04-15

### Added

- IaC scanner with 25 built-in rules (Terraform, Kubernetes, Dockerfile, CloudFormation, Docker Compose, Helm)
- Binary/SCA scanner (Go binaries, JARs, Python wheels)
- Supply chain integrity verification (`--verify-integrity`)
- Phantom dependency detection
- Vulnerability cache with configurable TTL
- OS keyring secret store with file fallback
- SPDX 2.3 reporter
- Pattern rules SEC-013 through SEC-029
- AI enrichment layer with structured evidence

### Changed

- Module path updated to `github.com/Calsoft-Pvt-Ltd/calvigil`

---

## [4.2.0] — 2026-03-01

### Added

- Initial release
- Multi-ecosystem dependency scanning (Go, Java, Python, Node.js, Rust, Ruby, PHP, C/C++)
- Vulnerability matching via OSV, NVD, and GitHub Advisory databases
- AI-powered code analysis (OpenAI GPT-4, Ollama local LLM)
- Semgrep CE integration with bundled OWASP Top 10 and language-specific rule packs
- Pattern rules SEC-001 through SEC-012
- License compliance scanning with SPDX classification
- Output formats: Table, JSON, SARIF, CycloneDX, OpenVEX, HTML, PDF
- PURL generation for all packages
- Transitive dependency classification
- Configuration management with `config` command
