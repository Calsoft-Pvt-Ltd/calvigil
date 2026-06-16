# Changelog

All notable changes to calvigil are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [5.1.0] — 2026-06-16

### Added
- **`calvigil push`**: Upload an existing JSON scan report to Calvigil Enterprise.
  - Supports Enterprise URL/API key via flags, config, or environment variables.
  - Supports CI metadata headers: project, ref, commit, environment, CLI version, and idempotency key.
  - `--fail-on-policy` evaluates the Enterprise policy gate before storing and exits non-zero without consuming quota on policy failure.
  - `--evaluate-only` checks policy without storing the scan.
- Enterprise config keys: `enterprise-url`, `enterprise-key`; env vars:
  `CALVIGIL_ENTERPRISE_URL`, `CALVIGIL_API_KEY`, and `CALVIGIL_ENTERPRISE_API_KEY`.
- Implemented NVD CVSS enrichment for already-matched CVEs:
  - Uses the NVD `cveIds` batch parameter with up to 100 IDs per request.
  - Fills missing `score` and `severity` on OSV/other-source findings while preserving the original match source.
  - Fixes Go advisory cases such as OSV `GO-*` records that alias a CVE but do not include CVSS data.

---

## [5.0.0] — 2026-06-12

### Added
- **Sonatype OSS Index matcher**: New always-on vulnerability database alongside OSV.dev
  - PURL-based component-report API covering all supported ecosystems
  - Works anonymously; optional free account raises rate limits
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
  - Availability check via `/v1/models` endpoint
- **AI-Generated Code Detection**: 18 new pattern rules (AI-SEC-001 through AI-SEC-018) targeting anti-patterns commonly introduced by AI code generators (Copilot, ChatGPT, Claude, etc.)
  - Resource leak detection: unclosed HTTP response bodies, files/connections opened in loops (CWE-404)
  - Race condition detection: concurrent map access without sync, goroutine loop variable capture (CWE-362)
  - Inefficient algorithm detection: O(n²) nested loops, string concatenation in loops (CWE-400, CWE-407)
  - Error handling anti-patterns: ignored error return values, overly broad exception handlers (CWE-252, CWE-396)
  - Deprecated API usage: ioutil (Go), distutils (Python), Buffer() (Node.js), Thread.stop (Java) (CWE-477)
  - Insecure defaults: overly permissive file permissions (0777/0666), hardcoded server addresses (CWE-732, CWE-547)
  - Unbounded data loading: SELECT * without LIMIT, ReadAll on request bodies (CWE-770)
  - Missing input validation: unchecked type conversions from user input (CWE-20)
  - Sensitive data in logs: passwords, tokens, API keys in log output (CWE-532)
  - Missing timeouts: HTTP/DB calls with context.Background() instead of timeout context (CWE-400)
  - Synchronous crypto in Node.js event loop: pbkdf2Sync, scryptSync (CWE-400)
  - Template literal SQL injection in JavaScript/TypeScript (CWE-89)
  - State-changing endpoints without CSRF protection (CWE-352)
- **Semgrep AI Code Quality Rule Pack**: New `rules/semgrep/ai-code-quality.yaml` with 25+ semantic rules for deep AST-level detection of AI-generated code issues across Go, Python, Java, and JavaScript/TypeScript
- **AI Code Indicator in Enrichment**: AI enrichment layer now classifies findings as `LIKELY_AI`, `POSSIBLY_AI`, or `UNLIKELY_AI` to help teams identify AI-generated code risks
- **Enhanced AI Prompts**: System and enrichment prompts updated to specifically target AI-generated code fingerprints (boilerplate security disabling, missing cleanup, naive implementations)
- **CHANGELOG.md**: This file, for tracking changes date-wise going forward

### Changed
- **Vulnerability aggregation now merges duplicate findings across databases** (by ID or alias)
  instead of keeping only the first occurrence — reports may show richer data for the same finding
- `AIEnrichment` model now includes `AICodeIndicator` field for AI-generated code classification
- `aiEnrichmentResult` struct updated with `ai_code_indicator` JSON field
- HTML reporter displays AI code indicator alongside enrichment details
- Table reporter shows `[AI-Generated: LIKELY_AI]` tag in enrichment output
- Pattern rule count increased from 29 to 47 (29 SEC + 18 AI-SEC)
- Semgrep bundled rule packs increased from 52 to 77+ rules (3 YAML files)

### Fixed
- **`UNKNOWN` severity** appearing when a source omitted a severity label:
  - OSV: severity now derived from CVSS v3 → v4 → v2 vectors (top-level and per-affected)
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
- Image reference validation against shell metacharacters
- Semgrep project-rules trust opt-in (`--trust-project-rules`)
- Shared filesystem skip helper (`internal/fsutil/`)
- SPDX 2.3 reporter
- Pattern rules SEC-013 through SEC-029 (Unsafe Rust, C/C++ buffer overflow, format strings, PHP file inclusion, Ruby mass assignment, insecure random, weak ciphers, XXE, JWT misconfiguration, debug mode, empty catch, SSRF, open redirect, private keys, DB connection strings, bearer tokens, generic secrets)
- AI enrichment layer with structured evidence and per-finding analysis
- CI integration examples

### Changed
- Renumbered duplicate HLD Section 9
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
