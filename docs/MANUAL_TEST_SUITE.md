---
title: Manual Test Suite
layout: default
nav_order: 9
---

# Manual Test Suite
{: .no_toc }

This guide is the user-facing manual regression suite for the open-source
Calvigil CLI. It is written so a tester can verify the product end to end from
an installed binary or a local source checkout.

Use this guide before releases, after large dependency or reporter changes, and
whenever a bug fix touches CLI behavior, configuration, parsers, matchers,
reporting, or Enterprise upload.

## Test Record

For every run, record:

| Field | Value |
|:------|:------|
| Tester | |
| Date | |
| OS / architecture | |
| Calvigil version | |
| Binary path | |
| Network mode | Online / offline / proxy |
| Optional services | OpenAI / Ollama / LM Studio / Semgrep / Syft / Enterprise |
| Result | Pass / fail / blocked |

## Prerequisites

1. Install Go 1.25 or newer when testing from source.
2. Install `jq` for JSON validation.
3. Install `semgrep` if SAST execution is in scope.
4. Install `syft` if container or binary SBOM extraction is in scope.
5. Keep optional API credentials ready only when testing those sources:
   `OPENAI_API_KEY`, `NVD_API_KEY`, `GITHUB_TOKEN`, `OSSINDEX_USER`,
   `OSSINDEX_TOKEN`.
6. Use a non-production Calvigil Enterprise tenant and API key when testing
   `calvigil push`.

From the OSS repo root:

```bash
make build
export CALVIGIL_BIN="$PWD/bin/calvigil"
export FIXTURE="$PWD/tests/integration/testdata"
```

To avoid changing your real user config during manual testing:

```bash
export CALVIGIL_SECRET_BACKEND=file
export HOME="$(mktemp -d)"
```

## Release Smoke Gate

Run these before the detailed suite. A release candidate is not acceptable if
any smoke test fails.

| ID | Area | Steps | Expected result |
|:---|:-----|:------|:----------------|
| OSS-SMOKE-001 | Build | `make build` | `bin/calvigil` is created with no compile errors. |
| OSS-SMOKE-002 | Unit tests | `make test-unit` | Unit suite passes with the race detector. |
| OSS-SMOKE-003 | Integration tests | `make test-integration` | Integration suite passes or is explicitly blocked by network access. |
| OSS-SMOKE-004 | Root help | `$CALVIGIL_BIN --help` | Help lists `scan`, `scan-image`, `scan-binary`, `scan-iac`, `scan-license`, `push`, `config`, and `version`. |
| OSS-SMOKE-005 | Basic scan | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format json --output /tmp/calvigil-smoke.json` | Exit is successful; `/tmp/calvigil-smoke.json` is valid JSON and contains packages or findings. |
| OSS-SMOKE-006 | Human output | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format table` | Terminal output is readable, grouped, and contains no panic or raw secret. |

Validate the smoke JSON:

```bash
jq empty /tmp/calvigil-smoke.json
```

## CLI Discovery And Errors

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-CLI-001 | Version command | `$CALVIGIL_BIN version` | Prints Calvigil version plus runtime/build information. |
| OSS-CLI-002 | Command help | Run `--help` for every command: `scan`, `scan-image`, `scan-binary`, `scan-iac`, `scan-license`, `push`, `config`, `version`. | Each command shows usage, examples, and supported flags. |
| OSS-CLI-003 | Unknown command | `$CALVIGIL_BIN definitely-not-a-command` | Exits non-zero with a helpful error; no stack trace. |
| OSS-CLI-004 | Invalid flag value | `$CALVIGIL_BIN scan "$FIXTURE" --format not-real` | Exits non-zero and explains the invalid format. |
| OSS-CLI-005 | Missing path default | Run `$CALVIGIL_BIN scan --skip-ai --skip-semgrep --format json --output /tmp/calvigil-default.json` from a small project directory. | Current directory is scanned. |
| OSS-CLI-006 | Invalid path | `$CALVIGIL_BIN scan /path/that/does/not/exist` | Exits non-zero with a clear path error. |
| OSS-CLI-007 | Verbose logging | `$CALVIGIL_BIN --verbose scan "$FIXTURE" --skip-ai --skip-semgrep` | Shows progress and optional-source decisions without printing secrets. |

## Configuration And Secret Handling

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-CONFIG-001 | Non-secret config | `$CALVIGIL_BIN config set openai-model gpt-4-turbo` then `$CALVIGIL_BIN config get openai-model` | Value is saved and returned. |
| OSS-CONFIG-002 | Secret config masking | `$CALVIGIL_BIN config set openai-key sk-test-secret-1234567890` then `$CALVIGIL_BIN config get openai-key` | Output is masked; raw secret is not displayed. |
| OSS-CONFIG-003 | NVD key config | `$CALVIGIL_BIN config set nvd-key nvd-test-key` then `$CALVIGIL_BIN config get nvd-key` | Key is accepted and masked. |
| OSS-CONFIG-004 | GitHub token config | `$CALVIGIL_BIN config set github-token ghp_testtoken` then `$CALVIGIL_BIN config get github-token` | Token is accepted and masked. |
| OSS-CONFIG-005 | OSS Index credentials | Set `ossindex-user` and `ossindex-token`; run `config get` for both. | User is readable if non-secret; token is masked. |
| OSS-CONFIG-006 | Enterprise defaults | Set `enterprise-url` and `enterprise-key`; run `config get` for both. | URL is readable; key is masked. |
| OSS-CONFIG-007 | Environment precedence | Set a config value, then export the matching env var, for example `OPENAI_MODEL=env-model`, and run `config get openai-model`. | Environment value wins over persisted config. |
| OSS-CONFIG-008 | Legacy config migration | Put legacy inline credentials in `~/.calvigil.json`, run `config get`, then inspect the file. | Calvigil reads legacy values and does not write new secrets back into the main config file. |
| OSS-CONFIG-009 | Unknown key | `$CALVIGIL_BIN config get not-a-key` | Exits non-zero with an unknown-key message. |
| OSS-CONFIG-010 | Missing credentials log | Clear optional env vars and run verbose scan. | Logs show optional sources skipped, for example NVD/GitHub/OSS Index, but OSV scanning still runs. |

Important environment variables to verify:

```bash
OPENAI_API_KEY
OPENAI_MODEL
NVD_API_KEY
GITHUB_TOKEN
OSSINDEX_USER
OSSINDEX_TOKEN
OLLAMA_URL
OLLAMA_MODEL
LMSTUDIO_URL
LMSTUDIO_MODEL
CALVIGIL_ENTERPRISE_URL
CALVIGIL_ENTERPRISE_API_KEY
CALVIGIL_API_KEY
CALVIGIL_PROJECT
CALVIGIL_REF
CALVIGIL_COMMIT
CALVIGIL_ENVIRONMENT
CALVIGIL_IDEMPOTENCY_KEY
```

## Dependency Scanning

Run dependency tests against `tests/integration/testdata`, which contains
representative Go, Node.js, Java, Python, Rust, Dockerfile, Terraform, and code
fixtures.

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-SCAN-001 | Multi-ecosystem discovery | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format json --output /tmp/calvigil-deps.json` | Report includes detected packages from supported manifests. |
| OSS-SCAN-002 | Go manifest | Confirm `go.mod` packages appear in `/tmp/calvigil-deps.json`. | Go ecosystem is present with package names and versions. |
| OSS-SCAN-003 | npm lockfile | Confirm `package-lock.json` packages appear. | Node.js ecosystem packages are present, including direct/transitive distinction when available. |
| OSS-SCAN-004 | Maven manifest | Confirm `pom.xml` packages appear. | Java ecosystem packages are present. |
| OSS-SCAN-005 | Python requirements | Confirm `requirements.txt` packages appear. | Python ecosystem packages are present. |
| OSS-SCAN-006 | Rust lockfile | Confirm `Cargo.lock` packages appear. | Rust ecosystem packages are present and checksums are parsed when available. |
| OSS-SCAN-007 | Skip dependency scan | `$CALVIGIL_BIN scan "$FIXTURE" --skip-deps --skip-ai --skip-semgrep --format json --output /tmp/calvigil-nodeps.json` | Dependency packages/findings are absent; other enabled scanners may still run. |
| OSS-SCAN-008 | Severity filter | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --severity high` | Output excludes medium/low findings. |
| OSS-SCAN-009 | Cache default | Run the same scan twice. | Second run is not slower than the first and uses cache when available. |
| OSS-SCAN-010 | Cache disabled | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --no-cache` | Scan runs without cache errors. |
| OSS-SCAN-011 | Cache TTL | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --cache-ttl 1h` | Scan accepts TTL and completes. |
| OSS-SCAN-012 | Empty project | Run scan against an empty temp directory. | Exits cleanly with zero findings or an actionable no-input message. |
| OSS-SCAN-013 | Malformed manifest | Create a temp project with invalid lockfile JSON and scan it. | Error is clear; scanner does not panic. |
| OSS-SCAN-014 | Optional source failures | Configure an intentionally invalid optional token and run verbose scan. | Error is isolated to that source and represented as a scan error finding or warning; base scan does not crash. |

## Vulnerability Sources And Enrichment

| ID | Source | Steps | Expected result |
|:---|:-------|:------|:----------------|
| OSS-SRC-001 | OSV | Run a dependency scan with no optional credentials. | OSV queries execute because no credential is required. |
| OSS-SRC-002 | NVD package search skipped | Unset `NVD_API_KEY` and config `nvd-key`; run verbose scan. | Log states NVD package search is skipped, while exact CVE CVSS enrichment remains best-effort. |
| OSS-SRC-003 | NVD configured | Set `NVD_API_KEY` or `nvd-key`; run verbose scan. | NVD package search is attempted; rate-limit errors are handled gracefully. |
| OSS-SRC-004 | GitHub Advisory skipped | Unset `GITHUB_TOKEN`; run verbose scan. | Log states GitHub Advisory is skipped. |
| OSS-SRC-005 | GitHub Advisory configured | Set `GITHUB_TOKEN`; run scan. | GitHub Advisory data is decoded without type errors. |
| OSS-SRC-006 | OSS Index skipped | Unset `OSSINDEX_USER` and `OSSINDEX_TOKEN`; run verbose scan. | Log states OSS Index is skipped. |
| OSS-SRC-007 | OSS Index configured | Set Sonatype credentials; run scan. | 401 responses produce an actionable credential error; valid credentials query successfully. |
| OSS-SRC-008 | Canonical merge | Scan a fixture with overlapping CVE/GHSA results from multiple sources. | Duplicate records merge into one canonical vulnerability with aliases. |
| OSS-SRC-009 | Severity fallback | Inspect JSON for findings with score/vector data. | Severity is normalized to CRITICAL/HIGH/MEDIUM/LOW where possible. |
| OSS-SRC-010 | OSV alias severity enrichment | Scan a Go project with a `GO-*` advisory that aliases a CVE with CVSS data, for example `CVE-2025-47911`. | JSON shows the canonical CVE with OSV as source and populated `score`/severity even if NVD is unavailable. |
| OSS-SRC-011 | NVD CVE batch enrichment | Scan a project that reports OSV CVE findings with missing scores, for example vulnerable Go modules. | Verbose output reports `NVD CVSS enrichment`; JSON findings have NVD-filled `score` and severity while preserving the original match source. Slow NVD responses can wait up to 45s per request within a bounded 2-minute enrichment budget; output may include cache/retry/unavailable detail while keeping partial successes. |
| OSS-SRC-012 | CISA KEV enrichment | Scan data containing a known exploited CVE, or use a controlled fixture. | Finding has `known_exploited` set and is visible in table/HTML output. |

## AI Code Analysis

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-AI-001 | AI skipped | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-deps --skip-semgrep` | AI analysis is not run. |
| OSS-AI-002 | Provider auto | With no local provider and no OpenAI key, run `--provider auto` without `--skip-ai`. | Scanner reports AI unavailable or falls back without crashing. |
| OSS-AI-003 | OpenAI provider | Export `OPENAI_API_KEY`, then run `--provider openai --skip-deps --skip-semgrep`. | AI findings are returned or a clean provider error is shown. |
| OSS-AI-004 | Ollama provider | Start Ollama, set `OLLAMA_URL` and `OLLAMA_MODEL`, then run `--provider ollama --skip-deps --skip-semgrep`. | Local model is used; no OpenAI key is required. |
| OSS-AI-005 | LM Studio provider | Start LM Studio, set `LMSTUDIO_URL` and `LMSTUDIO_MODEL`, then run `--provider lmstudio --skip-deps --skip-semgrep`. | Local model is used through the OpenAI-compatible endpoint. |
| OSS-AI-006 | AI output fields | Save JSON output from an AI-enabled scan. | AI findings include id, summary, severity, file path, line/snippet when available, and matched rule/context. |
| OSS-AI-007 | Provider timeout/error | Point provider URL to an unavailable localhost port. | Error is clear and scan does not hang indefinitely. |

## SAST And Pattern Detection

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-SAST-001 | Built-in SAST | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-deps --format json --output /tmp/calvigil-sast.json` | Semgrep and built-in patterns run when available. |
| OSS-SAST-002 | Semgrep skipped | `$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-deps --skip-semgrep` | Semgrep findings are absent; pattern-only findings may remain. |
| OSS-SAST-003 | Missing Semgrep binary | Temporarily remove Semgrep from PATH and run SAST scan. | Scanner reports Semgrep unavailable without a panic. |
| OSS-SAST-004 | Custom Semgrep rules | Run with `--semgrep-rules /path/to/rules`. | Trusted external rules are loaded and findings map into Calvigil report fields. |
| OSS-SAST-005 | Project rules untrusted | Put rules in a project and run without `--trust-project-rules`. | Project rules are not silently executed. |
| OSS-SAST-006 | Project rules trusted | Re-run with `--trust-project-rules`. | Project rules execute and findings appear. |
| OSS-SAST-007 | Secret patterns | Scan `vuln_sample.go` with dependencies and AI skipped. | Hardcoded secret and insecure-code patterns are detected. |
| OSS-SAST-008 | AI-generated code patterns | Scan a fixture with known AI anti-patterns. | Findings include the AI-generated/code-quality rule category where applicable. |
| OSS-SAST-009 | Line metadata | Inspect JSON/SARIF for SAST findings. | File path, start line, end line, and snippet fields are populated when available. |

## License Compliance

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-LIC-001 | Integrated license scan | `$CALVIGIL_BIN scan "$FIXTURE" --check-licenses --skip-ai --skip-semgrep --format json --output /tmp/calvigil-license-integrated.json` | Report includes `license_issues` and package license metadata. |
| OSS-LIC-002 | Standalone license scan | `$CALVIGIL_BIN scan-license "$FIXTURE" --format json --output /tmp/calvigil-license.json` | License-only report is produced without vulnerability sections dominating the output. |
| OSS-LIC-003 | Risk filter copyleft | `$CALVIGIL_BIN scan-license "$FIXTURE" --risk copyleft` | Output only shows copyleft issues. |
| OSS-LIC-004 | Risk filter unknown | `$CALVIGIL_BIN scan-license "$FIXTURE" --risk unknown` | Output only shows unknown/unresolved license issues. |
| OSS-LIC-005 | SPDX expression handling | Test packages with `MIT OR GPL-3.0-only`, `MIT AND Apache-2.0`, and `GPL-2.0 WITH Classpath-exception-2.0`. | Risk classification follows expression semantics documented in the scanner. |
| OSS-LIC-006 | Registry resolution | Scan packages with missing lockfile license data while online. | Resolver fills licenses from supported registries when available. |
| OSS-LIC-007 | Offline behavior | Disable network and run `scan-license`. | Scanner completes with unknown licenses where registry resolution is unavailable. |
| OSS-LIC-008 | HTML/PDF license report | Generate `--format html` and `--format pdf`. | Files open and show license summary, issues, and package context. |

## Supply Chain Protection

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-SC-001 | npm integrity verification | `$CALVIGIL_BIN scan "$FIXTURE" --verify-integrity --skip-ai --skip-semgrep --format json --output /tmp/calvigil-integrity.json` | Integrity checks run for npm lockfile packages. |
| OSS-SC-002 | Package not found | Test a controlled lockfile containing a fake package. | Finding is reported as a possible supply-chain issue. |
| OSS-SC-003 | Phantom dependency detection | Scan a project where lockfile contains undeclared packages. | Consistency issue is reported. |
| OSS-SC-004 | Cargo checksum parsing | Inspect Rust packages in JSON. | Cargo checksum fields are parsed when present. |
| OSS-SC-005 | Malicious package advisory | Scan data containing OSV `MAL-` advisories. | Malicious package finding is surfaced distinctly. |
| OSS-SC-006 | Supply-chain output formats | Generate table, JSON, HTML, and SARIF for a project with supply-chain issues. | Issues appear consistently across applicable formats. |

## IaC Scanning

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-IAC-001 | Directory scan | `$CALVIGIL_BIN scan-iac "$FIXTURE" --format json --output /tmp/calvigil-iac.json` | Terraform and Dockerfile fixtures are scanned. |
| OSS-IAC-002 | Terraform rules | Inspect findings from `insecure.tf`. | Open ingress/public or encryption misconfiguration rules are reported. |
| OSS-IAC-003 | Dockerfile rules | Inspect findings from `Dockerfile`. | Root user/latest tag/curl-pipe or related Dockerfile rules are reported when present. |
| OSS-IAC-004 | Kubernetes rules | Scan a temp directory with an intentionally privileged Pod manifest. | Kubernetes misconfiguration is reported. |
| OSS-IAC-005 | CloudFormation rules | Scan a temp CloudFormation file with public S3/open ingress. | CloudFormation findings are reported. |
| OSS-IAC-006 | Helm rules | Scan a temp Helm chart with `values.yaml`, `Chart.yaml`, and template files. | Helm-specific findings are reported. |
| OSS-IAC-007 | Severity filter | `$CALVIGIL_BIN scan-iac "$FIXTURE" --severity high` | Lower-severity IaC findings are excluded. |
| OSS-IAC-008 | Invalid IaC path | `$CALVIGIL_BIN scan-iac /not/real` | Clear non-zero error, no panic. |

## Container Image Scanning

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-IMG-001 | Image scan | `$CALVIGIL_BIN scan-image nginx:latest --format json --output /tmp/calvigil-image.json` | Image SBOM is generated through Syft and vulnerabilities are queried. |
| OSS-IMG-002 | Severity filter | `$CALVIGIL_BIN scan-image nginx:latest --severity high` | Only high and critical findings are shown. |
| OSS-IMG-003 | Output formats | Generate table, JSON, SARIF, CycloneDX, OpenVEX, HTML, and PDF. | Each supported format is produced or an actionable dependency error is shown. |
| OSS-IMG-004 | Invalid image | `$CALVIGIL_BIN scan-image does-not-exist.invalid/image:never` | Clean pull/SBOM error, no panic. |
| OSS-IMG-005 | Missing Syft | Remove Syft from PATH and run image scan. | Error explains Syft requirement. |
| OSS-IMG-006 | Local archive/directory | Scan a supported local image archive or directory if available. | Scanner accepts non-registry sources supported by Syft. |

## Binary And Archive Scanning

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-BIN-001 | Go binary | Build a small Go app with module deps, then run `$CALVIGIL_BIN scan-binary ./app --format json`. | Embedded module dependencies are extracted. |
| OSS-BIN-002 | Java JAR | Scan a JAR containing `pom.properties` or `MANIFEST.MF`. | Java dependencies are extracted. |
| OSS-BIN-003 | Python wheel | Scan a wheel containing `METADATA`. | Package name/version and dependencies are extracted. |
| OSS-BIN-004 | Directory recursion | `$CALVIGIL_BIN scan-binary /path/to/artifact-dir` | Supported artifacts under the directory are scanned. |
| OSS-BIN-005 | Invalid artifact | `$CALVIGIL_BIN scan-binary /not/real` | Clear non-zero error, no panic. |
| OSS-BIN-006 | Binary output formats | Generate table, JSON, SARIF, CycloneDX, OpenVEX, HTML, and PDF. | Each supported format is generated. |

## Reporting Formats

Create one dependency report and verify every supported format.

```bash
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format json --output /tmp/calvigil.json
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format sarif --output /tmp/calvigil.sarif
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format cyclonedx --output /tmp/calvigil.cdx.json
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format spdx --output /tmp/calvigil.spdx.json
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format openvex --output /tmp/calvigil.openvex.json
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format html --output /tmp/calvigil.html
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format pdf --output /tmp/calvigil.pdf
```

| ID | Format | Validation | Expected result |
|:---|:-------|:-----------|:----------------|
| OSS-RPT-001 | Table | Inspect terminal output. | Columns align and grouped sections are readable. |
| OSS-RPT-002 | JSON | `jq empty /tmp/calvigil.json` | Valid JSON with project, packages, vulnerabilities, and issue arrays. |
| OSS-RPT-003 | SARIF | `jq '.version,.runs[0].tool.driver.name' /tmp/calvigil.sarif` | SARIF v2.1.0 structure with Calvigil as tool. |
| OSS-RPT-004 | CycloneDX | `jq '.bomFormat,.specVersion' /tmp/calvigil.cdx.json` | CycloneDX BOM/VDR structure is valid JSON. |
| OSS-RPT-005 | SPDX | `jq '.spdxVersion,.packages' /tmp/calvigil.spdx.json` | SPDX 2.3 JSON contains root and package relationships. |
| OSS-RPT-006 | OpenVEX | `jq '.\"@context\",.statements' /tmp/calvigil.openvex.json` | OpenVEX statements are present. |
| OSS-RPT-007 | HTML | Open `/tmp/calvigil.html` in a browser. | Summary, findings, packages, and styling render correctly. |
| OSS-RPT-008 | PDF | Open `/tmp/calvigil.pdf`. | PDF is readable and includes the same major summary sections. |
| OSS-RPT-009 | Output overwrite | Re-run a command with the same `--output` path. | File is overwritten cleanly or an explicit error is shown. |
| OSS-RPT-010 | Stdout mode | Run without `--output`. | Report writes to stdout and exits correctly. |

## Enterprise Push

These tests require a running Calvigil Enterprise API and an API key scoped for
the tested project.

Generate a report:

```bash
$CALVIGIL_BIN scan "$FIXTURE" --skip-ai --skip-semgrep --format json --output /tmp/calvigil-push.json
```

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-PUSH-001 | Missing URL | Unset Enterprise URL and run `$CALVIGIL_BIN push /tmp/calvigil-push.json --api-key cvgk_fake`. | Non-zero error says Enterprise URL is missing. |
| OSS-PUSH-002 | Missing API key | Set URL only and run push. | Non-zero error says Enterprise API key is missing. |
| OSS-PUSH-003 | Invalid URL | Use `--server-url ftp://example.invalid`. | Non-zero validation error for URL scheme. |
| OSS-PUSH-004 | Successful push | Run with valid `--server-url`, `--api-key`, `--project`, `--ref`, and `--commit`. | Response includes `scan_id`, `url`, `summary`, and `replay:false`. |
| OSS-PUSH-005 | Idempotent replay | Re-run with same `--idempotency-key`. | Response points to same scan and `replay:true`. |
| OSS-PUSH-006 | Environment metadata | Add `--environment prod`. | Enterprise receives `X-Calvigil-Environment` for policy evaluation. |
| OSS-PUSH-007 | Evaluate only | Add `--evaluate-only`. | Enterprise returns policy result; no scan is stored. |
| OSS-PUSH-008 | Fail on policy | Use `--fail-on-policy` against a failing policy. | CLI exits non-zero and prints violations. |
| OSS-PUSH-009 | Config fallback | Set `enterprise-url` and `enterprise-key`, then push without those flags. | Config values are used. |
| OSS-PUSH-010 | Env fallback | Set `CALVIGIL_ENTERPRISE_URL` and `CALVIGIL_API_KEY`, then push without flags. | Environment values are used and override config. |
| OSS-PUSH-011 | Timeout | Use a very low `--timeout` against a slow/unreachable server. | CLI exits with a timeout error. |
| OSS-PUSH-012 | Scoped key denial | Push a project outside the key's project scopes. | Enterprise returns forbidden; CLI prints actionable error. |

## CI/CD Workflows

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-CI-001 | JSON artifact | Run scan in CI mode with `--format json --output calvigil.json`. | Artifact is generated and can be uploaded. |
| OSS-CI-002 | SARIF upload | Generate SARIF and upload it to a GitHub code scanning test workflow. | GitHub accepts the SARIF file. |
| OSS-CI-003 | Policy gate | Run `calvigil push --fail-on-policy`. | Build fails only when Enterprise policy returns `pass:false`. |
| OSS-CI-004 | Offline cache | Run two CI jobs with cache directory persisted. | Second job uses cache and produces equivalent findings. |
| OSS-CI-005 | No-secret logs | Inspect CI logs. | API keys and tokens are not printed by Calvigil. |

## Documentation And Schema

| ID | Functionality | Steps | Expected result |
|:---|:--------------|:------|:----------------|
| OSS-DOC-001 | Command docs | Review pages under `docs/commands/`. | Public docs match CLI flags and examples. |
| OSS-DOC-002 | Report schema | `jq empty pkg/report/schema.json` | Schema file is valid JSON. |
| OSS-DOC-003 | Enterprise contract | Compare `pkg/report` JSON with Enterprise ingestion docs. | Wire fields needed by Enterprise are documented and stable. |
| OSS-DOC-004 | GitHub Pages local build | From `docs`, run `bundle exec jekyll serve` if Ruby deps are installed. | Manual suite appears in navigation and links render. |

## Negative And Security Checks

| ID | Check | Steps | Expected result |
|:---|:------|:------|:----------------|
| OSS-SEC-001 | No raw secrets in logs | Run verbose scans with configured tokens. | Logs do not print raw tokens, API keys, or bearer values. |
| OSS-SEC-002 | Malformed JSON response | Use a proxy/mock source returning invalid JSON. | Source error is contained and reported clearly. |
| OSS-SEC-003 | Huge report output | Scan a large fixture and write JSON/HTML. | Process completes within acceptable memory for the test machine. |
| OSS-SEC-004 | Path traversal output | Try an output path outside allowed test directory only in a disposable environment. | CLI follows normal OS permissions and errors cleanly if denied. |
| OSS-SEC-005 | Terminal safety | Findings containing control characters render safely. | Output does not corrupt terminal or hide text. |

## Release Signoff Checklist

- [ ] Build, unit, and integration gates pass.
- [ ] Root command and every subcommand have working help.
- [ ] Configuration values persist, secrets are masked, and env precedence works.
- [ ] Dependency scanning covers all supported manifest ecosystems.
- [ ] Optional vulnerability sources work when configured and skip cleanly when not configured.
- [ ] AI providers are either tested or explicitly marked out of scope for the run.
- [ ] SAST, pattern detection, and custom rule trust behavior are verified.
- [ ] License, supply-chain, IaC, image, and binary scanning are verified.
- [ ] Every supported report format is generated and opened/validated.
- [ ] `calvigil push` works against Enterprise, including idempotency and policy gate behavior.
- [ ] Logs, reports, and errors do not expose raw secrets.
- [ ] GitHub Pages documentation includes this manual suite.
