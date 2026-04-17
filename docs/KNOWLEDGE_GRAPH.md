# calvigil Knowledge Graph

> **Audience**: Claude (and other AI assistants) doing future enhancement,
> bug fixing, or extension work on calvigil. This file is the
> **human-readable** view; a machine-parseable mirror lives at
> [KNOWLEDGE_GRAPH.json](KNOWLEDGE_GRAPH.json).
>
> Use this file as the *index*. Drill down into:
> - [HLD.md](HLD.md)  — system architecture, data flows, NFRs
> - [LLD.md](LLD.md)  — package-by-package types, signatures, algorithms
> - Source under `internal/`, `cmd/`, `rules/`

---

## 1. Project Identity

| Field        | Value |
|--------------|-------|
| Module path  | `github.com/Calsoft-Pvt-Ltd/calvigil` |
| Language     | Go 1.25.0 |
| Binary name  | `calvigil` |
| Entry point  | [main.go](../main.go) → `cmd.Execute()` |
| License      | See [LICENSE](../LICENSE) |
| Domain       | DevSecOps — multi-ecosystem dependency, license, IaC, binary, container, and AI-enriched code scanner |

---

## 2. Layered Architecture (depends-on edges)

```
cmd/  ───────────────────────────────────────┐
   ├─ scanner/     (orchestrator)            │
   │     ├─ detector/                        │
   │     │     └─ fsutil/                    │
   │     ├─ parser/    ─── models/           │
   │     │     ├─ integrity/                 │
   │     │     └─ consistency/               │
   │     ├─ matcher/   ─── cache/  ─ models/ │
   │     ├─ analyzer/  ─── models/           │
   │     │     ├─ openai / ollama            │
   │     │     ├─ patterns ─── fsutil/       │
   │     │     └─ semgrep                    │
   │     ├─ license/                         │
   │     └─ reporter/  ─── models/           │
   ├─ image/      ─── matcher/, validate     │
   ├─ binary/     ─── matcher/, fsutil       │
   ├─ iac/        ─── fsutil/                │
   └─ config/     ─── secrets (keyring|file) │
```

Rule of thumb: **lower layers never import upward**. `models` is a leaf; `cmd` is the only place tying packages together.

---

## 3. Package Inventory

| Package                     | Files                                                                                               | Responsibility | HLD § | LLD § |
|-----------------------------|-----------------------------------------------------------------------------------------------------|----------------|-------|-------|
| `cmd/`                      | [root.go](../cmd/root.go), [scan.go](../cmd/scan.go), [scan_image.go](../cmd/scan_image.go), [scan_license.go](../cmd/scan_license.go), [scan_binary.go](../cmd/scan_binary.go), [scan_iac.go](../cmd/scan_iac.go), [config.go](../cmd/config.go), [version.go](../cmd/version.go), [helpers.go](../cmd/helpers.go) | CLI surface (Cobra), flag parsing, output orchestration | 5, 12 | 1, 22 |
| `internal/models/`          | [vulnerability.go](../internal/models/vulnerability.go), [purl.go](../internal/models/purl.go)      | Domain types (leaf) | 4 | 2 |
| `internal/config/`          | [config.go](../internal/config/config.go), [secrets.go](../internal/config/secrets.go)              | YAML config + pluggable secret store | 12 | 3, 20 |
| `internal/detector/`        | [detector.go](../internal/detector/detector.go)                                                     | Filesystem walk, ecosystem identification | 6 | 4 |
| `internal/fsutil/`          | [walk.go](../internal/fsutil/walk.go)                                                               | Canonical skip-dir set, `ShouldSkipSubDir` | 6 | 19 |
| `internal/parser/`          | [parser.go](../internal/parser/parser.go), [golang.go](../internal/parser/golang.go), [maven.go](../internal/parser/maven.go), [npm.go](../internal/parser/npm.go), [python.go](../internal/parser/python.go), [rust.go](../internal/parser/rust.go), [ruby.go](../internal/parser/ruby.go), [php.go](../internal/parser/php.go), [conan.go](../internal/parser/conan.go), [integrity.go](../internal/parser/integrity.go), [consistency.go](../internal/parser/consistency.go) | Manifest/lockfile → `[]models.Package` | 7 | 5 |
| `internal/matcher/`         | [matcher.go](../internal/matcher/matcher.go), [osv.go](../internal/matcher/osv.go), [nvd.go](../internal/matcher/nvd.go), [ghsa.go](../internal/matcher/ghsa.go) | Packages → vulnerabilities (OSV / NVD / GHSA), with caching | 8 | 6 |
| `internal/analyzer/`        | [analyzer.go](../internal/analyzer/analyzer.go), [openai.go](../internal/analyzer/openai.go), [ollama.go](../internal/analyzer/ollama.go), [patterns.go](../internal/analyzer/patterns.go), [prompts.go](../internal/analyzer/prompts.go), [evidence.go](../internal/analyzer/evidence.go), [semgrep.go](../internal/analyzer/semgrep.go) | AI enrichment + regex pattern rules + Semgrep | 8 | 7 |
| `internal/license/`         | (license.go, spdx_licenses.go, resolver.go)                                                         | SPDX classification, copyleft/permissive checks | 8 | 8 |
| `internal/cache/`           | [cache.go](../internal/cache/cache.go)                                                              | sha256-keyed file cache for vuln results | 18 | 18 |
| `internal/scanner/`         | [scanner.go](../internal/scanner/scanner.go)                                                        | Pipeline orchestrator: detect → parse → match → analyze → report | 6 | 9 |
| `internal/iac/`             | [scanner.go](../internal/iac/scanner.go)                                                            | 25 built-in IaC misconfig rules | 16 | 16 |
| `internal/binary/`          | [scanner.go](../internal/binary/scanner.go)                                                         | Go binaries / JARs / Python wheels SCA | 17 | 17 |
| `internal/image/`           | [image.go](../internal/image/image.go), [validate.go](../internal/image/validate.go)                | Container image scan via Syft + ref validation | 10, 21 | 14, 21 |
| `internal/reporter/`        | (reporter.go, table.go, json.go, sarif.go, cyclonedx.go, openvex.go, spdx.go, html.go, pdf.go)      | Output formatters (table/JSON/SARIF/CycloneDX/OpenVEX/SPDX/HTML/PDF) | 11 | 10 |
| `rules/semgrep/`            | owasp-top10.yaml, language-specific.yaml                                                             | Built-in Semgrep ruleset (trusted; project rules opt-in) | 12.5 | 7 |

---

## 4. Public API Reference (functions / methods to remember)

### `internal/iac`
- `Scan(root, verbose) (*ScanResult, error)`
- `ToVulnerabilities(findings, projectPath) []models.Vulnerability`
- `Categories(files) []string`
- `IaCRule{ID, Name, Description, Severity, Pattern, FileTypes, Category}`
- 25 rules: `IAC-001 .. IAC-025` (see [LLD §16.4](LLD.md#164-built-in-rule-catalog-25-rules))

### `internal/binary`
- `Scan(root, verbose) (*ScanResult, error)`
- Internal: `scanGoBinary` (debug/buildinfo), `scanJAR` (zip → pom.properties → MANIFEST.MF → filename), `scanWheel` (METADATA), `parsePomProperties`, `parseJARFilename`, `parsePythonMetadata`

### `internal/cache`
- `New(dir, ttl) *Cache`     · `DefaultDir()` · `DefaultTTL = 24h`
- `(*Cache).Get(source, packages) ([]Vulnerability, bool)`
- `(*Cache).Put(source, packages, vulns) error`
- `(*Cache).Clear() error`
- Key: `sha256(source || foreach pkg: name+version+ecosystem)`
- File mode `0600`, dir mode `0700`

### `internal/fsutil`
- `var SkippedSubDirs map[string]struct{}` — single source of truth
- `ShouldSkipSubDir(name) bool`
- **Invariant**: every walker MUST guard with `path != root` so explicit user targets still scan

### `internal/config` (secrets)
- `secretStore` interface: `Get`, `Set`, `Delete`
- Backends: `keyringStore` (zalando/go-keyring, service `"calvigil"`), `fileStore` (`~/.calvigil-secrets.json` mode 0600)
- `getStore()` — `sync.Once` keyring probe, falls back to file
- Override: `CALVIGIL_SECRET_BACKEND={keyring|file}`
- Sentinel error: `errSecretNotFound`

### `internal/image`
- `validateImageRef(ref) error` — boundary check before `exec.Command("syft", ...)`
- Allowed schemes: `docker, docker-archive, oci, oci-archive, oci-dir, podman, containerd, singularity, registry, dir, file`
- Reject: control chars, whitespace, shell metachars `` ` $ ; & | < > ( ) * ? ! \ " ' ``, `..` traversal in path

### `internal/parser`
- `Parser` interface · `ForFile(path) Parser`
- Implementations: `GoModParser`, `PomXMLParser`, `GradleParser`, `NpmLockParser`, `YarnLockParser`, `PnpmLockParser`, `RequirementsTxtParser`, `PipfileLockParser`, `PoetryLockParser`, `UvLockParser`, `CargoLockParser`, `GemfileLockParser`, `ComposerLockParser`, `ConanLockParser`
- Cross-cutting: `VerifyIntegrity()`, `CheckConsistency()` (phantom dep detection)

### `internal/matcher`
- `Matcher` interface · `AggregatedMatcher` (dedupes across providers)
- `OSVMatcher`, `NVDMatcher`, `GitHubAdvisoryMatcher`

### `internal/analyzer`
- `Analyzer` interface
- `OpenAIAnalyzer`, `OllamaAnalyzer` (AI enrichment of vulns)
- `PatternRule` (12 built-in regex rules; uses `fsutil.ShouldSkipSubDir`)
- `SemgrepAnalyzer` (external CLI; **project rules require opt-in `--trust-project-rules`**)

### `internal/reporter`
- `Reporter` interface · `ForFormat(fmt) Reporter`
- 8 implementations: `table, json, sarif, cyclonedx, openvex, spdx, html, pdf`
- All output goes through `cmd/helpers.go::writeReport` → mode `0600`

---

## 5. Cross-Cutting Invariants (NEVER violate)

| # | Invariant | Where to enforce |
|---|-----------|------------------|
| I1 | Every filesystem walker uses `fsutil.ShouldSkipSubDir(name)` **with `path != root` guard** | `detector`, `binary`, `iac`, `analyzer/patterns`, `scanner` |
| I2 | Every report file is written with mode `0600` (never `0644`) | `cmd/helpers.go::writeReport`, future reporters |
| I3 | Secrets NEVER live in the YAML config struct or `.calvigil.yaml` — always via `secretStore` | `internal/config/secrets.go`, `cmd/config.go` |
| I4 | `scan-image <ref>` always passes through `validateImageRef` before any `exec.Command` | `internal/image/image.go` |
| I5 | External Semgrep rule directories from the scanned project are loaded **only** if `--trust-project-rules` was passed | `internal/analyzer/semgrep.go` |
| I6 | Symlinks resolved (and confirmed inside scan root) before reading | `detector`, walkers reading file content |
| I7 | New ecosystems get a parser **and** a PURL type entry in `models/purl.go` | `internal/models/purl.go`, `internal/parser/parser.go::ForFile` |
| I8 | New report formats route through `cmd/helpers.go::writeReport`; do not write files in the reporter itself | `internal/reporter/*.go` |
| I9 | All matchers consult `cache.Get` first and `cache.Put` after; key derivation uses `(source, []Package)` | `internal/matcher/*.go` |
| I10 | Test-only HOME / env mutations use `t.Setenv` / `t.Chdir` (not raw `os.Setenv`) for parallel safety | `*_test.go` |

---

## 6. Extension Recipes (how to add X)

| Goal                            | Touch these files |
|---------------------------------|-------------------|
| New language ecosystem          | `internal/parser/<lang>.go` (impl `Parser`), register in `parser.ForFile`; add PURL type in `models/purl.go`; add ecosystem row to HLD §3 supported ecosystems table |
| New vulnerability source        | `internal/matcher/<src>.go` (impl `Matcher`); add to `AggregatedMatcher` wiring in `cmd/scan.go`; ensure `cache.Get/Put` call with unique `source` string |
| New AI provider                 | `internal/analyzer/<provider>.go` (impl `Analyzer`); add provider switch in `cmd/scan.go`; reuse `prompts.go` and `evidence.go` |
| New IaC rule                    | Append `IaCRule{}` literal to `iacRules` in `internal/iac/scanner.go`; add positive + negative fixture under `internal/iac/testdata/`; bump rule count in HLD §16 + LLD §16.4 |
| New code-pattern rule           | Append `PatternRule{}` to the rule list in `internal/analyzer/patterns.go` |
| New report format               | `internal/reporter/<fmt>.go` (impl `Reporter`); register in `reporter.ForFormat`; route output through `cmd/helpers.go::writeReport`; add format to `--format` help string in every relevant command |
| New skip-dir convention         | Add string to `SkippedSubDirs` map in `internal/fsutil/walk.go`; assert in `walk_test.go` |
| New secret backend (e.g. Vault) | Implement `secretStore` in `internal/config/secrets.go`; extend `getStore()` switch on `CALVIGIL_SECRET_BACKEND` |
| New binary format               | Add ext branch in `internal/binary/scanner.go::scanFile`; implement `scan<Format>(path) []models.Package` returning a recognized PURL ecosystem |
| New CLI subcommand              | `cmd/<command>.go` with Cobra command, register in `cmd/root.go::init`; reuse `helpers.go::writeReport` + `filterVulnsBySeverity` |

---

## 7. Data Flow Quick Reference

```
[scan]          path → detector.Walk → parser.ForFile → matcher.Match (cache) → analyzer.Enrich (optional) → reporter
[scan-image]    ref  → validateImageRef → image.Scan (syft) → matcher.Match (cache) → reporter
[scan-binary]   path → binary.Scan (Go/JAR/wheel) → matcher.Match (cache) → reporter
[scan-iac]      path → iac.Scan (25 rules) → iac.ToVulnerabilities → reporter
[scan-license]  path → detector → parser → license.CheckPackages → reporter
[config]        key/value → config.Set → secretStore.Set (keyring|file)
```

---

## 8. Configuration & Environment Variables

| Variable                       | Effect |
|--------------------------------|--------|
| `CALVIGIL_SECRET_BACKEND`      | `keyring` \| `file` — pin secret backend (default: probe → keyring else file) |
| `OPENAI_API_KEY`               | Override stored OpenAI key for current process |
| `NVD_API_KEY`                  | Override stored NVD key for current process |
| `GITHUB_TOKEN`                 | Override stored GHSA token for current process |
| `HOME`                         | Used for `~/.calvigil/cache`, `~/.calvigil-secrets.json`, `~/.calvigil.yaml` |

Config file: `~/.calvigil.yaml` (created mode `0600`). Never contains secret values; secrets live separately in the keyring or `~/.calvigil-secrets.json`.

---

## 9. Test Conventions

- All packages have `*_test.go` covering happy path + at least one error branch.
- `testdata/` directories are skipped by all walkers (Go convention) — fixtures placed there must NOT be expected in self-scan output.
- Tests that mutate process-global state (`HOME`, `CALVIGIL_SECRET_BACKEND`, cwd) use `t.Setenv` / `t.Chdir` for automatic restoration and parallel safety.
- Coverage targets per package: ≥ 70% (see HLD §15 NFRs).

---

## 10. Glossary

| Term         | Meaning |
|--------------|---------|
| SBOM         | Software Bill of Materials (CycloneDX / SPDX) |
| VDR          | Vulnerability Disclosure Report (CycloneDX extension) |
| VEX          | Vulnerability Exploitability eXchange (OpenVEX) |
| SARIF        | Static Analysis Results Interchange Format (v2.1.0) |
| PURL         | Package URL (`pkg:type/namespace/name@version`) |
| OSV          | Open Source Vulnerabilities database |
| NVD          | National Vulnerability Database |
| GHSA         | GitHub Security Advisories |
| IaC          | Infrastructure-as-Code |
| Phantom dep  | Dep declared in manifest but missing from lockfile (or vice versa) |

---

## 11. How Claude Should Use This Graph

1. **Locating code**: start from §3 (Package Inventory) — every public package has a one-line responsibility and links into `LLD.md` for detail.
2. **Adding a feature**: consult §6 (Extension Recipes) — it lists the *minimum* set of files to touch.
3. **Avoiding regressions**: check §5 (Invariants) before editing walkers, reporters, or anything touching secrets/credentials.
4. **Understanding flow**: §7 (Data Flow) gives the per-command pipeline; cross-reference HLD §6, §10, §16, §17 for diagrams.
5. **Verifying types**: §4 (Public API Reference) lists exact signatures. The structured form in [KNOWLEDGE_GRAPH.json](KNOWLEDGE_GRAPH.json) is suitable for retrieval-augmented prompts.
