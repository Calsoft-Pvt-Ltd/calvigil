# Calvigil — Low-Level Design (LLD)

**Version:** 1.2
**Date:** May 2026
**Module:** `github.com/Calsoft-Pvt-Ltd/calvigil`

> **Change log**
> - **1.2 (May 2026):** Added 18 AI-generated code anti-pattern rules (AI-SEC-001..018), updated `PatternRule` struct with `Excludes` field, `AIEnrichment` model gains `AICodeIndicator`, new Semgrep `ai-code-quality.yaml` pack, updated prompts for AI-code detection.
> - **1.1 (Apr 2026):** Added `internal/binary/`, `internal/iac/`, `internal/fsutil/`, `internal/cache/`, `internal/config/secrets.go`, `internal/image/validate.go`, `internal/parser/integrity.go|consistency.go|rust.go|ruby.go|php.go|conan.go`, `cmd/scan_binary.go`, `cmd/scan_iac.go`, `cmd/helpers.go`, SPDX reporter section, security hardening notes.
> - **1.0 (Mar 2026):** Initial LLD.

---

## Table of Contents

1. [Package Structure](#1-package-structure)
2. [Data Models](#2-data-models)
3. [CLI Layer — `cmd/`](#3-cli-layer)
4. [Configuration — `internal/config/`](#4-configuration)
5. [Ecosystem Detector — `internal/detector/`](#5-ecosystem-detector)
6. [Dependency Parsers — `internal/parser/`](#6-dependency-parsers)
7. [Vulnerability Matchers — `internal/matcher/`](#7-vulnerability-matchers)
8. [Code Analyzers — `internal/analyzer/`](#8-code-analyzers)
9. [Scanner Orchestrator — `internal/scanner/`](#9-scanner-orchestrator)
10. [Reporters — `internal/reporter/`](#10-reporters)
11. [Container Image Scanner — `internal/image/`](#11-container-image-scanner)
12. [License Compliance — `internal/license/`](#12-license-compliance--internallicense)
13. [Semgrep Rules — `rules/semgrep/`](#13-semgrep-rules)
14. [Error Handling Strategy](#14-error-handling-strategy)
15. [Sequence Diagrams](#15-sequence-diagrams)
16. [IaC Scanner — `internal/iac/`](#16-iac-scanner--internaliac)
17. [Binary / SCA Scanner — `internal/binary/`](#17-binary--sca-scanner--internalbinary)
18. [Vulnerability Cache — `internal/cache/`](#18-vulnerability-cache--internalcache)
19. [Filesystem Skip Helper — `internal/fsutil/`](#19-filesystem-skip-helper--internalfsutil)
20. [Secret Store — `internal/config/secrets.go`](#20-secret-store--internalconfigsecretsgo)
21. [Image Reference Validation — `internal/image/validate.go`](#21-image-reference-validation--internalimagevalidatego)
22. [Additional `cmd/` files](#22-additional-cmd-files)

---

## 1. Package Structure

```
github.com/Calsoft-Pvt-Ltd/calvigil/
├── main.go                          # Entry point → cmd.Execute()
├── cmd/
│   ├── root.go                      # Root cobra command + global flags
│   ├── scan.go                      # `scan [path]` command
│   ├── scan_image.go                # `scan-image <image>` command
│   ├── scan_license.go              # `scan-license [path]` command (license-only)
│   ├── scan_binary.go               # `scan-binary <path>` command (Go binaries / JARs / wheels)
│   ├── scan_iac.go                  # `scan-iac <path>` command (Terraform / K8s / Dockerfile / etc.)
│   ├── helpers.go                   # writeReport(), filterVulnsBySeverity(), output-file 0600 perms
│   ├── config.go                    # `config set/get` commands
│   └── version.go                   # `version` command
├── internal/
│   ├── models/
│   │   ├── vulnerability.go         # Vulnerability, Package, ScanResult, ScanOptions, Severity, LicenseIssue, LicenseRisk, IntegrityIssue, ConsistencyIssue
│   │   └── purl.go                  # PURL generation (pkg:type/ns/name@version)
│   ├── config/
│   │   ├── config.go                # Config load/save (YAML), env var override
│   │   └── secrets.go               # Pluggable secretStore: keyring (go-keyring) + file fallback (~/.calvigil-secrets.json, 0600)
│   ├── detector/
│   │   └── detector.go              # Filesystem walk (uses fsutil.ShouldSkipSubDir), ecosystem identification
│   ├── fsutil/
│   │   └── walk.go                  # SkippedSubDirs map + ShouldSkipSubDir() — single source of truth for all walkers
│   ├── parser/
│   │   ├── parser.go                # Parser interface + ForFile() factory
│   │   ├── golang.go                # GoModParser
│   │   ├── maven.go                 # PomXMLParser, GradleParser
│   │   ├── npm.go                   # NpmLockParser, YarnLockParser, PnpmLockParser
│   │   ├── python.go                # RequirementsTxtParser, PipfileLockParser, PoetryLockParser, UvLockParser
│   │   ├── rust.go                  # CargoLockParser
│   │   ├── ruby.go                  # GemfileLockParser
│   │   ├── php.go                   # ComposerLockParser
│   │   ├── conan.go                 # ConanLockParser (C/C++)
│   │   ├── integrity.go             # Lockfile integrity verification (npm registry, Cargo checksum)
│   │   └── consistency.go           # Phantom dependency detection (lockfile vs manifest)
│   ├── matcher/
│   │   ├── matcher.go               # Matcher interface + AggregatedMatcher (normalize + merge)
│   │   ├── canonical.go             # Canonical Data Model (Normalize + Merge)
│   │   ├── osv.go                   # OSVMatcher (batch API)
│   │   ├── ossindex.go              # OSSIndexMatcher (Sonatype OSS Index, PURL-based)
│   │   ├── nvd.go                   # NVDMatcher (REST API)
│   │   ├── kev.go                   # KEVEnricher (CISA Known Exploited Vulnerabilities)
│   │   └── ghsa.go                  # GitHubAdvisoryMatcher (REST API)
│   ├── analyzer/
│   │   ├── analyzer.go              # Analyzer interface
│   │   ├── openai.go                # OpenAIAnalyzer (GPT-4 ChatCompletion)
│   │   ├── ollama.go                # OllamaAnalyzer (local LLM)
│   │   ├── lmstudio.go              # LMStudioAnalyzer (LM Studio local LLM)
│   │   ├── patterns.go              # PatternRule regex scanner (47 rules: 29 SEC + 18 AI-SEC)
│   │   ├── prompts.go               # AI prompt templates (system, analysis, enrichment)
│   │   ├── evidence.go              # Evidence packet builder for AI enrichment
│   │   └── semgrep.go               # SemgrepAnalyzer (external CLI integration; trust-project-rules opt-in)
│   ├── reporter/
│   │   ├── reporter.go              # Reporter interface + ForFormat() factory
│   │   ├── table.go                 # TableReporter (go-pretty terminal tables)
│   │   ├── json.go                  # JSONReporter (indented JSON)
│   │   ├── sarif.go                 # SARIFReporter (v2.1.0)
│   │   ├── cyclonedx.go             # CycloneDXReporter (v1.5 BOM + VDR)
│   │   ├── openvex.go               # OpenVEXReporter (v0.2.0)
│   │   ├── spdx.go                  # SPDXReporter (SPDX 2.3 JSON)
│   │   ├── html.go                  # HTMLReporter (self-contained HTML with license donut chart)
│   │   └── pdf.go                   # PDFReporter (headless Chrome)
│   ├── license/
│   │   ├── license.go               # Classify(), CheckPackages(), SPDX expression parser (OR/AND/WITH)
│   │   ├── spdx_licenses.go         # Comprehensive SPDX license database (~480 permissive + ~130 copyleft)
│   │   └── resolver.go              # License resolver (deps.dev, PyPI, npm, RubyGems)
│   ├── cache/
│   │   └── cache.go                 # File-based vulnerability cache (~/.calvigil/cache/, configurable TTL)
│   ├── scanner/
│   │   └── scanner.go               # Pipeline orchestrator
│   ├── iac/
│   │   └── scanner.go               # IaCRule + 25 built-in rules; Scan(); ToVulnerabilities(); Categories()
│   ├── binary/
│   │   └── scanner.go               # Go binary (debug/buildinfo) + JAR (zip + pom.properties + MANIFEST.MF) + Python wheel
│   └── image/
│       ├── image.go                 # Container image scanner (via Syft); parseSBOM()
│       └── validate.go              # Image-reference validation (scheme allow-list + OCI ref pattern)
└── rules/
    └── semgrep/
        ├── owasp-top10.yaml         # OWASP-style security rules (SQLi, CMDi, XSS, SSRF, weak crypto, ...)
        └── language-specific.yaml   # Go/Python language-specific rules
```

---

## 2. Data Models

### 2.1 Package: `internal/models/vulnerability.go`

#### Severity Enum
```go
type Severity string

const (
    SeverityCritical Severity = "CRITICAL"  // Rank 4
    SeverityHigh     Severity = "HIGH"      // Rank 3
    SeverityMedium   Severity = "MEDIUM"    // Rank 2
    SeverityLow      Severity = "LOW"       // Rank 1
    SeverityUnknown  Severity = "UNKNOWN"   // Rank 0
)

func (s Severity) Rank() int   // Numeric rank for comparison/sorting
```

#### Ecosystem Enum
```go
type Ecosystem string

const (
    EcosystemGo     Ecosystem = "Go"
    EcosystemMaven  Ecosystem = "Maven"
    EcosystemPyPI   Ecosystem = "PyPI"
    EcosystemNpm    Ecosystem = "npm"
    EcosystemGradle Ecosystem = "Maven"   // Maps to Maven Central
)
```

#### Package Struct
```go
type Package struct {
    Name      string    `json:"name"`
    Version   string    `json:"version"`
    Ecosystem Ecosystem `json:"ecosystem"`
    FilePath  string    `json:"file_path"`
    PURL      string    `json:"purl"`
    Indirect  bool      `json:"indirect"`
    License   string    `json:"license,omitempty"`
    Integrity string    `json:"integrity,omitempty"` // SRI hash (npm) or sha256 (Cargo)
}
```

#### VulnerabilitySource Enum
```go
type VulnerabilitySource string

const (
    SourceOSV          VulnerabilitySource = "osv"
    SourceNVD          VulnerabilitySource = "nvd"
    SourceGitHubAdv    VulnerabilitySource = "github-advisory"
    SourceAIAnalysis   VulnerabilitySource = "ai-analysis"
    SourcePatternMatch VulnerabilitySource = "pattern-match"
    SourceSemgrep      VulnerabilitySource = "semgrep"
)
```

#### Vulnerability Struct
```go
type Vulnerability struct {
    ID           string              `json:"id"`
    Aliases      []string            `json:"aliases,omitempty"`
    Summary      string              `json:"summary"`
    Details      string              `json:"details,omitempty"`
    Severity     Severity            `json:"severity"`
    Score        float64             `json:"score"`
    Package      Package             `json:"package"`
    FixedIn      string              `json:"fixed_in,omitempty"`
    References   []string            `json:"references,omitempty"`
    Source       VulnerabilitySource `json:"source"`
    FilePath     string              `json:"file_path,omitempty"`
    StartLine    int                 `json:"start_line,omitempty"`
    EndLine      int                 `json:"end_line,omitempty"`
    Snippet      string              `json:"snippet,omitempty"`
    DepPath      string              `json:"dep_path,omitempty"`
    Reachable    string              `json:"reachable,omitempty"`
    MatchedRule  string              `json:"matched_rule,omitempty"`
    PublishedAt  time.Time           `json:"published_at,omitempty"`
    AIEnrichment *AIEnrichment       `json:"ai_enrichment,omitempty"`
}
```

#### AIEnrichment Struct
```go
type AIEnrichment struct {
    Summary              string `json:"summary"`
    LikelyImpact         string `json:"likely_impact"`
    Confidence           string `json:"confidence"`            // HIGH, MEDIUM, LOW
    MinimalRemediation   string `json:"minimal_remediation"`
    SuppressionRationale string `json:"suppression_rationale"`
}
```

#### ScanResult Struct
```go
type ScanResult struct {
    ProjectPath     string          `json:"project_path"`
    Ecosystems      []Ecosystem     `json:"ecosystems"`
    TotalPackages   int             `json:"total_packages"`
    Packages        []Package       `json:"packages,omitempty"`       // All packages (for SBOM/license reports)
    LicenseIssues   []LicenseIssue  `json:"license_issues,omitempty"` // License compliance findings
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    ScannedAt       time.Time       `json:"scanned_at"`
    Duration        time.Duration   `json:"duration"`
    Errors          []string        `json:"errors,omitempty"`
    LicenseOnly     bool            `json:"license_only,omitempty"`   // True for scan-license command
}
```

#### IntegrityIssue Struct
```go
type IntegrityIssue struct {
    Package  Package `json:"package"`
    Expected string  `json:"expected"` // Hash from registry
    Actual   string  `json:"actual"`   // Hash from lockfile
    Reason   string  `json:"reason"`
}
```

#### ConsistencyIssue Struct
```go
type ConsistencyIssue struct {
    Package  Package `json:"package"`
    LockFile string  `json:"lock_file"` // Lockfile where package appears
    Manifest string  `json:"manifest"`  // Manifest that should declare it
    Reason   string  `json:"reason"`
}
```

#### LicenseRisk Enum
```go
type LicenseRisk string

const (
    LicensePermissive LicenseRisk = "permissive"
    LicenseCopyleft   LicenseRisk = "copyleft"
    LicenseUnknown    LicenseRisk = "unknown"
)
```

#### LicenseIssue Struct
```go
type LicenseIssue struct {
    Package Package     `json:"package"`
    License string      `json:"license"`
    Risk    LicenseRisk `json:"risk"`
    Reason  string      `json:"reason"`
}
```

#### ScanOptions Struct
```go
type ScanOptions struct {
    Path           string
    Format         string       // table, json, sarif, cyclonedx, openvex, spdx, html, pdf
    SeverityFilter Severity
    SkipAI         bool
    SkipDeps       bool
    SkipSemgrep    bool
    SemgrepRules   string
    OutputFile     string
    Verbose        bool
    AIProvider     string       // "openai", "ollama", "lmstudio", "auto"
    OllamaURL      string       // Default: http://localhost:11434
    OllamaModel    string
    LMStudioURL    string       // Default: http://localhost:1234
    LMStudioModel  string
    ImageRef       string
    CheckLicenses  bool
    VerifyIntegrity bool        // Verify lockfile hashes against registries
    NoCache        bool
    CacheTTL       string
}
```

### 2.2 Package: `internal/models/purl.go`

```go
func (p Package) ToPURL() string
// Generates Package URL per https://github.com/package-url/purl-spec
// Format: pkg:<type>/<namespace>/<name>@<version>
//
// Ecosystem mappings:
//   Go    → pkg:golang/<full-module-path>@<version>
//   npm   → pkg:npm/%40<scope>/<name>@<version>  (scoped)
//           pkg:npm/<name>@<version>              (unscoped)
//   PyPI  → pkg:pypi/<name>@<version>
//   Maven → pkg:maven/<groupId>/<artifactId>@<version>

func ecosystemToPURL(eco Ecosystem, pkgName string) (purlType, namespace, name string)
func (p *Package) EnsurePURL()   // Populates PURL field if empty
```

---

## 3. CLI Layer

### 3.1 `cmd/root.go` — Root Command

```go
var rootCmd = &cobra.Command{Use: "calvigil", ...}

func Execute()           // Entry point called from main.go
func init()              // Registers subcommands: scan, scanImage, configCmd, versionCmd
                         // Global flag: --verbose/-v (bool)
```

**Command Tree:**
```
calvigil
├── scan [path]              # Project vulnerability scan
├── scan-image <image>       # Container image scan
├── scan-license [path]      # License compliance scan (standalone)
├── scan-binary <path>       # Binary/SCA scan
├── scan-iac <path>          # IaC misconfiguration scan
├── config
│   ├── set <key> <value>    # Set configuration key
│   └── get <key>            # Get configuration value
└── version                  # Print version info
```

### 3.2 `cmd/scan.go` — Scan Command

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `"table"` | Output format |
| `--output` | `-o` | string | `""` | Output file path (stdout if empty) |
| `--severity` | `-s` | string | `""` | Minimum severity filter |
| `--skip-ai` | | bool | `false` | Skip AI code analysis |
| `--skip-deps` | | bool | `false` | Skip dependency scanning |
| `--skip-semgrep` | | bool | `false` | Skip Semgrep SAST |
| `--semgrep-rules` | | string | `""` | Custom Semgrep rule directory |
| `--provider` | | string | `""` | AI provider: openai, ollama, lmstudio, auto |
| `--ollama-url` | | string | `http://localhost:11434` | Ollama server URL |
| `--ollama-model` | | string | `""` | Ollama model name |
| `--lmstudio-url` | | string | `http://localhost:1234` | LM Studio server URL |
| `--lmstudio-model` | | string | `""` | LM Studio model name |
| `--check-licenses` | | bool | `false` | Enable license compliance checking |
| `--verify-integrity` | | bool | `false` | Verify lockfile integrity hashes against registries |
| `--no-cache` | | bool | `false` | Disable vulnerability response caching |
| `--cache-ttl` | | string | `"24h"` | Cache TTL duration |
| `--verbose` | `-v` | bool | `false` | Verbose output |

**Logic:**
1. Default path to `"."` if not provided
2. Validate path exists and is a directory
3. Resolve to absolute path
4. Build `models.ScanOptions` from flags
5. Create `scanner.New(opts)` → `scanner.Run(ctx)`

### 3.3 `cmd/scan_image.go` — Image Scan Command

**Logic:**
1. Verify `syft` is installed (`image.SyftAvailable()`)
2. Load config (`config.Load()`)
3. Build matcher list:
   - Always: `matcher.NewOSVMatcher()`
   - If OSS Index user and token: `matcher.NewOSSIndexMatcher(user, token)`
   - If NVD key: `matcher.NewNVDMatcher(key)`
   - If GitHub token: `matcher.NewGitHubAdvisoryMatcher(token)`
4. Create `image.NewScanner(imageRef, verbose, matchers)`
5. Run `scanner.Scan(ctx)` → get `ScanResult`
6. Filter by severity
7. Select reporter via `reporter.ForFormat(format)`
8. Output to file or stdout

### 3.4 `cmd/scan_license.go` — License Scan Command

**Flags:**
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `"table"` | Output format: table, json, html, pdf |
| `--output` | `-o` | string | `""` | Output file path |
| `--risk` | | string | `""` | Filter: copyleft, unknown |
| `--verbose` | `-v` | bool | `false` | Verbose output |

**Logic:**
1. Validate path exists and is a directory
2. `detector.Detect(path)` → find manifest files
3. Parse dependencies from each manifest file
4. `license.ResolvePackages()` → resolve missing licenses from registries (parallel, bounded at 10)
5. `license.CheckPackages()` → classify and flag copyleft/unknown licenses
6. Apply `--risk` filter if specified (`filterByRisk()`)
7. Build `ScanResult` with `LicenseOnly: true` (hides vuln sections in reports)
8. `printLicenseSummary()` → table summary to stderr
9. Select reporter and output results

### 3.5 `cmd/config.go` — Configuration Commands

**Supported keys:**
| Key | Environment Variable | Description |
|-----|---------------------|-------------|
| `openai-key` | `OPENAI_API_KEY` | OpenAI API key |
| `openai-model` | `OPENAI_MODEL` | OpenAI model (default: gpt-4) |
| `nvd-key` | `NVD_API_KEY` | NVD API key |
| `github-token` | `GITHUB_TOKEN` | GitHub personal access token |
| `ollama-url` | `OLLAMA_URL` | Ollama server URL |
| `ollama-model` | `OLLAMA_MODEL` | Ollama model name |
| `lmstudio-url` | `LMSTUDIO_URL` | LM Studio server URL |
| `lmstudio-model` | `LMSTUDIO_MODEL` | LM Studio model name |

### 3.6 `cmd/version.go`

```go
var version = "dev"   // Overridden at build time via LDFLAGS

// Output: "calvigil <version> (built with go<version>)"
```

---

## 4. Configuration

### Package: `internal/config/`

```go
type Config struct {
    OpenAIKey   string `json:"openai_key,omitempty"`
    OpenAIModel string `json:"openai_model,omitempty"`
    NVDKey      string `json:"nvd_key,omitempty"`
    GitHubToken string `json:"github_token,omitempty"`
    OllamaURL   string `json:"ollama_url,omitempty"`
    OllamaModel string `json:"ollama_model,omitempty"`
}
```

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `Load` | `() (*Config, error)` | Read `~/.calvigil.json`, overlay env vars |
| `Save` | `(cfg *Config) error` | Write to `~/.calvigil.json` (0600 perms) |
| `Set` | `(key, value string) error` | Load → update field → Save |
| `Get` | `(key string) (string, error)` | Load → return value (masked if secret) |
| `maskSecret` | `(s string) string` | Returns `"****" + last4` |

#### Environment Variable Precedence
Environment variables override file-based values during `Load()`:
```
OPENAI_API_KEY  → Config.OpenAIKey
OPENAI_MODEL    → Config.OpenAIModel
NVD_API_KEY     → Config.NVDKey
GITHUB_TOKEN    → Config.GitHubToken
OLLAMA_URL      → Config.OllamaURL
OLLAMA_MODEL    → Config.OllamaModel
```

---

## 5. Ecosystem Detector

### Package: `internal/detector/`

#### Types
```go
type MarkerFile struct {
    Name      string            // Filename to look for (e.g., "go.mod")
    Ecosystem models.Ecosystem  // Associated ecosystem
}

type DetectedFile struct {
    Path      string            // Absolute path to found file
    Filename  string            // Base filename
    Ecosystem models.Ecosystem
}
```

#### Known Markers

| Filename | Ecosystem |
|----------|-----------|
| `go.mod` | Go |
| `requirements.txt` | PyPI |
| `Pipfile.lock` | PyPI |
| `poetry.lock` | PyPI |
| `package-lock.json` | npm |
| `yarn.lock` | npm |
| `pnpm-lock.yaml` | npm |
| `pom.xml` | Maven |
| `build.gradle` | Gradle (→Maven) |
| `build.gradle.kts` | Gradle (→Maven) |

#### Function: `Detect(root string) ([]DetectedFile, []Ecosystem, error)`

**Algorithm:**
1. Walk directory tree starting at `root`
2. Skip directories: `node_modules`, `.git`, `vendor`, `__pycache__`, `.idea`, `.vscode`, `target`, `build`, `dist`
3. For each file, match filename against `knownMarkers`
4. Return list of detected files + deduplicated ecosystem list

---

## 6. Dependency Parsers

### Package: `internal/parser/`

#### Interface
```go
type Parser interface {
    Parse(r io.Reader, filePath string) ([]models.Package, error)
}
```

#### Factory
```go
func ForFile(filename string) Parser
// Mapping:
//   "go.mod"             → &GoModParser{}
//   "requirements.txt"   → &RequirementsTxtParser{}
//   "Pipfile.lock"       → &PipfileLockParser{}
//   "poetry.lock"        → &PoetryLockParser{}
//   "package-lock.json"  → &NpmLockParser{}
//   "yarn.lock"          → &YarnLockParser{}
//   "pnpm-lock.yaml"     → &PnpmLockParser{}
//   "pom.xml"            → &PomXMLParser{}
//   "build.gradle[.kts]" → &GradleParser{}
//   default              → nil
```

### 6.1 GoModParser (`golang.go`)

```go
type GoModParser struct{}
func (p *GoModParser) Parse(r io.Reader, filePath string) ([]Package, error)
```

**Algorithm:**
1. Read file content via `io.ReadAll(r)`
2. Parse using `modfile.Parse()` from `golang.org/x/mod`
3. Iterate `modFile.Require` entries
4. Skip indirect dependencies (`req.Indirect == true`)
5. Return `Package{Name, Version, Ecosystem: Go, FilePath}`

### 6.2 NpmLockParser (`npm.go`)

```go
type NpmLockParser struct{}
```

**Parsed Structure (package-lock.json v2/v3):**
```json
{
  "packages": {
    "node_modules/<name>": {
      "version": "1.0.0"
    }
  }
}
```

**Algorithm:**
1. JSON decode into struct with `Packages` map
2. Skip root entry (empty key `""`)
3. Extract package name from key path (strip `node_modules/` prefix)
4. Return `Package{Name, Version, Ecosystem: npm, FilePath}`

### 6.3 YarnLockParser (`npm.go`)

**Algorithm:**
1. Line-by-line regex parsing
2. Pattern: `^"?(@?[^@]+)@` for package name, `^\s+version "(.+)"` for version
3. Handle scoped packages (`@scope/name`)

### 6.4 PnpmLockParser (`npm.go`)

**Algorithm:**
1. YAML decode of `pnpm-lock.yaml`
2. Parse `packages` map — keys contain `/<name>/<version>` or `/<name>@<version>`
3. Extract name and version from key or nested fields

### 6.5 RequirementsTxtParser (`python.go`)

```go
type RequirementsTxtParser struct{}
```

**Algorithm:**
1. Line-by-line scan
2. Skip comments (`#`) and blank lines
3. Regex: `^([a-zA-Z0-9._-]+)\s*[=<>!~]=?\s*([0-9][^\s,;]*)` 
4. Extract name + version, normalize with `strings.ToLower`

### 6.6 PipfileLockParser (`python.go`)

**Algorithm:**
1. JSON decode Pipfile.lock
2. Iterate `default` section (production dependencies)
3. Extract name from key, version from `"version"` field (strip `==` prefix)

### 6.7 PoetryLockParser (`python.go`)

**Algorithm:**
1. Regex-based TOML parsing (no TOML dependency)
2. Match `[[package]]` sections
3. Extract `name = "..."` and `version = "..."` fields

### 6.8 PomXMLParser (`maven.go`)

```go
type PomXMLParser struct{}
```

**Parsed Structure:**
```xml
<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>1.0</version>
      <scope>test</scope>  <!-- skipped if scope=test -->
    </dependency>
  </dependencies>
</project>
```

**Algorithm:**
1. XML decode into struct
2. Skip dependencies with `scope == "test"`
3. Package name: `groupId:artifactId`
4. Return `Package{Name, Version, Ecosystem: Maven}`

### 6.9 GradleParser (`maven.go`)

**Algorithm:**
1. Regex: `(?:implementation|api|compile)\s+['"]([^:]+):([^:]+):([^'"]+)['"]`
2. Extract groupId, artifactId, version from matches
3. Package name: `groupId:artifactId`

### 6.10 Lockfile Integrity Verification (`integrity.go`)

**Purpose:** Verify lockfile integrity hashes against upstream registries to detect tampering.

```go
func VerifyIntegrity(ctx context.Context, packages []models.Package, verbose bool) []models.IntegrityIssue
func verifyNpmIntegrity(ctx context.Context, client *http.Client, pkg models.Package) *models.IntegrityIssue
func normalizeIntegrity(s string) string
```

**Algorithm:**
1. For each package with `Integrity` populated:
   - **npm packages:** Query `registry.npmjs.org/{name}/{version}`, extract `dist.integrity` from response
     - Compare `normalizeIntegrity(lockfile hash)` vs `normalizeIntegrity(registry hash)`
     - If mismatch → `IntegrityIssue{Reason: "integrity hash mismatch"}`
     - If 404 → `IntegrityIssue{Reason: "package not found on npm registry — possible supply chain injection"}`
   - **Cargo packages:** Flag if `Integrity` field is empty → `IntegrityIssue{Reason: "missing checksum in Cargo.lock"}`
2. Process npm packages concurrently (up to 10 goroutines) with `errgroup`
3. `normalizeIntegrity()` strips algorithm prefix (e.g., `sha512-`) for comparison

### 6.11 Phantom Dependency Detection (`consistency.go`)

**Purpose:** Detect dependencies present in the lockfile but not declared in the project manifest.

```go
func CheckConsistency(projectPath string, packages []models.Package) []models.ConsistencyIssue
func manifestForLockfile(lockFile string) string
func readManifestDeps(manifestPath string) (map[string]bool, error)
func readPackageJSONDeps(path string) (map[string]bool, error)
```

**Algorithm:**
1. Group packages by lockfile source
2. `manifestForLockfile()` maps lockfile → manifest:
   - `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` → `package.json`
3. `readManifestDeps()` reads the manifest and collects all declared dependency names:
   - `readPackageJSONDeps()` reads `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`
4. For each **direct** (non-transitive) lockfile package:
   - If not found in manifest dependencies → `ConsistencyIssue{Reason: "found in lockfile but not declared in manifest"}`
5. Transitive dependencies are excluded from checks (they are expected to exist only in the lockfile)

---

## 7. Vulnerability Matchers

### Package: `internal/matcher/`

#### Interface
```go
type Matcher interface {
    Name() string
    Match(ctx context.Context, packages []models.Package) ([]models.Vulnerability, error)
}
```

#### AggregatedMatcher
```go
type AggregatedMatcher struct {
    matchers []Matcher
}

func NewAggregatedMatcher(matchers ...Matcher) *AggregatedMatcher
func (a *AggregatedMatcher) Match(ctx, packages) ([]Vulnerability, error)
```

**Normalize-and-Merge Algorithm:**
1. Run all matchers concurrently, collect all vulnerabilities
2. Normalize each record through the Canonical Data Model (`Normalize`)
3. Build seen-map keyed by canonical ID **and** every alias → index into results
4. On a duplicate (ID or alias already seen), `Merge` the new record into the
   existing one — fill missing severity / CVSS score / fix version / summary /
   references; existing data always wins

#### Canonical Data Model (`canonical.go`)

```go
func Normalize(v *models.Vulnerability)
func Merge(dst *models.Vulnerability, src models.Vulnerability)
```

- **`Normalize`** — picks the most authoritative ID (CVE > GHSA > ecosystem ID),
  demotes the previous ID to aliases, dedupes aliases, derives severity from the
  CVSS score when the source label is UNKNOWN, trims summary/details whitespace.
- **`Merge`** — fills `dst`'s missing fields (severity, score, summary, details,
  `FixedIn`, `PublishedAt`, `KnownExploited`) from `src`; unions aliases and
  references.

### 7.1 OSVMatcher (`osv.go`)

```go
type OSVMatcher struct {
    client *http.Client
}

func NewOSVMatcher() *OSVMatcher
```

**API:**
| Method | Endpoint | Payload |
|--------|---------|---------|
| Batch Query | `POST https://api.osv.dev/v1/querybatch` | `{"queries": [{package: {name, ecosystem}, version}]}` |
| Vuln Detail | `GET https://api.osv.dev/v1/vulns/{ID}` | — |

**Algorithm:**
1. Build query batch from packages (name, ecosystem, version)
2. Chunk into batches of **1000** (OSV API limit)
3. POST to `/v1/querybatch`
4. For each returned vuln ID, fetch full details from `/v1/vulns/{ID}`
5. Parse severity from:
   - `severity[].score` (CVSS vector) → parse base score
   - `database_specific.severity` (fallback)
6. Extract fixed version from `affected[].ranges[].events[].fixed`
7. Map to `Vulnerability` struct with `Source: SourceOSV`

**Response Mapping:**
```
osvVuln.ID         → Vulnerability.ID
osvVuln.Aliases    → Vulnerability.Aliases
osvVuln.Summary    → Vulnerability.Summary
osvVuln.Details    → Vulnerability.Details
osvVuln.Severity   → Vulnerability.Severity + Score (parsed from CVSS)
osvVuln.References → Vulnerability.References
osvVuln.Published  → Vulnerability.PublishedAt
affected.ranges.events.fixed → Vulnerability.FixedIn
```

### 7.2 NVDMatcher (`nvd.go`)

```go
type NVDMatcher struct {
    client *http.Client
    apiKey string
}

func NewNVDMatcher(apiKey string) *NVDMatcher
```

**API:**
| Method | Endpoint |
|--------|---------|
| Search | `GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<pkg>&resultsPerPage=10` |

**Rate Limiting:**
- Without API key: 5 requests per 30 seconds (6-second delay between requests)
- With API key: 50 requests per 30 seconds (0.6-second delay)
- **Max 20 queries per scan** (hard cap to prevent long scans)

**Algorithm:**
1. For each package (up to 20): send keyword search to NVD
2. Apply rate limiting delay between requests
3. Parse CVSSv3.1 metrics: `baseScore` and `baseSeverity`
4. Filter results: only include CVEs where package name appears in description
5. Map to `Vulnerability` with `Source: SourceNVD`

### 7.3 GitHubAdvisoryMatcher (`ghsa.go`)

```go
type GitHubAdvisoryMatcher struct {
    client *http.Client
    token  string
}

func NewGitHubAdvisoryMatcher(token string) *GitHubAdvisoryMatcher
```

**API:**
| Method | Endpoint |
|--------|---------|
| List | `GET https://api.github.com/advisories?ecosystem=<eco>&per_page=100` |

**Ecosystem Mapping:**
```
Go    → "go"
PyPI  → "pip"
npm   → "npm"
Maven → "maven"
```

**Algorithm:**
1. Group packages by ecosystem
2. For each ecosystem, fetch advisories from GitHub API
3. For each advisory, check if any vulnerable package matches by name
4. Parse `vulnerable_version_range` (e.g., `>= 1.0, < 1.5`)
5. Use `first_patched_version.identifier` for `FixedIn`
6. Map GHSA severity strings (critical/high/medium/low) to Severity enum;
   fall back to `models.ScoreToSeverity(CVSSScore)` when the label is missing
7. Set `Source: SourceGitHubAdv`

### 7.4 OSSIndexMatcher (`ossindex.go`)

```go
type OSSIndexMatcher struct {
    client   *http.Client
    baseURL  string
    username string
    token    string
}

func NewOSSIndexMatcher(username, token string) *OSSIndexMatcher
```

**API:**
| Method | Endpoint |
|--------|---------|
| Batch | `POST https://ossindex.sonatype.org/api/v3/component-report` |

**Algorithm:**
1. Build PURL coordinates via `pkg.EnsurePURL()` (packages without a PURL are skipped)
2. POST in batches of 128 coordinates; basic auth when credentials are configured
3. Look up responses by lowercased PURL (qualifiers after `?` stripped)
4. Prefer the CVE as the vulnerability ID; `DisplayName` becomes an alias
5. Severity from `CVSSScore`, falling back to parsing `CVSSVector`
6. HTTP 429 surfaces a friendly rate-limit error (suggests `ossindex-user`/`ossindex-token`)
7. Set `Source: SourceOSSIndex`

### 7.5 KEVEnricher (`kev.go`)

```go
type KEVEnricher struct {
    client  *http.Client
    baseURL string
}

func NewKEVEnricher() *KEVEnricher
func (k *KEVEnricher) Enrich(ctx context.Context, vulns []models.Vulnerability) error
```

**Algorithm:**
1. Skip entirely when the input slice is empty (no network call)
2. Fetch the CISA KEV catalog JSON
3. Set `KnownExploited = true` on any vulnerability whose ID or alias matches a
   KEV CVE (case-insensitive)
4. Enrichment-only and best-effort: feed failures never alter scan findings

---

## 8. Code Analyzers

### Package: `internal/analyzer/`

#### Interface
```go
type Analyzer interface {
    Analyze(ctx context.Context, projectPath string, verbose bool) ([]models.Vulnerability, error)
}
```

### 8.1 Pattern Scanner (`patterns.go`)

#### PatternRule Struct
```go
type PatternRule struct {
    ID          string
    Name        string
    Description string
    Severity    models.Severity
    Pattern     *regexp.Regexp
    Excludes    *regexp.Regexp     // Optional: if match also matches this, skip (false-positive filter)
    Languages   []string          // File extensions (e.g., ".go", ".py")
}
```

#### Built-in Rules (47 total: 29 SEC + 18 AI-SEC)

**Security Rules (SEC-001 through SEC-029):**

| Rule ID | Name | Severity | Pattern Description |
|---------|------|----------|-------------------|
| SEC-001 | SQL Injection (format string) | HIGH | `fmt.Sprintf` with SQL keywords |
| SEC-002 | SQL Injection (string concat) | HIGH | String concat with SQL keywords |
| SEC-003 | Command Injection | CRITICAL | `exec.Command`, `subprocess`, `child_process` with variables |
| SEC-004 | Path Traversal | HIGH | `../` in file operations |
| SEC-005 | Hardcoded Secrets | HIGH | `password|secret|api_key|token` = literal values |
| SEC-006 | Cloud Provider Credentials | CRITICAL | AWS/GCP/Azure/GitHub/Slack/Stripe/OpenAI patterns |
| SEC-007 | Weak Cryptography | MEDIUM | `md5`, `sha1` usage |
| SEC-008 | Cross-Site Scripting | HIGH | `innerHTML`, `document.write` |
| SEC-009 | Insecure HTTP | LOW | `http://` URLs (non-localhost, with exclusions) |
| SEC-010 | TLS Verification Disabled | CRITICAL | `InsecureSkipVerify: true`, `verify=False` |
| SEC-011 | Insecure Deserialization | HIGH | `pickle.loads`, `yaml.load`, `ObjectInputStream` |
| SEC-012 | Permissive CORS | MEDIUM | `Access-Control-Allow-Origin: *` |
| SEC-013 | Unsafe Rust | MEDIUM | `unsafe` blocks |
| SEC-014 | Buffer Overflow (C/C++) | HIGH | `strcpy`, `gets`, `sprintf` |
| SEC-015 | Format String (C/C++) | CRITICAL | User-controlled printf args |
| SEC-016 | PHP File Inclusion | CRITICAL | `include`/`require` with `$_GET` |
| SEC-017 | Ruby Mass Assignment | HIGH | `.create(params)` without strong params |
| SEC-018 | Insecure Random | MEDIUM | `math/rand`, `random.randint`, `Math.random()` |
| SEC-019 | Weak Cipher | HIGH | DES, 3DES, RC4, Blowfish, AES/ECB |
| SEC-020 | XXE Processing | HIGH | XML parsers without entity disabling |
| SEC-021 | JWT Misconfiguration | CRITICAL | `verify=False`, algorithm `none` |
| SEC-022 | Debug Mode | MEDIUM | `debug=True`, `gin.DebugMode` |
| SEC-023 | Empty Error Handler | LOW | `catch() {}`, bare `except:` |
| SEC-024 | SSRF | HIGH | HTTP requests with variable URLs |
| SEC-025 | Open Redirect | MEDIUM | Redirect from request params |
| SEC-026 | Private Key Detected | CRITICAL | RSA/EC/PGP/SSH private key headers |
| SEC-027 | DB Connection String | HIGH | Credentials in connection URIs |
| SEC-028 | Bearer/Auth Token | HIGH | Hardcoded authorization tokens |
| SEC-029 | Generic API Key | MEDIUM | `api_key`/`secret_key` = long strings |

**AI-Generated Code Anti-Pattern Rules (AI-SEC-001 through AI-SEC-018):**

| Rule ID | Name | Severity | CWE | What It Catches |
|---------|------|----------|-----|------------------|
| AI-SEC-001 | HTTP Response Body Not Closed | MEDIUM | CWE-404 | Go `http.Get()` without `defer resp.Body.Close()` |
| AI-SEC-002 | Resource Opened in Loop | MEDIUM | CWE-404 | Files/connections opened in loop without close |
| AI-SEC-003 | Concurrent Map Access | HIGH | CWE-362 | Go map writes inside goroutines without mutex |
| AI-SEC-004 | Goroutine Loop Variable | HIGH | CWE-362 | Loop variable captured by reference in goroutine |
| AI-SEC-005 | O(n²) Nested Loop | LOW | CWE-407 | Nested iteration over same collection |
| AI-SEC-006 | String Concat in Loop | LOW | CWE-400 | `+=` string building instead of Builder |
| AI-SEC-007 | Ignored Error Return | MEDIUM | CWE-252 | `_ = file.Close()` discarding errors |
| AI-SEC-008 | Overly Broad Exception | MEDIUM | CWE-396 | Bare `except:`, `catch(Throwable)` |
| AI-SEC-009 | Deprecated API | MEDIUM | CWE-477 | `ioutil`, `distutils`, `Buffer()`, `Thread.stop` |
| AI-SEC-010 | Hardcoded Server Address | LOW | CWE-547 | IP:port in Listen/Dial/connect calls |
| AI-SEC-011 | Unbounded Data Loading | MEDIUM | CWE-770 | `SELECT *` without LIMIT, `ReadAll(resp.Body)` |
| AI-SEC-012 | Permissive File Permissions | MEDIUM | CWE-732 | `os.WriteFile(..., 0777)` |
| AI-SEC-013 | Unchecked Type Conversion | MEDIUM | CWE-20 | `_, _ := strconv.Atoi(input)` |
| AI-SEC-014 | Sensitive Data in Logs | MEDIUM | CWE-532 | `log.Printf("password: %s", pw)` |
| AI-SEC-015 | Missing Timeout | MEDIUM | CWE-400 | `context.Background()` in HTTP/DB calls |
| AI-SEC-016 | Sync Crypto in Event Loop | MEDIUM | CWE-400 | `crypto.pbkdf2Sync`, `scryptSync` (Node.js) |
| AI-SEC-017 | Template Literal SQL | HIGH | CWE-89 | JS/TS `` query(`...${input}`) `` |
| AI-SEC-018 | Missing CSRF Protection | MEDIUM | CWE-352 | POST/PUT/DELETE without CSRF middleware |

#### Source Extensions Scanned
```
.go, .py, .java, .js, .ts, .jsx, .tsx, .vue, .html,
.yaml, .yml, .json, .env, .properties
```

#### Directories Skipped
```
node_modules, .git, vendor, __pycache__, .idea, .vscode,
target, build, dist, .next, .nuxt
```

#### Functions
```go
func ScanPatterns(projectPath string) ([]PatternMatch, error)
// Walks directory tree, scans each file line-by-line for pattern matches

func scanFile(filePath string, ext string) ([]PatternMatch, error)
// Opens file, reads line-by-line, tests each pattern against each line

func PatternMatchesToVulnerabilities(matches []PatternMatch) []models.Vulnerability
// Converts PatternMatch → Vulnerability with Source: SourcePatternMatch
```

### 8.2 OpenAIAnalyzer (`openai.go`)

```go
type OpenAIAnalyzer struct {
    client *openai.Client
    model  string              // Default: "gpt-4"
}

func NewOpenAIAnalyzer(apiKey, model string) *OpenAIAnalyzer
```

#### Analyze Flow
```
Analyze(ctx, projectPath, verbose)
  │
  ├── 1. ScanPatterns(projectPath) → []PatternMatch
  │
  ├── 2. analyzePatternMatches(ctx, matches, projectPath, verbose)
  │       │
  │       ├── Collect 5 lines of surrounding context per match
  │       ├── Format using snippetTemplate
  │       ├── Batch up to 20 snippets per API call
  │       └── callOpenAI(batchPrompt) → []aiVulnResult
  │
  ├── 3. analyzeSourceFiles(ctx, projectPath, verbose)
  │       │
  │       ├── findImportantFiles() → entry points + key files
  │       ├── readFileContent() (max 500 lines)
  │       ├── Format using analysisPromptTemplate
  │       └── callOpenAI(analysisPrompt) → []aiVulnResult
  │
  └── 4. Merge results, convert to []Vulnerability (Source: SourceAIAnalysis)
```

#### AI API Call Details
```go
func (a *OpenAIAnalyzer) callOpenAI(userPrompt, projectPath string, verbose bool) ([]aiVulnResult, error)
```

**Request:**
```
Model:       a.model (default "gpt-4")
Temperature: 0.1 (near-deterministic)
Messages:    [
    {Role: "system", Content: systemPrompt},
    {Role: "user", Content: userPrompt}
]
```

**Response Parsing:**
1. Extract response content string
2. `extractJSONArray()` — strips markdown fences, finds `[...]` block
3. JSON unmarshal into `[]aiVulnResult`

#### AI Response Structure
```go
type aiVulnResult struct {
    ID             string  `json:"id"`
    Name           string  `json:"name"`
    Description    string  `json:"description"`
    Severity       string  `json:"severity"`
    File           string  `json:"file"`
    Line           flexInt `json:"line"`       // Handles int or string
    Recommendation string  `json:"recommendation"`
}
```

#### AI Enrichment
```go
func (a *OpenAIAnalyzer) EnrichVulnerabilities(ctx, vulns []Vulnerability, projectPath string, verbose bool) error
```

**Algorithm:**
1. Batch vulnerabilities into groups of 20
2. For each vuln: `BuildEvidence(vuln, projectPath)` → `Evidence`
3. Format: `FormatEvidenceForPrompt(evidence, index)` per vulnerability
4. Combine into `enrichmentPromptTemplate` with count + blocks
5. `callEnrichment()` → `[]aiEnrichmentResult`
6. Map results back to vulns by `VulnID` or index
7. Set `vuln.AIEnrichment = &AIEnrichment{...}`

#### Evidence Struct (`evidence.go`)
```go
type Evidence struct {
    VulnID         string
    VulnIndex      int
    PackageName    string
    PackageVersion string
    Ecosystem      string
    AdvisoryText   string
    Severity       string
    CVSSScore      float64
    DepPath        string
    FilePath       string
    StartLine      int
    EndLine        int
    Snippet        string
    MatchedRule    string
    Reachable      string
    FixedIn        string
    References     []string
}

func BuildEvidence(v Vulnerability, projectPath string) Evidence
func FormatEvidenceForPrompt(e Evidence, index int) string
```

### 8.3 OllamaAnalyzer (`ollama.go`)

```go
type OllamaAnalyzer struct {
    baseURL string    // Default: http://localhost:11434
    model   string    // e.g., llama3, codellama, mistral
}

func NewOllamaAnalyzer(baseURL, model string) *OllamaAnalyzer
```

#### Availability Check
```go
func (o *OllamaAnalyzer) Available() bool
// GET http://<baseURL>/api/tags → HTTP 200 means available
```

#### API Integration
Uses Ollama's OpenAI-compatible endpoint:

```
POST http://<baseURL>/v1/chat/completions

Request Body:
{
    "model": "<model>",
    "messages": [
        {"role": "system", "content": "<systemPrompt>"},
        {"role": "user", "content": "<userPrompt>"}
    ],
    "temperature": 0.1,
    "stream": false
}
```

**Differences from OpenAI analyzer:**
- Smaller batch sizes (10–15 snippets vs 20) due to smaller context windows
- Same prompt templates and response parsing logic
- Same enrichment flow

### 8.4 AI Prompt Templates (`prompts.go`)

| Constant | Purpose | Key Instructions |
|----------|---------|-----------------|
| `systemPrompt` | System message for analysis | "Senior AppSec engineer", OWASP Top 10 focus, JSON-only output |
| `analysisPromptTemplate` | Per-file source analysis | `"Analyze the following %s code..."` with language, filename, code |
| `batchAnalysisPromptTemplate` | Multi-snippet batch | `"Analyze the following code snippets..."`, dismiss false positives |
| `snippetTemplate` | Format single code snippet | File, line, extension, rule name, code context |
| `enrichmentSystemPrompt` | System message for enrichment | Generate summary, impact, confidence, remediation, suppression |
| `enrichmentPromptTemplate` | Enrichment request | `"Enrich the following %d security findings..."` with evidence blocks |

### 8.5 SemgrepAnalyzer (`semgrep.go`)

```go
type SemgrepAnalyzer struct {
    RulesDir string
    Verbose  bool
}

func NewSemgrepAnalyzer(rulesDir string, verbose bool) *SemgrepAnalyzer
```

#### Availability
```go
func (s *SemgrepAnalyzer) Available() bool
// exec.LookPath("semgrep") != nil
```

#### Rule Resolution Order
1. Custom `RulesDir` if provided and exists
2. `<projectPath>/.semgrep/` directory
3. `<projectPath>/.semgrep.yml` file
4. Bundled rules: `getBundledRulesDir()` → `rules/semgrep/`
5. Fallback: `semgrep --config auto`

#### Command Execution
```bash
semgrep --json --no-git-ignore --metrics off --config <rules> <projectPath>
```

#### Response Parsing
```go
type semgrepOutput struct {
    Results []struct {
        CheckID string
        Path    string
        Start   struct { Line, Col int }
        End     struct { Line, Col int }
        Extra   struct {
            Message  string
            Severity string   // ERROR, WARNING, INFO
            Metadata map[string]interface{}
            Lines    string
        }
    }
    Errors []struct { Message, Level string }
}

func parseSemgrepOutput(data []byte, projectPath string) ([]Vulnerability, error)
```

**Severity Mapping:**
| Semgrep Severity | Calvigil Severity |
|-----------------|-------------------|
| `ERROR` | `HIGH` |
| `WARNING` | `MEDIUM` |
| `INFO` | `LOW` |

**Metadata Extraction:**
- `cwe` → Appended to summary (e.g., `[CWE-89]`)
- `owasp` → Appended to summary
- `references` → `Vulnerability.References`

---

## 9. Scanner Orchestrator

### Package: `internal/scanner/`

```go
type Scanner struct {
    opts     models.ScanOptions
    cfg      *config.Config
    reporter reporter.Reporter
}

func New(opts models.ScanOptions) (*Scanner, error)
func (s *Scanner) Run(ctx context.Context) error
```

### `New()` Constructor Logic
1. Load config via `config.Load()`
2. Select reporter via `reporter.ForFormat(opts.Format)`
3. Return `&Scanner{opts, cfg, reporter}`

### `Run()` Pipeline Steps

```
Run(ctx)
│
├── Step 1: DETECT ECOSYSTEMS
│   detector.Detect(opts.Path) → ([]DetectedFile, []Ecosystem)
│
├── Step 2: SCAN DEPENDENCIES (unless --skip-deps)
│   scanDependencies(ctx, detectedFiles)
│   ├── parsePackages(files) → parse + EnsurePURL()
│   ├── Build AggregatedMatcher:
│   │   ├── Always: NewOSVMatcher()
│   │   ├── Always: NewOSSIndexMatcher(user, token)
│   │   ├── If NVD key: NewNVDMatcher(key)
│   │   └── If GitHub token: NewGitHubAdvisoryMatcher(token)
│   └── matcher.Match(ctx, allPackages) → []Vulnerability
│   (If --skip-deps but --verify-integrity: parsePackages only, no matching)
│
├── Step 2a: SUPPLY CHAIN CHECKS (on parsed packages)
│   ├── If --verify-integrity:
│   │   parser.VerifyIntegrity(ctx, packages) → []IntegrityIssue
│   │   └── npm: compare SRI hash vs registry.npmjs.org
│   │   └── Cargo: flag missing checksums
│   │   └── 404 from registry → "possible supply chain injection"
│   └── Always:
│       parser.CheckConsistency(path, packages) → []ConsistencyIssue
│       └── Compare lockfile direct deps vs manifest (package.json)
│       └── Flag undeclared packages as phantom dependencies
│
├── Step 3: AI CODE ANALYSIS (unless --skip-ai)
│   scanSourceCode(ctx)
│   ├── resolveAIProvider() → "openai" | "ollama" | ""
│   ├── If "openai": NewOpenAIAnalyzer(key, model)
│   ├── If "ollama": NewOllamaAnalyzer(url, model)
│   └── analyzer.Analyze(ctx, path, verbose) → []Vulnerability
│
├── Step 4: SEMGREP SAST (unless --skip-semgrep)
│   scanSemgrep(ctx)
│   ├── NewSemgrepAnalyzer(rulesDir, verbose)
│   ├── Check Available()
│   └── analyzer.Analyze(ctx, path, verbose) → []Vulnerability
│
├── Step 5: POST-PROCESSING
│   ├── populateDepPaths(vulns, projectPath)
│   │   └── Format: "<project> → <manifest> → <pkg>@<version>"
│   │
│   ├── populateReachability(vulns, projectPath, verbose)
│   │   ├── For dep vulns: grep source files for import patterns
│   │   │   └── buildImportPatterns(packageNames) → map[string]*regexp.Regexp
│   │   ├── Match → "Referenced in <file> (possible reachable path)"
│   │   └── Code/Semgrep findings → "Directly reachable (found in source code)"
│   │
│   └── AI ENRICHMENT (if AI provider available && not --skip-ai)
│       ├── getAIEnricher() → Analyzer (OpenAI or Ollama)
│       └── enricher.EnrichVulnerabilities(ctx, vulns, path, verbose)
│
├── Step 6: SEVERITY FILTER
│   filterBySeverity(vulns, opts.SeverityFilter)
│   └── Keep vulns where vuln.Severity.Rank() >= filter.Rank()
│
└── Step 7: REPORT
    ├── Build ScanResult{Path, Ecosystems, TotalPkgs, Vulns,
    │   IntegrityIssues, ConsistencyIssues, Timestamp, Duration, Errors}
    ├── Open output (file or stdout)
    └── s.reporter.Report(result, writer)
```

### AI Provider Resolution
```go
func (s *Scanner) resolveAIProvider() string
```

| Condition | Result |
|-----------|--------|
| `opts.AIProvider == "openai"` | `"openai"` |
| `opts.AIProvider == "ollama"` | `"ollama"` |
| `opts.AIProvider == "auto"` or empty | Check Ollama → OpenAI → `""` |
| Ollama available locally | `"ollama"` |
| OpenAI key configured | `"openai"` |
| Neither | `""` (skip AI) |

### Ollama Settings Resolution
```go
func (s *Scanner) ollamaSettings() (url, model string)
// Priority: CLI flags > config file > defaults
// Default URL: http://localhost:11434
```

---

## 10. Reporters

### Package: `internal/reporter/`

#### Interface
```go
type Reporter interface {
    Report(result *models.ScanResult, w io.Writer) error
}
```

#### Factory
```go
func ForFormat(format string) Reporter
// "table"     → &TableReporter{}
// "json"      → &JSONReporter{}
// "sarif"     → &SARIFReporter{}
// "cyclonedx" → &CycloneDXReporter{}
// "openvex"   → &OpenVEXReporter{}
// "spdx"      → &SPDXReporter{}
// "html"      → &HTMLReporter{}
// "pdf"       → &PDFReporter{}
// default     → &TableReporter{}
```

### 10.1 TableReporter (`table.go`)

**Output Sections:**
1. **Header** — Project path, scan duration, total packages
2. **☠️ Malicious Packages Table** — MAL- prefixed advisories separated from normal CVEs via `splitMalicious()` and rendered by `printMaliciousTable()`. Uses `hasMalAlias()` to detect MAL- IDs in primary ID or aliases.
   - Columns: `ID | Package | Version | Summary`
3. **Dependency Vulns Table** — Grouped by ecosystem with emoji badges:
   - Go 🐹, npm 📗, PyPI 🐍, Maven ☕, Rust 🦀, Ruby 💎, PHP 🐘, C/C++ ⚙️
   - Columns: `Severity | ID | Package | Version | Fixed In | Summary`
4. **Code Analysis Table** — `Severity | ID | File | Line | Finding`
5. **Semgrep SAST Table** — Same format as code analysis
6. **License Issues Table** (if `--check-licenses` used) — `Risk | Package | Version | License | Reason`
7. **AI Enrichment Details** (if present) — Summary, impact, confidence, remediation, suppression
8. **🔐 Lockfile Integrity Issues Table** — Rendered by `printIntegrityTable()` when `--verify-integrity` is used. Shows hash mismatches, missing checksums, and packages not found on registries.
   - Columns: `Package | Version | Expected | Actual | Reason`
9. **👻 Phantom Dependencies Table** — Rendered by `printConsistencyTable()`. Shows dependencies present in the lockfile but not declared in the manifest.
   - Columns: `Package | Lock File | Manifest | Reason`
10. **Summary** — Severity distribution counts + malicious package count
11. **Warnings/Errors** — Non-fatal errors from scan

**License-Only Mode:**
When `result.LicenseOnly` is true (from `scan-license` command), the `reportLicenseOnly()` method is called, which outputs only the License Issues table and a license compliance summary.

**Color Scheme:**
| Severity | Color |
|----------|-------|
| CRITICAL | Red (bold) |
| HIGH | Red |
| MEDIUM | Yellow |
| LOW | Blue |

### 10.2 JSONReporter (`json.go`)

```go
type JSONReporter struct{}
func (r *JSONReporter) Report(result *ScanResult, w io.Writer) error
// json.NewEncoder(w).SetIndent("", "  ").Encode(result)
```

Output: Full `ScanResult` struct as indented JSON.

### 10.3 SARIFReporter (`sarif.go`)

**SARIF v2.1.0 Schema:**
```go
type sarifReport struct {
    Schema  string     `json:"$schema"`   // SARIF schema URI
    Version string     `json:"version"`   // "2.1.0"
    Runs    []sarifRun `json:"runs"`
}

type sarifDriver struct {
    Name           string      // "calvigil"
    Version        string      // Build version
    InformationURI string      // GitHub repo URL
    Rules          []sarifRule // One per unique vuln ID
}

type sarifResult struct {
    RuleID    string            // Matches rule ID
    Level     string            // "error" | "warning" | "note"
    Message   sarifMessage
    Locations []sarifLocation   // Physical file + region
}
```

**Severity → SARIF Level Mapping:**
| Severity | SARIF Level |
|----------|------------|
| CRITICAL, HIGH | `"error"` |
| MEDIUM | `"warning"` |
| LOW, UNKNOWN | `"note"` |

### 10.4 CycloneDXReporter (`cyclonedx.go`)

**CycloneDX v1.5 BOM:**
```go
type cdxBOM struct {
    BOMFormat       string               // "CycloneDX"
    SpecVersion     string               // "1.5"
    SerialNumber    string               // "urn:uuid:<UUID>"
    Version         int                  // 1
    Metadata        cdxMetadata
    Components      []cdxComponent       // Package inventory (type: "library")
    Vulnerabilities []cdxVulnerability   // VDR data
}
```

**Component generation:** One component per unique package found in vulnerabilities, with PURL and optional group (Maven groupId).

**Vulnerability mapping includes:**
- `Source` → OSV/NVD/GitHub/etc.
- `Ratings` → CVSS score + severity
- `CWEs` → Extracted from metadata if available
- `Analysis` → AI enrichment mapped to VDR analysis states:
  - HIGH confidence → `exploitable`
  - MEDIUM confidence → `in_triage`
  - LOW confidence → `false_positive` with justification `requires_environment`

### 10.5 OpenVEXReporter (`openvex.go`)

**OpenVEX v0.2.0 Document:**
```go
type vexDocument struct {
    Context    string          // "https://openvex.dev/ns/v0.2.0"
    ID         string          // Document ID
    Author     string          // "calvigil"
    Role       string          // "tool"
    Timestamp  string
    Version    int
    Tooling    string          // "calvigil/0.1.0"
    Statements []vexStatement
}
```

**VEX Status Determination:**
```go
func determineVEXStatus(v Vulnerability) (status, justification, impact, action string)
```

| AI Confidence | VEX Status | Justification |
|--------------|-----------|---------------|
| HIGH | `"affected"` | — (action = remediation) |
| MEDIUM | `"under_investigation"` | — |
| LOW | `"not_affected"` | `"requires_environment"` |
| No enrichment | `"affected"` (if HIGH/CRITICAL) or `"under_investigation"` | — |

### 10.6 HTMLReporter (`html.go`)

**Self-contained HTML with embedded CSS.** Uses Go `html/template`.

**Template Data:**
```go
type htmlData struct {
    ProjectPath    string
    GeneratedAt    string
    Duration       string
    TotalPackages  int
    Ecosystems     []string
    TotalVulns     int
    CriticalCount  int
    HighCount      int
    MediumCount    int
    LowCount       int
    DepGroups      []htmlEcoGroup    // Grouped by ecosystem
    CodeVulns      []htmlVuln
    SemgrepVulns   []htmlVuln
    IaCVulns       []htmlVuln
    LicenseSummary *htmlLicenseSummary // License compliance donut chart data
    LicenseIssues  []htmlLicense       // License compliance findings
    LicenseOnly    bool                // True when only license scanning was performed
    Errors         []string
    HasEnrichment  bool
}
```

**License Compliance Section:**
```go
type htmlLicenseSummary struct {
    Total      int
    Permissive int
    Copyleft   int
    Unknown    int
}

type htmlLicense struct {
    Package   string
    Version   string
    Ecosystem string
    License   string
    Risk      string    // "copyleft" or "unknown"
    Reason    string
    RiskClass string    // CSS class for styling
}
```

**Features:**
- Responsive CSS grid layout
- Color-coded severity badges
- Severity distribution bar chart (CSS-based)
- **SVG donut chart** for license compliance (permissive/copyleft/unknown distribution with 2x2 legend)
- License compliance issues table with risk badges
- Expandable AI enrichment sections
- Grouped by ecosystem with section headers
- **LicenseOnly mode**: when `LicenseOnly` is true, vulnerability sections (severity cards, dep/code/semgrep/IaC sections) are hidden via `{{if not .LicenseOnly}}` guards; title changes to "License Compliance Report"

**Template Helper Functions:**
- `pctSum(a, b int) float64` — sum two values as percentage of total, used for donut chart stroke-dashoffset
- `pctSum3(a, b, c int) float64` — sum three values as percentage

### 10.7 SPDXReporter (`spdx.go`)

```go
type SPDXReporter struct{}
```

**SPDX 2.3 JSON Document:**
```go
type spdxDocument struct {
    SPDXVersion       string             // "SPDX-2.3"
    DataLicense       string             // "CC0-1.0"
    SPDXID            string             // "SPDXRef-DOCUMENT"
    Name              string             // Project name
    DocumentNamespace string             // UUID-based namespace
    CreationInfo      spdxCreationInfo   // Tool, timestamp
    Packages          []spdxPackage      // All detected packages with PURLs
    Relationships     []spdxRelationship // DESCRIBES and DEPENDS_ON
}
```

**Package generation:** One SPDX package per detected dependency, with:
- SPDX ID derived from package name
- External references (PURLs)
- DESCRIBES relationship from document to each package

### 10.8 PDFReporter (`pdf.go`)

```go
func ChromeAvailable() bool
// Searches for: google-chrome, chromium, chromium-browser,
//               /Applications/Google Chrome.app/..., $CHROME_PATH
```

**Pipeline:**
1. Render HTML report (using HTMLReporter internally)
2. Write HTML to temporary file
3. Execute headless Chrome:
   ```bash
   <chrome-binary> --headless --disable-gpu --no-sandbox --print-to-pdf=<output.pdf> <input.html>
   ```
4. Read PDF bytes, write to output writer
5. Clean up temp files

---

## 11. Container Image Scanner

### Package: `internal/image/`

```go
type Scanner struct {
    imageRef string
    verbose  bool
    matchers []matcher.Matcher
}

func NewScanner(imageRef string, verbose bool, matchers []matcher.Matcher) *Scanner
func SyftAvailable() bool    // exec.LookPath("syft") != nil
```

#### Scan Pipeline
```go
func (s *Scanner) Scan(ctx context.Context) (*models.ScanResult, error)
```

1. **Extract packages:** `extractPackages(ctx)` → runs `syft <imageRef> -o json --quiet`
2. **Generate PURLs:** `EnsurePURL()` for all packages
3. **Match vulnerabilities:** Run all matchers against extracted packages
4. **Build ScanResult** with image ref as project path

#### Syft Response Parsing
```go
type syftArtifact struct {
    Name      string
    Version   string
    Type      string        // npm, python, go-module, java-archive, etc.
    Language  string
    PURL      string
    Locations []struct{ Path string }
    Metadata  struct{ ManifestName string }
}
```

**Type → Ecosystem Mapping:**
| Syft Type | Ecosystem |
|-----------|-----------|
| `npm` | npm |
| `python`, `pip`, `python-wheel`, `python-egg` | PyPI |
| `go-module` | Go |
| `java-archive`, `maven`, `gradle` | Maven |
| `gem` | RubyGems |
| `deb` | Debian |
| `rpm` | RPM |
| `apk` | Alpine |
| `rust-crate` | crates.io |

---

## 12. License Compliance — `internal/license/`

### 12.1 Classifier (`license.go`)

```go
func Classify(spdxID string) models.LicenseRisk
```

**Algorithm:**
1. Strip outer parentheses
2. Handle **OR** expressions (case-insensitive): recursively classify each side, return the most permissive (developer chooses which license to comply with)
3. Handle **AND** expressions: recursively classify each side, return the most restrictive (both apply)
4. Handle **WITH** exceptions: ignore the exception clause, classify the base license
5. Check `licenseAliases` map for common non-SPDX names (e.g., `"BSD"` → `BSD-2-Clause`, `"Apache 2.0"` → `Apache-2.0`)
6. Case-insensitive O(1) lookup in precomputed lowercase maps
7. Look up in `permissiveLicenses` map (~480 entries) → `LicensePermissive`
8. Look up in `copyleftLicenses` map (~130 entries) → `LicenseCopyleft`
9. Otherwise → `LicenseUnknown`

```go
func splitSPDXOp(expr, op string) []string
// Case-insensitive split of SPDX expression by binary operator

func CheckPackages(packages []models.Package) []models.LicenseIssue
// Evaluates all packages and returns issues for copyleft and unknown licenses

func normalizeID(spdxID string) string
// Normalizes informal license names to canonical SPDX identifiers via alias map + O(1) lookup

var licenseAliases map[string]string
// ~60 common non-SPDX names mapped to canonical SPDX IDs (BSD, Apache 2.0, GPL, etc.)
```

### 12.2 SPDX License Database (`spdx_licenses.go`)

Two maps containing comprehensive SPDX license identifiers sourced from spdx.org:

```go
var permissiveLicenses = map[string]bool{ ... }  // ~480 identifiers
var copyleftLicenses   = map[string]bool{ ... }   // ~130 identifiers
```

Includes standard SPDX short identifiers plus common variants (e.g., `mit`, `apache-2.0`, `bsd-3-clause`).

### 12.3 License Resolver (`resolver.go`)

```go
func ResolvePackages(ctx context.Context, packages []models.Package, verbose bool)
```

**Algorithm:**
1. Scan packages for missing license metadata (`pkg.License == ""`)
2. Resolve in parallel with bounded concurrency (10 goroutines + semaphore)
3. For each package, dispatch by ecosystem:

| Ecosystem | Registry | API Endpoint |
|-----------|----------|-------------|
| Go | deps.dev | `GET /v3alpha/systems/go/packages/{name}/versions/{version}` |
| Maven | deps.dev | `GET /v3alpha/systems/maven/packages/{name}` |
| Rust | deps.dev | `GET /v3alpha/systems/cargo/packages/{name}` |
| Python | PyPI | `GET /pypi/{name}/json` → `.info.license` (skips >60 chars) |
| Node.js | npm | `GET /{name}/{version}` → `.license` or legacy `.licenses[]` array |
| Ruby | RubyGems | `GET /api/v1/gems/{name}.json` → `.licenses[]` |

4. Modify packages slice in place with resolved license data

---

## 13. Semgrep Rules

### 13.1 OWASP Top 10 Rules (`rules/semgrep/owasp-top10.yaml`)

| Rule ID | Category | Languages | CWE |
|---------|---------|-----------|-----|
| `calvigil.sql-injection-go` | SQL Injection | Go | CWE-89 |
| `calvigil.sql-injection-python` | SQL Injection | Python | CWE-89 |
| `calvigil.sql-injection-java` | SQL Injection | Java | CWE-89 |
| `calvigil.sql-injection-js` | SQL Injection | JS/TS | CWE-89 |
| `calvigil.command-injection-go` | Command Injection | Go | CWE-78 |
| `calvigil.command-injection-python` | Command Injection | Python | CWE-78 |
| `calvigil.command-injection-js` | Command Injection | JS/TS | CWE-78 |
| `calvigil.path-traversal-go` | Path Traversal | Go | CWE-22 |
| `calvigil.path-traversal-python` | Path Traversal | Python | CWE-22 |
| `calvigil.hardcoded-secrets` | Hardcoded Secrets | All | CWE-798 |
| `calvigil.aws-access-keys` | AWS Access Keys | All | CWE-798 |
| `calvigil.insecure-tls-go` | Insecure TLS Config | Go | CWE-295 |
| `calvigil.insecure-tls-python` | Insecure TLS Config | Python | CWE-295 |
| `calvigil.weak-crypto-go` | Weak Cryptography | Go | CWE-327 |
| `calvigil.weak-crypto-python` | Weak Cryptography | Python | CWE-327 |
| `calvigil.xss-go` | Cross-Site Scripting | Go | CWE-79 |
| `calvigil.xss-js` | Cross-Site Scripting | JS/TS | CWE-79 |
| `calvigil.insecure-deserialization-python` | Insecure Deserialization | Python | CWE-502 |
| `calvigil.insecure-deserialization-java` | Insecure Deserialization | Java | CWE-502 |
| `calvigil.ssrf-go` | Server-Side Request Forgery | Go | CWE-918 |
| `calvigil.ssrf-python` | Server-Side Request Forgery | Python | CWE-918 |
| `calvigil.cors-misconfiguration` | CORS Misconfiguration | Go/Python/JS | CWE-942 |

### 13.2 Language-Specific Rules (`rules/semgrep/language-specific.yaml`)

| Rule ID | Category | Language | CWE |
|---------|---------|----------|-----|
| `calvigil.go-unsafe-pointer` | Unsafe Pointer Usage | Go | CWE-704 |
| `calvigil.go-http-no-timeout` | HTTP Server Without Timeout | Go | CWE-400 |
| `calvigil.go-defer-in-loop` | Defer in Loop | Go | CWE-404 |
| `calvigil.python-flask-debug` | Flask Debug Mode in Production | Python | CWE-489 |
| `calvigil.python-bind-all-interfaces` | Binding to All Interfaces | Python | CWE-668 |

---

## 14. Error Handling Strategy

Calvigil uses a **non-fatal error accumulation** strategy:

| Component | Error Behavior |
|-----------|---------------|
| Parser failure | Log error, skip file, continue scanning |
| Matcher API failure | Log error, continue with other matchers |
| AI provider unavailable | Skip AI analysis, continue scan |
| Semgrep not installed | Skip SAST, continue scan |
| Syft not installed | Fail `scan-image` (required dependency) |
| Chrome not available | Fail `--format pdf` (required for PDF) |
| Config file missing | Use defaults + env vars |

All non-fatal errors are collected in `ScanResult.Errors[]` and displayed in the report.

---

## 15. Sequence Diagrams

### 15.1 Project Scan (`calvigil scan ./myproject`)

```
User         CLI(cmd)       Scanner       Detector    Parser    Matcher(OSV)   Analyzer(AI)   Reporter
 │              │              │              │          │           │              │              │
 │──scan ./p──→│              │              │          │           │              │              │
 │              │──New(opts)──→│              │          │           │              │              │
 │              │              │──Detect(p)──→│          │           │              │              │
 │              │              │←─files,ecos──│          │           │              │              │
 │              │              │              │          │           │              │              │
 │              │              │──ForFile()────────────→│           │              │              │
 │              │              │──Parse()──────────────→│           │              │              │
 │              │              │←─packages─────────────│           │              │              │
 │              │              │              │          │           │              │              │
 │              │              │──Match(pkgs)──────────────────────→│              │              │
 │              │              │←─dep vulns────────────────────────│              │              │
 │              │              │              │          │           │              │              │
 │              │              │──Analyze(path)─────────────────────────────────→│              │
 │              │              │←─code vulns────────────────────────────────────│              │
 │              │              │              │          │           │              │              │
 │              │              │──Enrich(vulns)─────────────────────────────────→│              │
 │              │              │←─enriched──────────────────────────────────────│              │
 │              │              │              │          │           │              │              │
 │              │              │──Report(result)──────────────────────────────────────────────→│
 │              │←─────────────│              │          │           │              │              │
 │←─output─────│              │              │          │           │              │              │
```

### 15.2 Image Scan (`calvigil scan-image nginx:latest`)

```
User         CLI(cmd)       ImageScanner    Syft(ext)    Matcher(OSV)    Reporter
 │              │              │               │              │              │
 │──scan-img──→│              │               │              │              │
 │              │──NewScanner──→│              │              │              │
 │              │──Scan(ctx)───→│              │              │              │
 │              │              │──syft -o json──→│            │              │
 │              │              │←─SBOM JSON──────│            │              │
 │              │              │              │               │              │
 │              │              │──Match(pkgs)─────────────────→│             │
 │              │              │←─vulns──────────────────────│             │
 │              │              │              │               │              │
 │              │←─ScanResult──│              │               │              │
 │              │──Report(result)───────────────────────────────────────────→│
 │←─output─────│              │               │              │              │
```

### 15.3 AI Enrichment Flow

```
Scanner             Analyzer(AI)           OpenAI/Ollama API
  │                     │                       │
  │──EnrichVulns(v[])──→│                       │
  │                     │──BuildEvidence(v[0])   │
  │                     │──BuildEvidence(v[1])   │
  │                     │  ...                   │
  │                     │──FormatPrompt(batch)   │
  │                     │                       │
  │                     │──POST /chat/completions→│
  │                     │  System: enrichmentSys  │
  │                     │  User: enrichmentPrompt │
  │                     │  Temp: 0.1             │
  │                     │←─JSON response─────────│
  │                     │                       │
  │                     │──Parse aiEnrichResult[] │
  │                     │──Map to vulns by ID    │
  │                     │                       │
  │←─vulns[].AIEnrich──│                       │
```

---

## 16. IaC Scanner — `internal/iac/`

### 16.1 Purpose

Detect security misconfigurations in **Infrastructure-as-Code** files (Terraform, Kubernetes, Dockerfile, CloudFormation, Docker Compose, Helm) using a built-in catalog of regex-based rules. Findings are convertible to `models.Vulnerability` so they flow through the same reporters as SCA findings.

### 16.2 Public API

```go
// Scan walks root, applies every rule whose FileTypes match each file's
// extension/basename, and returns aggregated findings. Skips standard dirs
// via fsutil.ShouldSkipSubDir (with the path != root guard).
func Scan(root string, verbose bool) (*ScanResult, error)

// ToVulnerabilities maps Findings into models.Vulnerability records. The
// vuln ID is the rule ID (e.g. "IAC-007"), the affected "package" carries
// the file path so existing reporters can render it.
func ToVulnerabilities(findings []Finding, projectPath string) []models.Vulnerability

// Categories returns the unique IaC categories present in the supplied
// scanned-file list (Terraform, Kubernetes, ...). Used by reporters for
// summary stats.
func Categories(files []ScannedFile) []string
```

### 16.3 Types

```go
type IaCRule struct {
    ID          string             // "IAC-001" .. "IAC-025"
    Name        string             // human-readable
    Description string
    Severity    models.Severity    // Critical | High | Medium | Low
    Pattern     *regexp.Regexp     // compiled at init
    FileTypes   []string           // e.g. {".tf"}, {"Dockerfile"}, {".yaml", ".yml"}
    Category    string             // Terraform | Kubernetes | Dockerfile | ...
}

type Finding struct {
    Rule     IaCRule
    FilePath string
    Line     int    // 1-based line where the regex matched
    Content  string // matched line, trimmed
}

type ScanResult struct {
    Findings []Finding
    Files    []ScannedFile
}

type ScannedFile struct {
    Path     string
    Category string
    Findings int
}
```

### 16.4 Built-in Rule Catalog (25 rules)

| ID       | Name                                       | Severity | Category       |
|----------|--------------------------------------------|----------|----------------|
| IAC-001  | Security Group -- Unrestricted Ingress     | High     | Terraform      |
| IAC-002  | S3 Bucket -- Public ACL                    | Critical | Terraform      |
| IAC-003  | S3 Bucket -- Server-Side Encryption Disabled | Medium | Terraform      |
| IAC-004  | IAM Policy -- Wildcard Actions             | Critical | Terraform      |
| IAC-005  | RDS -- Storage Not Encrypted               | High     | Terraform      |
| IAC-006  | CloudTrail -- Logging Disabled             | High     | Terraform      |
| IAC-007  | Security Group -- Unrestricted SSH         | Critical | Terraform      |
| IAC-008  | Kubernetes -- Privileged Container         | Critical | Kubernetes     |
| IAC-009  | Kubernetes -- Run As Root                  | High     | Kubernetes     |
| IAC-010  | Kubernetes -- Missing Resource Limits      | Medium   | Kubernetes     |
| IAC-011  | Kubernetes -- Host Network Enabled         | High     | Kubernetes     |
| IAC-012  | Kubernetes -- Default Namespace            | Low      | Kubernetes     |
| IAC-013  | Kubernetes -- Host PID Enabled             | High     | Kubernetes     |
| IAC-014  | Dockerfile -- Running as Root              | Medium   | Dockerfile     |
| IAC-015  | Dockerfile -- Using latest Tag             | Medium   | Dockerfile     |
| IAC-016  | Dockerfile -- ADD Instead of COPY          | Low      | Dockerfile     |
| IAC-017  | Dockerfile -- Curl Pipe to Shell           | High     | Dockerfile     |
| IAC-018  | CloudFormation -- Public S3 Bucket         | Critical | CloudFormation |
| IAC-019  | CloudFormation -- Open Security Group Ingress | High  | CloudFormation |
| IAC-020  | Docker Compose -- Privileged Mode          | Critical | Docker Compose |
| IAC-021  | Helm -- Tiller Enabled (Helm 2)            | Critical | Helm           |
| IAC-022  | Helm -- Container Uses latest Tag          | Medium   | Helm           |
| IAC-023  | Helm -- No Resource Limits                 | Medium   | Helm           |
| IAC-024  | Helm -- Host Network Enabled               | High     | Helm           |
| IAC-025  | Helm -- Privileged Container               | Critical | Helm           |

### 16.5 Walk Algorithm

```
Scan(root)
 ├── filepath.Walk(root)
 │    ├── if dir && path != root && fsutil.ShouldSkipSubDir(name) → SkipDir
 │    └── for each file: identify candidate rules by ext/basename
 ├── concurrent file scan (sync.WaitGroup, mutex-guarded result)
 │    └── per-file: bufio.Scanner over lines × rules whose FileTypes match
 └── return ScanResult{Findings, Files}
```

### 16.6 Extension

To add a new rule: append an `IaCRule` literal to `iacRules` in [internal/iac/scanner.go](internal/iac/scanner.go). No other changes required — the walker, reporter mapping, and severity filtering pick it up automatically. New tests should cover both a positive (matching) fixture and a negative (non-matching) fixture.

---

## 17. Binary / SCA Scanner — `internal/binary/`

### 17.1 Purpose

Extract embedded dependency information from compiled artifacts so SBOM/vulnerability matching works even when source / lockfiles are unavailable (production tarballs, container layers, CI build outputs).

### 17.2 Supported Formats

| Format       | Extension(s)         | Extractor function | Source of truth |
|--------------|----------------------|--------------------|-----------------|
| Go binary    | (no ext, executable) | `scanGoBinary`     | `debug/buildinfo` (BuildInfo embedded by Go ≥ 1.18) |
| JAR / WAR    | `.jar`, `.war`, `.ear` | `scanJAR`        | `META-INF/maven/**/pom.properties` → `MANIFEST.MF` → filename heuristic |
| Python wheel | `.whl`               | `scanWheel`        | `*.dist-info/METADATA` (PEP 566) |

### 17.3 Public API

```go
type ScanResult struct {
    Packages []models.Package
    Files    []ScannedFile
}

type ScannedFile struct {
    Path     string
    Type     string // "go-binary" | "jar" | "python-wheel"
    PkgCount int
}

// Scan walks root, identifies supported binaries, and extracts
// their embedded dependency lists. Deduplicates by ecosystem|name|version.
// Honours fsutil.ShouldSkipSubDir with the path != root guard.
func Scan(root string, verbose bool) (*ScanResult, error)
```

### 17.4 Extractor Details

**Go binary (`scanGoBinary`)**
1. `buildinfo.ReadFile(path)` — succeeds only on Go binaries, fails fast otherwise.
2. Returns one `models.Package` per `*BuildInfo.Deps` entry plus the main module, ecosystem `"go"`.

**JAR (`scanJAR`)**
1. Open as ZIP via `archive/zip`.
2. **Primary**: walk entries matching `META-INF/maven/<group>/<artifact>/pom.properties` → parse `groupId`, `artifactId`, `version`.
3. **Fallback**: read `META-INF/MANIFEST.MF`, look for `Bundle-SymbolicName` / `Implementation-Title` / `Implementation-Version` (`scanJARManifest`).
4. **Last resort**: parse the filename (`<artifact>-<version>.jar`) via `parseJARFilename` regex.
5. Ecosystem `"maven"`, name `<group>:<artifact>`.

**Python wheel (`scanWheel`)**
1. Open as ZIP.
2. Locate `*.dist-info/METADATA`, parse `Name:` and `Version:` headers (`parsePythonMetadata`).
3. Ecosystem `"pypi"`.

### 17.5 Helper Functions

| Helper                  | Purpose |
|-------------------------|---------|
| `parsePomProperties(r)` | Parse Java `.properties` format into a map |
| `parseJARFilename(p)`   | Regex `^(.+?)-(\d.*?)\.jar$` → name+version fallback |
| `scanJARManifest(zr,p)` | Build a `*models.Package` from MANIFEST.MF when pom.properties is absent |
| `parsePythonMetadata(r)` | Read `Name:`/`Version:` from PEP 566 METADATA |
| `extractRegex(s,re)`    | Generic single-group match helper |

### 17.6 Pipeline Integration

The `cmd/scan_binary.go` command bypasses `detector` and `parser` entirely:

```
scan-binary <path>
 → binary.Scan(path, verbose)
 → matcher.AggregatedMatcher.Match(packages)
 → reporter.Report(result, format) [writes 0600]
```

### 17.7 Extension

Add a new format by:
1. Adding the extension to the switch in `scanFile()`.
2. Implementing `scan<Format>(path string) []models.Package` returning `Ecosystem` matching an existing PURL type recognized by OSV/NVD.
3. Adding a `ScannedFile.Type` label string.

---

## 18. Vulnerability Cache — `internal/cache/`

### 18.1 Purpose

Avoid hammering OSV / NVD / GHSA endpoints when re-running scans on unchanged dependency sets. File-based, sha256-keyed, TTL-expiring.

### 18.2 Public API

```go
const DefaultTTL = 24 * time.Hour

func DefaultDir() string                          // ~/.calvigil/cache (empty if no $HOME)

type Cache struct { /* dir, ttl */ }

func New(dir string, ttl time.Duration) *Cache    // empty dir → DefaultDir; ttl ≤ 0 → DefaultTTL
func (c *Cache) Get(source string, packages []models.Package) ([]models.Vulnerability, bool)
func (c *Cache) Put(source string, packages []models.Package, vulns []models.Vulnerability) error
func (c *Cache) Clear() error
```

### 18.3 Internal Layout

```go
type entry struct {
    Vulns     []models.Vulnerability `json:"vulns"`
    CachedAt  time.Time              `json:"cached_at"`
    ExpiresAt time.Time              `json:"expires_at"`
}
```

- Key derivation: `sha256(source || pkg.Name || pkg.Version || pkg.Ecosystem ...)` then hex.
- File path: `<dir>/<hex>.json`, file mode `0o600`, dir mode `0o700`.
- Expiry: lazy — `Get` deletes the entry if `time.Now().After(e.ExpiresAt)` and returns miss.
- Corrupt file: deleted on unmarshal failure, treated as miss.

### 18.4 Integration

Each `Matcher` (OSV/NVD/GHSA) consults the cache before issuing network requests:

```
matcher.Match(pkgs)
 ├── if v, ok := cache.Get(source, pkgs); ok → return v   (cache hit)
 ├── otherwise → call upstream API
 └── cache.Put(source, pkgs, result)                       (best-effort)
```

### 18.5 Tunables

| Knob                                          | Default        | Source |
|-----------------------------------------------|----------------|--------|
| Cache directory                               | `~/.calvigil/cache` | `DefaultDir()` |
| TTL                                           | 24h            | `DefaultTTL` |
| Per-scanner override                          | n/a            | Pass non-empty `dir`/`ttl` to `cache.New` |
| Manual eviction                               | n/a            | `Cache.Clear()` (rm-rf semantics over `*.json`) |

---

## 19. Filesystem Skip Helper — `internal/fsutil/`

### 19.1 Purpose

Single source of truth for which subdirectory names every walker (detector, binary scanner, IaC scanner, pattern scanner, scanner orchestrator) must skip. Eliminates the prior bug where each walker had its own divergent skip list and `testdata/` fixtures were being scanned as if they were real code.

### 19.2 Public API

```go
var SkippedSubDirs = map[string]struct{}{ ... } // canonical set
func ShouldSkipSubDir(name string) bool
```

### 19.3 Skip Set Categories

| Category            | Members |
|---------------------|---------|
| Test fixtures       | `testdata`, `test-fixtures` |
| Package managers    | `node_modules`, `vendor`, `target`, `__pycache__`, `site-packages`, `.venv`, `venv`, `.env`, `env`, `.bundle`, `.cargo`, `.terraform`, `.terragrunt-cache`, `.serverless` |
| VCS / IDE           | `.git`, `.idea`, `.vscode` |
| Build / cache / out | `build`, `dist`, `out`, `bin`, `obj`, `.next`, `.nuxt`, `.cache`, `.tox`, `.nox`, `.mypy_cache`, `.pytest_cache` |

### 19.4 Required Usage Pattern (invariant)

Walkers **must** apply the skip rule with a `path != root` guard so users who explicitly point `calvigil` at one of these directories (e.g. `calvigil scan ./testdata`) still get it scanned:

```go
err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
    if err != nil { return nil }
    if info.IsDir() && path != root && fsutil.ShouldSkipSubDir(info.Name()) {
        return filepath.SkipDir
    }
    // ... per-file work
    return nil
})
```

### 19.5 Extension

Add a directory name to the `SkippedSubDirs` map literal in [internal/fsutil/walk.go](internal/fsutil/walk.go) — no other change is required because all walkers route through `ShouldSkipSubDir`. Update `walk_test.go` to assert membership.

---

## 20. Secret Store — `internal/config/secrets.go`

### 20.1 Purpose

Persist API keys (OpenAI, NVD, GHSA) outside the YAML config file so credentials never appear in plain text on disk by default. Pluggable backend with automatic OS keyring → file fallback.

### 20.2 Backends

```go
type secretStore interface {
    Get(key string) (string, error)        // errSecretNotFound on miss
    Set(key, value string) error
    Delete(key string) error                // missing → no-op (no error)
}
```

| Backend         | Implementation     | Storage location | Notes |
|-----------------|--------------------|------------------|-------|
| `keyringStore`  | `github.com/zalando/go-keyring` (service `"calvigil"`) | macOS Keychain / Windows Cred Mgr / Linux Secret Service | Preferred when available |
| `fileStore`     | JSON file          | `~/.calvigil-secrets.json` mode `0600` | Headless / CI / containers |

### 20.3 Backend Selection (`getStore()`)

```go
sync.Once first call:
 1. Read CALVIGIL_SECRET_BACKEND env var:
       "file"    → fileStore
       "keyring" → keyringStore (no probe)
       (other)   → continue
 2. Probe: keyring.Set("calvigil", "_calvigil_probe", "ok")
       success → keyring.Delete probe; use keyringStore
       failure → use fileStore
```

The probe avoids paying the runtime cost on every call and ensures cleanly headless environments degrade silently.

### 20.4 File Layout (`fileStore`)

```json
{
  "openai_api_key": "sk-...",
  "nvd_api_key":    "...",
  "github_token":   "ghp_..."
}
```

Mode `0600`. Mutated under a `sync.Mutex`. The path is re-resolved from `os.UserHomeDir()` on every operation so changing `$HOME` mid-process (in tests) works.

### 20.5 Test Hook

```go
func resetStoreForTests()  // clears defaultStoreOnce + defaultStoreImpl
```

Allows the same test process to re-probe after switching `CALVIGIL_SECRET_BACKEND`.

---

## 21. Image Reference Validation — `internal/image/validate.go`

### 21.1 Purpose

`scan-image <ref>` ultimately invokes `syft <ref>` (and syft may delegate to `docker`/`podman`). A malformed or hostile `<ref>` could either confuse syft or — worse — be interpreted by an underlying runtime in unexpected ways. `validateImageRef` is the boundary check that runs before any external process is spawned.

### 21.2 Algorithm

```
validateImageRef(ref):
 1. reject empty
 2. reject len > 1024
 3. reject any control char (< 0x20 or 0x7f) or whitespace
 4. reject shell metacharacters: ` $ ; & | < > ( ) * ? ! \ " '
 5. if ref contains ":" with non-empty prefix:
       scheme = ToLower(ref[:i])
       if scheme ∈ supportedSchemes:
           path = ref[i+1:]
           reject empty path
           reject ".." traversal sequence
           require safePathPattern match  → return nil
 6. require ociRefPattern match           → return nil
```

### 21.3 Supported Schemes

```go
{"docker", "docker-archive", "oci", "oci-archive", "oci-dir",
 "podman", "containerd", "singularity", "registry", "dir", "file"}
```

### 21.4 Patterns

```go
ociRefPattern = `^[A-Za-z0-9][A-Za-z0-9._-]*` +
                `(?::[0-9]{1,5})?` +
                `(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*` +
                `(?::[A-Za-z0-9][A-Za-z0-9._-]*)?` +
                `(?:@sha256:[a-f0-9]{64})?$`

safePathPattern = `^[A-Za-z0-9._/@:+\-]+$`
```

### 21.5 Accepted vs Rejected

| Input                                          | Result |
|------------------------------------------------|--------|
| `nginx`                                        | accept |
| `nginx:1.25`                                   | accept |
| `ghcr.io/org/app:tag`                          | accept |
| `library/nginx@sha256:<64hex>`                 | accept |
| `docker-archive:/tmp/image.tar`                | accept |
| `dir:/rootfs`                                  | accept |
| `nginx; rm -rf /`                              | reject (metachar) |
| `$(curl evil.sh)`                              | reject (metachar) |
| `dir:/etc/../etc/shadow`                       | reject (`..`) |
| `nginx ` (trailing space)                      | reject (whitespace) |

### 21.6 Caller

```go
// internal/image/image.go : Scanner.Scan()
if err := validateImageRef(s.imageRef); err != nil {
    return nil, fmt.Errorf("invalid image reference: %w", err)
}
cmd := exec.Command("syft", s.imageRef, "-o", "json")
```

---

## 22. Additional `cmd/` Files

### 22.1 `cmd/scan_iac.go`

| Flag             | Short | Default  | Purpose |
|------------------|-------|----------|---------|
| `--format`       | `-f`  | `table`  | `table\|json\|sarif\|cyclonedx\|openvex\|html\|pdf` |
| `--output`       | `-o`  | (stdout) | Output file path (written 0600) |
| `--severity`     | `-s`  | (all)    | Minimum severity: `critical\|high\|medium\|low` |

Flow:
```
scan-iac <path>
 → iac.Scan(path, verbose)
 → iac.ToVulnerabilities(findings, path)
 → filterVulnsBySeverity(vulns, min)
 → reporter.ForFormat(fmt).Report(scanResult, output)
```

### 22.2 `cmd/scan_binary.go`

Identical flag set to `scan-iac` (`--format`, `--output`, `--severity`). Flow:
```
scan-binary <path>
 → binary.Scan(path, verbose)
 → matcher.AggregatedMatcher.Match(packages)
 → filterVulnsBySeverity
 → writeReport(...)
```

### 22.3 `cmd/helpers.go`

```go
// Render report through the chosen reporter; if outputFile != "" the file
// is created with mode 0600 (so secrets in evidence packets are not
// world-readable). Otherwise writes to stdout.
func writeReport(rep reporter.Reporter, result *models.ScanResult, outputFile string) error

// Drop vulnerabilities below the requested minimum severity. min == "" or
// an unrecognised value is treated as "no filter".
func filterVulnsBySeverity(vulns []models.Vulnerability, min models.Severity) []models.Vulnerability
```

The `0600` mode applies uniformly to every output format (JSON/SARIF/CycloneDX/OpenVEX/HTML/PDF) because reports may embed AI-enriched evidence (snippets of source, secrets-likely strings, exploit chains). This is a project-wide invariant — every new reporter must route through `writeReport`.
