<p align="center">
  <img src="calvigil2.png" alt="Calvigil Logo" width="300">
</p>

# calvigil

An open-source, AI-powered vulnerability scanner CLI for **Go**, **Java**, **Python**, **Node.js**, **Rust**, **Ruby**, **PHP**, and **C/C++** projects.

## Features

- **Dependency Scanning** — checks your lock files against multiple CVE databases:
  - [OSV.dev](https://osv.dev) (primary, batch API, no rate limits)
  - [NVD](https://nvd.nist.gov/) (NIST National Vulnerability Database)
  - [GitHub Advisory Database](https://github.com/advisories)

- **AI-Powered Code Analysis** — uses OpenAI GPT-4 or local Ollama models to detect OWASP Top 10 vulnerabilities:
  - SQL Injection, Command Injection, XSS
  - Hardcoded secrets & API keys
  - Insecure cryptography, TLS misconfigurations
  - Path traversal, insecure deserialization
  - CORS misconfiguration, and more
  - **Provider choice**: `--provider openai`, `--provider ollama`, or `--provider auto` (default)

- **Local LLM Support — Ollama Integration**:
  - Run AI analysis entirely offline with models like `llama3`, `codellama`, `mistral`
  - OpenAI-compatible API with native Ollama fallback
  - Auto-detection: if Ollama is reachable, it's preferred over OpenAI
  - Configure via CLI flags (`--ollama-url`, `--ollama-model`) or config/env vars

- **Container Image Scanning**:
  - Scan Docker/OCI images for known vulnerabilities
  - Powered by [syft](https://github.com/anchore/syft) for SBOM extraction
  - Supports Docker images, archives, and directories
  - Full vulnerability matching against OSV, NVD, and GitHub Advisory

- **SAST Engine — Semgrep CE Integration** with custom rule packs:
  - 31 bundled security rules covering OWASP Top 10 + language-specific patterns
  - Custom rule packs for Go, Python, Java, JavaScript/TypeScript, Rust, Ruby, PHP, and C/C++
  - Bring your own rules with `--semgrep-rules`

- **Standards Compliance**:
  - **PURL** (Package URL) — standard package identifiers (`pkg:npm/@babel/core@7.0.0`)
  - **CycloneDX v1.5** — SBOM/VDR format with components, vulnerabilities, and PURLs
  - **OpenVEX v0.2.0** — Vulnerability Exploitability Exchange with status and justification

- **Transitive Dependency Scanning**:
  - Distinguishes direct vs transitive (indirect) dependencies across all ecosystems
  - Go: `// indirect` comment detection in `go.mod`
  - npm: nesting depth (v2/v3) and recursive tree walk (v1)
  - Rust: root crate dependency list analysis in `Cargo.lock`
  - Ruby: indentation depth in `Gemfile.lock` (4-space direct, 6+ transitive)
  - PHP: companion `composer.json` cross-reference
  - Python: companion `pyproject.toml` cross-reference for `poetry.lock`/`uv.lock`
  - Transitive badge in HTML reports, `[transitive]` marker in dependency paths

- **Multi-Ecosystem Support** (grouped output with ecosystem icons):
  - **Go** 🐹: `go.mod`
  - **Java** ☕: `pom.xml`, `build.gradle`, `build.gradle.kts`
  - **Python** 🐍: `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`
  - **Node.js** 📗: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - **Rust** 🦀: `Cargo.lock`
  - **Ruby** 💎: `Gemfile.lock`
  - **PHP** 🐘: `composer.lock`
  - **C/C++** ⚙️: `conan.lock`

- **Multiple Output Formats**: Terminal table, JSON, SARIF v2.1.0, CycloneDX v1.5, OpenVEX v0.2.0, HTML, PDF

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/Calsoft-Pvt-Ltd/calvigil/releases).

**macOS:**
```bash
# Apple Silicon (M1/M2/M3)
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-darwin-arm64.tar.gz
tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/

# Intel
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-darwin-amd64.tar.gz
tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
```

> **macOS Gatekeeper:** If you see _"calvigil cannot be opened because Apple cannot verify it"_, run the following command to remove the quarantine attribute before running calvigil:
> ```bash
> xattr -dr com.apple.quarantine ./calvigil
> ```

**Linux:**
```bash
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
```

**Debian / Ubuntu (.deb):**
```bash
curl -Lo calvigil.deb https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil_<version>_amd64.deb
sudo dpkg -i calvigil.deb
```

**RHEL / CentOS / Fedora (.rpm):**
```bash
curl -Lo calvigil.rpm https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-<version>-1.x86_64.rpm
sudo rpm -i calvigil.rpm
```

**Windows:**
Download `calvigil-windows-amd64.zip` from [Releases](https://github.com/Calsoft-Pvt-Ltd/calvigil/releases), extract, and add to your PATH.

### From Source

```bash
git clone https://github.com/Calsoft-Pvt-Ltd/calvigil.git
cd calvigil
make build
```

The binary will be at `./bin/calvigil`.

### Go Install

```bash
go install github.com/Calsoft-Pvt-Ltd/calvigil@latest
```

## Quick Start

```bash
# Scan current directory (dependency scan only — no API key needed)
calvigil scan --skip-ai

# Scan a specific project
calvigil scan /path/to/project

# Full scan with AI analysis (requires OpenAI API key)
calvigil config set openai-key sk-...
calvigil scan

# Use local Ollama model (no API key needed)
calvigil scan --provider ollama --ollama-model llama3

# Auto-detect: uses Ollama if reachable, otherwise OpenAI
calvigil scan --provider auto

# Scan a container image for vulnerabilities (requires syft)
calvigil scan-image nginx:latest
calvigil scan-image python:3.12-slim --format json

# Output as JSON
calvigil scan --format json

# Output as SARIF (for GitHub Code Scanning, VS Code, etc.)
calvigil scan --format sarif --output results.sarif

# Output as CycloneDX SBOM
calvigil scan --format cyclonedx --output sbom.json

# Output as OpenVEX
calvigil scan --format openvex --output vex.json

# Executive-friendly HTML report
calvigil scan --format html --output report.html

# PDF report (requires Chrome or Chromium)
calvigil scan --format pdf --output report.pdf

# Run with custom Semgrep rules
calvigil scan --semgrep-rules ./my-rules/

# Skip Semgrep SAST analysis
calvigil scan --skip-semgrep

# Only show high and critical vulnerabilities
calvigil scan --severity high

# Verbose output
calvigil scan -v
```

## Configuration

Configuration is stored in `~/.calvigil.json`. Environment variables take precedence.

### API Keys

```bash
# OpenAI (required for AI code analysis with OpenAI provider)
calvigil config set openai-key sk-...
# or: export OPENAI_API_KEY=sk-...

# OpenAI model (default: gpt-4)
calvigil config set openai-model gpt-4-turbo

# Ollama URL (default: http://localhost:11434)
calvigil config set ollama-url http://localhost:11434
# or: export OLLAMA_URL=http://localhost:11434

# Ollama model (e.g. llama3, codellama, mistral)
calvigil config set ollama-model llama3
# or: export OLLAMA_MODEL=llama3

# NVD API key (optional, increases rate limits)
calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# or: export NVD_API_KEY=...

# GitHub token (optional, for GitHub Advisory Database)
calvigil config set github-token ghp_...
# or: export GITHUB_TOKEN=...
```

### View Configuration

```bash
calvigil config get openai-model
```

## CLI Reference

```
calvigil [command]

Available Commands:
  scan        Scan a project for security vulnerabilities
  scan-image  Scan a container image for vulnerabilities
  config      Manage scanner configuration
  version     Print the version
  help        Help about any command

Scan Flags:
  -f, --format string           Output format: table, json, sarif, cyclonedx, openvex, html, pdf (default "table")
  -o, --output string           Write output to file (default: stdout)
  -s, --severity string         Minimum severity: critical, high, medium, low
      --skip-ai                 Skip AI-powered code analysis
      --skip-deps               Skip dependency vulnerability scanning
      --skip-semgrep            Skip Semgrep SAST analysis
      --semgrep-rules string    Path to custom Semgrep rule directory
      --provider string         AI provider: openai, ollama, or auto (default "auto")
      --ollama-url string       Ollama server URL (default: http://localhost:11434)
      --ollama-model string     Ollama model name (e.g. llama3, codellama, mistral)
  -v, --verbose                 Enable verbose output

Scan-Image Flags:
  -f, --format string           Output format: table, json, sarif, cyclonedx, openvex, html, pdf (default "table")
  -o, --output string           Write output to file (default: stdout)
  -s, --severity string         Minimum severity: critical, high, medium, low
  -v, --verbose                 Enable verbose output
```

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐     ┌──────────────┐
│  Detect     │────▶│  Parse &     │────▶│  Match        │────▶│  AI Enrich   │────▶│  Report      │
│  Ecosystems │     │  PURL Gen    │     │  Against CVEs │     │  & Analyze   │     │  Results     │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘     └──────────────┘
                                                │                      │
                    ┌──────────────┐             │       ┌──────────────┐
                    │  AI Code     │─────────────┘       │  Semgrep CE  │
                    │  Analysis    │                     │  SAST Engine │
                    └──────────────┘                     └──────────────┘
```

1. **Detect**: Walks the project directory to find dependency manifest files (go.mod, pom.xml, package-lock.json, Cargo.lock, Gemfile.lock, composer.lock, conan.lock, etc.)
2. **Parse & PURL**: Extracts package names and versions, classifies direct vs transitive dependencies, generates Package URLs (PURLs) per the [PURL spec](https://github.com/package-url/purl-spec)
3. **Match**: Queries OSV, NVD, and GitHub Advisory databases for known CVEs
4. **Analyze**: Runs regex pattern matching + AI analysis (OpenAI or Ollama) on source code
5. **Semgrep SAST**: Runs Semgrep CE with bundled or custom rule packs for static analysis
6. **Enrich**: AI enrichment layer adds impact, confidence, remediation, and suppression rationale
7. **Report**: Outputs results in the requested format (table, JSON, SARIF, CycloneDX, OpenVEX, HTML, or PDF)

## Supported Vulnerability Patterns (Code Analysis)

| ID | Pattern | Severity |
|----|---------|----------|
| SEC-001 | SQL Injection (format strings) | HIGH |
| SEC-002 | SQL Injection (string concat) | HIGH |
| SEC-003 | Command Injection | CRITICAL |
| SEC-004 | Path Traversal | HIGH |
| SEC-005 | Hardcoded Secrets | HIGH |
| SEC-006 | AWS Access Keys | CRITICAL |
| SEC-007 | Weak Crypto (MD5/SHA1) | MEDIUM |
| SEC-008 | Cross-Site Scripting (XSS) | HIGH |
| SEC-009 | Insecure HTTP | LOW |
| SEC-010 | TLS Verification Disabled | CRITICAL |
| SEC-011 | Insecure Deserialization | HIGH |
| SEC-012 | Permissive CORS | MEDIUM |
| SEC-013 | Unsafe Rust (`unsafe` blocks) | MEDIUM |
| SEC-014 | C/C++ Buffer Overflow (`strcpy`, `gets`, `sprintf`) | HIGH |
| SEC-015 | C/C++ Format String Vulnerability | HIGH |
| SEC-016 | PHP File Inclusion (`include`/`require` with user input) | HIGH |
| SEC-017 | Ruby Mass Assignment | MEDIUM |

## Semgrep CE Integration

The scanner integrates with [Semgrep CE](https://semgrep.dev/) for static application security testing. Install Semgrep and the scanner will automatically use it:

```bash
pip install semgrep

# Scan with bundled rule packs (OWASP Top 10 + language-specific)
calvigil scan /path/to/project

# Scan with your own custom rules
calvigil scan --semgrep-rules ./my-rules/ /path/to/project

# Skip Semgrep entirely
calvigil scan --skip-semgrep /path/to/project
```

**Bundled rule packs** (in `rules/semgrep/`):
- `owasp-top10.yaml` — 20 rules: SQL injection, command injection, path traversal, hardcoded secrets, insecure TLS, weak crypto, XSS, insecure deserialization, SSRF
- `language-specific.yaml` — 11 rules: Go (unsafe pointer, HTTP no timeout, defer in loop), Python (Flask debug, bind 0.0.0.0), JS (eval, CORS wildcard, JWT no verify), Java (XXE, ECB mode), plus Rust, C/C++, PHP, Ruby patterns

## Standards & Output Formats

| Format | Flag | Spec | Use Case |
|--------|------|------|----------|
| Table | `--format table` | — | Human-readable terminal output (grouped by ecosystem) |
| JSON | `--format json` | — | Machine-readable, CI/CD pipelines, scripting |
| SARIF | `--format sarif` | v2.1.0 | GitHub Code Scanning, VS Code, IDE integrations |
| CycloneDX | `--format cyclonedx` | v1.5 | SBOM/VDR with components, PURLs, and vulnerabilities |
| OpenVEX | `--format openvex` | v0.2.0 | Vulnerability exploitability exchange with status/justification |
| HTML | `--format html` | — | Executive-friendly report with severity charts, badges, and AI enrichment |
| PDF | `--format pdf` | — | Print-ready PDF report for MIS/management audiences (requires Chrome or Chromium) |

### PURL (Package URL)

All packages are identified using [PURL](https://github.com/package-url/purl-spec) standard identifiers:

| Ecosystem | Example PURL |
|-----------|-------------|
| Go | `pkg:golang/github.com/hashicorp/vault@v1.15.2` |
| npm | `pkg:npm/@babel/helpers@7.15.4` |
| PyPI | `pkg:pypi/requests@2.28.0` |
| Maven | `pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0` |
| Rust | `pkg:cargo/serde@1.0.180` |
| Ruby | `pkg:gem/rails@7.0.4` |
| PHP | `pkg:composer/monolog/monolog@3.5.0` |
| C/C++ | `pkg:conan/openssl@3.1.0` |

## Ollama (Local LLM) Support

Run AI-powered analysis entirely offline using [Ollama](https://ollama.ai/) with models like `llama3`, `codellama`, or `mistral`.

```bash
# Install Ollama and pull a model
ollama pull llama3

# Scan with Ollama
calvigil scan --provider ollama --ollama-model llama3

# Use a remote Ollama server
calvigil scan --provider ollama --ollama-url http://gpu-server:11434 --ollama-model codellama

# Auto mode (default): uses Ollama if reachable, otherwise OpenAI
calvigil scan
```

**Provider selection (`--provider`)**:
- `auto` (default): Tries Ollama first (if configured and reachable), falls back to OpenAI
- `ollama`: Use only Ollama (fails if unreachable)
- `openai`: Use only OpenAI (requires API key)

### AI Enrichment & Model Recommendations

Calvigil enriches findings in batches via the AI provider. Smaller local models (≤3B parameters, e.g. `qwen3:1.7b`) may return malformed JSON or incorrect finding IDs, resulting in **partial enrichment** (typically 50–70% of findings). This is by design — failed batches are skipped gracefully so the scan always completes.

For best enrichment coverage:

| Model | Enrichment Rate | Notes |
|-------|----------------|-------|
| GPT-4 / GPT-4o (OpenAI) | ~100% | Most reliable, requires API key |
| `llama3:8b`, `qwen3:8b` | ~90–95% | Good balance of quality and speed |
| `codellama:13b`, `mistral:7b` | ~85–95% | Strong for code-focused analysis |
| `qwen3:1.7b`, `phi3:mini` | ~50–70% | Lightweight but limited JSON reliability |

## Container Image Scanning

Scan Docker/OCI container images for vulnerabilities using [syft](https://github.com/anchore/syft):

```bash
# Install syft
brew install syft  # macOS
# or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Scan a Docker image
calvigil scan-image nginx:latest

# Scan with a specific output format
calvigil scan-image python:3.12-slim --format json
calvigil scan-image node:20 --format sarif --output results.sarif

# Scan local archives or directories
calvigil scan-image docker-archive:image.tar
calvigil scan-image dir:/path/to/rootfs

# Filter by severity
calvigil scan-image alpine:3.18 --severity high
```

The image scanner:
1. Uses **syft** to extract an SBOM from the container image
2. Maps packages to supported ecosystems (npm, PyPI, Go, Maven, Ruby, Rust, Debian, Alpine, RPM)
3. Matches all packages against **OSV**, **NVD**, and **GitHub Advisory** databases
4. Reports findings in any supported format (table, JSON, SARIF, CycloneDX, OpenVEX)

## License

Apache License 2.0 — see [LICENSE](LICENSE)
