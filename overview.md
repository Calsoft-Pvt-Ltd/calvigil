# Calvigil — Overview

## What Is Calvigil?

Calvigil is a **command-line security scanner** that finds vulnerabilities in your software projects. Think of it as a security guard that checks your code and its dependencies for known weaknesses before attackers can exploit them.

It works across **8 programming languages** — Go, Java, Python, Node.js, Rust, Ruby, PHP, and C/C++ — and you can run it with a single command:

```bash
calvigil scan /path/to/your/project
```

No cloud accounts, no dashboards, no complex setup. Just point it at your code and get results.

---

## How Does It Work?

Calvigil runs up to **six types of security checks**, each looking for different kinds of problems:

### 1. Dependency Scanning (automatic)

Every modern project uses third-party libraries. Calvigil reads your lockfiles (`package-lock.json`, `go.mod`, `Cargo.lock`, etc.) and checks every dependency against four vulnerability databases:

- **OSV.dev** — Google's open vulnerability database
- **Sonatype OSS Index** — free, PURL-based component vulnerability data for all major ecosystems
- **NVD** — The US government's National Vulnerability Database
- **GitHub Advisory Database** — GitHub's curated security advisories

Results from every database are normalized into a single canonical form (CVE IDs preferred, duplicates merged, missing severity filled in from other sources) and then checked against the **CISA Known Exploited Vulnerabilities (KEV)** catalog — anything actively exploited in the wild is flagged `⚠ KEV` so you know what to fix first.

If any of your dependencies have a known CVE (security flaw), Calvigil tells you which package, which version, how severe it is, and which version to upgrade to.

### 2. AI-Powered Code Analysis (optional)

Calvigil can send your source files to an AI model (OpenAI GPT-4, a local Ollama model, or LM Studio) to detect **OWASP Top 10** vulnerabilities directly in your code:

- SQL injection, command injection, cross-site scripting (XSS)
- Hardcoded secrets and API keys
- Insecure TLS configuration, weak cryptography
- Path traversal, insecure deserialization

The AI enrichment layer also classifies findings as `LIKELY_AI`, `POSSIBLY_AI`, or `UNLIKELY_AI` — helping teams identify and prioritize risks introduced by AI code generators.

This catches security bugs that no dependency database can find — the ones **you** wrote (or the ones your AI assistant wrote).

### 2a. AI-Generated Code Detection (automatic)

Calvigil includes **18 dedicated rules** that detect anti-patterns commonly introduced by AI code generators (Copilot, ChatGPT, Claude, etc.):

- **Resource leaks**: unclosed HTTP response bodies, files opened in loops without close
- **Race conditions**: concurrent map writes in goroutines, loop variable capture
- **Inefficient algorithms**: O(n²) nested loops, string concatenation in loops
- **Error handling**: ignored error returns, overly broad exception handlers
- **Deprecated APIs**: `ioutil` (Go), `distutils` (Python), `Buffer()` (Node.js)
- **Insecure defaults**: 0777 file permissions, hardcoded server addresses
- **Missing validation**: unchecked type conversions, unbounded data loading
- **Sensitive data leaks**: passwords and tokens in log output

These run automatically as part of the pattern scanner — no AI model or API key required.

### 3. SAST Engine — Semgrep (automatic)

Calvigil ships with **77+ built-in security rules** powered by Semgrep, covering Go, Python, Java, JavaScript/TypeScript, Rust, Ruby, PHP, and C/C++. This includes a dedicated **AI code quality** rule pack that detects resource leaks, race conditions, deprecated APIs, and inefficient patterns at the AST level. All of this works without needing an AI model.

### 4. Supply Chain Protection (automatic + opt-in)

Calvigil guards against software supply chain attacks:

- **Malicious package detection** — Flags packages with MAL- advisories (known trojan/malware libraries)
- **Lockfile integrity verification** (`--verify-integrity`) — Compares hash values in your lockfile against the npm registry to catch tampered packages
- **Phantom dependency detection** — Finds packages in your lockfile that aren't declared in your manifest (package.json) — a sign of lockfile injection

### 5. Infrastructure-as-Code Scanning

Calvigil scans Terraform, Kubernetes YAML, Dockerfiles, CloudFormation, Docker Compose, and Helm charts for security misconfigurations:

- Open security groups, public S3 buckets
- Containers running as root, using `latest` tag
- Missing resource limits, exposed host networks

### 6. License Compliance

Calvigil checks which open-source licenses your dependencies use so you don't accidentally include a copyleft license (GPL, AGPL) in a proprietary product. It queries registries for license data and understands compound SPDX expressions.

---

## What It Scans

| What | How | Example Files |
|------|-----|---------------|
| **Dependencies** | Reads lockfiles, matches against CVE databases | `go.mod`, `package-lock.json`, `Cargo.lock`, `pom.xml` |
| **Source code** | AI model + Semgrep static analysis | `.go`, `.py`, `.java`, `.js`, `.ts`, `.rs` |
| **Infrastructure** | Built-in regex rules for IaC misconfigurations | `*.tf`, `Dockerfile`, `k8s/*.yaml`, `docker-compose.yml` |
| **Binaries** | Extracts embedded dependency info from compiled artifacts | Go binaries, `.jar`/`.war` archives, Python wheels |
| **Container images** | Uses Syft to extract SBOM, then matches CVEs | `nginx:latest`, `python:3.12-slim` |
| **Licenses** | Checks SPDX identifiers against risk categories | All supported lockfiles |
| **Supply chain** | Integrity hashes, phantom deps, MAL advisories | `package-lock.json`, `Cargo.lock`, `package.json` |

---

## Output Formats

Calvigil generates reports in **8 formats** to fit into any workflow:

| Format | Use Case |
|--------|----------|
| **Terminal table** (default) | Quick check during development |
| **JSON** | Pipe into scripts, dashboards, or other tools |
| **SARIF** | Upload to GitHub Code Scanning, VS Code Problems tab |
| **HTML** | Executive or team-facing reports |
| **PDF** | Attach to compliance documents |
| **CycloneDX** | Standard SBOM format for auditors |
| **SPDX** | Alternative SBOM standard |
| **OpenVEX** | Vulnerability exploitability exchange |

---

## Real-Life Use Cases

### 1. Pre-Commit Security Check for Developers

**Scenario:** You're a developer about to push code to your team's repository.

```bash
calvigil scan --skip-ai
```

In seconds you see if any of your dependencies have known CVEs and what versions to upgrade to. This catches problems before they enter pull requests.

---

### 2. CI/CD Pipeline Gate

**Scenario:** Your team wants to block deployments that contain critical vulnerabilities.

```bash
calvigil scan --severity high --format sarif --output results.sarif
```

Add this to your GitHub Actions, GitLab CI, or Jenkins pipeline. The SARIF output integrates with GitHub Code Scanning. Fail the build if critical issues are found.

---

### 3. Open-Source Dependency Audit Before Release

**Scenario:** You're preparing a release and need to verify all third-party libraries are safe.

```bash
calvigil scan --format cyclonedx --output sbom.json
calvigil scan --check-licenses --format html --output audit.html
```

Generate a full Software Bill of Materials (SBOM) for compliance, and an HTML license report for legal review.

---

### 4. Detecting Supply Chain Attacks

**Scenario:** A compromised maintainer has published a tampered version of a popular npm package, or someone has injected an undeclared package into your lockfile.

```bash
calvigil scan --verify-integrity
```

Calvigil compares every npm package hash against the official registry. If a hash doesn't match or a package doesn't exist on the registry at all — you'll know immediately. Phantom dependencies (packages in the lockfile but not in package.json) are flagged automatically.

---

### 5. Scanning Legacy Code for Security Debt

**Scenario:** Your team inherited a legacy codebase and needs to understand its security posture.

```bash
calvigil scan --provider ollama --ollama-model llama3
```

The AI analysis scans source files for hardcoded secrets, SQL injection, insecure crypto, and other OWASP Top 10 issues. Using Ollama means everything stays on your local machine — no code leaves your network.

---

### 6. Infrastructure Security Review

**Scenario:** Your DevOps team has Terraform and Kubernetes manifests that need a security check before provisioning cloud resources.

```bash
calvigil scan-iac ./infrastructure/
```

Calvigil flags open security groups, public S3 buckets, containers running as root, missing resource limits, and 20+ other misconfigurations without needing any external tool.

---

### 7. Container Image Assessment

**Scenario:** You're pulling a base image from Docker Hub and want to know what vulnerabilities it ships with.

```bash
calvigil scan-image python:3.12-slim --format json
```

Calvigil extracts an SBOM from the image using Syft, then matches every embedded package against CVE databases.

---

### 8. Binary Artifact Inspection

**Scenario:** You received a compiled Go binary or Java JAR from a vendor and need to verify what dependencies are embedded.

```bash
calvigil scan-binary /path/to/vendor-app
```

Calvigil extracts dependency metadata embedded in Go binaries, Java archives (JAR/WAR/EAR), and Python wheels, then checks them all for known vulnerabilities.

---

### 9. License Compliance for Enterprise Software

**Scenario:** Your legal team needs confirmation that no copyleft-licensed code (GPL, AGPL) is included in a commercial product.

```bash
calvigil scan-license /path/to/project --risk copyleft --format html --output license-report.html
```

This runs a standalone license scan (no API keys needed) and generates an HTML report filtered to only show copyleft or unknown licenses.

---

### 10. Offline / Air-Gapped Security Scanning

**Scenario:** Your environment has no internet access. You still need to run code analysis.

```bash
# Use Ollama for fully local AI analysis
calvigil scan --provider ollama --ollama-model codellama --skip-deps

# Or use LM Studio
calvigil scan --provider lmstudio --lmstudio-model codellama --skip-deps

# Use cached vulnerability data from a previous online scan
calvigil scan --cache-ttl 168h   # use cached data up to 7 days old
```

Calvigil's Semgrep rules are bundled locally, Ollama and LM Studio run entirely on your machine, and the vulnerability cache stores results from previous scans.

---

### 11. Multi-Language Monorepo Scan

**Scenario:** Your repository contains a Go backend, a React frontend, and Python data-processing scripts — all in one repo.

```bash
calvigil scan /path/to/monorepo
```

Calvigil auto-detects all ecosystems in the project tree. It reads `go.mod`, `package-lock.json`, and `requirements.txt` in a single run and groups results by ecosystem with clear icons (🐹 Go, 📗 npm, 🐍 Python).

---

### 12. Executive Security Report

**Scenario:** Management wants a security overview of a project for a quarterly review.

```bash
calvigil scan --format html --output security-report.html
# or
calvigil scan --format pdf --output security-report.pdf
```

HTML and PDF reports include severity breakdowns, dependency paths, and AI-enriched remediation advice — ready to share with non-technical stakeholders.

---

## Key Highlights

- **No cloud service required** — Calvigil is a single binary you run locally
- **Zero mandatory API keys** — Dependency scanning, Semgrep SAST, IaC scanning, license checking, and supply chain detection all work without any keys
- **AI is opt-in** — Use OpenAI, use local Ollama, use LM Studio, or skip AI entirely
- **Works offline** — Bundled Semgrep rules + Ollama/LM Studio + vulnerability cache
- **Standards-compliant** — PURL, CycloneDX, SPDX, OpenVEX, SARIF
- **Fast** — Cached scans complete in seconds; concurrent matching against multiple databases
