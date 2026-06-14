---
title: Getting Started
layout: default
nav_order: 2
---

# Getting Started
{: .no_toc }

Install calvigil and run your first vulnerability scan in under 2 minutes.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/Calsoft-Pvt-Ltd/calvigil/releases).

**macOS (Apple Silicon):**
```bash
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-darwin-arm64.tar.gz
tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
```

**macOS (Intel):**
```bash
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-darwin-amd64.tar.gz
tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
```

{: .warning }
> **macOS Gatekeeper:** If you see _"calvigil cannot be opened because Apple cannot verify it"_, run:
> ```bash
> xattr -dr com.apple.quarantine ./calvigil
> ```

**Linux (amd64):**
```bash
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
```

**Debian / Ubuntu:**
```bash
curl -Lo calvigil.deb https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil_5.0.0_amd64.deb
sudo dpkg -i calvigil.deb
```

**RHEL / CentOS / Fedora:**
```bash
curl -Lo calvigil.rpm https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-5.0.0-1.x86_64.rpm
sudo rpm -i calvigil.rpm
```

**Windows:**

Download `calvigil-windows-amd64.zip` from [Releases](https://github.com/Calsoft-Pvt-Ltd/calvigil/releases), extract, and add to your PATH.

### From Source

```bash
git clone https://github.com/Calsoft-Pvt-Ltd/calvigil.git
cd calvigil
make build
# binary is at ./bin/calvigil
```

### Go Install

```bash
go install github.com/Calsoft-Pvt-Ltd/calvigil@latest
```

---

## Verify Installation

```bash
calvigil version
```

Expected output:
```
calvigil version 5.0.0 (go1.22.x)
```

---

## Your First Scan

Run a basic dependency vulnerability scan — no API keys needed:

```bash
calvigil scan /path/to/your/project
```

This will:
1. Detect project ecosystems (Go, Python, Node.js, etc.)
2. Parse all dependency lock files
3. Query OSV.dev, plus Sonatype OSS Index when credentials are configured
4. Check CISA KEV for actively exploited CVEs
5. Print a table of findings

### Example Output

```
🔍 Scanning /home/user/my-app ...

📂 Detecting project ecosystems...
   Found 2 manifest files across 2 ecosystems
   - package-lock.json (npm)
   - requirements.txt (Python)

📦 Parsing dependencies...
   Parsed 142 packages
   Total: 142 packages (28 direct, 114 transitive)

🔎 Querying vulnerability databases...
   Found 5 dependency vulnerabilities (3 merged from multiple sources)

┌──────────────────┬──────────────┬──────────┬─────────────────┬───────────┐
│ ID               │ Package      │ Severity │ Installed       │ Fixed In  │
├──────────────────┼──────────────┼──────────┼─────────────────┼───────────┤
│ CVE-2024-1234 ⚠ KEV │ lodash  │ CRITICAL │ 4.17.20         │ 4.17.21   │
│ CVE-2024-5678    │ express      │ HIGH     │ 4.17.1          │ 4.18.2    │
│ CVE-2024-9012    │ requests     │ MEDIUM   │ 2.28.0          │ 2.31.0    │
└──────────────────┴──────────────┴──────────┴─────────────────┴───────────┘

⚠️ Known exploited (CISA KEV): 1 — prioritize these fixes
```

---

## Next Steps

- [Configure API keys]({% link configuration.md %}) for NVD, GitHub Advisory, and OSS Index
- [Enable AI code analysis]({% link ai-analysis.md %}) with OpenAI, Ollama, or LM Studio
- [Choose an output format]({% link reporting.md %}) (JSON, SARIF, CycloneDX, HTML, PDF)
- [Integrate into CI/CD]({% link ci-cd.md %}) — GitHub Actions, GitLab, Bitbucket, Azure DevOps, GCP, Jenkins
- [Scan container images]({% link commands/scan-image.md %}) with `scan-image`
- [Scan IaC files]({% link commands/scan-iac.md %}) for misconfigurations
