---
title: scan-image
layout: default
parent: Commands
nav_order: 2
---

# calvigil scan-image
{: .no_toc }

Scan Docker/OCI container images for known vulnerabilities.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Usage

```bash
calvigil scan-image [flags] <image-reference>
```

## Prerequisites

- [Syft](https://github.com/anchore/syft) must be installed and on your PATH
- Docker (for pulling images that aren't local)

```bash
# Install syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

## Flags

| Flag | Short | Default | Description |
|:-----|:------|:--------|:------------|
| `--format` | `-f` | `table` | Output format |
| `--output` | `-o` | stdout | Output file path |
| `--severity` | `-s` | all | Minimum severity filter |
| `--verbose` | `-v` | `false` | Verbose output |

---

## Supported Image References

| Format | Example |
|:-------|:--------|
| Docker Hub | `nginx:latest`, `library/nginx:1.25` |
| Registry | `ghcr.io/org/image:tag` |
| Local archive | `./image.tar` |
| Directory | `dir:/path/to/rootfs` |

---

## Examples

### Scan a Docker Hub Image

```bash
calvigil scan-image nginx:latest
```

### Scan a Private Registry Image

```bash
calvigil scan-image ghcr.io/myorg/myapp:v2.1.0
```

### JSON Output

```bash
calvigil scan-image --format json --output image-vulns.json python:3.12-slim
```

### Filter Critical Only

```bash
calvigil scan-image --severity critical node:20-alpine
```

---

## How It Works

1. **SBOM extraction** — Syft analyzes the image layers and produces a software bill of materials
2. **Ecosystem mapping** — Package types (deb, rpm, apk, npm, pip, etc.) are mapped to calvigil ecosystems
3. **PURL generation** — Each package gets a Package URL for precise database lookups
4. **Vulnerability matching** — Aggregated matcher pipeline (OSV plus configured NVD/GitHub Advisory sources)
5. **Canonical normalization** — Results are normalized and merged across databases
6. **KEV enrichment** — Actively exploited CVEs are flagged

---

## Supported Image Ecosystems

| Package Type | Ecosystem | Database Coverage |
|:-------------|:----------|:-----------------|
| `npm` | npm | OSV plus configured NVD/GitHub Advisory sources |
| `python`, `pip`, `wheel` | PyPI | OSV plus configured NVD/GitHub Advisory sources |
| `go-module` | Go | OSV plus configured NVD/GitHub Advisory sources |
| `java-archive`, `maven` | Maven | OSV plus configured NVD/GitHub Advisory sources |
| `deb` | Debian | OSV |
| `rpm` | RPM | OSV |
| `apk` | Alpine | OSV |
