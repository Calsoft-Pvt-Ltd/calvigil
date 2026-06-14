---
title: scan-binary
layout: default
parent: Commands
nav_order: 3
---

# calvigil scan-binary
{: .no_toc }

Extract dependencies from compiled binaries and scan for vulnerabilities.
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
calvigil scan-binary [flags] <path>
```

## Flags

| Flag | Short | Default | Description |
|:-----|:------|:--------|:------------|
| `--format` | `-f` | `table` | Output format |
| `--output` | `-o` | stdout | Output file path |
| `--severity` | `-s` | all | Minimum severity filter |
| `--verbose` | `-v` | `false` | Verbose output |

---

## Supported Binary Types

| Binary Type | Detection Method | Extracted Info |
|:------------|:----------------|:---------------|
| **Go binaries** | `debug/buildinfo` | Embedded module path + version for all dependencies |
| **Java JARs/WARs/EARs** | `pom.properties`, `MANIFEST.MF`, Spring Boot `BOOT-INF/lib/` | Group ID, artifact ID, version |
| **Python wheels/eggs** | `.dist-info/METADATA`, `PKG-INFO` | Package name and version |

---

## Examples

### Scan a Go Binary

```bash
calvigil scan-binary ./bin/myapp
```

### Scan a Directory of JARs

```bash
calvigil scan-binary ./lib/
```

### Scan a Spring Boot Uber-JAR

```bash
calvigil scan-binary ./target/application.jar
```

### JSON Output

```bash
calvigil scan-binary --format json --output binary-vulns.json ./bin/server
```

---

## How It Works

1. **File-type detection** — Automatically identifies binary type (Go ELF/Mach-O, JAR/WAR/EAR, Python wheel)
2. **Recursive walk** — Scans directories recursively, detecting all supported binary files
3. **Dependency extraction** — Reads embedded metadata specific to each binary type
4. **PURL generation** — Creates Package URLs for each extracted dependency
5. **Vulnerability matching** — OSV plus configured NVD/GitHub Advisory sources
6. **KEV enrichment** — Flags actively exploited CVEs

{: .tip }
> Go binaries embed full dependency information at compile time via `debug/buildinfo`. This makes Go binary scanning particularly accurate — you get exact versions of every module used.
