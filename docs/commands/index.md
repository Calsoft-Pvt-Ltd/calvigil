---
title: Commands
layout: default
nav_order: 4
has_children: true
---

# Commands Reference
{: .no_toc }

calvigil provides scan commands, supply-chain analysis, Enterprise upload, and configuration management.
{: .fs-5 .fw-300 }

---

## Overview

| Command | Purpose |
|:--------|:--------|
| [`scan`]({% link commands/scan.md %}) | Dependency scanning + optional AI code analysis |
| [`scan-image`]({% link commands/scan-image.md %}) | Container image vulnerability scanning |
| [`scan-binary`]({% link commands/scan-binary.md %}) | Binary/SCA scanning (Go, JAR, Python wheel) |
| [`scan-iac`]({% link commands/scan-iac.md %}) | Infrastructure-as-Code misconfiguration scanning |
| [`scan-license`]({% link commands/scan-license.md %}) | License compliance analysis |
| [`supply-chain`]({% link commands/supply-chain.md %}) | Compare JSON reports for dependency trust drift and supply-chain guard signals |
| [`push`]({% link commands/push.md %}) | Upload an existing JSON report to Calvigil Enterprise |
| `config set` | Persist a configuration key |
| `config get` | View a configuration key (secrets masked) |
| `version` | Print version and Go runtime info |

---

## Global Flags

These flags are available on all scan commands:

| Flag | Description |
|:-----|:------------|
| `--verbose`, `-v` | Show detailed progress and debug output |
| `--format` | Output format: `table`, `json`, `sarif`, `cyclonedx`, `spdx`, `openvex`, `html`, `pdf` |
| `--output`, `-o` | Write output to a file (default: stdout) |
| `--severity` | Filter by minimum severity: `low`, `medium`, `high`, `critical` |
| `--no-cache` | Disable vulnerability cache |
| `--cache-ttl` | Cache time-to-live (default: `24h`) |
