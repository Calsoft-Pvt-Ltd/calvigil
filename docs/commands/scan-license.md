---
title: scan-license
layout: default
parent: Commands
nav_order: 5
---

# calvigil scan-license
{: .no_toc }

Analyze dependency licenses for compliance risks.
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
calvigil scan-license [flags] <path>
```

## Flags

| Flag | Short | Default | Description |
|:-----|:------|:--------|:------------|
| `--format` | `-f` | `table` | Output format |
| `--output` | `-o` | stdout | Output file path |
| `--verbose` | `-v` | `false` | Verbose output |

---

## License Classification

calvigil classifies every dependency license into one of three categories:

| Category | Risk | Examples |
|:---------|:-----|:---------|
| **Permissive** | Low | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC |
| **Copyleft** | High | GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, MPL-2.0 |
| **Unknown** | Review needed | No license detected, non-standard license text |

---

## How It Works

1. **Parse dependencies** — Same parser pipeline as `scan`
2. **Resolve licenses** — Queries package registries (npm, PyPI, RubyGems, deps.dev) for declared licenses
3. **SPDX classification** — Maps license strings to SPDX identifiers
4. **Risk categorization** — Groups into permissive/copyleft/unknown

---

## Examples

### Basic License Scan

```bash
calvigil scan-license .
```

### JSON Output

```bash
calvigil scan-license --format json --output licenses.json .
```

### Verbose (Shows Resolution Source)

```bash
calvigil scan-license -v /path/to/project
```

---

## Example Output

```
📋 License Compliance Report

Total packages: 45
  Permissive: 38 (84%)
  Copyleft:    4 (9%)
  Unknown:     3 (7%)

┌──────────────────────┬─────────────┬────────────┬────────────┐
│ Package              │ Version     │ License    │ Category   │
├──────────────────────┼─────────────┼────────────┼────────────┤
│ express              │ 4.18.2      │ MIT        │ Permissive │
│ lodash               │ 4.17.21     │ MIT        │ Permissive │
│ readline-sync        │ 1.4.10      │ GPL-3.0    │ Copyleft   │
│ some-package         │ 2.0.0       │ —          │ Unknown    │
└──────────────────────┴─────────────┴────────────┴────────────┘

⚠️  4 copyleft licenses found — review for commercial compatibility
⚠️  3 packages with unknown licenses — manual review recommended
```

{: .warning }
> Copyleft licenses (GPL, AGPL) may require you to open-source your own code. Review with your legal team before shipping.
