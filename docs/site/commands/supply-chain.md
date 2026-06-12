---
title: Supply Chain Security
layout: default
nav_order: 8
parent: Commands
---

# Supply Chain Security
{: .no_toc }

Detect malicious packages, verify lockfile integrity, and find phantom dependencies.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Integrity Verification

Verify that package checksums in your lockfile match what registries serve:

```bash
calvigil scan --verify-integrity /path/to/project
```

This checks:
- **npm** (`package-lock.json`): SHA-512 integrity hashes
- **Go** (`go.sum`): Module hash verification
- **Python** (`Pipfile.lock`, `poetry.lock`): SHA-256 hashes

A mismatch could indicate:
- A compromised registry mirror
- A supply chain attack (package replaced after install)
- Corrupted local cache

---

## Phantom Dependency Detection

Detects packages that exist in the lockfile but are **not** referenced by the manifest:

```bash
calvigil scan -v /path/to/project
```

Phantom dependencies may indicate:
- Leftover packages from removed features
- Packages injected by a malicious contributor
- Lockfile manipulation attacks

---

## Malicious Package Detection

calvigil checks for known malicious packages flagged by vulnerability databases. These include:
- Typosquatting packages (e.g., `lod-ash` instead of `lodash`)
- Packages with known malicious payload (flagged by OSV/GitHub Advisory)
- Deprecated packages with known exploits

---

## Example Output

```
🔍 Supply Chain Analysis:

⚠️  Integrity Issues:
  - lodash@4.17.20: SHA mismatch (expected: sha512-abc... got: sha512-xyz...)

⚠️  Phantom Dependencies:
  - evil-package@1.0.0: in lockfile but not referenced by package.json

✅ No known malicious packages detected
```
