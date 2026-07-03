---
title: Supply Chain Security
layout: default
nav_order: 8
parent: Commands
---

# Supply Chain Security
{: .no_toc }

Detect malicious packages, verify lockfile integrity, and review dependency trust drift before it reaches production.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Supply Chain Guard

Supply Chain Guard is Calvigil's local-first M1-M3 protection layer for dependency-risk changes that ordinary CVE matching can miss.

```bash
calvigil scan --supply-chain-guard --format json --output guarded.json /path/to/project
```

The scan report includes a `supply_chain_risk` object with:

- A 0-100 score and release decision
- New dependency, downgrade, phantom dependency, and dependency-confusion signals
- Suspicious package metadata such as unknown licenses, non-registry sources, and loose direct dependency specs
- Install-time behavior signals from npm lifecycle scripts and Python `setup.py`
- Actionable guidance for engineering review

{: .note }
> M1-M3 checks are deterministic and local. They do not execute package install hooks, run untrusted code, or require registry credentials.

## M1: Dependency Trust Drift

Compare a known-good report against a target report:

```bash
calvigil supply-chain diff \
  --baseline-report baseline.json \
  --target-report guarded.json
```

JSON output is also available:

```bash
calvigil supply-chain diff \
  --baseline-report baseline.json \
  --target-report guarded.json \
  --format json \
  --output supply-chain-risk.json
```

Signals include:

| Signal | Meaning | Typical action |
|:-------|:--------|:---------------|
| `SCM-101` | New direct dependency introduced | Confirm owner, purpose, and source before release |
| `SCM-102` | Dependency version downgrade | Verify rollback intent and vulnerability exposure |
| `SCM-104` | Lockfile package not declared in manifest | Regenerate lockfile or investigate lockfile injection |
| `SCM-105` | New dependency name resembles an existing package | Review for typosquatting or dependency-confusion risk |

## M2: Package Metadata Suspicion

Run with `--supply-chain-guard` to inspect local manifest and package inventory metadata.

Signals include:

| Signal | Meaning | Typical action |
|:-------|:--------|:---------------|
| `SCM-201` | Direct dependency has unknown license | Resolve SPDX identity before distribution |
| `SCM-202` | Dependency resolved from git/file/http/tarball source | Confirm this source is intentional and pinned |
| `SCM-203` | Direct dependency has a loose version spec | Pin release inputs for reproducible builds |

## M3: Install-Time Behavior

Run with `--supply-chain-guard` to inspect install-time behavior without executing it.

Signals include:

| Signal | Meaning | Typical action |
|:-------|:--------|:---------------|
| `SCM-301` | npm dependency declares install/postinstall/preinstall behavior | Review package provenance and hook purpose |
| `SCM-302` | npm project lifecycle script downloads or executes remote content | Remove curl/wget pipe execution or isolate build |
| `SCM-303` | Python `setup.py` invokes process/network behavior | Review packaging script before build or publish |
| `SCM-304` | Lifecycle script includes obfuscated execution markers | Treat as high-risk until reviewed |

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
Supply Chain Guard: HIGH score=74 decision=review_before_merge findings=3

- Review new direct dependencies before release.
- Confirm install-time scripts are intentional and pinned.

┌──────────┬─────────────────────────────────────┬───────────────┬──────────────────────────────┐
│ Severity │ Signal                              │ Package       │ Recommendation               │
├──────────┼─────────────────────────────────────┼───────────────┼──────────────────────────────┤
│ HIGH     │ SCM-102 Dependency downgrade        │ openssl@1.0.2 │ Verify rollback intent        │
│ HIGH     │ SCM-301 npm install script present  │ esbuild@0.21  │ Review package hook behavior  │
│ MEDIUM   │ SCM-203 Loose direct dependency     │ lodash@^4.17  │ Pin direct dependency version │
└──────────┴─────────────────────────────────────┴───────────────┴──────────────────────────────┘
```

## CI Pattern

Create a baseline report from the protected branch and compare the pull-request report:

```bash
calvigil scan --supply-chain-guard --skip-ai --skip-semgrep \
  --format json --output pr-report.json .

calvigil supply-chain diff \
  --baseline-report main-report.json \
  --target-report pr-report.json \
  --format json \
  --output supply-chain-risk.json
```

Fail the pipeline when `supply_chain_risk.decision` is `block_release` or when your policy treats `review_before_merge` as blocking.

## Limitations

Supply Chain Guard M1-M3 is intentionally conservative:

- It does not execute package manager scripts.
- It does not prove malicious intent.
- It does not replace vulnerability matching, license review, or human approval for risky dependency changes.
- Registry reputation, maintainer-change intelligence, and package provenance feeds are planned for later milestones.
