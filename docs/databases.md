---
title: Vulnerability Databases
layout: default
nav_order: 5
---

# Vulnerability Databases
{: .no_toc }

How calvigil queries, normalizes, and merges vulnerability data from multiple sources.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Database Overview

| Database | Always On | Auth | Rate Limit | Role |
|:---------|:---------:|:-----|:-----------|:-----|
| **[OSV.dev](https://osv.dev)** | ✅ | None | Unlimited | Primary — batch queries, covers all ecosystems |
| **[Sonatype OSS Index](https://ossindex.sonatype.org/)** | ❌ | Basic auth with existing/migrated token | 128 coords/request | Optional — PURL-based, all ecosystems |
| **[NVD](https://nvd.nist.gov/)** | ❌ | Optional API key | 5 req/30s (free), 50 req/30s (keyed) | Optional keyword search; best-effort batched CVSS enrichment |
| **[GitHub Advisory](https://github.com/advisories)** | ❌ | Optional PAT | 60/hr (no token), 5000/hr (with token) | Supplementary — GHSA cross-references |
| **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** | ✅ | None | Unlimited | Enrichment — flags actively exploited CVEs |

{: .note }
> **OSV.dev** is always enabled and requires no configuration. **Sonatype OSS Index** is enabled only when `OSSINDEX_USER` and `OSSINDEX_TOKEN` are configured.

---

## Canonical Data Model

Every database reports vulnerabilities in a different format with different IDs, severity labels, and metadata. calvigil normalizes everything into one consistent shape before reporting.

### ID Normalization

calvigil picks the most authoritative ID as the **canonical identifier**:

```
CVE-YYYY-NNNNN  >  GHSA-xxxx-xxxx-xxxx  >  ecosystem IDs (GO-..., PYSEC-..., SONATYPE-...)
```

The previous ID becomes an **alias**. This means a finding reported as `GHSA-1234-abcd-5678` by GitHub Advisory and as `CVE-2024-1234` by NVD will show as:
- **ID:** `CVE-2024-1234`
- **Aliases:** `GHSA-1234-abcd-5678`

### Cross-Source Merging

When two databases report the same vulnerability (matched by ID **or** alias), the records are **merged** instead of one being dropped:

| Field | Rule |
|:------|:-----|
| Severity | First non-UNKNOWN value wins |
| CVSS Score | First non-zero value wins |
| Summary | First non-empty value wins |
| Details | First non-empty value wins |
| Fixed In | First non-empty value wins |
| Published At | First non-zero timestamp wins |
| Aliases | Union of all aliases from all sources |
| References | Union of all reference URLs |
| Known Exploited | `true` if any source or KEV says so |

### Severity Fallback Chain

When a source doesn't provide a severity label, calvigil derives it:

```
CVSS v3 vector → CVSS v4 vector → CVSS v2 vector → Numeric CVSS score → Source label
```

| CVSS Score | Derived Severity |
|:-----------|:----------------|
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0.1 – 3.9 | LOW |

{: .tip }
> Thanks to the fallback chain and cross-source merging, `UNKNOWN` severity only appears when **no source** provides any severity signal at all — which is extremely rare in practice.

---

## CISA KEV Enrichment

After vulnerability matching and normalization, calvigil checks all findings against the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.

- Findings with a matching CVE ID or alias are flagged: `KnownExploited = true`
- In table output, these appear as: `CVE-2024-1234 ⚠ KEV`
- The scan summary shows: `⚠️ Known exploited (CISA KEV): N — prioritize these fixes`
- In JSON output: `"known_exploited": true`

{: .important }
> KEV-flagged vulnerabilities are being **actively exploited in the wild**. These should be your highest priority for remediation, regardless of CVSS score.

### Best-Effort Design

KEV enrichment is designed to never degrade scan results:
- If the CISA feed is unreachable, the scan completes normally (without KEV flags)
- Empty vulnerability lists skip the network call entirely
- Matching is case-insensitive on CVE IDs and aliases

---

## Database-Specific Details

### OSV.dev

- **API:** `POST https://api.osv.dev/v1/querybatch`
- **Batch size:** Up to 1000 packages per request
- **Matching:** By PURL (Package URL) and version
- **Severity sources:** CVSS v3 vectors (top-level), CVSS v4 vectors (per-affected), CVSS v2 fallback. When an ecosystem-specific OSV record such as `GO-*` omits CVSS data but aliases a CVE, CalVigil fetches the CVE alias record and carries over its CVSS score/severity.
- **Ecosystems:** Go, npm, PyPI, Maven, crates.io, RubyGems, Packagist, and more

### Sonatype OSS Index

- **API:** `POST https://ossindex.sonatype.org/api/v3/component-report`
- **Batch size:** 128 coordinates per request
- **Matching:** By PURL (Package URL)
- **Auth:** Basic auth (email + existing/migrated token). CalVigil skips OSS Index when credentials are missing; stale credentials that return 401 are retried once anonymously and then reported as a credential issue if Sonatype still rejects the request.
- **Severity:** From `CVSSScore` field, with fallback to `CVSSVector` parsing
- **ID preference:** CVE IDs when available; `DisplayName` becomes an alias

### NVD (National Vulnerability Database)

- **API:** `GET https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Package matching:** By keyword (package name + version), capped to keep scans responsive
- **CVSS enrichment:** Exact CVE lookup uses the `cveIds` batch parameter with resilient 10-ID requests, a 60s NVD request timeout, a bounded 3-minute enrichment budget, and a CalVigil User-Agent. Transient failures are retried with backoff, timed-out batches are split into smaller requests, partial successes are preserved, and CVE records are cached locally for 24 hours. This fills missing `score` and `severity` on findings that OSV/other sources already matched, without creating new findings. NVD/NIST primary CVSS is preferred; if NVD primary scoring is not yet provided, contributed CVSS from sources such as CISA-ADP is accepted as fallback.
- **Rate limiting:** 5 requests/30s without key, 50 requests/30s with key
- **API key:** Free — register at [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key)

### GitHub Advisory Database

- **API:** `GET https://api.github.com/advisories`
- **Matching:** By ecosystem + package name + version range
- **Rate limiting:** Standard GitHub API limits (60/hr unauthenticated, 5000/hr with token)
- **Severity:** From advisory severity label; falls back to numeric CVSS score

---

## Configuration

### Minimum Setup (Zero Config)

OSV.dev works immediately with no setup; OSS Index is enabled only when credentials are configured:

```bash
calvigil scan .   # Already queries 2 databases + KEV
```

### Recommended Setup

```bash
# Get better NVD rate limits
calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Enable GitHub Advisory
calvigil config set github-token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Optional: higher OSS Index rate limits with an existing/migrated token
calvigil config set ossindex-user you@example.com
calvigil config set ossindex-token xxxxxxxx
```

### Verbose Database Output

Use `--verbose` to see which databases are queried and how many results each returns:

```bash
calvigil scan -v .
```

```
🔎 Querying vulnerability databases...
   [OSV] Found 3 vulnerabilities
   [OSS-INDEX] Found 2 vulnerabilities
   Skipping NVD package search (no API key configured; exact CVE CVSS enrichment remains best-effort)
   Skipping GitHub Advisory (no token configured)
   Normalized and merged: 4 unique vulnerabilities (1 merged from multiple sources)
   [KEV] 1 vulnerability is known exploited
```
