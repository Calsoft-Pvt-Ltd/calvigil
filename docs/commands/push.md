---
title: push
layout: default
parent: Commands
nav_order: 6
---

# `calvigil push`
{: .no_toc }

Upload an existing JSON scan report to Calvigil Enterprise.
{: .fs-5 .fw-300 }

---

## Usage

```bash
calvigil push <report.json> [flags]
```

`push` does not run a scan by itself. Generate a JSON report first with any
Calvigil scanner command, then upload that report:

```bash
calvigil scan . --skip-ai --format json --output calvigil.json
calvigil push calvigil.json
```

---

## Configuration

CI pipelines should use environment variables:

```bash
export CALVIGIL_ENTERPRISE_URL="https://calvigil.example.com"
export CALVIGIL_API_KEY="cvgk_..."
```

For local developer machines, you can persist the Enterprise URL and API key:

```bash
calvigil config set enterprise-url https://calvigil.example.com
calvigil config set enterprise-key cvgk_...
```

The API key is stored in the Calvigil secret store and is masked by
`calvigil config get enterprise-key`.

---

## Flags

| Flag | Environment | Description |
|:-----|:------------|:------------|
| `--server-url` | `CALVIGIL_ENTERPRISE_URL` | Enterprise API/web origin. `/api/v1` is appended automatically. |
| `--api-key` | `CALVIGIL_API_KEY` or `CALVIGIL_ENTERPRISE_API_KEY` | Enterprise API key. Prefer environment variables in CI. |
| `--project` | `CALVIGIL_PROJECT` | Project name override shown in Enterprise. |
| `--ref` | `CALVIGIL_REF` | Git branch, tag, or ref. |
| `--commit` | `CALVIGIL_COMMIT` | Git commit SHA. |
| `--environment` | `CALVIGIL_ENVIRONMENT` | Policy environment such as `dev`, `staging`, or `prod`. |
| `--idempotency-key` | `CALVIGIL_IDEMPOTENCY_KEY` | Safe retry key. Duplicate pushes return the original scan. |
| `--fail-on-policy` | - | Evaluate policy first; if it fails, exit non-zero without storing the scan. |
| `--evaluate-only` | - | Evaluate policy without storing the scan. |
| `--timeout` | - | HTTP timeout. Default: `30s`. |

---

## Policy Gates

Use `--fail-on-policy` when CI should block on the Enterprise policy result:

```bash
calvigil scan . --skip-ai --format json --output calvigil.json
calvigil push calvigil.json \
  --project payments-service \
  --ref "$GITHUB_REF_NAME" \
  --commit "$GITHUB_SHA" \
  --environment prod \
  --idempotency-key "$GITHUB_RUN_ID-$GITHUB_SHA" \
  --fail-on-policy
```

When policy fails, `calvigil push` prints the violations and exits non-zero
without storing the scan or consuming scan quota.

Use `--evaluate-only` for a dry policy check:

```bash
calvigil push calvigil.json --environment prod --evaluate-only
```

---

## GitHub Actions Example

```yaml
- name: Scan
  run: calvigil scan . --skip-ai --format json --output calvigil.json

- name: Push to Calvigil Enterprise
  env:
    CALVIGIL_ENTERPRISE_URL: ${{ vars.CALVIGIL_ENTERPRISE_URL }}
    CALVIGIL_API_KEY: ${{ secrets.CALVIGIL_API_KEY }}
  run: |
    calvigil push calvigil.json \
      --project "${{ github.repository }}" \
      --ref "${{ github.ref_name }}" \
      --commit "${{ github.sha }}" \
      --idempotency-key "${{ github.run_id }}-${{ github.sha }}" \
      --fail-on-policy
```
