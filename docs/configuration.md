---
title: Configuration
layout: default
nav_order: 3
---

# Configuration
{: .no_toc }

Manage API keys, model settings, and scanner preferences.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Config File

Configuration is stored in `~/.calvigil.json`:

```json
{
  "openai_model": "gpt-4",
  "ossindex_user": "you@example.com",
  "ollama_url": "http://localhost:11434",
  "ollama_model": "llama3",
  "lmstudio_url": "http://localhost:1234",
  "lmstudio_model": "",
  "enterprise_url": "https://calvigil.example.com"
}
```

{: .note }
> Secrets (`openai-key`, `nvd-key`, `github-token`, `ossindex-token`, `enterprise-key`) are stored in your OS keyring when available (macOS Keychain, Windows Credential Manager, Linux Secret Service). When keyring isn't available (CI, containers), they fall back to `~/.calvigil-secrets.json` (mode `0600`).

---

## Environment Variables

Environment variables **always take precedence** over config file values:

| Variable | Purpose |
|:---------|:--------|
| `OPENAI_API_KEY` | OpenAI API key for AI code analysis |
| `OPENAI_MODEL` | OpenAI model name (default: `gpt-4`) |
| `NVD_API_KEY` | NIST NVD API key for vulnerability lookups |
| `GITHUB_TOKEN` | GitHub token for advisory database access |
| `OSSINDEX_USER` | Sonatype OSS Index account email (optional) |
| `OSSINDEX_TOKEN` | Sonatype OSS Index API token (optional) |
| `OLLAMA_URL` | Ollama server URL (default: `http://localhost:11434`) |
| `OLLAMA_MODEL` | Ollama model name (e.g. `llama3`, `codellama`) |
| `LMSTUDIO_URL` | LM Studio server URL (default: `http://localhost:1234`) |
| `LMSTUDIO_MODEL` | LM Studio model name |
| `CALVIGIL_ENTERPRISE_URL` | Calvigil Enterprise URL for `calvigil push` |
| `CALVIGIL_API_KEY` | Calvigil Enterprise API key for `calvigil push` |
| `CALVIGIL_ENTERPRISE_API_KEY` | Alternate Enterprise API key variable |
| `CALVIGIL_PROJECT` | Project name metadata for `calvigil push` |
| `CALVIGIL_REF` | Git ref metadata for `calvigil push` |
| `CALVIGIL_COMMIT` | Git commit metadata for `calvigil push` |
| `CALVIGIL_ENVIRONMENT` | Policy environment metadata for `calvigil push` |
| `CALVIGIL_IDEMPOTENCY_KEY` | Idempotency key for safe `calvigil push` retries |

**Example — using environment variables:**

```bash
# Set keys via environment (add to ~/.zshrc or ~/.bashrc for persistence)
export OPENAI_API_KEY="sk-proj-abc123..."
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Now run scans — keys are picked up automatically
calvigil scan /path/to/project
```

---

## Setting API Keys

Use `config set` to persist keys to the config file:

```bash
# Required for AI-powered code analysis
calvigil config set openai-key sk-proj-abc123def456...

# Choose a specific OpenAI model
calvigil config set openai-model gpt-4-turbo

# Optional: NVD key gives higher rate limits (50 req/30s vs 5 req/30s)
# Get one free at: https://nvd.nist.gov/developers/request-an-api-key
calvigil config set nvd-key xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Optional: GitHub token for advisory database access
# Create at: https://github.com/settings/tokens
calvigil config set github-token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Optional: Sonatype OSS Index (existing/migrated token)
# If OSS Index returns 401, clear stale credentials to skip this source.
calvigil config set ossindex-user you@example.com
calvigil config set ossindex-token xxxxxxxx

# Optional: Calvigil Enterprise upload
calvigil config set enterprise-url https://calvigil.example.com
calvigil config set enterprise-key cvgk_...
```

---

## Viewing Configuration

```bash
# View a specific key (secrets are masked)
calvigil config get openai-key
# Output: ****abc1

calvigil config get openai-model
# Output: gpt-4-turbo

calvigil config get nvd-key
# Output: ****xxxx

calvigil config get enterprise-key
# Output: ****abcd
```

---

## All Config Keys

| Key | Required | Default | Description |
|:----|:---------|:--------|:------------|
| `openai-key` | For AI scan | — | OpenAI API key (`sk-proj-...` or `sk-...`) |
| `openai-model` | No | `gpt-4` | Model to use (`gpt-4`, `gpt-4-turbo`, `gpt-4o`, etc.) |
| `nvd-key` | No | — | NVD API key for higher rate limits |
| `github-token` | No | — | GitHub personal access token |
| `ossindex-user` | No | — | Sonatype OSS Index account email |
| `ossindex-token` | No | — | Sonatype OSS Index API token |
| `ollama-url` | No | `http://localhost:11434` | Ollama server URL |
| `ollama-model` | No | — | Ollama model name (e.g. `llama3`, `codellama`) |
| `lmstudio-url` | No | `http://localhost:1234` | LM Studio server URL |
| `lmstudio-model` | No | — | LM Studio model name |
| `enterprise-url` | For push | — | Calvigil Enterprise URL |
| `enterprise-key` | For push | — | Calvigil Enterprise API key (`cvgk_...`) |

---

## Secret Storage

calvigil uses a tiered approach for API key storage:

| Backend | When Used | Storage |
|:--------|:----------|:--------|
| OS keyring | Default when available | macOS Keychain / Windows Credential Manager / Linux Secret Service |
| Encrypted file | When keyring isn't available (CI, containers, headless) | `~/.calvigil-secrets.json` (mode `0600`) |

Override with `CALVIGIL_SECRET_BACKEND` environment variable: `keyring`, `file`, or unset (auto).

{: .tip }
> In CI pipelines, set API keys via environment variables. The keyring won't be available, and environment variables take precedence anyway.

---

## Cache Settings

Vulnerability results are cached to avoid redundant API calls:

| Option | Description |
|:-------|:------------|
| `--cache-ttl=1h` | Set cache time-to-live (default: 24h) |
| `--no-cache` | Disable caching entirely |

Cache location: `~/.calvigil/cache/`

To purge the cache manually:
```bash
rm -rf ~/.calvigil/cache/
```
