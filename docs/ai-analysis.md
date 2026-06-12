---
title: AI Code Analysis
layout: default
nav_order: 6
---

# AI Code Analysis
{: .no_toc }

Use AI models to detect OWASP Top 10 vulnerabilities directly in your source code.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Overview

calvigil supports three AI providers for code vulnerability analysis:

| Provider | Type | Cost | Quality | Setup |
|:---------|:-----|:-----|:--------|:------|
| **OpenAI** | Cloud | Paid (API usage) | Highest (GPT-4) | API key |
| **Ollama** | Local | Free | Good (depends on model) | Install Ollama + model |
| **LM Studio** | Local | Free | Good (depends on model) | Install LM Studio + model |

{: .note }
> AI analysis is **optional**. Dependency scanning, pattern rules, and Semgrep SAST all work without any AI provider configured.

---

## Provider Selection

```bash
# Auto-detect best available provider (default)
calvigil scan --ai --provider auto .

# Use specific provider
calvigil scan --ai --provider openai .
calvigil scan --ai --provider ollama .
calvigil scan --ai --provider lmstudio .
```

**Auto-detection order:**
1. Ollama (check `http://localhost:11434`)
2. LM Studio (check `http://localhost:1234`)
3. OpenAI (check for API key)

---

## OpenAI Setup

```bash
# Set your API key
calvigil config set openai-key sk-proj-abc123...
# or: export OPENAI_API_KEY=sk-proj-abc123...

# Optionally choose a model (default: gpt-4)
calvigil config set openai-model gpt-4-turbo
```

**Supported models:** `gpt-4`, `gpt-4-turbo`, `gpt-4o`, `gpt-4o-mini`

---

## Ollama Setup (Local, Free)

1. Install [Ollama](https://ollama.ai/)
2. Pull a model:
   ```bash
   ollama pull llama3
   # or: ollama pull codellama
   # or: ollama pull mistral
   ```
3. Configure calvigil:
   ```bash
   calvigil config set ollama-model llama3
   # URL defaults to http://localhost:11434
   ```
4. Run:
   ```bash
   calvigil scan --ai --provider ollama .
   ```

---

## LM Studio Setup (Local, Free)

1. Install [LM Studio](https://lmstudio.ai/)
2. Download a model (e.g., CodeLlama, Mistral, Deepseek Coder)
3. Start the local server (LM Studio → Local Server → Start)
4. Configure calvigil:
   ```bash
   calvigil config set lmstudio-model <model-name>
   # URL defaults to http://localhost:1234
   ```
5. Run:
   ```bash
   calvigil scan --ai --provider lmstudio .
   ```

---

## What AI Detects

The AI analysis targets **OWASP Top 10** vulnerabilities:

| OWASP Category | Examples Detected |
|:---------------|:-----------------|
| A01: Broken Access Control | Missing auth checks, IDOR, privilege escalation |
| A02: Cryptographic Failures | Weak ciphers, hardcoded keys, insecure TLS |
| A03: Injection | SQL injection, command injection, XSS, LDAP injection |
| A04: Insecure Design | Race conditions, business logic flaws |
| A05: Security Misconfiguration | Debug mode, default credentials, CORS misconfiguration |
| A06: Vulnerable Components | (Covered by dependency scanning) |
| A07: Auth Failures | Weak passwords, session fixation, JWT issues |
| A08: Data Integrity Failures | Insecure deserialization, unsigned updates |
| A09: Logging Failures | Sensitive data in logs, insufficient logging |
| A10: SSRF | Server-side request forgery patterns |

---

## AI Enrichment Layer

When AI analysis finds potential vulnerabilities, calvigil runs a second-pass **enrichment** that provides:

| Field | Description |
|:------|:------------|
| `real_world_impact` | Practical exploitation scenario |
| `attack_vector` | How an attacker would exploit this |
| `remediation_steps` | Specific fix recommendations |
| `cvss_estimate` | Estimated CVSS score |
| `confidence` | AI's confidence level (HIGH/MEDIUM/LOW) |
| `ai_code_indicator` | Whether the code appears AI-generated (`LIKELY_AI`, `POSSIBLY_AI`, `UNLIKELY_AI`) |

---

## AI-Generated Code Detection

calvigil includes **18 pattern rules** (AI-SEC-001 through AI-SEC-018) specifically targeting anti-patterns commonly introduced by AI code generators:

- Resource leaks (unclosed HTTP bodies, files opened in loops)
- Race conditions (concurrent map access, goroutine loop variable capture)
- Inefficient algorithms (O(n²) loops, string concatenation in loops)
- Missing error handling
- Deprecated API usage
- Insecure defaults
- Unbounded data loading
- Missing input validation

These rules run **without** an AI provider — they're regex-based pattern matchers.

---

## Semgrep SAST Engine

In addition to AI analysis, calvigil integrates [Semgrep CE](https://semgrep.dev/) for deep semantic analysis:

### Bundled Rule Packs (77+ rules)

| Pack | File | Focus |
|:-----|:-----|:------|
| OWASP Top 10 | `rules/semgrep/owasp-top10.yaml` | Injection, auth, crypto, XSS |
| Language-Specific | `rules/semgrep/language-specific.yaml` | Go, Python, Java, JS/TS, Rust, Ruby, PHP, C/C++ |
| AI Code Quality | `rules/semgrep/ai-code-quality.yaml` | AI-generated code anti-patterns |

### Custom Rules

```bash
# Use your own rules
calvigil scan --ai --semgrep-rules ./my-rules.yaml .

# Skip Semgrep entirely
calvigil scan --ai --skip-semgrep .
```

### Prerequisites

Semgrep CE must be installed:

```bash
pip install semgrep
# or: brew install semgrep
```

{: .tip }
> If Semgrep is not installed, calvigil will log a warning and continue without SAST — it won't fail.

---

## Performance Tips

- **Batch processing:** AI analysis sends files in batches of 20 to minimize API calls
- **Skip tests:** Use `--skip-tests` to exclude test files from analysis
- **Local models:** Ollama and LM Studio avoid API rate limits and keep code private
- **Cache:** Vulnerability results are cached (AI findings are not cached since code changes frequently)
