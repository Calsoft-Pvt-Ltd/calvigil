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

calvigil includes **23 pattern rules** (AI-SEC-001 through AI-SEC-023) specifically targeting anti-patterns commonly introduced by AI code generators:

- Resource leaks (unclosed HTTP bodies, files opened in loops)
- Race conditions (concurrent map access, goroutine loop variable capture)
- Inefficient algorithms (O(n²) loops, string concatenation in loops)
- Missing error handling
- Deprecated API usage
- Insecure defaults
- Unbounded data loading
- Missing input validation
- Missing client/server request timeouts
- Fail-open authorization, authentication, or validation error handling
- Temporary security bypass comments left in release paths
- Unbounded goroutine fan-out in Go services

These rules run **without** an AI provider — they're regex-based pattern matchers.

The built-in pattern set can be extended with custom YAML or JSON rule packs:

```bash
calvigil scan . --pattern-rules ./company-ai-sec-rules.yaml
```

Rule packs are line-oriented RE2 regular expressions with explicit severity
and language filters. Project-local rule packs require
`--trust-project-rules` so a repository cannot silently introduce scanner
logic without reviewer intent.

---

## AI Slop Code Smell Scoring

AI-generated code detection used to be spread across individual `AI-SEC-*` findings, Semgrep AI code-quality findings, and optional AI enrichment fields. Calvigil now merges those signals into one `slop_code_smells` summary so reviewers can quickly see whether a scan contains risky generated-code-style symptoms.

The score is based on concrete findings, not on vibe or authorship guessing:

| Signal family | Examples | Category |
|:--------------|:---------|:---------|
| Resource lifecycle | Unclosed HTTP bodies, files opened in loops | `resource_leak` |
| Concurrency safety | Map writes from goroutines, loop variable captures | `concurrency` |
| Error handling | Ignored errors, bare `except`, empty handlers | `error_handling` |
| Stale APIs | Deprecated APIs, removed APIs, old platform patterns | `stale_api` |
| Unbounded work | `ReadAll`, missing timeouts, O(n²) loops, sync crypto in event loops | `unbounded_work` |
| Insecure defaults | Disabled TLS verification, wildcard CORS, debug mode | `insecure_defaults` |
| Input validation | SQL/template injection patterns, unchecked conversions | `input_validation` |
| Secret exposure | Tokens, passwords, private keys, sensitive logging | `secret_exposure` |

The generated JSON looks like this when signals are present:

```json
{
  "slop_code_smells": {
    "score": 37,
    "level": "MODERATE",
    "signal_count": 2,
    "generated_code_signal": "LIKELY_AI",
    "confidence": "HIGH",
    "categories": [
      {
        "id": "concurrency",
        "name": "Concurrency safety",
        "count": 1,
        "weight": 24
      }
    ],
    "top_signals": [
      {
        "finding_id": "AI-SEC-003",
        "rule_id": "AI-SEC-003",
        "category_id": "concurrency",
        "title": "Concurrent map access without synchronization"
      }
    ],
    "authorship_disclaimer": "Slop code smells are quality and security symptoms, not proof that code was AI-generated."
  }
}
```

Use the score as a review queue:

- `LOW`: review during normal pull-request hardening
- `MODERATE`: add targeted tests and confirm production limits
- `HIGH`: block release until the top categories are reviewed
- `CRITICAL`: treat as a security engineering stop-the-line signal

---

## Semgrep SAST Engine

In addition to AI analysis, calvigil integrates [Semgrep CE](https://semgrep.dev/) for deep semantic analysis:

### Bundled Rule Packs (101 rules)

| Pack | File | Focus |
|:-----|:-----|:------|
| OWASP Top 10 | `rules/semgrep/owasp-top10.yaml` | Injection, auth, crypto, XSS |
| Language-Specific | `rules/semgrep/language-specific.yaml` | Go, Python, Java, JS/TS, Rust, Ruby, PHP, C/C++ |
| AI Code Quality | `rules/semgrep/ai-code-quality.yaml` | AI-generated code anti-patterns |
| Community-Aligned | `rules/semgrep/community-aligned.yaml` | Original Calvigil rules for framework, JWT, TLS, deserialization, C/C++, container, and shell supply-chain gaps identified from the public `semgrep/semgrep-rules` structure |

### Custom Rules

```bash
# Use your own rules
calvigil scan --ai --semgrep-rules ./my-rules .

# Use one specific bundled/custom rule pack
calvigil scan --ai --semgrep-rules ./rules/semgrep/community-aligned.yaml .

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
