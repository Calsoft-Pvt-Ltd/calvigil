---
title: Semgrep Coverage
layout: default
nav_order: 8
---

# Semgrep Coverage
{: .no_toc }

Calvigil includes trusted, bundled Semgrep rule packs for static application security testing.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## Current Bundle

The OSS scanner ships with **101 original Calvigil Semgrep rules** in `rules/semgrep/`.

| Pack | Rules | Focus |
|:-----|------:|:------|
| `owasp-top10.yaml` | 32 | Injection, auth, crypto, XSS, deserialization, SSRF, CORS, and other OWASP-style risks |
| `language-specific.yaml` | 20 | Go, Python, Java, JavaScript/TypeScript, Rust, Ruby, PHP, and C/C++ secure-coding checks |
| `ai-code-quality.yaml` | 22 | AI-generated-code quality and security anti-patterns at the AST layer |
| `community-aligned.yaml` | 27 | Framework, JWT, TLS, deserialization, C/C++, PHP/Ruby, Dockerfile, and shell supply-chain gaps |

The bundled rules are loaded automatically when Semgrep is installed:

```bash
calvigil scan /path/to/project
```

Semgrep can be skipped without affecting dependency, license, IaC, binary, or container scanning:

```bash
calvigil scan --skip-semgrep /path/to/project
```

---

## Community Comparison

Calvigil was compared against the public `semgrep/semgrep-rules` repository structure. That repository is much larger than Calvigil's built-in pack and is organized by language, framework, product area, and problem-based packs.

The comparison highlighted coverage gaps in:

| Area | Examples added to Calvigil |
|:-----|:---------------------------|
| Python web frameworks | Flask template injection, Django CSRF bypass, Django `mark_safe`, Jinja autoescape disabled, FastAPI permissive CORS |
| JavaScript and TypeScript | React `dangerouslySetInnerHTML`, Express insecure session cookies, Sequelize raw SQL concatenation, JWT `none` algorithm |
| Go services | JWT parse without verification, insecure gRPC transport, archive extraction path traversal |
| Java and Spring | CSRF disabled, SpEL expression injection, LDAP filter concatenation |
| C/C++ | `gets`, unsafe string copy, direct `system()` execution |
| PHP and Ruby | Dynamic `eval`, unsafe `unserialize`, Laravel debug mode, Ruby YAML unsafe load, Rails CSRF disablement |
| Containers and shell | Explicit root container user, `curl`/`wget` piped to a shell |

Calvigil does **not** vendor upstream community YAML directly. The upstream community rules are distributed under the Semgrep Rules License, so the bundled `community-aligned.yaml` pack is original Calvigil content that closes similar defensive gaps without copying upstream rule files.

---

## New Community-Aligned Rules

| Rule ID | Ecosystem | Risk |
|:--------|:----------|:-----|
| `py-requests-disable-cert-validation` | Python | TLS verification disabled |
| `py-flask-render-template-string` | Python | Server-side template injection |
| `py-django-mark-safe` | Python | XSS via unsafe HTML marking |
| `py-django-csrf-exempt` | Python | CSRF protection disabled |
| `py-jinja2-autoescape-disabled` | Python | Template autoescape disabled |
| `py-fastapi-cors-wildcard-credentials` | Python | Permissive CORS with credentials |
| `js-node-child-process-shell-true` | JS/TS | Shell injection exposure |
| `js-express-session-cookie-insecure` | JS/TS | Insecure session cookie |
| `js-react-dangerously-set-inner-html` | JS/TS | XSS exposure |
| `js-sequelize-raw-query-concat` | JS/TS | SQL injection |
| `js-jsonwebtoken-none-algorithm` | JS/TS | JWT signature bypass |
| `go-jwt-parse-unverified` | Go | JWT verification bypass |
| `go-grpc-insecure-transport` | Go | Insecure transport |
| `go-zip-slip-archive-extract` | Go | Zip Slip path traversal |
| `java-spring-csrf-disabled` | Java | CSRF protection disabled |
| `java-spel-expression-injection` | Java | Expression injection |
| `java-ldap-filter-concat` | Java | LDAP injection |
| `c-unsafe-gets` | C/C++ | Buffer overflow |
| `c-unsafe-string-copy` | C/C++ | Buffer overflow |
| `c-system-command-execution` | C/C++ | Command injection |
| `php-eval-dynamic-code` | PHP | Dynamic code execution |
| `php-unserialize-untrusted` | PHP | Insecure deserialization |
| `php-laravel-debug-enabled` | PHP | Debug information disclosure |
| `ruby-yaml-load-untrusted` | Ruby | Insecure deserialization |
| `ruby-rails-csrf-disabled` | Ruby | CSRF protection disabled |
| `dockerfile-root-user` | Dockerfile | Container runs as root |
| `bash-curl-pipe-shell` | Bash | Unverified remote script execution |

---

## Custom Rules

Use `--semgrep-rules` to point Calvigil at your own Semgrep rule directory or a single YAML file:

```bash
calvigil scan --semgrep-rules ./company-semgrep-rules /path/to/project
calvigil scan --semgrep-rules ./rules/semgrep/community-aligned.yaml /path/to/project
```

When no explicit directory is supplied, Calvigil discovers bundled rules from
`rules/semgrep/` in the current working directory or from `rules/semgrep/`
beside the executable. If neither location exists, the scan reports a clear
configuration error. Calvigil does not use Semgrep `--config auto` because
Semgrep auto configuration requires metrics, and Calvigil runs Semgrep with
metrics disabled.

Project-local rules inside the scanned repository are ignored by default because Semgrep rules execute code through the rule engine. For trusted repositories, explicitly opt in:

```bash
calvigil scan . --semgrep-rules ./.semgrep --trust-project-rules
```

Symlinks in `--semgrep-rules` are resolved before trust checks, so in-project symlinks cannot escape the project boundary silently.

---

## Validation

The analyzer test suite includes bundled rule integrity checks:

- every `rules/semgrep/*.yaml` file must parse as YAML
- every file must contain at least one rule
- each rule must have an ID, message, language list, and valid severity
- duplicate rule IDs fail the test suite
- representative community-aligned rule IDs are verified

Run the focused validation with:

```bash
go test ./internal/analyzer -run 'TestBundledSemgrepRules|TestSemgrep' -count=1
```
