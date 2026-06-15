---
title: CI/CD Integration
layout: default
nav_order: 8
---

# CI/CD Pipeline Integration
{: .no_toc }

Integrate calvigil into GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps, Google Cloud Build, Jenkins, and CircleCI.
{: .fs-5 .fw-300 }

<details open markdown="block">
  <summary>Table of contents</summary>
  {: .text-delta }
1. TOC
{:toc}
</details>

---

## General Principles

These apply to every CI platform:

| Practice | Why |
|:---------|:----|
| `export CALVIGIL_SECRET_BACKEND=file` | CI runners have no OS keyring; skip the probe |
| Pass API keys via **CI secrets → environment variables** | Env vars always take precedence; nothing written to disk |
| Use `--skip-ai` on PR builds | Avoid spending LLM tokens on every push |
| Use `--format sarif` or `--format json` | Machine-readable output for code-scanning dashboards |
| Use `--no-cache` or cache `~/.calvigil/cache/` | Runners are ephemeral; either skip the cache or persist it between builds |
| Pin a calvigil version in production pipelines | Reproducible builds (`releases/download/v5.0.0/...` instead of `latest`) |

### Installing calvigil in any Linux CI runner

```bash
curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
tar xzf calvigil.tar.gz
sudo mv calvigil /usr/local/bin/   # or move to a PATH dir you control
calvigil version
```

### Failing the build on findings

calvigil exits `0` even when vulnerabilities are found (errors exit `1`). To gate a pipeline on findings, post-process the JSON:

```bash
calvigil scan . --skip-ai --format json --output results.json

# Fail if any CRITICAL or HIGH vulnerabilities exist (requires jq)
CRITICALS=$(jq '[.vulnerabilities[] | select(.severity=="CRITICAL" or .severity=="HIGH")] | length' results.json)
if [ "$CRITICALS" -gt 0 ]; then
  echo "❌ Found $CRITICALS HIGH/CRITICAL vulnerabilities"
  exit 1
fi

# Or: fail on any known-exploited (CISA KEV) finding
KEV=$(jq '[.vulnerabilities[] | select(.known_exploited==true)] | length' results.json)
if [ "$KEV" -gt 0 ]; then
  echo "❌ Found $KEV actively exploited vulnerabilities (CISA KEV)"
  exit 1
fi
```

---

## GitHub Actions

### Basic scan on every push / PR

```yaml
# .github/workflows/calvigil.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Install calvigil
        run: |
          curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
          tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/

      - name: Run dependency scan
        env:
          CALVIGIL_SECRET_BACKEND: file
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}        # optional
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}      # enables GitHub Advisory DB
          OSSINDEX_USER: ${{ secrets.OSSINDEX_USER }}    # optional
          OSSINDEX_TOKEN: ${{ secrets.OSSINDEX_TOKEN }}  # optional
        run: calvigil scan . --skip-ai --format sarif --output calvigil.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: calvigil.sarif
```

Findings appear in the repository's **Security → Code scanning** tab and as PR annotations.

### Push results to Calvigil Enterprise

Use `calvigil push` when you want Enterprise dashboards, audit logs, scan diffs,
and policy gates:

```yaml
name: Calvigil Enterprise

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan-and-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install calvigil
        run: |
          curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
          tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/

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
            --environment prod \
            --fail-on-policy
```

`--fail-on-policy` evaluates the Enterprise policy first. If the policy fails,
the command exits non-zero and does not store the scan or consume scan quota.

### Nightly full scan with AI analysis

```yaml
name: Nightly Deep Scan

on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  deep-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install calvigil + semgrep
        run: |
          curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
          tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
          pip install semgrep

      - name: Full scan (deps + AI + SAST + licenses + integrity)
        env:
          CALVIGIL_SECRET_BACKEND: file
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          calvigil scan . --check-licenses --verify-integrity \
            --format html --output report.html

      - name: Upload report artifact
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.html
```

### Container image scan after build

```yaml
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Install syft
        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Scan image
        run: calvigil scan-image myapp:${{ github.sha }} --severity high --format sarif --output image.sarif

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: image.sarif
          category: container-image
```

### Caching vulnerability results between runs

```yaml
      - name: Cache vulnerability DB responses
        uses: actions/cache@v4
        with:
          path: ~/.calvigil/cache
          key: calvigil-cache-${{ hashFiles('**/go.sum', '**/package-lock.json', '**/requirements.txt') }}
          restore-keys: calvigil-cache-
```

---

## GitLab CI

### Basic scan

```yaml
# .gitlab-ci.yml
stages:
  - security

calvigil-scan:
  stage: security
  image: ubuntu:24.04
  variables:
    CALVIGIL_SECRET_BACKEND: "file"
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl ca-certificates
    - curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
    - tar xzf calvigil.tar.gz && mv calvigil /usr/local/bin/
  script:
    - calvigil scan . --skip-ai --format json --output gl-dependency-scanning-report.json
  artifacts:
    paths:
      - gl-dependency-scanning-report.json
    expire_in: 30 days
```

Set `NVD_API_KEY`, `GITHUB_TOKEN`, `OSSINDEX_USER`, `OSSINDEX_TOKEN` under **Settings → CI/CD → Variables** (mark as *Masked*).

### Merge-request gate (fail on HIGH+)

```yaml
calvigil-gate:
  stage: security
  image: ubuntu:24.04
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl jq ca-certificates
    - curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
    - tar xzf calvigil.tar.gz && mv calvigil /usr/local/bin/
  script:
    - calvigil scan . --skip-ai --severity high --format json --output results.json
    - |
      COUNT=$(jq '.vulnerabilities | length' results.json)
      if [ "$COUNT" -gt 0 ]; then
        echo "Found $COUNT HIGH/CRITICAL vulnerabilities — blocking merge"
        jq -r '.vulnerabilities[] | "\(.id) \(.severity) \(.package.name)@\(.package.version)"' results.json
        exit 1
      fi
```

### Caching between pipelines

```yaml
calvigil-scan:
  cache:
    key: calvigil-vuln-cache
    paths:
      - .calvigil-cache/
  variables:
    # calvigil uses ~/.calvigil/cache; point HOME inside the project dir to make it cacheable
    HOME: "$CI_PROJECT_DIR"
```

---

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: ubuntu:24.04

definitions:
  steps:
    - step: &calvigil-scan
        name: Calvigil Security Scan
        caches:
          - calvigil
        script:
          - apt-get update -qq && apt-get install -y -qq curl jq ca-certificates
          - curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
          - tar xzf calvigil.tar.gz && mv calvigil /usr/local/bin/
          - export CALVIGIL_SECRET_BACKEND=file
          - calvigil scan . --skip-ai --format json --output results.json
          # Fail on CRITICAL findings
          - |
            CRIT=$(jq '[.vulnerabilities[] | select(.severity=="CRITICAL")] | length' results.json)
            if [ "$CRIT" -gt 0 ]; then
              echo "Found $CRIT CRITICAL vulnerabilities"
              exit 1
            fi
        artifacts:
          - results.json

  caches:
    calvigil: ~/.calvigil/cache

pipelines:
  default:
    - step: *calvigil-scan
  pull-requests:
    '**':
      - step: *calvigil-scan
```

Set secrets under **Repository settings → Repository variables** (check *Secured*): `NVD_API_KEY`, `GITHUB_TOKEN`, `OSSINDEX_USER`, `OSSINDEX_TOKEN`. They are automatically exposed as environment variables.

{: .tip }
> Bitbucket's **Code Insights** can display report annotations. Generate JSON with calvigil and post it to the Code Insights REST API in a follow-up script step for inline PR annotations.

---

## Azure DevOps (Azure Pipelines)

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include: [main]

pr:
  branches:
    include: ['*']

pool:
  vmImage: 'ubuntu-latest'

variables:
  CALVIGIL_SECRET_BACKEND: 'file'

steps:
  - checkout: self

  - script: |
      curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
      tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
      calvigil version
    displayName: 'Install calvigil'

  - script: |
      calvigil scan . --skip-ai --format sarif --output $(Build.ArtifactStagingDirectory)/calvigil.sarif
    displayName: 'Run security scan'
    env:
      NVD_API_KEY: $(NVD_API_KEY)            # define as secret pipeline variables
      GITHUB_TOKEN: $(GITHUB_TOKEN)
      OSSINDEX_USER: $(OSSINDEX_USER)
      OSSINDEX_TOKEN: $(OSSINDEX_TOKEN)

  - task: PublishBuildArtifacts@1
    displayName: 'Publish SARIF report'
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)/calvigil.sarif'
      artifactName: 'CodeAnalysisLogs'   # this exact name makes SARIF visible in the "Scans" tab
```

{: .note }
> Install the free [**SARIF SAST Scans Tab**](https://marketplace.visualstudio.com/items?itemName=sariftools.scans) extension from the Azure DevOps Marketplace. Publishing the SARIF artifact with the name `CodeAnalysisLogs` makes findings appear in a dedicated **Scans** tab on the pipeline run.

### Quality gate stage

```yaml
  - script: |
      calvigil scan . --skip-ai --severity high --format json --output results.json
      COUNT=$(jq '.vulnerabilities | length' results.json)
      if [ "$COUNT" -gt 0 ]; then
        echo "##vso[task.logissue type=error]Found $COUNT HIGH/CRITICAL vulnerabilities"
        echo "##vso[task.complete result=Failed;]"
      fi
    displayName: 'Security quality gate'
```

---

## Google Cloud Build

```yaml
# cloudbuild.yaml
steps:
  # Install and run calvigil
  - name: 'ubuntu'
    id: 'security-scan'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        apt-get update -qq && apt-get install -y -qq curl ca-certificates jq
        curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
        tar xzf calvigil.tar.gz && mv calvigil /usr/local/bin/
        export CALVIGIL_SECRET_BACKEND=file
        calvigil scan . --skip-ai --format json --output /workspace/results.json
        # Gate on critical findings
        CRIT=$$(jq '[.vulnerabilities[] | select(.severity=="CRITICAL")] | length' /workspace/results.json)
        if [ "$$CRIT" -gt 0 ]; then
          echo "Found $$CRIT CRITICAL vulnerabilities"
          exit 1
        fi
    secretEnv: ['NVD_API_KEY', 'GITHUB_TOKEN']

# Pull API keys from Secret Manager
availableSecrets:
  secretManager:
    - versionName: projects/$PROJECT_ID/secrets/nvd-api-key/versions/latest
      env: 'NVD_API_KEY'
    - versionName: projects/$PROJECT_ID/secrets/github-token/versions/latest
      env: 'GITHUB_TOKEN'

# Store the report in a bucket
artifacts:
  objects:
    location: 'gs://$PROJECT_ID-security-reports/$BUILD_ID/'
    paths: ['/workspace/results.json']
```

### Scanning a container image built in Cloud Build

```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/myapp:$SHORT_SHA', '.']

  - name: 'ubuntu'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        apt-get update -qq && apt-get install -y -qq curl ca-certificates
        curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
        tar xzf calvigil.tar.gz && mv calvigil /usr/local/bin/
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        calvigil scan-image gcr.io/$PROJECT_ID/myapp:$SHORT_SHA --severity high
```

---

## Jenkins

```groovy
// Jenkinsfile (declarative pipeline)
pipeline {
    agent any

    environment {
        CALVIGIL_SECRET_BACKEND = 'file'
        NVD_API_KEY     = credentials('nvd-api-key')      // Jenkins credential IDs
        GITHUB_TOKEN    = credentials('github-token')
    }

    stages {
        stage('Install calvigil') {
            steps {
                sh '''
                    curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
                    tar xzf calvigil.tar.gz
                    chmod +x calvigil
                '''
            }
        }

        stage('Security Scan') {
            steps {
                sh './calvigil scan . --skip-ai --format json --output results.json'
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    def count = sh(
                        script: "jq '[.vulnerabilities[] | select(.severity==\"CRITICAL\" or .severity==\"HIGH\")] | length' results.json",
                        returnStdout: true
                    ).trim().toInteger()
                    if (count > 0) {
                        error "Found ${count} HIGH/CRITICAL vulnerabilities"
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'results.json', fingerprint: true
        }
    }
}
```

{: .tip }
> With the [Warnings Next Generation plugin](https://plugins.jenkins.io/warnings-ng/), output SARIF (`--format sarif`) and use `recordIssues tool: sarif(pattern: 'calvigil.sarif')` to get findings rendered in the Jenkins UI with trend charts.

---

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/base:current
    environment:
      CALVIGIL_SECRET_BACKEND: file
    steps:
      - checkout
      - restore_cache:
          keys:
            - calvigil-cache-v1-
      - run:
          name: Install calvigil
          command: |
            curl -Lo calvigil.tar.gz https://github.com/Calsoft-Pvt-Ltd/calvigil/releases/latest/download/calvigil-linux-amd64.tar.gz
            tar xzf calvigil.tar.gz && sudo mv calvigil /usr/local/bin/
      - run:
          name: Run scan
          command: calvigil scan . --skip-ai --format json --output results.json
      - save_cache:
          key: calvigil-cache-v1-{{ epoch }}
          paths:
            - ~/.calvigil/cache
      - store_artifacts:
          path: results.json

workflows:
  security:
    jobs:
      - security-scan
```

Set `NVD_API_KEY`, `GITHUB_TOKEN`, etc. under **Project Settings → Environment Variables**.

---

## Pre-commit Hook (any platform)

Catch issues before they ever reach CI:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: calvigil
        name: calvigil security scan
        entry: calvigil scan . --skip-ai --skip-semgrep --severity high
        language: system
        pass_filenames: false
        stages: [pre-push]   # scan on push, not every commit
```

---

## Recommended Pipeline Strategy

| Trigger | Scan profile | Rationale |
|:--------|:-------------|:----------|
| **Every PR** | `scan --skip-ai --severity high --format sarif` | Fast feedback, gate on serious issues only |
| **Merge to main** | `scan --skip-ai --check-licenses --format sarif` | Add license compliance on mainline |
| **Nightly** | `scan --check-licenses --verify-integrity` + AI | Full depth including AI analysis and supply-chain checks |
| **Release tag** | `scan` + `scan-image` + `--format cyclonedx` SBOM | Produce SBOM artifacts and scan the shipped container |

### Secrets to configure per platform

| Secret | Required | Purpose |
|:-------|:---------|:--------|
| `NVD_API_KEY` | Optional | 10× higher NVD rate limits |
| `GITHUB_TOKEN` | Optional | Enables GitHub Advisory database |
| `OSSINDEX_USER` / `OSSINDEX_TOKEN` | Optional | Higher OSS Index rate limits |
| `OPENAI_API_KEY` | Only for AI scans | AI code analysis |

{: .note }
> OSV.dev works with **zero secrets configured**. Configure `OSSINDEX_USER` and `OSSINDEX_TOKEN` only when you have existing/migrated Sonatype OSS Index credentials.
