---
title: scan-iac
layout: default
parent: Commands
nav_order: 4
---

# calvigil scan-iac
{: .no_toc }

Scan Infrastructure-as-Code files for security misconfigurations.
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
calvigil scan-iac [flags] <path>
```

## Flags

| Flag | Short | Default | Description |
|:-----|:------|:--------|:------------|
| `--format` | `-f` | `table` | Output format |
| `--output` | `-o` | stdout | Output file path |
| `--severity` | `-s` | all | Minimum severity filter |
| `--verbose` | `-v` | `false` | Verbose output |

---

## Supported IaC Types

| Type | File Patterns | Rules |
|:-----|:-------------|:------|
| **Terraform** | `*.tf` | Unencrypted resources, public access, missing logging |
| **Kubernetes** | `*.yaml`, `*.yml` (with `kind:`) | Privileged containers, host networking, missing resource limits |
| **Dockerfile** | `Dockerfile*` | Running as root, latest tag, missing healthcheck |
| **CloudFormation** | `*.yaml`, `*.yml` (with `AWSTemplateFormatVersion`) | Unencrypted storage, public buckets, weak IAM |
| **Docker Compose** | `docker-compose*.yml` | Privileged mode, host network, exposed ports |
| **Helm** | `Chart.yaml` + templates | Same as Kubernetes rules applied to Helm templates |

---

## Built-in Rules (25)

| Category | Examples |
|:---------|:---------|
| **Encryption** | S3 bucket without encryption, RDS without encryption at rest, EBS without encryption |
| **Access Control** | S3 public access, security group open to 0.0.0.0/0, IAM wildcard permissions |
| **Container Security** | Privileged containers, host PID/network, running as root |
| **Resource Limits** | Missing CPU/memory limits, missing healthcheck |
| **Logging** | CloudTrail disabled, access logging disabled |
| **Network** | Unrestricted ingress, SSH open to world |

---

## Examples

### Scan Terraform Files

```bash
calvigil scan-iac ./terraform/
```

### Scan Kubernetes Manifests

```bash
calvigil scan-iac ./k8s/
```

### Scan Dockerfiles

```bash
calvigil scan-iac .
```

### JSON Output

```bash
calvigil scan-iac --format json --output iac-findings.json ./infrastructure/
```

### Filter by Severity

```bash
calvigil scan-iac --severity high ./terraform/
```

---

## Example Output

```
🔍 Scanning IaC files in ./terraform/ ...

Found 3 IaC misconfigurations:

┌─────────────────────┬──────────┬─────────────────────────────────────────┬──────────┐
│ Rule                │ Severity │ Description                             │ File     │
├─────────────────────┼──────────┼─────────────────────────────────────────┼──────────┤
│ IAC-AWS-001         │ HIGH     │ S3 bucket without encryption            │ main.tf:12 │
│ IAC-K8S-003         │ MEDIUM   │ Container running as root               │ deploy.yaml:8 │
│ IAC-DOCKER-002      │ LOW      │ Using 'latest' tag in FROM instruction  │ Dockerfile:1 │
└─────────────────────┴──────────┴─────────────────────────────────────────┴──────────┘
```
