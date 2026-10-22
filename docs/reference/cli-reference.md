---
title: CLI Command & Configuration Reference
description: CLI Command & Configuration Reference for iam-shrink
---

[← Documentation Hub](../index.md)

# CLI Command & Configuration Reference

This document provides a complete reference for all `iam-shrink` subcommands, flags, and configuration options.

---

## Command Index

| Command | Description |
|---|---|
| [`iam-shrink run`](#iam-shrink-run) | Execute a test command and synthesize an IAM policy from captured CSM/proxy telemetry |
| [`iam-shrink ingest`](#iam-shrink-ingest) | Ingest historical CloudTrail logs (`.json`, `.json.gz`) and synthesize a policy |
| [`iam-shrink patch`](#iam-shrink-patch) | Execute a test suite and replace the target Terraform `.tf` policy block in-place |
| [`iam-shrink prune-role`](#iam-shrink-prune-role) | Prune unused permissions from an existing IAM role policy |
| [`iam-shrink verify`](#iam-shrink-verify) | Formally verify that a candidate policy is a strict mathematical subset of a base policy |
| [`iam-shrink optimize`](#iam-shrink-optimize) | Compress policy byte size and merge statements to fit under AWS quotas |
| [`iam-shrink impact`](#iam-shrink-impact) | Replay historical CloudTrail logs to evaluate operational safety and severed calls |
| [`iam-shrink report`](#iam-shrink-report) | Audit an IAM policy against CIS AWS Foundations Benchmark or NIST SP 800-53 |
| [`iam-shrink gate`](#iam-shrink-gate) | CI/CD security quality gate (fails builds on wildcards or compliance violations) |
| [`iam-shrink pr-comment`](#iam-shrink-pr-comment) | Generate a formatted GitHub/GitLab Pull Request review comment |
| [`iam-shrink diff`](#iam-shrink-diff) | Compare an existing policy against captured runtime permissions |
| [`iam-shrink lint`](#iam-shrink-lint) | Statically analyze an IAM policy for privilege escalation and security flaws |
| [`iam-shrink explain`](#iam-shrink-explain) | Inspect internal SDK-to-IAM mappings and required ARNs for a specific API |
| [`iam-shrink state`](#iam-shrink-state) | Resolve parameterized ARN placeholders using `terraform.tfstate` |
| [`iam-shrink k8s`](#iam-shrink-k8s) | Generate Kubernetes IRSA pod telemetry sidecar manifests |
| [`iam-shrink session`](#iam-shrink-session) | Manage a standalone background collector daemon session |
| [`iam-shrink ui`](#iam-shrink-ui) | Launch the interactive local Web UI visualizer |
| [`iam-shrink update-rules`](#iam-shrink-update-rules) | Download updated CIS and NIST benchmark schemas |
| [`iam-shrink export-mappings`](#iam-shrink-export-mappings) | Dump the embedded SDK-to-IAM mapping catalog to YAML |
| [`iam-shrink init-vscode`](#iam-shrink-init-vscode) | Generate a `.vscode/tasks.json` configuration for editor workflows |
| [`iam-shrink version`](#iam-shrink-version) | Print version, license, and build information |

---

## `iam-shrink run`

Executes a command under loopback CSM telemetry (and optional proxy), intercepting all AWS operations and outputting a synthesized policy.

### Syntax
```bash
iam-shrink run [flags] -- <command> [args...]
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | string | `json` | Output format: `json`, `tf`, `cdk`, `cdktf`, `pulumi`, `cfn`, `sso`, `gcp`, `azure`, `k8s-rbac`, `vault` |
| `--strict-arns` | bool | `false` | Parameterize resource ARNs with variable placeholders instead of `*` |
| `--emit-vars` | bool | `false` | Append companion Terraform variable definitions (used with `--format=tf`) |
| `--proxy` | bool | `false` | Enable local HTTP/HTTPS interception proxy to extract exact runtime resource names |
| `--out` | string | `""` (stdout) | Output file path |
| `--include-failed` | bool | `true` | Include failed AWS API operations (e.g. 403 AccessDenied, 404 NotFound) |
| `--split-by-access-level` | bool | `false` | Split statements into distinct Read, Write, List, Tagging, and Permissions blocks |
| `--annotate` | bool | `false` | Inject code provenance and access-level comments above each statement |
| `--conditions` | bool | `false` | Synthesize condition keys (e.g. `aws:RequestedRegion`) |
| `--synthesize-notaction` | bool | `false` | Invert policy into an explicit Deny with `NotAction` |
| `--policy-type` | string | `identity` | Policy type: `identity`, `boundary`, `scp`, `resource` |
| `--principal` | string | `""` | Principal ARN for resource-based policies (defaults to account root) |
| `--compliance` | string | `""` | Evaluate compliance during run (`cis`, `nist`, `all`) |
| `--lint` | bool | `false` | Run static security linters on generated policy |
| `--diff-against` | string | `""` | Compare generated policy against an existing policy JSON file |
| `--export-otel` | string | `""` | Export captured calls to an OpenTelemetry JSON trace file |

---

## `iam-shrink ingest`

Parses AWS CloudTrail logs (single `.json`, `.json.gz`, or an entire directory tree) and emits a synthesized least-privilege policy.

### Syntax
```bash
iam-shrink ingest [flags] <cloudtrail-file-or-dir>
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--format` | string | `json` | Output format: `json`, `tf`, `cdk`, `cdktf`, `pulumi`, `cfn` |
| `--strict-arns` | bool | `false` | Extract and retain concrete resource ARNs from CloudTrail events |
| `--out` | string | `""` (stdout) | Output file path |

---

## `iam-shrink patch`

Executes a command and patches the target Terraform `.tf` file in-place with an automatic `.bak` backup.

### Syntax
```bash
iam-shrink patch --file=<path/to/main.tf> [flags] -- <command> [args...]
```

---

## `iam-shrink prune-role`

Removes unexercised actions from a legacy role policy.

### Syntax
```bash
iam-shrink prune-role --active-actions="s3:GetObject,dynamodb:PutItem" [flags] <legacy-role.json>
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--active-actions` | string | `""` | Comma-separated list of active IAM actions |
| `--out` | string | `""` (stdout) | Output file for the pruned policy |

---

## `iam-shrink verify`

Mathematically proves whether a candidate shrunk policy is a strict subset of an approved base policy. Exits with code `1` if any ungranted permissions or wildcard escalations are detected.

### Syntax
```bash
iam-shrink verify <base-policy.json> <shrunk-policy.json>
```

---

## `iam-shrink impact`

Evaluates a proposed candidate policy against historical CloudTrail logs, computing an **Operational Safety Score** and listing any historical calls that would be severed.

### Syntax
```bash
iam-shrink impact [flags] <cloudtrail-file-or-dir> <candidate-policy.json>
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--min-score` | float | `0.0` | Minimum acceptable safety score (0-100); fails with exit code 1 if below |
| `--fail-on-severed` | bool | `false` | Fail with exit code 1 if any historical call would be severed |

---

## `iam-shrink optimize`

Audits policy size against AWS quotas (2,048B inline, 10,240B managed), merges shared-resource statements, and minifies JSON.

### Syntax
```bash
iam-shrink optimize [flags] <policy.json>
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--check` | bool | `false` | Check quota limits only and display byte breakdown |
| `--out` | string | `""` (stdout) | File path to write optimized policy |

---

## `iam-shrink report`

Audits a policy against CIS AWS Foundations Benchmark (v3.0.0) or NIST SP 800-53 Rev 5.

### Syntax
```bash
iam-shrink report [flags] <policy.json>
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--standard` | string | `cis` | Benchmark standard: `cis`, `nist`, `all` |
| `--format` | string | `terminal` | Output format: `terminal`, `markdown`, `json` |

---

## `iam-shrink gate`

CI/CD quality gate enforcement tool.

### Syntax
```bash
iam-shrink gate [flags] <policy.json>
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--fail-on-wildcard` | bool | `false` | Fail if any wildcard (`*`) action is present |
| `--min-compliance` | float | `0.0` | Minimum compliance score threshold (0-100) |
| `--standard` | string | `cis` | Compliance benchmark to evaluate (`cis`, `nist`) |

---

## `iam-shrink pr-comment`

Generates rich Markdown for GitHub/GitLab Pull Request review comments.

### Syntax
```bash
iam-shrink pr-comment --existing=<base.json> --captured=<candidate.json> [flags]
```

---

## `iam-shrink diff`

Compares an existing deployed policy against captured runtime permissions.

### Syntax
```bash
iam-shrink diff <existing-policy.json> [captured-policy.json]
```

---

## `iam-shrink explain`

Displays internal IAM action mapping, required target ARNs, and dependencies for an SDK operation.

### Syntax
```bash
iam-shrink explain <service>:<api>
# Example:
iam-shrink explain Bedrock:InvokeModel
```

---

## `iam-shrink state`

Resolves parameterized ARN variables using real deployed cloud resources from `terraform.tfstate`.

### Syntax
```bash
iam-shrink state <terraform.tfstate> [policy.json]
```

---

## `iam-shrink k8s manifest`

Generates Kubernetes pod sidecar manifests with injected CSM telemetry.

### Syntax
```bash
iam-shrink k8s manifest [flags]
```

### Flags
| Flag | Type | Default | Description |
|---|---|---|---|
| `--deployment` | string | `my-app` | Kubernetes deployment name |
| `--namespace` | string | `default` | Kubernetes namespace |
| `--csm-port` | int | `31000` | Loopback UDP telemetry port |
| `--image` | string | `ghcr.io/smford/iam-shrink:latest` | Collector container image |

---

## `iam-shrink session`

Manages a background telemetry collector daemon for multi-command or multi-container test suites.

### Syntax
```bash
iam-shrink session <start|status|dump|stop> [flags]
```

### Subcommands
* `start`: Spawns the background UDP collector daemon.
* `status`: Shows number of captured calls and active session duration.
* `dump`: Emits the synthesized policy across all recorded calls.
* `stop`: Terminates the background daemon.

---

## `iam-shrink ui`

Starts the local interactive single-page web visualizer on `127.0.0.1`.

### Syntax
```bash
iam-shrink ui [--port=8080] [policy.json]
```

---

**Navigation:** [← Previous: Troubleshooting & FAQ](../guides/09-troubleshooting-and-faq.md) | [Next: Documentation Home →](../index.md)
