---
title: Compliance Benchmarks & Auditing (CIS & NIST)
description: Compliance Benchmarks & Auditing (CIS & NIST) for iam-shrink
---

[← Documentation Hub](../index.md)

# Compliance Benchmarks & Auditing (CIS & NIST)

This guide covers `iam-shrink`'s built-in compliance engine, supporting automated auditing against the **Center for Internet Security (CIS) AWS Foundations Benchmark v3.0** and **NIST SP 800-53 Rev 5**.

---

## 1. Supported Compliance Frameworks

### CIS AWS Foundations Benchmark (v3.0.0)

| Control ID | Severity | Description | Evaluation Rule in iam-shrink |
|---|:---:|---|---|
| **1.16** | `CRITICAL` | Full administrative privileges (`*:*`) must not be attached | Flags any statement with `Action: "*"` and `Resource: "*"` |
| **1.20** | `HIGH` | `iam:PassRole` must not be granted on wildcard resource `*` | Flags `iam:PassRole` combined with `Resource: "*"` (prevents privilege escalation) |
| **1.21** | `HIGH` | `sts:AssumeRole` must not be granted on wildcard resource `*` | Flags `sts:AssumeRole` without explicit target role ARNs |
| **1.22** | `MEDIUM` | Service-level wildcards should be avoided (e.g. `s3:*`) | Flags wildcards within service prefixes |

### NIST SP 800-53 Rev 5

| Control ID | Name | Objective |
|---|---|---|
| **AC-6** | Least Privilege | The organization employs the principle of least privilege, allowing only authorized access for necessary functions. |
| **AC-2** | Account Management | Establishes automated mechanisms to audit and prevent unauthorized credential escalation. |
| **SC-7** | Boundary Protection | Segregates administrative interfaces and restricts broad API permissions. |

---

## 2. Generating Compliance Reports (`iam-shrink report`)

### Terminal Output
```bash
iam-shrink report --standard=cis policy.json
```

*Sample CLI Output:*
```text
=== CIS AWS Foundations Benchmark (v3.0.0) Audit Report ===

Policy: policy.json
Score:  100.0% (4/4 controls passed)
Status: 🟢 COMPLIANT

  CONTROL   SEVERITY   STATUS   DETAILS
  -------------------------------------------------------------
  1.16      CRITICAL   ✅ PASS   No full '*:*' wildcard found
  1.20      HIGH       ✅ PASS   iam:PassRole scoped to specific ARN
  1.21      HIGH       ✅ PASS   sts:AssumeRole scoped to specific ARN
  1.22      MEDIUM     ✅ PASS   All actions explicitly enumerated
```

### Markdown Format (for Documentation & PRs)
```bash
iam-shrink report --standard=cis --format=markdown policy.json
```

*Outputs a clean Markdown table with pass/fail badges ready to pipe into documentation artifacts or release notes.*

### JSON Format (for SIEM & Audit Ingestion)
```bash
iam-shrink report --standard=all --format=json policy.json > compliance_audit.json
```

---

## 3. Weekly Rule Synchronization (`update-rules`)

AWS frequently introduces new APIs, and benchmark bodies periodically release revised controls.

* **Locally:** Run `iam-shrink update-rules` to download the latest vetted rule schemas directly into `~/.iam-shrink/rules/`.
* **Automated CI Sync:** The repository maintains an automated GitHub Action workflow (`compliance-sync.yml`) that runs weekly, parsing upstream catalogs and keeping the embedded rule definitions up-to-date.

---

**Navigation:** [← Previous: CI/CD Quality Gates](06-ci-cd-quality-gates.md) | [Next: Architecture & Telemetry →](01-architecture-and-telemetry.md)
