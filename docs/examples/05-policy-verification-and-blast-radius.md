---
title: 05. Verification & Blast Radius
description: Worked tutorial 05. Verification & Blast Radius for iam-shrink
---

[← Documentation Hub](../index.md)

# Example 05: Mathematical Verification & Operational Blast Radius

This worked example demonstrates how to solve the two biggest fears when locking down IAM:
1. **Accidental Privilege Expansion:** Did our refactored policy accidentally grant permissions not in the base policy? (`iam-shrink verify`)
2. **Production Outages:** Will removing permissions break infrequent tasks (like monthly reports or disaster recovery)? (`iam-shrink impact`)

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`base_policy.json`](base_policy.json) | The approved production base policy currently deployed in AWS. |
| [`candidate_policy.json`](candidate_policy.json) | A proposed shrunk policy that is a clean subset of `base_policy.json`. |
| [`violating_policy.json`](violating_policy.json) | A flawed policy that adds an unauthorized action (`dynamodb:DeleteItem`). |
| [`historical_cloudtrail.json`](historical_cloudtrail.json) | Historical CloudTrail audit log covering 90 days of operational calls. |
| [`expected_impact_report.txt`](expected_impact_report.txt) | Terminal output showing the Operational Safety Score and severed call detection. |
| [`run.sh`](run.sh) | Runnable shell script executing verification and blast radius scoring. |

---

## 1. Mathematical Subset Verification (`iam-shrink verify`)

`iam-shrink verify` mathematically evaluates whether policy $B \subseteq A$. If policy $B$ expands any action or wildcard, it fails with exit code `1`:

```bash
# Valid candidate policy (Succeeds - clean subset)
iam-shrink verify base_policy.json candidate_policy.json

# Flawed candidate policy (Fails - detects unauthorized dynamodb:DeleteItem)
iam-shrink verify base_policy.json violating_policy.json
```

---

## 2. Historical Blast Radius Analysis (`iam-shrink impact`)

`iam-shrink impact` scans real historical CloudTrail logs and flags every operation that the proposed policy would block:

```bash
iam-shrink impact historical_cloudtrail.json candidate_policy.json
```

View the generated report in [expected_impact_report.txt](expected_impact_report.txt):
```text
=== Operational Blast Radius & Impact Analysis ===

  Historical Events Analyzed: 5
  Permitted by Shrunk Policy: 4 (80.00%)
  Potentially Severed Calls:  1
  Operational Safety Score:   80.0% [HIGH RISK]

⚠️  The following historical calls would be SEVERED if this policy is applied:
    SERVICE / API        IAM ACTION                     OCCURRENCES
    --------------------------------------------------------------------
    s3:DeleteBucket      s3:DeleteBucket                1
```

---

## Running the Example

Run the automated script:
```bash
./examples/05-policy-verification-and-blast-radius/run.sh
```

---

**Navigation:** [← Previous: 04. CI/CD Quality Gate](04-ci-cd-quality-gate.md) | [Next: 06. Legacy IAM Role Pruning →](06-legacy-role-pruning.md)
