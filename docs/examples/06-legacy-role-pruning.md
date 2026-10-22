---
title: 06. Legacy IAM Role Pruning
description: Worked tutorial 06. Legacy IAM Role Pruning for iam-shrink
---

[← Documentation Hub](../index.md)

# Example 06: Legacy IAM Role Pruning & Operational Blast Radius

This worked example demonstrates how to safely shrink a bloated, legacy AWS IAM role that has accumulated permissions over years.

By combining `prune-role`, `verify`, and `impact`, you can achieve an **85–95% attack surface reduction** with **mathematical proof of no unintended privilege expansion** and **zero risk of production downtime**.

---

## The Scenario

You have an existing production IAM role policy ([`legacy_role.json`](legacy_role.json)) granting 17 actions across S3, DynamoDB, EC2, CloudWatch, and SQS.

Auditing 90 days of CloudTrail traffic ([`cloudtrail_active.json`](cloudtrail_active.json)) proves that only 2 operations are actively utilized in production:
1. `s3:GetObject`
2. `dynamodb:PutItem`

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`legacy_role.json`](legacy_role.json) | The over-privileged role with 17 broad AWS actions. |
| [`cloudtrail_active.json`](cloudtrail_active.json) | 90 days of CloudTrail activity proving which actions are actually used. |
| [`expected_pruned_role.json`](expected_pruned_role.json) | Resulting policy with 15 dead permissions safely removed. |
| [`expected_diff.txt`](expected_diff.txt) | Detailed terminal diff report showing an 88.2% reduction. |
| [`run.sh`](run.sh) | Standalone script demonstrating the complete lifecycle. |

---

## The 4-Step Pruning Workflow

### 1. Prune Unused Actions (`iam-shrink prune-role`)
```bash
iam-shrink prune-role \
  --active-actions="s3:GetObject,dynamodb:PutItem" \
  --out=pruned_role.json \
  legacy_role.json
```
*Output: `Pruning complete: Removed 15 actions (88.2% attack surface reduction).`*

### 2. Formally Verify Subset Boundaries (`iam-shrink verify`)
```bash
iam-shrink verify legacy_role.json pruned_role.json
```
*Result: Mathematically guarantees that `pruned_role.json` is a pure subset of `legacy_role.json` and introduces zero shadow expansions.*

### 3. Confirm 100% Operational Safety (`iam-shrink impact`)
```bash
iam-shrink impact cloudtrail_active.json pruned_role.json
```
*Result: Simulates all historical calls against the proposed policy, reporting `Operational Safety Score: 100.0% [MINIMAL RISK]` and 0 severed calls.*

### 4. Inspect Permission Diff (`iam-shrink diff`)
```bash
iam-shrink diff legacy_role.json pruned_role.json
```
*Result: See [expected_diff.txt](expected_diff.txt) for the full breakdown.*

---

## Running the Example

```bash
./examples/06-legacy-role-pruning/run.sh
```

---

**Navigation:** [← Previous: 05. Verification & Blast Radius](05-policy-verification-and-blast-radius.md) | [Next: 07. Kubernetes IRSA & Multi-Cloud →](07-kubernetes-irsa-and-multi-cloud.md)
