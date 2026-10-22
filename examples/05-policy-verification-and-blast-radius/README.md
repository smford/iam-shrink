# Example 05: Mathematical Subset Verification & Blast Radius Risk Analysis

This example demonstrates how to safely apply tightened IAM policies to production workloads without risking accidental privilege expansions or breaking live traffic.

---

## The Problems

1. **Unintended Privilege Expansion**: When refactoring or tightening a policy, it is dangerously easy to inadvertently grant permissions or resource scopes that the original policy never permitted (e.g. converting `s3:*` on bucket `A` to `*` on bucket `B`, or adding an unrelated service like SQS).
2. **Production Outages from Severed Calls**: Developers fear deploying shrunk policies because background cron jobs, disaster recovery drills, or infrequently used API calls might get severed, causing downtime.

---

## How iam-shrink Solves It

1. **`iam-shrink verify <base-policy> <shrunk-policy>`**:
   Uses formal mathematical subset analysis to prove that the shrunk policy grants strictly less than or equal to the permissions in the base policy. If any action or resource scope expands outside the base policy, verification immediately fails.

2. **`iam-shrink impact <cloudtrail-history> <candidate-policy>`**:
   Replays historical production CloudTrail logs against the proposed policy. It calculates an **Operational Safety Score** and itemizes any API calls that would be severed before the policy is applied.

---

## Files in this Directory

* `base_policy.json`: Broad existing IAM role policy (`s3:*`, `dynamodb:*`, `kms:*`).
* `candidate_policy.json`: Valid shrunk least-privilege policy.
* `violating_policy.json`: Flawed candidate policy containing an illegal expansion (`sqs:SendMessage`).
* `historical_cloudtrail.json`: Recorded production log entries.
* `run.sh`: Automated demo script demonstrating subset verification and blast radius scoring.

---

## Usage

Run the sample script:

```bash
./run.sh
```

Or run individual commands:

```bash
# Verify candidate policy is a strict subset of base
iam-shrink verify base_policy.json candidate_policy.json

# Detect illegal expansion
iam-shrink verify base_policy.json violating_policy.json

# Assess blast radius against historical CloudTrail logs
iam-shrink impact historical_cloudtrail.json candidate_policy.json
```
