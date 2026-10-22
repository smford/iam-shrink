---
title: 04. CI/CD Security Quality Gate
description: Worked tutorial 04. CI/CD Security Quality Gate for iam-shrink
---

[← Documentation Hub](../index.md)

# Example 04: CI/CD Quality Gate & Automated PR Commenter

This worked example demonstrates how to integrate `iam-shrink` into GitHub Actions or GitLab CI to:
1. **Block pull requests** that introduce wildcards or security risks (`iam-shrink gate`).
2. **Audit policies** against the **CIS AWS Foundations Benchmark v3.0** (`iam-shrink report`).
3. **Generate PR comments** showing exactly which permissions were added, retained, or pruned (`iam-shrink pr-comment`).

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`insecure_policy.json`](insecure_policy.json) | Dangerous policy containing `s3:*` and privilege escalation risk (`iam:CreatePolicyVersion`). |
| [`compliant_policy.json`](compliant_policy.json) | Least-privilege compliant policy with specific permissions. |
| [`expected_pr_comment.md`](expected_pr_comment.md) | Generated GitHub Pull Request review comment with badges and diff. |
| [`run.sh`](run.sh) | Runnable shell script demonstrating linting, quality gating, reporting, and PR comments. |

---

## Sample PR Comment Output

See [expected_pr_comment.md](expected_pr_comment.md) for the exact Markdown emitted for GitHub PR reviews. It includes:
* Attack surface reduction percentage.
* Color-coded permission diff (`+` added, `-` pruned).
* CIS AWS Foundations Benchmark checklist with PASS/FAIL status.

---

## Running the Example

Run the automated script:
```bash
./examples/04-ci-cd-quality-gate/run.sh
```

Or run manually:

```bash
# 1. Check for security vulnerabilities & privilege escalation
iam-shrink lint examples/04-ci-cd-quality-gate/insecure_policy.json

# 2. Block CI on wildcards (fails with exit code 1)
iam-shrink gate --fail-on-wildcard examples/04-ci-cd-quality-gate/insecure_policy.json

# 3. Audit compliant policy against CIS Benchmark
iam-shrink report --standard=cis examples/04-ci-cd-quality-gate/compliant_policy.json

# 4. Generate GitHub PR review comment
iam-shrink pr-comment \
  --existing=examples/04-ci-cd-quality-gate/insecure_policy.json \
  --captured=examples/04-ci-cd-quality-gate/compliant_policy.json \
  --standard=cis
```

---

**Navigation:** [← Previous: 03. Terraform Patching](03-terraform-patching.md) | [Next: 05. Verification & Blast Radius →](05-policy-verification-and-blast-radius.md)
