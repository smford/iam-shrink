# Example 04: CI/CD Security Quality Gate & PR Review Automation

This example demonstrates how to integrate `iam-shrink` into CI/CD pipelines (GitHub Actions, GitLab CI, Bitbucket Pipelines) to block over-permissive policies from merging, audit compliance against CIS/NIST benchmarks, and generate pull request comments.

---

## The Problem

- Security teams struggle to enforce least-privilege standards before pull requests are merged.
- Developers inadvertently check in wildcard permissions (`s3:*`, `*`) or dangerous privilege-escalation actions (like `iam:CreatePolicyVersion`).
- Code reviewers lack clear visibility into what permissions an application actually exercised versus what is declared in code.

---

## How iam-shrink Solves It

1. **`iam-shrink lint`**: Static security scanner detecting critical privilege escalation paths (pass-role, policy-version creation, admin wildcards).
2. **`iam-shrink gate`**: Pipeline circuit-breaker returning exit code `1` if policies violate least-privilege rules (e.g. `--fail-on-wildcard` or `--standard=cis`).
3. **`iam-shrink report`**: Audits policies against CIS AWS Foundations Benchmark (v3.0.0) or NIST SP 800-53 (Rev 5).
4. **`iam-shrink pr-comment`**: Generates rich Markdown summarizing pruned permissions, required permissions, and compliance scores for direct posting to GitHub/GitLab PRs.

---

## Files in this Directory

* `insecure_policy.json`: Example IAM policy with wildcard actions and privilege escalation risks.
* `compliant_policy.json`: Least-privilege IAM policy adhering to CIS benchmark standards.
* `run.sh`: Automated demo script executing all 5 CI/CD checks.

---

## Usage

Run the sample script:

```bash
./run.sh
```

Or run individual commands:

```bash
# Run security linter on a candidate policy
iam-shrink lint insecure_policy.json

# Enforce quality gate in CI build (blocks on wildcards)
iam-shrink gate --fail-on-wildcard insecure_policy.json

# Audit compliance against CIS benchmark
iam-shrink report --standard=cis compliant_policy.json

# Generate a PR comment comparing existing vs newly captured policy
iam-shrink pr-comment --existing=insecure_policy.json --captured=compliant_policy.json --standard=cis
```

### GitHub Actions Workflow Example

```yaml
- name: IAM Quality Gate
  run: |
    iam-shrink gate --fail-on-wildcard --standard=cis ./terraform/policies/*.json
```
