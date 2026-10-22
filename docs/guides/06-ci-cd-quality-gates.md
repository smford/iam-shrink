---
title: CI/CD Security Quality Gates & PR Automation
description: CI/CD Security Quality Gates & PR Automation for iam-shrink
---

[← Documentation Hub](../index.md)

# CI/CD Security Quality Gates & PR Automation

This guide demonstrates how to integrate `iam-shrink` into GitHub Actions, GitLab CI, and other continuous integration pipelines to **block wildcard policies**, **enforce compliance benchmarks**, and **post automated PR review comments**.

---

## 1. Using the Turnkey GitHub Composite Action

The repository provides an official GitHub Action (`action.yml`):

```yaml
name: IAM Least-Privilege Verification
on: [pull_request]

jobs:
  least-privilege:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run iam-shrink Telemetry & Synthesis
        uses: smford/iam-shrink@main
        with:
          command: 'pytest tests/'
          format: 'tf'
          out: 'infrastructure/generated_policy.tf'
          strict-arns: 'true'
          compliance: 'cis'
```

---

## 2. Standalone CLI Quality Gate (`iam-shrink gate`)

Use `iam-shrink gate` in any pipeline environment (Docker, Linux, macOS) to enforce security criteria with strict exit codes:

```bash
# Block pipeline if wildcards ('*') are present:
iam-shrink gate --fail-on-wildcard policy.json

# Enforce minimum CIS AWS Foundations compliance score:
iam-shrink gate --fail-on-wildcard --min-compliance=95.0 --standard=cis policy.json
```

### Exit Codes:
* `0`: Policy passes all quality gates.
* `1`: Quality gate failed (wildcard detected or compliance score below threshold).

---

## 3. Automated PR Review Comments (`iam-shrink pr-comment`)

`iam-shrink pr-comment` compares an existing base policy against the newly captured runtime policy, calculating the attack surface reduction and formatting a GitHub Pull Request review comment.

### Full GitHub Actions Workflow

```yaml
name: IAM Policy PR Review Bot
on:
  pull_request:
    paths:
      - 'infrastructure/**'
      - 'src/**'

permissions:
  pull-requests: write
  contents: read

jobs:
  iam-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Install iam-shrink
        run: go install github.com/smford/iam-shrink/cmd/iam-shrink@latest

      - name: Capture Test Telemetry
        run: |
          iam-shrink run -- pytest tests/ > new_policy.json

      - name: Generate PR Comment Markdown
        run: |
          iam-shrink pr-comment \
            --existing=infrastructure/base_policy.json \
            --captured=new_policy.json \
            --standard=cis > pr_comment.md

      - name: Post Comment to Pull Request
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const commentBody = fs.readFileSync('pr_comment.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: commentBody
            });
```

### Sample PR Comment Rendered in GitHub
The generated comment includes:
* **Attack Surface Reduction Badge:** e.g. `📉 Reduced Permission Attack Surface by 88.2%`
* **Collapsible Diff Breakdown:** Showing pruned actions in red (`- s3:*`) and verified active actions in green (`+ s3:GetObject`).
* **CIS AWS Foundations Benchmark Table:** Checking controls 1.16, 1.20, 1.21, and 1.22 with severity badges.

---

## 4. GitLab CI Integration

```yaml
stages:
  - security

iam-gate:
  stage: security
  image: ghcr.io/smford/iam-shrink:latest
  script:
    - iam-shrink run -- pytest tests/ > candidate_policy.json
    - iam-shrink gate --fail-on-wildcard candidate_policy.json
    - iam-shrink report --standard=cis candidate_policy.json
```

---

**Navigation:** [← Previous: Blast Radius Analysis](05-blast-radius-and-impact.md) | [Next: Compliance Benchmarks →](08-compliance-benchmarks.md)
