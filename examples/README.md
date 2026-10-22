# iam-shrink Interactive Examples & Tutorials

Welcome to the `iam-shrink` examples directory! These runnable examples teach you how to use `iam-shrink` across local development, historical log analysis, infrastructure-as-code patching, and automated CI/CD pipelines.

---

## Examples Index

| Example | Title | Description | Primary Command |
|---|---|---|---|
| [**01-local-test-runner**](./01-local-test-runner) | Local Test Suite Telemetry | Capture IAM calls from test suites via CSM and emit JSON, Terraform, and CDK. | `iam-shrink run` |
| [**02-cloudtrail-ingest**](./02-cloudtrail-ingest) | CloudTrail Log Ingestion | Synthesize least-privilege policies directly from historical `.json` and `.json.gz` logs. | `iam-shrink ingest` |
| [**03-terraform-patching**](./03-terraform-patching) | In-Place Terraform Patching | Replace wildcard policies in `.tf` files in-place with automatic `.bak` backups. | `iam-shrink patch` |
| [**04-ci-cd-quality-gate**](./04-ci-cd-quality-gate) | CI/CD Security Quality Gate | Block wildcard policies in pipelines, run security linters, and generate PR review comments. | `iam-shrink gate`, `lint`, `pr-comment` |
| [**05-policy-verification-and-blast-radius**](./05-policy-verification-and-blast-radius) | Verification & Blast Radius | Mathematically prove policy subset boundaries and calculate severed call risks. | `iam-shrink verify`, `impact` |

---

## Quick Start: Running All Examples

Every example includes a standalone, self-contained `run.sh` script:

```bash
# Example 1: Local Test Suite Telemetry
./examples/01-local-test-runner/run.sh

# Example 2: CloudTrail Log Ingestion
./examples/02-cloudtrail-ingest/run.sh

# Example 3: In-Place Terraform Patching
./examples/03-terraform-patching/run.sh

# Example 4: CI/CD Quality Gate & Compliance Reporting
./examples/04-ci-cd-quality-gate/run.sh

# Example 5: Mathematical Verification & Blast Radius
./examples/05-policy-verification-and-blast-radius/run.sh
```

---

## Key Concepts Taught

### 1. Zero-Credential Observation
`iam-shrink` uses local Client-Side Monitoring (CSM) telemetry on loopback UDP (`127.0.0.1`). You do not need an active AWS connection, cloud credentials, or production permissions to generate strict policies during local test runs.

### 2. Multi-Format Code Generation
Synthesize policies directly in:
* AWS JSON (`--format=json`)
* Terraform HCL (`--format=tf` with `--strict-arns` and `--emit-vars`)
* AWS CDK TypeScript (`--format=cdk`)
* CloudFormation (`--format=cfn`)
* GCP IAM Custom Roles (`--format=gcp`)
* Azure RBAC Roles (`--format=azure`)
* Kubernetes RBAC (`--format=k8s-rbac`)

### 3. Shift-Left Security & Guardrails
Enforce least-privilege standards before code ever hits production:
* `gate --fail-on-wildcard`: Blocks builds if wildcards are present.
* `report --standard=cis`: Verifies compliance against CIS AWS Foundations Benchmark.
* `verify`: Mathematically proves that refactored policies do not unintentionally expand access.
