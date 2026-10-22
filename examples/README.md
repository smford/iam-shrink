# iam-shrink Interactive Examples & Worked Tutorials

Welcome to the `iam-shrink` interactive tutorials directory. Every example in this folder is **fully runnable**, self-contained, and accompanied by **pre-committed expected output files** so you can inspect the exact results directly on GitHub without cloning the repository.

---

## Interactive Examples Index

| Example | Title | Description | Primary Command | Pre-Committed Outputs |
|---|---|---|---|:---:|
| [**01-local-test-runner**](./01-local-test-runner) | Local Test Suite Telemetry (Go, Python, Node.js) | Intercept calls in real time via CSM with zero cloud credentials and synthesize JSON, Terraform, CDK, and GCP roles. | `iam-shrink run` | [JSON](01-local-test-runner/expected_policy.json), [Terraform](01-local-test-runner/expected_policy.tf), [CDK](01-local-test-runner/expected_policy.ts), [GCP](01-local-test-runner/expected_policy_gcp.yaml) |
| [**02-cloudtrail-ingest**](./02-cloudtrail-ingest) | CloudTrail Log Ingestion | Ingest historical `.json` and compressed `.json.gz` audit logs to synthesize least-privilege policies. | `iam-shrink ingest` | [JSON](02-cloudtrail-ingest/expected_policy.json), [Terraform](02-cloudtrail-ingest/expected_policy.tf) |
| [**03-terraform-patching**](./03-terraform-patching) | In-Place Terraform Patching | Automatically find and replace wildcard `data "aws_iam_policy_document"` blocks in `.tf` files with automatic backups. | `iam-shrink patch` | [Patched HCL](03-terraform-patching/main.tf.patched) |
| [**04-ci-cd-quality-gate**](./04-ci-cd-quality-gate) | CI/CD Security Quality Gate | Block wildcards in CI pipelines, audit against CIS AWS Foundations Benchmark, and generate PR review comments. | `iam-shrink gate`, `lint`, `pr-comment` | [PR Review Comment](04-ci-cd-quality-gate/expected_pr_comment.md) |
| [**05-policy-verification-and-blast-radius**](./05-policy-verification-and-blast-radius) | Verification & Blast Radius | Mathematically prove policy subset boundaries and calculate operational risk / severed calls against historical traffic. | `iam-shrink verify`, `impact` | [Impact Report](05-policy-verification-and-blast-radius/expected_impact_report.txt) |
| [**06-legacy-role-pruning**](./06-legacy-role-pruning) | Legacy Role Pruning & Diff Analysis | Prune 85%+ unused actions from legacy roles, prove zero privilege expansion, and verify 100% operational safety. | `iam-shrink prune-role`, `diff`, `optimize` | [Pruned Role](06-legacy-role-pruning/expected_pruned_role.json), [Diff Report](06-legacy-role-pruning/expected_diff.txt) |
| [**07-kubernetes-irsa-and-multi-cloud**](./07-kubernetes-irsa-and-multi-cloud) | Kubernetes IRSA & Multi-Cloud | Generate Kubernetes pod sidecar manifests and translate AWS permissions into GCP Custom Roles, Azure RBAC, and K8s RBAC. | `iam-shrink k8s`, `--format=gcp\|azure\|k8s-rbac\|vault` | [K8s Pod](07-kubernetes-irsa-and-multi-cloud/expected_k8s_deployment.yaml), [K8s Role](07-kubernetes-irsa-and-multi-cloud/expected_k8s_role.yaml), [GCP](07-kubernetes-irsa-and-multi-cloud/expected_gcp_role.yaml), [Azure](07-kubernetes-irsa-and-multi-cloud/expected_azure_role.json), [Vault](07-kubernetes-irsa-and-multi-cloud/expected_vault_role.sh) |

---

## Quick Start: Running the Examples

Every folder contains an executable `run.sh` script:

```bash
# Example 1: Local Test Suite Telemetry (Go, Python, Node.js)
./examples/01-local-test-runner/run.sh

# Example 2: Historical CloudTrail Log Ingestion
./examples/02-cloudtrail-ingest/run.sh

# Example 3: In-Place Terraform Patching
./examples/03-terraform-patching/run.sh

# Example 4: CI/CD Quality Gate & Automated PR Commenter
./examples/04-ci-cd-quality-gate/run.sh

# Example 5: Mathematical Verification & Operational Blast Radius
./examples/05-policy-verification-and-blast-radius/run.sh

# Example 6: Pruning Legacy Roles & Diff Reporting
./examples/06-legacy-role-pruning/run.sh

# Example 7: Kubernetes IRSA Manifest & Multi-Cloud Translation
./examples/07-kubernetes-irsa-and-multi-cloud/run.sh
```

---

## Key Core Principles Taught Across Examples

### 1. Zero-Credential Observation
`iam-shrink` captures telemetry via standard AWS Client-Side Monitoring (CSM) over local loopback UDP (`127.0.0.1`). You do **not** need an AWS account, cloud credentials, or live network access to synthesize precise security policies during development.

### 2. Multi-Format Native Synthesis
Generate policies natively in:
* **Terraform HCL** (`--format=tf` with `--strict-arns` and `--emit-vars`)
* **AWS CDK TypeScript** (`--format=cdk`)
* **CDKTF & Pulumi** (`--format=cdktf`, `--format=pulumi`)
* **AWS Identity Center (SSO)** (`--format=sso`)
* **CloudFormation** (`--format=cfn`)
* **Google Cloud IAM Custom Roles** (`--format=gcp`)
* **Azure RBAC Custom Roles** (`--format=azure`)
* **Kubernetes RBAC** (`--format=k8s-rbac`)
* **HashiCorp Vault Dynamic Roles** (`--format=vault`)

### 3. Production Safety First
* **Mathematical Verification (`verify`)**: Formally checks whether a candidate policy is a strict subset of an approved base policy, blocking shadow escalations.
* **Historical Blast Radius Scoring (`impact`)**: Tests a candidate policy against real CloudTrail history, warning you of any rare operations that would be broken before you push to production.
* **AWS Quota Compression (`optimize`)**: Merges statements sharing resources and minifies JSON to guarantee policies fit within AWS 2,048-byte inline and 10,240-byte managed policy limits.
