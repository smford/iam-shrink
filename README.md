# iam-shrink

**Local-to-Least-Privilege AWS IAM Policy Generator**

`iam-shrink` is a single-binary, zero-CGO CLI tool that intercepts AWS SDK and AWS CLI operations during local test suites, scripts, or deployment dry runs via AWS Client-Side Monitoring (CSM), local HTTP/HTTPS proxying, or CloudTrail log analysis. It translates captured API calls into exact, least-privilege IAM policies formatted in **Terraform HCL**, **CDKTF**, **AWS CDK (TypeScript)**, **Pulumi (TypeScript)**, **CloudFormation**, or **IAM Policy JSON**.

---

## Key Features

* **Zero-CGO & Single Binary:** Compiles with `CGO_ENABLED=0` across Linux, macOS, and Windows.
* **Dual Interception Engine:**
  * **AWS CSM (Client-Side Monitoring):** Lightweight UDP listener (`127.0.0.1`) capturing SDK execution with trailing packet drain.
  * **HTTP/HTTPS Interception Proxy (`--proxy`):** Generates an ephemeral Root CA to inspect requests on-the-fly and extract exact runtime ARNs (e.g. S3 bucket/keys, DynamoDB tables, KMS keys) instead of placeholders.
* **Multi-Source Ingestion:**
  * **Local Test Suite / CLI Execution:** `iam-shrink run -- <command>`
  * **AWS CloudTrail Ingestion:** `iam-shrink ingest <file-or-dir>` processes `.json` and `.json.gz` logs.
* **Security Standards & Compliance Auditing:**
  * **CIS AWS Foundations Benchmark v3.0 & NIST SP 800-53 Rev 5:** Audit policies with `iam-shrink report --standard=cis|nist`.
  * **Rule Engine with Remote Sync:** `iam-shrink update-rules` downloads the latest baseline benchmarks; automated weekly sync via GitHub Actions.
  * **CI Quality Gate:** `iam-shrink gate` blocks PRs on wildcards or high-risk findings.
  * **Automated PR Commenter:** `iam-shrink pr-comment` generates rich markdown reviews with collapsible diff tables and compliance badges.
* **OpenTofu & Terraform State Resolution:**
  * `iam-shrink state terraform.tfstate`: Matches `${var.bucket_name}` and `${var.table_name}` placeholders against actual deployed state resources, converting variables into concrete deployed ARNs.
  * `iam-shrink patch --file=main.tf`: Patches existing Terraform `.tf` files in-place with automatic backups.
* **Policy Boundaries & Perimeter Synthesis:**
  * **Identity-based Policies:** Standard IAM roles and user policies.
  * **Service Control Policies (SCPs) (`--policy-type=scp`):** AWS Organizations account guardrails.
  * **Permissions Boundaries (`--policy-type=boundary`):** Delegation caps.
  * **Resource-based Policies (`--policy-type=resource`):** S3 Bucket Policies and KMS Key Policies with principal assignment.
  * **Explicit Deny & NotAction Inversion (`--synthesize-notaction`):** Generates restrictive perimeter guardrails.
  * **Condition Synthesis (`--conditions`):** Synthesizes `aws:RequestedRegion` condition blocks.
* **Multi-Format Synthesis:**
  * **Terraform HCL:** `data "aws_iam_policy_document"` with optional companion variable blocks (`--emit-vars`).
  * **CDKTF (Cloud Development Kit for Terraform):** TypeScript `new DataAwsIamPolicyDocument(this, "generated", { ... })`.
  * **AWS CDK:** TypeScript `new iam.PolicyStatement({ ... })`.
  * **Pulumi:** TypeScript `aws.iam.getPolicyDocumentOutput({ ... })`.
  * **CloudFormation:** YAML/JSON `AWS::IAM::ManagedPolicy`.
  * **IAM Policy JSON:** Canonical AWS IAM policy format.
* **OpenTelemetry (OTel) Export (`--export-otel`):**
  * Streams intercepted IAM API calls as standard OpenTelemetry trace spans in OTLP JSON format.
* **Kubernetes IRSA Manifest Generator (`iam-shrink k8s`):** Generates sidecar and environment specs for EKS pods.
* **VS Code Integration (`iam-shrink init-vscode`):** Generates `.vscode/tasks.json` for one-click test runs.
* **Daemon / Session Mode (`iam-shrink session`):** Long-running background sessions for Docker Compose or dev servers.

---

## Architecture Overview

```
                                  +------------------------------------+
                                  |            iam-shrink              |
                                  |                                    |
                                  | 1. Starts UDP listener on 127.0.0.1|
                                  | 2. (Optional) Starts HTTP CA Proxy |
                                  +-----------------+------------------+
                                                    | Injected Env:
                                                    | AWS_CSM_ENABLED=true
                                                    | AWS_CSM_PORT=<port>
                                                    | HTTP_PROXY / AWS_CA_BUNDLE
                                                    v
                                  +------------------------------------+
                                  |          Target Command            |
                                  | (e.g. go test, python, terraform)  |
                                  +-----------------+------------------+
                                                    |
                                                    | CSM UDP / HTTP Traffic
                                                    v
+----------------------------------------------------------------------+
| iam-shrink Ingestion Engine                                          |
| - UDP CSM Collector: ApiCall & ApiCallAttempt events                 |
| - MITM Proxy: Extracts exact bucket, table, key, queue ARNs          |
| - CloudTrail Log Reader: Ingests raw historical records              |
| - State Resolver: Ingests terraform.tfstate deployed ARNs            |
+----------------------------------------------------------------------+
                                   |
                                   v
+----------------------------------------------------------------------+
| Translation & Compliance Engine                                      |
| - Maps SDK (Service, Api) -> Canonical IAM Actions                   |
| - Compliance Benchmarks (CIS AWS Benchmark v3.0, NIST SP 800-53)     |
| - Policy Perimeters (Identity, Boundary, SCP, Resource Policies)     |
| - NotAction Inversion & Condition Key Synthesis                      |
| - OpenTelemetry Span Generation                                      |
+----------------------------------------------------------------------+
                                   |
        +--------------------------+--------------------------+
        |                          |                          |
        v                          v                          v
+---------------+          +---------------+          +---------------+
| Terraform HCL |          | AWS CDK /     |          | IAM JSON /    |
| & CDKTF       |          | Pulumi TS     |          | CloudFormation|
+---------------+          +---------------+          +---------------+
```

---

## Installation

### From Source (Go 1.23+)
```bash
git clone https://github.com/smford/iam-shrink.git
cd iam-shrink
make build
# Binary output at ./bin/iam-shrink
```

### Direct Go Install
```bash
go install github.com/smford/iam-shrink/cmd/iam-shrink@latest
```

---

## CLI Reference & Usage

```text
Usage:
  iam-shrink run [flags] -- <command> [args...]
  iam-shrink ingest [flags] <cloudtrail-file-or-dir>
  iam-shrink patch --file=<main.tf> [flags] -- <command> [args...]
  iam-shrink prune-role <role-policy.json> [flags]
  iam-shrink report [flags] <policy.json>
  iam-shrink update-rules [flags]
  iam-shrink state <terraform.tfstate> [policy.json]
  iam-shrink pr-comment [flags]
  iam-shrink gate [flags] <policy.json>
  iam-shrink diff <existing-policy.json> [captured-policy.json]
  iam-shrink lint <policy.json>
  iam-shrink explain <service>:<api>
  iam-shrink export-mappings [flags]
  iam-shrink k8s manifest [flags]
  iam-shrink init-vscode [flags]
  iam-shrink session <start|status|dump|stop> [flags]
  iam-shrink version
```

---

### 1. Generating Policies (`iam-shrink run`)

Wrap any test suite, script, or CLI tool after `--`:

```bash
# Output Terraform HCL
iam-shrink run --format=tf -- go test ./...

# Output CDKTF (Cloud Development Kit for Terraform)
iam-shrink run --format=cdktf -- python test_suite.py

# Output Terraform with strict parameterized ARNs and companion variable definitions
iam-shrink run --format=tf --strict-arns --emit-vars -- go test ./...

# Generate an AWS Organizations Service Control Policy (SCP)
iam-shrink run --policy-type=scp --format=json -- python test_suite.py

# Invert into an explicit Deny with NotAction perimeter guardrail
iam-shrink run --synthesize-notaction --format=json -- go test ./...

# Evaluate CIS benchmark compliance during execution
iam-shrink run --compliance=cis --format=tf -- go test ./...

# Stream intercepted operations as OpenTelemetry traces
iam-shrink run --export-otel=traces.json --format=tf -- go test ./...
```

#### Flags for `run`

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `json` | Format: `json`, `tf`, `cdk`, `cdktf`, `pulumi`, `cfn` |
| `--policy-type` | `identity` | Type: `identity`, `boundary`, `scp`, `resource` |
| `--out` | `""` | Output file path (if omitted, writes to stdout) |
| `--patch-file` | `""` | Path to Terraform `.tf` file to patch directly in-place |
| `--include-failed` | `true` | Include API calls that failed (e.g., 403 `AccessDenied`) |
| `--group-by-service` | `true` | Group IAM statements by AWS service prefix |
| `--split-by-access-level` | `false` | Group statements by access level (`Read`, `Write`, `List`, `Tagging`, `Permissions`) |
| `--strict-arns` | `false` | Generate parameterized ARN placeholders instead of `*` |
| `--emit-vars` | `false` | Emit companion Terraform variable definitions for ARNs |
| `--conditions` | `false` | Synthesize condition blocks (e.g. `aws:RequestedRegion`) |
| `--synthesize-notaction` | `false` | Invert policy into explicit Deny with NotAction |
| `--compliance` | `""` | Evaluate compliance benchmark: `cis`, `nist`, `all` |
| `--export-otel` | `""` | Export captured calls to OpenTelemetry trace JSON file |
| `--proxy` | `false` | Enable local HTTP/HTTPS proxy to capture exact concrete ARNs |
| `--lint` | `false` | Run automated security linter checks on generated statements |
| `--diff-against` | `""` | Compare generated policy against an existing policy JSON file |

---

### 2. CIS & NIST Compliance Reporting (`iam-shrink report`)

Audit policies against the **CIS AWS Foundations Benchmark (v3.0.0)** or **NIST SP 800-53 (Rev 5)**:

```bash
# Terminal Report
iam-shrink report --standard=cis policy.json

# Markdown Report (for PR comments or wiki)
iam-shrink report --standard=nist --format=markdown policy.json
```

---

### 3. CI/CD Quality Gate & PR Comments

Enforce least-privilege quality gates in CI/CD pipelines to block over-privileged changes:

```bash
# Fail build if wildcard actions or critical security issues are introduced
iam-shrink gate --fail-on-wildcard --min-compliance=80.0 policy.json

# Post a formatted review comment to GitHub / GitLab PRs
iam-shrink pr-comment --existing=base_role.json --captured=new_policy.json --standard=cis
```

---

### 4. Terraform / OpenTofu State Interrogation (`iam-shrink state`)

Match policy placeholders (`${var.bucket_name}`, `${var.table_name}`) against actual deployed resources in `terraform.tfstate` / OpenTofu state:

```bash
iam-shrink state terraform.tfstate policy.json
```

---

### 5. CloudTrail Log Ingestion (`iam-shrink ingest`)

Synthesize least-privilege policies directly from production CloudTrail logs (`.json` or `.json.gz` files, or an entire directory):

```bash
iam-shrink ingest --format=tf --strict-arns /path/to/cloudtrail/logs/
```

---

### 6. In-Place Terraform Patching (`iam-shrink patch`)

Run tests and automatically patch the target `data "aws_iam_policy_document"` block in an existing Terraform file, creating an automatic backup (`.tf.bak`):

```bash
iam-shrink patch --file=main.tf -- go test ./...
```

---

### 7. Role Pruning (`iam-shrink prune-role`)

Prune stale, unused actions from an over-privileged IAM role policy:

```bash
iam-shrink prune-role existing_role.json --active-actions="s3:GetObject,dynamodb:PutItem" --out=pruned_role.json
```

---

### 8. Kubernetes IRSA Deployment Spec (`iam-shrink k8s`)

Generate a Kubernetes Deployment YAML containing an `iam-shrink` telemetry sidecar and IRSA environment variables:

```bash
iam-shrink k8s manifest --deployment=auth-service --proxy > k8s-telemetry.yaml
```

---

### 9. VS Code Companion Setup (`iam-shrink init-vscode`)

Initialize `.vscode/tasks.json` in the current repository to run tests through `iam-shrink` with a keyboard shortcut:

```bash
iam-shrink init-vscode --test-cmd="go test ./..."
```

---

### 10. Daemon / Session Mode (`iam-shrink session`)

Ideal for Docker Compose environments or multi-step execution:

```bash
# 1. Start background session
iam-shrink session start

# 2. Configure terminal session
export AWS_CSM_ENABLED=true
export AWS_CSM_PORT=31000
export AWS_CSM_HOST=127.0.0.1

# 3. Run development tests
pytest tests/

# 4. Dump synthesized policy
iam-shrink session dump --format=tf

# 5. Stop session
iam-shrink session stop
```

---

## Development & Testing

```bash
# Run all unit, integration, and proxy tests
make test

# Run Go static analysis
make vet

# Build zero-CGO binary
make build
```

---

## License

MIT
