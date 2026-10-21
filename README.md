# iam-shrink

**Local-to-Least-Privilege AWS IAM Policy Generator**

`iam-shrink` is a single-binary, zero-CGO CLI tool that intercepts AWS SDK and AWS CLI operations during local test suites, scripts, or deployment dry runs via AWS Client-Side Monitoring (CSM), local HTTP/HTTPS proxying, or CloudTrail log analysis. It translates captured API calls into exact, least-privilege IAM policies formatted in **Terraform HCL**, **AWS CDK (TypeScript)**, **Pulumi (TypeScript)**, **CloudFormation**, or **IAM Policy JSON**.

---

## Key Features

* **Zero-CGO & Single Binary:** Compiles with `CGO_ENABLED=0` across Linux, macOS, and Windows.
* **Dual Interception Engine:**
  * **AWS CSM (Client-Side Monitoring):** Lightweight UDP listener (`127.0.0.1`) capturing SDK execution with trailing packet drain.
  * **HTTP/HTTPS Interception Proxy (`--proxy`):** Generates an ephemeral Root CA to inspect requests on-the-fly and extract exact runtime ARNs (e.g. S3 bucket/keys, DynamoDB tables, KMS keys) instead of placeholders.
* **Multi-Source Ingestion:**
  * **Local Test Suite / CLI Execution:** `iam-shrink run -- <command>`
  * **AWS CloudTrail Ingestion:** `iam-shrink ingest <file-or-dir>` processes `.json` and `.json.gz` logs.
* **Policy Boundaries & Perimeter Synthesis:**
  * **Identity-based Policies:** Standard IAM roles and user policies.
  * **Service Control Policies (SCPs) (`--policy-type=scp`):** AWS Organizations account guardrails.
  * **Permissions Boundaries (`--policy-type=boundary`):** Delegation caps.
  * **Resource-based Policies (`--policy-type=resource`):** S3 Bucket Policies and KMS Key Policies with principal assignment.
  * **Condition Synthesis (`--conditions`):** Synthesizes `aws:RequestedRegion` condition blocks.
* **Multi-Format Synthesis:**
  * **Terraform HCL:** `data "aws_iam_policy_document"` with optional companion variable blocks (`--emit-vars`).
  * **In-Place Terraform Patching (`iam-shrink patch`):** Directly updates existing `.tf` files with automatic backup creation.
  * **AWS CDK:** TypeScript `new iam.PolicyStatement({ ... })`.
  * **Pulumi:** TypeScript `aws.iam.getPolicyDocumentOutput({ ... })`.
  * **CloudFormation:** YAML/JSON `AWS::IAM::ManagedPolicy`.
  * **IAM Policy JSON:** Canonical AWS IAM policy format.
* **Separation of Duties (`--split-by-access-level`):** Segregates statements by access level (`Read`, `Write`, `List`, `Tagging`, `Permissions`).
* **Policy Diffing & Role Pruning:**
  * `iam-shrink diff`: Compares existing policies against runtime execution and calculates attack surface reduction.
  * `iam-shrink prune-role`: Prunes unaccessed permissions from an existing IAM role policy.
* **Security Linter (`iam-shrink lint`):** Analyzes IAM policies for privilege escalation risks (e.g. unconstrained `iam:PassRole`, `iam:CreatePolicyVersion`, wildcards).
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
| - Trailing packet drain (200ms post-exit)                            |
+----------------------------------------------------------------------+
                                   |
                                   v
+----------------------------------------------------------------------+
| Translation & Policy Synthesizer Engine                              |
| - Maps SDK (Service, Api) -> Canonical IAM Actions                   |
| - Classifies Access Levels (Read/Write/List/Tagging/Permissions)     |
| - Policy Perimeters (Identity, Boundary, SCP, Resource Policies)     |
| - Condition Key Synthesis (aws:RequestedRegion)                      |
| - Deterministic alphabetical sorting & deduplication                 |
+----------------------------------------------------------------------+
                                   |
        +--------------------------+--------------------------+
        |                          |                          |
        v                          v                          v
+---------------+          +---------------+          +---------------+
| Terraform HCL |          | AWS CDK /     |          | IAM JSON /    |
| (aws_iam_...) |          | Pulumi TS     |          | CloudFormation|
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

### 1. Generating Policies from Commands (`iam-shrink run`)

Wrap any command after `--`:

```bash
# Output Terraform HCL
iam-shrink run --format=tf -- go test ./...

# Output Terraform with strict parameterized ARNs and companion variable definitions
iam-shrink run --format=tf --strict-arns --emit-vars -- go test ./...

# Generate an AWS Organizations Service Control Policy (SCP)
iam-shrink run --policy-type=scp --format=json -- python test_suite.py

# Generate a Resource-based Policy with condition keys
iam-shrink run --policy-type=resource --principal="arn:aws:iam::123456789012:role/WorkerRole" --conditions --format=tf -- go test ./...

# Output AWS CDK (TypeScript)
iam-shrink run --format=cdk --out=policy.ts -- npm test

# Output Pulumi (TypeScript)
iam-shrink run --format=pulumi -- go test ./...

# Output CloudFormation JSON
iam-shrink run --format=cfn --out=cfn-policy.json -- python deploy_dryrun.py

# Enable HTTP proxy to capture exact runtime resource ARNs
iam-shrink run --proxy --format=tf --strict-arns -- python integration_test.py

# Split statements by access level (Read/Write/List/Tagging/Permissions)
iam-shrink run --format=tf --split-by-access-level -- go test ./...

# Run security linter and compare against an existing policy
iam-shrink run --lint --diff-against=existing_role.json -- go test ./...
```

#### Flags for `run`

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `json` | Format: `json`, `tf`, `cdk`, `pulumi`, `cfn` |
| `--policy-type` | `identity` | Type: `identity`, `boundary`, `scp`, `resource` |
| `--out` | `""` | Output file path (if omitted, writes to stdout) |
| `--patch-file` | `""` | Path to Terraform `.tf` file to patch directly in-place |
| `--include-failed` | `true` | Include API calls that failed (e.g., 403 `AccessDenied`) |
| `--group-by-service` | `true` | Group IAM statements by AWS service prefix |
| `--split-by-access-level` | `false` | Group statements by access level (`Read`, `Write`, `List`, `Tagging`, `Permissions`) |
| `--strict-arns` | `false` | Generate parameterized ARN placeholders instead of `*` |
| `--emit-vars` | `false` | Emit companion Terraform variable definitions for ARNs |
| `--conditions` | `false` | Synthesize condition blocks (e.g. `aws:RequestedRegion`) |
| `--principal` | `""` | Principal ARN for resource-based policies |
| `--proxy` | `false` | Enable local HTTP/HTTPS proxy to capture exact concrete ARNs |
| `--lint` | `false` | Run automated security linter checks on generated statements |
| `--diff-against` | `""` | Compare generated policy against an existing policy JSON file |
| `--mappings` | `""` | Path to custom YAML file to extend or override default mappings |

---

### 2. CloudTrail Log Ingestion (`iam-shrink ingest`)

Synthesize least-privilege policies directly from production CloudTrail logs (`.json` or `.json.gz` files, or an entire directory):

```bash
# Ingest single CloudTrail file
iam-shrink ingest --format=tf /var/log/cloudtrail/log.json.gz

# Ingest entire directory of CloudTrail logs
iam-shrink ingest --format=tf --strict-arns /path/to/cloudtrail/logs/
```

---

### 3. In-Place Terraform Patching (`iam-shrink patch`)

Run your tests and automatically patch the target `data "aws_iam_policy_document"` block in an existing Terraform file, creating an automatic backup (`.tf.bak`):

```bash
iam-shrink patch --file=main.tf -- go test ./...
```

---

### 4. Role Pruning (`iam-shrink prune-role`)

Prune stale, unused actions from an over-privileged IAM role policy:

```bash
iam-shrink prune-role existing_role.json --active-actions="s3:GetObject,dynamodb:PutItem" --out=pruned_role.json
```

---

### 5. Policy Diffing & Shrinking (`iam-shrink diff`)

Compare an existing policy against runtime permissions to calculate attack surface reduction:

```bash
iam-shrink diff existing_role.json captured_policy.json
```

---

### 6. Security Linter (`iam-shrink lint`)

Detect privilege escalation paths and wildcard vulnerabilities:

```bash
iam-shrink lint policy.json
```

---

### 7. Kubernetes IRSA Deployment Spec (`iam-shrink k8s`)

Generate a Kubernetes Deployment YAML containing an `iam-shrink` telemetry sidecar and IRSA environment variables:

```bash
iam-shrink k8s manifest --deployment=auth-service --proxy > k8s-telemetry.yaml
```

---

### 8. VS Code Companion Setup (`iam-shrink init-vscode`)

Initialize `.vscode/tasks.json` in the current repository to run tests through `iam-shrink` with a keyboard shortcut:

```bash
iam-shrink init-vscode --test-cmd="go test ./..."
```

---

### 9. Daemon / Session Mode (`iam-shrink session`)

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
