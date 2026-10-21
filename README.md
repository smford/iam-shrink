# iam-shrink

**Local-to-Least-Privilege AWS IAM Policy Generator**

`iam-shrink` is a single-binary, zero-CGO CLI tool that intercepts AWS SDK and AWS CLI operations during local test suites, scripts, or deployment dry runs via AWS Client-Side Monitoring (CSM) and local HTTP/HTTPS proxying, translating captured API calls into exact, least-privilege IAM policies formatted in **Terraform HCL**, **AWS CDK (TypeScript)**, **Pulumi (TypeScript)**, **CloudFormation**, or **IAM Policy JSON**.

---

## Key Features

* **Zero-CGO & Single Binary:** Compiles with `CGO_ENABLED=0` across Linux, macOS, and Windows.
* **Dual Interception Engine:**
  * **AWS CSM (Client-Side Monitoring):** Built-in UDP listener (`127.0.0.1`) capturing SDK execution with trailing packet drain.
  * **HTTP/HTTPS Interception Proxy (`--proxy`):** Generates an ephemeral Root CA to inspect requests on-the-fly and extract exact runtime ARNs (e.g. S3 bucket/keys, DynamoDB tables, KMS keys) instead of placeholders.
* **Multi-Format Synthesis:**
  * **Terraform HCL:** `data "aws_iam_policy_document"` with optional companion variable blocks (`--emit-vars`).
  * **AWS CDK:** TypeScript `new iam.PolicyStatement({ ... })`.
  * **Pulumi:** TypeScript `aws.iam.getPolicyDocumentOutput({ ... })`.
  * **CloudFormation:** YAML/JSON `AWS::IAM::ManagedPolicy`.
  * **IAM Policy JSON:** Canonical AWS IAM policy format.
* **Separation of Duties (`--split-by-access-level`):** Segregates statements by access level (`Read`, `Write`, `List`, `Tagging`, `Permissions`).
* **Policy Diffing & Shrinking (`iam-shrink diff`):** Compares live or existing IAM policies against runtime traffic, pinpointing unused permissions to prune and calculating overall attack surface reduction.
* **Security Linter (`iam-shrink lint`):** Analyzes IAM policies for privilege escalation risks (e.g. unconstrained `iam:PassRole`, `iam:CreatePolicyVersion`, wildcards).
* **Daemon / Session Mode (`iam-shrink session`):** Long-running background sessions for Docker Compose, integration clusters, or local dev servers.

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
| - Trailing packet drain (200ms post-exit)                            |
+----------------------------------------------------------------------+
                                   |
                                   v
+----------------------------------------------------------------------+
| Translation & ARN Synthesizer Engine                                 |
| - Maps SDK (Service, Api) -> Canonical IAM Actions                   |
| - Classifies Access Levels (Read/Write/List/Tagging/Permissions)     |
| - Resolves AWS edge cases (s3:ListObjectsV2 -> s3:ListBucket)        |
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
  iam-shrink explain <service>:<api>
  iam-shrink export-mappings [flags]
  iam-shrink diff <existing-policy.json> [captured-policy.json]
  iam-shrink lint <policy.json>
  iam-shrink session <start|status|dump|stop> [flags]
  iam-shrink version
```

---

### 1. Generating Policies (`iam-shrink run`)

Wrap any command after `--`:

```bash
# Output Terraform HCL
iam-shrink run --format=tf -- go test ./...

# Output Terraform with strict parameterized ARNs and companion variable definitions
iam-shrink run --format=tf --strict-arns --emit-vars -- go test ./...

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
| `--out` | `""` | Output file path (if omitted, writes to stdout) |
| `--include-failed` | `true` | Include API calls that failed (e.g., 403 `AccessDenied`) |
| `--group-by-service` | `true` | Group IAM statements by AWS service prefix |
| `--split-by-access-level` | `false` | Group statements by access level (`Read`, `Write`, `List`, `Tagging`, `Permissions`) |
| `--strict-arns` | `false` | Generate parameterized ARN placeholders instead of `*` |
| `--emit-vars` | `false` | Emit companion Terraform variable definitions for ARNs (with `--format=tf`) |
| `--proxy` | `false` | Enable local HTTP/HTTPS proxy to capture exact concrete ARNs |
| `--lint` | `false` | Run automated security linter checks on generated statements |
| `--diff-against` | `""` | Compare generated policy against an existing policy JSON file |
| `--mappings` | `""` | Path to custom YAML file to extend or override default mappings |

---

### 2. Inspecting API Mappings (`iam-shrink explain`)

Look up canonical IAM actions, access levels, required resource ARNs, and dependent permissions:

```bash
iam-shrink explain s3:ListObjectsV2
```
Output:
```text
Service:            S3 (IAM Prefix: s3)
SDK API:            ListObjectsV2
IAM Actions:        s3:ListBucket
Access Level:       List
Resource ARNs:
  - arn:aws:s3:::${var.bucket_name}
Dependent Actions:  (none)
Fallback:           false (canonical mapping)
```

Look up dependent permissions (e.g. KMS decryption for Secrets Manager):
```bash
iam-shrink explain secretsmanager:GetSecretValue
```
Output:
```text
Service:            SecretsManager (IAM Prefix: secretsmanager)
SDK API:            GetSecretValue
IAM Actions:        secretsmanager:GetSecretValue
Access Level:       Read
Resource ARNs:
  - arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.secret_name}
Dependent Actions:  kms:Decrypt
Fallback:           false (canonical mapping)
```

---

### 3. Policy Diffing & Shrinking (`iam-shrink diff`)

Compare an existing over-privileged policy against observed runtime traffic to find unused permissions that can be safely eliminated:

```bash
iam-shrink diff existing_role.json captured_policy.json
```
Output:
```text
============================================================
                  IAM Policy Diff & Shrink Report           
============================================================

Existing Policy Actions: 18
Captured Runtime Actions: 4
Retained (Used) Actions:  4
Unused (Prunable) Actions:14
Missing (Needed) Actions: 0
Privilege Attack Surface Reduction: 77.8%

--- UNUSED PERMISSIONS (Recommended to Prune) ---
  - dynamodb:DeleteTable
  - dynamodb:Scan
  - s3:DeleteBucket
  - s3:PutBucketPolicy
  - sqs:*
  ...
```

---

### 4. Policy Linter & Risk Analyzer (`iam-shrink lint`)

Detect privilege escalation paths and wildcard vulnerabilities:

```bash
iam-shrink lint policy.json
```
Output:
```text
============================================================
          IAM Security Linter Report (2 issues found)      
============================================================

[HIGH] #1: PRIV_ESC_PASS_ROLE (iam:PassRole)
  Resource:       *
  Description:    iam:PassRole granted on wildcard resource '*'. Allows passing any privileged role to a compute resource.
  Recommendation: Constrain Resource to the specific role ARN(s) needed.

[MEDIUM] #2: SERVICE_WILDCARD_ACTION (s3:*)
  Resource:       *
  Description:    Service-level wildcard 's3:*' grants all current and future APIs of this service.
  Recommendation: Scope down permissions to individual APIs invoked by the application.
```

---

### 5. Daemon / Session Mode (`iam-shrink session`)

Ideal for long-running processes, Docker Compose environments, or multi-step execution:

```bash
# 1. Start background session
iam-shrink session start

# 2. Configure your terminal session (or container env)
export AWS_CSM_ENABLED=true
export AWS_CSM_PORT=34567
export AWS_CSM_HOST=127.0.0.1

# 3. Run your tests or development server
docker compose up -d
pytest tests/integration/

# 4. Check session status
iam-shrink session status

# 5. Dump the synthesized policy anytime
iam-shrink session dump --format=tf

# 6. Terminate session
iam-shrink session stop
```

---

### 6. Custom Mappings & Overrides (`iam-shrink export-mappings`)

Export the default database:
```bash
iam-shrink export-mappings > custom_mappings.yaml
```

Override or extend actions in YAML:
```yaml
version: 1
mappings:
  - service: S3
    api: ListObjectsV2
    actions:
      - s3:ListBucket
    resource_arns:
      - "arn:aws:s3:::my-special-bucket"
```

Apply override:
```bash
iam-shrink run --mappings=custom_mappings.yaml --format=tf -- go test ./...
```

---

## Output Examples

### Pulumi TypeScript (`--format=pulumi`)
```typescript
import * as aws from "@pulumi/aws";

export const generatedPolicy = aws.iam.getPolicyDocumentOutput({
    statements: [
        {
            sid: "Dynamodb",
            effect: "Allow",
            actions: [
                "dynamodb:PutItem",
            ],
            resources: [
                "*",
            ],
        },
        {
            sid: "S3",
            effect: "Allow",
            actions: [
                "s3:ListBucket",
            ],
            resources: [
                "*",
            ],
        },
    ],
});
```

### Terraform HCL with Companion Variables (`--format=tf --strict-arns --emit-vars`)
```hcl
data "aws_iam_policy_document" "generated" {
  statement {
    sid    = "S3"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${var.bucket_name}",
    ]
  }
}

# Companion Terraform variable definitions:
variable "bucket_name" {
  type        = string
  description = "Auto-extracted IAM ARN placeholder"
}
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
