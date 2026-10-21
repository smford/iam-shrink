# iam-shrink

**Local-to-Least-Privilege AWS IAM Policy Generator**

`iam-shrink` is a single-binary, zero-CGO CLI tool that intercepts AWS SDK and AWS CLI operations during local test suites, scripts, or deployment dry runs via AWS Client-Side Monitoring (CSM), translating captured API calls into exact, least-privilege IAM policies formatted in **Terraform HCL**, **AWS CDK (TypeScript)**, or **IAM Policy JSON**.

---

## The Problem

Cloud engineers frequently over-privilege IAM roles (`Action: "*"`) because identifying the precise IAM actions and ARN patterns needed for an application is manual, error-prone, and frustrating. Furthermore, SDK method names often differ from canonical IAM actions (e.g., calling `s3.ListObjectsV2()` requires the `s3:ListBucket` IAM action).

`iam-shrink` eliminates this guesswork by observing real application execution and emitting tailored, deterministic policies.

---

## How It Works

```
                                  +------------------------------------+
                                  |            iam-shrink              |
                                  |                                    |
                                  | 1. Starts UDP listener on 127.0.0.1|
                                  +-----------------+------------------+
                                                    | Spawns with CSM env:
                                                    | AWS_CSM_ENABLED=true
                                                    | AWS_CSM_PORT=<port>
                                                    v
                                  +------------------------------------+
                                  |          Target Command            |
                                  | (e.g. go test, python, terraform)  |
                                  +-----------------+------------------+
                                                    |
                                                    | UDP Datagrams (CSM)
                                                    v
+----------------------------------------------------------------------+
| iam-shrink CSM Collector                                             |
| - Captures ApiCall & ApiCallAttempt events                           |
| - Drains trailing packets (200ms post-exit)                          |
+----------------------------------------------------------------------+
                                   |
                                   v
+----------------------------------------------------------------------+
| Translation & ARN Synthesizer Engine                                 |
| - Maps SDK (Service, Api) -> Canonical IAM Actions                   |
| - Handles AWS edge cases (s3:ListObjectsV2 -> s3:ListBucket)        |
| - Deterministic alphabetical sorting & deduplication                 |
+----------------------------------------------------------------------+
                                   |
                                   v
+----------------------------------------------------------------------+
| Formatter (Terraform HCL / AWS CDK / IAM JSON)                       |
+----------------------------------------------------------------------+
```

1. **Lightweight Local Telemetry:** Binds an ephemeral UDP listener on `127.0.0.1` using AWS Client-Side Monitoring (built into official AWS SDKs and AWS CLI).
2. **Transparent Execution:** Injects `AWS_CSM_ENABLED=true`, `AWS_CSM_PORT=<port>`, and `AWS_CSM_HOST=127.0.0.1` into the target command environment.
3. **Telemetry Capture:** Ingests `ApiCall` and `ApiCallAttempt` events, recording AWS services, APIs invoked, and HTTP response codes.
4. **Clean Stdout Guarantee:** If writing policy to `stdout`, child process stdout is cleanly routed to `stderr` to ensure generated policy syntax is never corrupted.
5. **Accurate Translation:** Maps SDK methods to canonical IAM actions, handles edge cases (e.g., S3 `ListObjectsV2` -> `s3:ListBucket`, KMS `Decrypt`, DynamoDB `Query`), synthesizes ARN patterns, and applies fallback heuristics for unmapped calls.
6. **Deterministic Output:** Statement actions and resources are sorted alphabetically to prevent git diff noise across test runs.

---

## Installation

### From Source
Requires Go 1.23+:
```bash
git clone https://github.com/smford/iam-shrink.git
cd iam-shrink
make build
# Binary created at ./bin/iam-shrink
```

### Direct Go Install
```bash
go install github.com/smford/iam-shrink/cmd/iam-shrink@latest
```

---

## Usage

### 1. Generating Policies (`iam-shrink run`)

Wrap any command after `--`:

```bash
# Output Terraform HCL
iam-shrink run --format=tf -- go test ./...

# Output IAM JSON
iam-shrink run --format=json -- python deploy_dryrun.py

# Output AWS CDK TypeScript to a file
iam-shrink run --format=cdk --out=iam_policy.ts -- npm test

# Generate strict parameterized resource ARNs instead of '*'
iam-shrink run --format=tf --strict-arns -- go test -v ./integration/...
```

#### CLI Flags for `run`

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `json` | Output format: `json`, `tf` (Terraform HCL), or `cdk` (AWS CDK TypeScript) |
| `--out` | `""` | Output file path (if omitted, writes to stdout) |
| `--include-failed` | `true` | Include API calls that failed (e.g., 403 `AccessDenied`), aiding permission discovery |
| `--group-by-service` | `true` | Group policy statements by AWS service prefix |
| `--strict-arns` | `false` | Generate parameterized ARN placeholders (e.g. `arn:aws:s3:::${var.bucket_name}/*`) instead of `*` |
| `--mappings` | `""` | Path to custom YAML file to extend or override default mappings |

---

### 2. Inspecting API Mappings (`iam-shrink explain`)

Look up canonical IAM actions, resource ARN templates, and dependent actions for any AWS SDK method:

```bash
iam-shrink explain s3:ListObjectsV2
```

Output:
```text
Service:            S3 (IAM Prefix: s3)
SDK API:            ListObjectsV2
IAM Actions:        s3:ListBucket
Resource ARNs:
  - arn:aws:s3:::${var.bucket_name}
Dependent Actions:  (none)
Fallback:           false (canonical mapping)
```

Look up dependent actions (e.g., KMS decryption for Secrets Manager):
```bash
iam-shrink explain secretsmanager:GetSecretValue
```

Output:
```text
Service:            SecretsManager (IAM Prefix: secretsmanager)
SDK API:            GetSecretValue
IAM Actions:        secretsmanager:GetSecretValue
Resource ARNs:
  - arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.secret_name}
Dependent Actions:  kms:Decrypt
Fallback:           false (canonical mapping)
```

---

### 3. Custom Mappings & Overrides (`iam-shrink export-mappings`)

Dump the curated mapping database to YAML:

```bash
iam-shrink export-mappings > custom_mappings.yaml
```

Customize or add new mappings:
```yaml
version: 1
mappings:
  - service: S3
    api: ListObjectsV2
    actions:
      - s3:ListBucket
    resource_arns:
      - "arn:aws:s3:::my-special-bucket"
  - service: InternalService
    api: CustomOperation
    actions:
      - internal:CustomOperation
    resource_arns:
      - "*"
```

Provide the override to `iam-shrink`:
```bash
iam-shrink run --mappings=custom_mappings.yaml --format=tf -- go test ./...
```

---

## Output Examples

### Terraform HCL (`--format=tf`)

```hcl
data "aws_iam_policy_document" "generated" {
  statement {
    sid    = "Dynamodb"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
    ]
    resources = [
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}",
    ]
  }

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
```

### AWS CDK TypeScript (`--format=cdk`)

```typescript
import * as iam from 'aws-cdk-lib/aws-iam';

export const generatedStatements = [
  new iam.PolicyStatement({
    sid: 'Dynamodb',
    effect: iam.Effect.ALLOW,
    actions: [
      'dynamodb:PutItem',
    ],
    resources: [
      '*',
    ],
  }),
  new iam.PolicyStatement({
    sid: 'S3',
    effect: iam.Effect.ALLOW,
    actions: [
      's3:ListBucket',
    ],
    resources: [
      '*',
    ],
  }),
];
```

### IAM JSON (`--format=json`)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Dynamodb",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Sid": "S3",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
```

---

## Curated Service Coverage

`iam-shrink` includes embedded offline mappings for common AWS services:
- **S3** (Object operations, bucket listings, multipart uploads, tagging)
- **DynamoDB** (Items, batch operations, queries, scans, transactions, tables)
- **SQS** (Send, receive, delete, purge, queue attributes)
- **SNS** (Publish, subscriptions, topics)
- **Lambda** (Invocation, function code/configuration, permissions)
- **KMS** (Decrypt, encrypt, data keys, grants, aliases)
- **Secrets Manager** (Secrets retrieval, rotation, encryption dependencies)
- **SSM Parameter Store** (Parameters by path, KMS decryption dependencies)
- **STS** (Caller identity, AssumeRole, federation)
- **CloudWatch Logs** (Log groups, log streams, event ingestion)
- **EventBridge / Events** (Rules, buses, targets)
- **ECR** (Token authorization, batch image operations, layer upload)
- **ECS** (Task execution, service management, definition registration)
- **EC2** (Instances, security groups, VPCs, subnets)
- **IAM** (Roles, policies, user operations)
- **CloudFormation** (Stack operations, events, deployments)

Any unmapped AWS service automatically falls back to `<service>:<Api>` with an inline comment flag.

---

## Development & Testing

Run all unit and end-to-end integration tests:
```bash
make test
```

Run linter / static analysis:
```bash
make vet
```

Compile with zero-CGO:
```bash
make build
```

---

## License

MIT
