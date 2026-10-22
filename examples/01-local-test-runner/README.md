# Example 01: Local Test Suite Telemetry & Policy Generation

This example demonstrates how `iam-shrink` observes your existing local test suite and synthesizes exact, minimal AWS IAM policies without requiring production cloud permissions or complicated mock setups.

---

## The Problem

When developers write microservices that interact with AWS (e.g. S3, DynamoDB, KMS, SQS), writing IAM policies manually usually leads to two outcomes:
1. **Over-permissive wildcards (`*`)**: Security risks, compliance violations, and excessive privileges.
2. **Slow, manual trial-and-error**: Guessing API names, missing secondary permissions (e.g. `s3:ListBucket` needed alongside `s3:GetObject`, or `kms:Decrypt` needed for encrypted tables).

---

## How iam-shrink Solves It

`iam-shrink` uses the AWS SDK's native **Client-Side Monitoring (CSM)** feature.
- When you execute `iam-shrink run -- <your-test-command>`, `iam-shrink` automatically binds an ephemeral UDP socket on `127.0.0.1` and injects `AWS_CSM_PORT=...` and `AWS_CSM_ENABLED=true` into the child process.
- All official AWS SDKs (Go, Python/Boto3, Node.js, Java, Rust) automatically stream lightweight UDP telemetry datagrams for every outbound API call.
- `iam-shrink` intercepts these calls, translates SDK calls to IAM actions, resolves resource requirements, and outputs a clean, synthesized policy.

---

## Project Structure

* `app.go`: Sample application logic reading S3, querying DynamoDB, and decrypting KMS.
* `app_test.go`: Unit test exercising application pathways.
* `run.sh`: Automated script executing `iam-shrink` across multiple output formats.

---

## Running the Example

Run the helper script:

```bash
./run.sh
```

Or run any of the individual commands below:

### 1. Synthesize Standard JSON IAM Policy
```bash
iam-shrink run -- go test -v ./...
```

### 2. Synthesize Terraform HCL with Parameterized ARNs and Variables
```bash
iam-shrink run --format=tf --strict-arns --emit-vars -- go test -v ./...
```

### 3. Synthesize AWS CDK (TypeScript) Construct
```bash
iam-shrink run --format=cdk -- go test -v ./...
```

### 4. Synthesize CloudFormation (JSON / YAML)
```bash
iam-shrink run --format=cfn -- go test -v ./...
```

### 5. Multi-Cloud / Cross-Platform Target (e.g. GCP Custom Role)
```bash
iam-shrink run --format=gcp -- go test -v ./...
```
