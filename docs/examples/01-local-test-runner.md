---
title: 01. Local Test Suite Telemetry
description: Worked tutorial 01. Local Test Suite Telemetry for iam-shrink
---

[← Documentation Hub](../index.md)

# Example 01: Local Test Suite Telemetry (Go, Python, Node.js)

This worked example demonstrates how `iam-shrink` captures AWS operations in real time from your local test suite—with **zero cloud credentials**, **zero mocks configuration**, and **zero code changes**—and synthesizes production-grade security policies in seconds.

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`app.go`](app.go) & [`app_test.go`](app_test.go) | Standard Go application test suite calling DynamoDB, KMS, and S3. |
| [`test_app.py`](test_app.py) | Python test suite (`pytest` / `unittest`) calling the same AWS services. |
| [`app.test.js`](app.test.js) | Node.js integration test (`node` / `jest`) demonstrating JavaScript SDK telemetry. |
| [`expected_policy.json`](expected_policy.json) | The exact IAM JSON policy synthesized by `iam-shrink run`. |
| [`expected_policy.tf`](expected_policy.tf) | Terraform HCL with strict ARNs and variable definitions. |
| [`expected_policy.ts`](expected_policy.ts) | AWS CDK TypeScript construct synthesized from the same run. |
| [`expected_policy_gcp.yaml`](expected_policy_gcp.yaml) | Equivalent Google Cloud IAM Custom Role mapping. |
| [`run.sh`](run.sh) | Runnable shell script executing Go, Python, and Node.js examples. |

---

## How It Works

1. When you prefix any test command with `iam-shrink run -- <cmd>`, `iam-shrink` spawns a high-speed loopback UDP daemon on `127.0.0.1`.
2. It injects environment variables (`AWS_CSM_ENABLED=true`, `AWS_CSM_PORT=<ephemeral_port>`) into the test runner's environment.
3. Every official AWS SDK (Go, Python/Boto3, Node.js `@aws-sdk`, Java, .NET) natively emits microsecond telemetry datagrams for every API call made.
4. When your test finishes, `iam-shrink` correlates the calls, looks up IAM permissions in its embedded database, and generates exact policies.

---

## Running the Example

Run all languages with the automated script:
```bash
./examples/01-local-test-runner/run.sh
```

Or run any language directly:

### Go (`go test`)
```bash
# Generate AWS JSON Policy
iam-shrink run -- go test -v ./...

# Generate Terraform HCL with strict ARNs and companion variable definitions
iam-shrink run --format=tf --strict-arns --emit-vars -- go test -v ./...
```

### Python (`pytest` or `python3`)
```bash
iam-shrink run --format=tf --strict-arns -- pytest test_app.py
```

### Node.js (`jest` or `node`)
```bash
iam-shrink run --format=cdk -- node app.test.js
```

### Cross-Cloud (GCP IAM Custom Role)
```bash
iam-shrink run --format=gcp -- pytest test_app.py
```

---

## Pre-Committed Output Samples

* View [expected_policy.tf](expected_policy.tf) to inspect the synthesized Terraform HCL.
* View [expected_policy.json](expected_policy.json) to inspect the standard AWS JSON policy.
* View [expected_policy.ts](expected_policy.ts) to inspect the AWS CDK TypeScript statements.
* View [expected_policy_gcp.yaml](expected_policy_gcp.yaml) to inspect the GCP custom role translation.

---

**Navigation:** [← Previous: Home](../index.md) | [Next: 02. CloudTrail Ingestion →](02-cloudtrail-ingest.md)
