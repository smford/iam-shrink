---
title: Troubleshooting & Frequently Asked Questions (FAQ)
description: Troubleshooting & Frequently Asked Questions (FAQ) for iam-shrink
---

[← Documentation Hub](../index.md)

# Troubleshooting & Frequently Asked Questions (FAQ)

This guide covers common issues, edge cases, and debugging techniques when using `iam-shrink`.

---

## 1. "0 calls captured" or an Empty Policy is Emitted

### Symptoms:
Your test suite runs and passes, but `iam-shrink` prints an empty policy with 0 statements.

### Possible Causes & Solutions:

#### Cause A: AWS CSM is not active in the SDK
* **Explanation:** `iam-shrink` injects `AWS_CSM_ENABLED=true` into the child process. If your test runner spawns an isolated subshell (e.g., a detached subprocess in Python or a custom shell script that unsets environment variables), the SDK will not see `AWS_CSM_ENABLED`.
* **Fix:** Verify environment variables in your test:
  ```python
  import os
  assert os.environ.get("AWS_CSM_ENABLED") == "true"
  ```

#### Cause B: Using an un-instrumented HTTP client or SDK v1
* **Explanation:** AWS SDK v1 (e.g., the legacy Node.js SDK v2 or Go SDK v1) has deprecated or non-standard CSM support.
* **Fix:** Upgrade to official AWS SDK v2/v3 (Go v2, Boto3, `@aws-sdk/client-*`, Java v2). Alternatively, use the HTTP proxy mode (`--proxy`), which intercepts all raw HTTP/HTTPS network traffic regardless of SDK version.

#### Cause C: Mocking libraries intercepting calls before the SDK transport
* **Explanation:** Libraries that monkey-patch high-level classes (e.g. `unittest.mock.patch('boto3.client')`) replace the entire AWS client, preventing the underlying SDK telemetry client from ever firing.
* **Fix:** Mock at the transport layer (e.g., `botocore.endpoint` or use `moto` in server mode / `localstack`) or use `--proxy`.

---

## 2. "Why are target resources `*` instead of exact bucket or table names?"

### Explanation:
This is by design in the official **AWS Client-Side Monitoring (CSM) specification**. AWS SDK CSM UDP datagrams transmit:
* `Service` (e.g. `"S3"`)
* `Api` (e.g. `"GetObject"`)
* `Region` (e.g. `"us-east-1"`)
* `HttpStatusCode` (e.g. `200`)

The AWS SDK protocol **deliberately does not include the target resource ARN or object key** in telemetry datagrams.

### Solutions:
1. **Enable the Interception Proxy (`--proxy`):**
   ```bash
   iam-shrink run --proxy --format=tf -- pytest tests/
   ```
   The local CA proxy inspects incoming HTTP request paths to extract exact bucket names, DynamoDB table names, and KMS key IDs.
2. **Use Parameterized ARNs with Variables (`--strict-arns` + `--emit-vars`):**
   Generates clean placeholders (`arn:aws:s3:::${var.bucket_name}/*`) and companion variable definitions.
3. **Resolve ARNs via `terraform.tfstate` (`iam-shrink state`):**
   Substitutes placeholders with concrete ARNs from deployed resources in your state file.

---

## 3. SSL / Certificate Verification Errors with `--proxy`

### Symptoms:
Tests fail with `SSLError: certificate verify failed` or `DEPTH_ZERO_SELF_SIGNED_CERT`.

### Explanation:
When `--proxy` is enabled, `iam-shrink` creates an ephemeral local Root CA and configures:
* `AWS_CA_BUNDLE`
* `SSL_CERT_FILE`
* `NODE_EXTRA_CA_CERTS`

If your runtime or HTTP client ignores standard SSL environment variables (e.g. older versions of `urllib3` or custom curl commands with `-k` disabled), the connection will fail.

### Solutions:
* Ensure your Python tests use `boto3` or standard `requests` which respect `AWS_CA_BUNDLE` and `SSL_CERT_FILE`.
* In Node.js, ensure `NODE_EXTRA_CA_CERTS` is allowed by Node (Node 14+ supports this natively).

---

## 4. What about Failed API Calls (e.g. 403 Forbidden)?

### Default Behavior:
By default, `iam-shrink` **includes failed calls** (`--include-failed=true`).

*Why?* Developers often write unit tests to verify failure cases (e.g. checking that an unauthorized user gets a 403). Excluding failed calls would omit the exact permissions required by your application during normal runs.

### How to Exclude Failed Calls:
If you want to record only calls that returned HTTP 2xx:
```bash
iam-shrink run --include-failed=false -- pytest tests/
```

---

## 5. Docker Containers Cannot Reach the Loopback Daemon

### Symptoms:
`iam-shrink session` or `run` fails to capture calls when tests run inside a Docker container.

### Explanation:
Inside a container, `127.0.0.1` refers to the container itself, not the host machine where `iam-shrink` is listening.

### Solutions:
1. **Use Host Networking (Linux):**
   ```bash
   docker run --net=host ...
   ```
2. **Use `host.docker.internal` (macOS & Windows):**
   ```bash
   docker run \
     -e AWS_CSM_ENABLED=true \
     -e AWS_CSM_PORT=31000 \
     -e AWS_CSM_HOST=host.docker.internal \
     --add-host host.docker.internal:host-gateway \
     my-test-image
   ```

---

## 6. Policy Exceeds AWS IAM Size Limits

### Quota Limits:
* **Inline Role Policies:** Max **2,048 bytes**
* **Customer Managed Policies:** Max **10,240 bytes**

### Solution:
Use `iam-shrink optimize` to merge shared resource blocks and minify JSON:
```bash
# Check size against AWS quotas
iam-shrink optimize --check policy.json

# Compress policy (typically saves 30-50% in byte size)
iam-shrink optimize --out=compressed_policy.json policy.json
```

---

**Navigation:** [← Previous: Architecture & Telemetry](01-architecture-and-telemetry.md) | [Next: CLI Command Reference →](../reference/cli-reference.md)
