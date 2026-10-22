# Language & SDK Integration Playbooks

This guide provides practical setup instructions, code snippets, and configuration tips for running `iam-shrink` across **Python**, **Node.js/TypeScript**, **Go**, **Java**, and **Dockerized environments**.

---

## 1. Python (Boto3 & Pytest)

Official AWS Boto3 (`botocore`) includes native Client-Side Monitoring support.

### Zero-Config Execution
Simply wrap your pytest command:
```bash
iam-shrink run --format=tf --strict-arns -- pytest tests/
```
`iam-shrink` sets `AWS_CSM_ENABLED=true` and `AWS_CSM_PORT=<loopback_port>` in the subshell. Boto3 detects these environment variables automatically.

### Handling Mocks (`moto` / `unittest.mock`)
If your test suite uses `moto` in decorator mode (`@mock_aws` or `@mock_s3`):
* `moto` intercepts requests in-memory before the network layer. In standard configurations, Boto3's internal CSM client fires during client initialization and method dispatch *before* handlers respond.
* To capture exact concrete ARNs when using mocks or local emulators (e.g., LocalStack), use `--proxy`:
```bash
iam-shrink run --proxy --format=tf -- pytest tests/
```

### Optional: Explicit Boto3 CSM Verification Helper
To verify that Boto3 is broadcasting CSM events in your tests, add this helper to `conftest.py`:

```python
# conftest.py
import os
import pytest

@pytest.fixture(autouse=True)
def verify_iam_shrink_telemetry():
    """Confirms iam-shrink telemetry injection is active during tests."""
    csm_enabled = os.environ.get("AWS_CSM_ENABLED", "false").lower() == "true"
    csm_port = os.environ.get("AWS_CSM_PORT")
    if csm_enabled and csm_port:
        print(f"\n[iam-shrink] Telemetry active on 127.0.0.1:{csm_port}")
```

---

## 2. Node.js & TypeScript (AWS SDK v3 & Jest / Vitest)

AWS SDK for JavaScript v3 (`@aws-sdk/client-*`) natively broadcasts CSM datagrams over loopback UDP.

### Zero-Config Execution
```bash
# Run Jest
iam-shrink run --format=cdk -- npm test

# Run Vitest
iam-shrink run --format=tf -- npx vitest run
```

### AWS SDK Client Initialization
No code modifications are required if using default client construction:

```typescript
// orderService.ts
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";

// Automatically picks up AWS_CSM_ENABLED and AWS_CSM_PORT from process.env
const s3 = new S3Client({ region: "us-east-1" });
const ddb = new DynamoDBClient({ region: "us-east-1" });

export async function processOrder(orderId: string) {
  await ddb.send(new QueryCommand({
    TableName: "Orders",
    KeyConditionExpression: "OrderId = :id",
    ExpressionAttributeValues: { ":id": { S: orderId } },
  }));

  await s3.send(new GetObjectCommand({
    Bucket: "company-invoices",
    Key: `invoices/${orderId}.pdf`,
  }));
}
```

---

## 3. Go (aws-sdk-go-v2)

The Go AWS SDK automatically loads CSM settings during configuration loading:

### Execution
```bash
iam-shrink run --format=tf --strict-arns --emit-vars -- go test -v ./...
```

### Go Application Setup
Ensure your application initializes the AWS config using `config.LoadDefaultConfig`:

```go
package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func NewS3Client(ctx context.Context) (*s3.Client, error) {
	// Automatically checks AWS_CSM_ENABLED, AWS_CSM_PORT, and AWS_CSM_HOST
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}
```

---

## 4. Java (AWS SDK for Java 2.x)

The AWS SDK for Java 2.x includes Client-Side Monitoring out-of-the-box.

### Execution with Maven or Gradle
```bash
# Maven
iam-shrink run --format=tf -- mvn test

# Gradle
iam-shrink run --format=tf -- ./gradlew test
```

### Gradle JVM System Properties Passing
In `build.gradle`, ensure environment variables are forwarded to the test JVM:

```groovy
// build.gradle
test {
    environment "AWS_CSM_ENABLED", System.getenv("AWS_CSM_ENABLED") ?: "false"
    environment "AWS_CSM_PORT", System.getenv("AWS_CSM_PORT") ?: ""
    environment "AWS_CSM_HOST", System.getenv("AWS_CSM_HOST") ?: "127.0.0.1"
}
```

---

## 5. Docker Compose & Multi-Container Microservices

When testing distributed applications across multiple Docker Compose services, use **Session Mode**:

### Step 1: Start the Background Daemon on the Host
```bash
iam-shrink session start --port=31000
```

### Step 2: Configure `docker-compose.yml`
Pass loopback networking so containers broadcast UDP datagrams to the host:

```yaml
version: '3.8'

services:
  order-service:
    build: ./services/order
    environment:
      - AWS_CSM_ENABLED=true
      - AWS_CSM_PORT=31000
      - AWS_CSM_HOST=host.docker.internal
    extra_hosts:
      - "host.docker.internal:host-gateway"

  payment-service:
    build: ./services/payment
    environment:
      - AWS_CSM_ENABLED=true
      - AWS_CSM_PORT=31000
      - AWS_CSM_HOST=host.docker.internal
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

### Step 3: Run Integration Tests
```bash
docker compose up -d
pytest tests/e2e/
docker compose down
```

### Step 4: Dump Aggregated Policy Across All Services
```bash
iam-shrink session dump --format=tf --strict-arns --out=microservices_iam.tf
iam-shrink session stop
```
