# Example 03: In-Place Terraform Policy Patching

This example demonstrates how `iam-shrink patch` directly updates existing Terraform `.tf` files in-place with synthesized least-privilege IAM policies, while automatically creating a `.bak` backup file for rollback safety.

---

## The Problem

When developers need to tighten IAM policies in infrastructure-as-code repositories:
1. They have to capture runtime calls.
2. Convert them into Terraform `aws_iam_policy_document` syntax.
3. Locate the corresponding `.tf` file and manually copy-paste statements into blocks, risking syntax errors or broken resource references.

---

## How iam-shrink Solves It

The `iam-shrink patch` command:
1. Runs your command or test suite under CSM telemetry.
2. Locates the targeted `data "aws_iam_policy_document"` block in your specified `.tf` file.
3. Automatically creates a backup (`<file>.tf.bak`).
4. Replaces the wildcard policy with the synthesized least-privilege statements while preserving the rest of your Terraform definitions.

---

## Files in this Directory

* `main.tf`: Initial Terraform file containing an over-permissive wildcard IAM policy.
* `mock_service.go`: Microservice simulating S3 and DynamoDB API calls.
* `run.sh`: Automated demo script executing `iam-shrink patch` and displaying the diff.

---

## Usage

Run the sample script:

```bash
./run.sh
```

Or run directly from the command line:

```bash
# Patch main.tf in-place using a test command
iam-shrink patch --file=main.tf -- go test -v ./...

# Target a specific policy document block if multiple exist in the file:
iam-shrink patch --file=main.tf --target=app_policy -- go run mock_service.go
```
