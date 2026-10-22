---
title: 03. In-Place Terraform Patching
description: Worked tutorial 03. In-Place Terraform Patching for iam-shrink
---

[← Documentation Hub](../index.md)

# Example 03: In-Place Terraform Patching (`iam-shrink patch`)

This worked example demonstrates how `iam-shrink` can automatically locate and update an insecure `data "aws_iam_policy_document"` block directly inside a Terraform `.tf` file in-place, while automatically creating a safe `.bak` backup.

---

## What This Example Contains

| File | Purpose |
|---|---|
| [`main.tf`](main.tf) | Original Terraform file containing an insecure `*` wildcard policy. |
| [`mock_service.go`](mock_service.go) | Standalone application simulating runtime AWS S3 and DynamoDB operations. |
| [`main.tf.patched`](main.tf.patched) | The resulting Terraform file after in-place replacement by `iam-shrink patch`. |
| [`run.sh`](run.sh) | Runnable shell script executing the patch and displaying the diff. |

---

## Before and After Comparison

### Before (`main.tf` - Overprivileged Wildcard):
```hcl
data "aws_iam_policy_document" "app_policy" {
  statement {
    sid       = "WildcardAdminAccess"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
```

### After (`main.tf.patched` - Automatically Patched):
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
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::${var.bucket_name}/*",
    ]
  }
}
```

---

## Running the Example

Run the automated script:
```bash
./examples/03-terraform-patching/run.sh
```

Or run manually:
```bash
iam-shrink patch --file=examples/03-terraform-patching/main.tf -- go run examples/03-terraform-patching/mock_service.go
```

---

**Navigation:** [← Previous: 02. CloudTrail Ingestion](02-cloudtrail-ingest.md) | [Next: 04. CI/CD Quality Gate →](04-ci-cd-quality-gate.md)
