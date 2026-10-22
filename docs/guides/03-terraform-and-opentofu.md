# Terraform & OpenTofu Workflow Guide

This guide covers how to integrate `iam-shrink` directly into your Terraform and OpenTofu infrastructure-as-code workflows, including **in-place `.tf` file patching** and **runtime ARN resolution via `terraform.tfstate`**.

---

## 1. In-Place Terraform Patching (`iam-shrink patch`)

Copying policies from terminal outputs into `.tf` files by hand is error-prone. `iam-shrink patch` automates this by executing your test suite, generating the minimal policy, and updating your `.tf` file in-place.

### How It Works
1. `iam-shrink` creates an automatic backup copy: `<file>.tf.bak`.
2. It parses the Terraform file and locates the target `data "aws_iam_policy_document"` block.
3. It replaces the old statements with the synthesized least-privilege statements while preserving the rest of your configuration (providers, resources, outputs).

### Usage
```bash
# Execute test suite and update main.tf
iam-shrink patch --file=infrastructure/iam.tf -- pytest tests/
```

### Before & After Diff
```diff
--- infrastructure/iam.tf.bak
+++ infrastructure/iam.tf
@@ -4,8 +4,17 @@
-data "aws_iam_policy_document" "app" {
-  statement {
-    sid       = "WildcardAdmin"
-    effect    = "Allow"
-    actions   = ["*"]
-    resources = ["*"]
-  }
+data "aws_iam_policy_document" "app" {
+  statement {
+    sid       = "Dynamodb"
+    effect    = "Allow"
+    actions   = ["dynamodb:PutItem"]
+    resources = ["arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}"]
+  }
+  statement {
+    sid       = "S3"
+    effect    = "Allow"
+    actions   = ["s3:GetObject"]
+    resources = ["arn:aws:s3:::${var.bucket_name}/*"]
+  }
 }
```

---

## 2. Parameterized Variable Generation (`--emit-vars`)

When generating Terraform HCL from test suites, target ARNs are automatically parameterized with standard Terraform variable interpolation syntax (`${var.account_id}`, `${var.region}`, `${var.bucket_name}`).

Passing `--emit-vars` appends clean companion variable declarations ready to paste into `variables.tf`:

```bash
iam-shrink run --format=tf --strict-arns --emit-vars -- go test ./...
```

*Output:*
```hcl
data "aws_iam_policy_document" "generated" {
  statement {
    sid    = "S3"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${var.bucket_name}",
      "arn:aws:s3:::${var.bucket_name}/*",
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

## 3. Resolving Variables via `terraform.tfstate` (`iam-shrink state`)

When preparing to apply policies to real environments, you often need concrete ARNs substituted into parameterized policies without hardcoding them manually.

`iam-shrink state` parses your local or pulled `terraform.tfstate`, inspects deployed cloud resources, and substitutes actual ARNs:

### Step 1: Pull Current Remote State
```bash
terraform state pull > terraform.tfstate
# Or with OpenTofu:
tofu state pull > terraform.tfstate
```

### Step 2: Substitute ARNs with `iam-shrink state`
```bash
iam-shrink state terraform.tfstate candidate_policy.json
```

*Example Transformation:*
```text
Before: arn:aws:s3:::${var.bucket_name}/*
After:  arn:aws:s3:::production-order-archive-us-east-1/*
```

---

## 4. Capturing Permissions for Terraform Plan / Apply

You can also use `iam-shrink` to capture the exact AWS permissions required by Terraform itself when running infrastructure deployments:

```bash
# Intercept all AWS API calls made during terraform plan
iam-shrink run --format=tf --strict-arns -- terraform plan

# Intercept calls made during OpenTofu plan
iam-shrink run --format=tf --strict-arns -- tofu plan
```

This creates an exact CI/CD deployment execution role policy containing only the AWS actions Terraform needs to manage your specific resources.
