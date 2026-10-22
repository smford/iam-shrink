data "aws_iam_policy_document" "generated" {
  statement {
    sid    = "Dynamodb"
    effect = "Allow"
    actions = [
      "dynamodb:Query",
    ]
    resources = [
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}",
      "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}/index/*",
    ]
  }

  statement {
    sid    = "Kms"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      "arn:aws:kms:${var.region}:${var.account_id}:key/${var.key_id}",
    ]
  }

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
variable "account_id" {
  type        = string
  description = "Auto-extracted IAM ARN placeholder"
}

variable "bucket_name" {
  type        = string
  description = "Auto-extracted IAM ARN placeholder"
}

variable "key_id" {
  type        = string
  description = "Auto-extracted IAM ARN placeholder"
}

variable "region" {
  type        = string
  description = "Auto-extracted IAM ARN placeholder"
}

variable "table_name" {
  type        = string
  description = "Auto-extracted IAM ARN placeholder"
}
