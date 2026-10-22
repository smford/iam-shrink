provider "aws" {
  region = "us-east-1"
}

# Insecure placeholder policy containing broad wildcards:
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


resource "aws_iam_policy" "app_exec" {
  name   = "microservice-execution-policy"
  policy = data.aws_iam_policy_document.app_policy.json
}
