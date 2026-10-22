data "aws_iam_policy_document" "generated" {
  statement {
    sid    = "Dynamodb"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
    ]
    resources = [
      "arn:aws:dynamodb:us-east-1:123456789012:table/CustomerAuditLogs",
    ]
  }

  statement {
    sid    = "Kms"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = [
      "arn:aws:kms:us-east-1:123456789012:key/b638f291-729a-4c92-b883-937210bcdef0",
    ]
  }

  statement {
    sid    = "S3"
    effect = "Allow"
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::production-data-lake-bucket/reports/2026/financial_q3.csv",
    ]
  }

  statement {
    sid    = "Sqs"
    effect = "Allow"
    actions = [
      "sqs:SendMessage",
    ]
    resources = [
      "arn:aws:sqs:us-east-1:123456789012:order-processing-queue",
    ]
  }
}
