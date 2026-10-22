#!/bin/sh
# shellcheck disable=SC2154
# HashiCorp Vault AWS Secret Engine Role Configuration:
vault write aws/roles/least-privilege-app \
    credential_type=assumed_role \
    role_arn="arn:aws:iam::${var.account_id}:role/AppRole" \
    policy_document=@- <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPolicyActions",
      "Effect": "Allow",
      "Action": [
        "dynamodb:Query",
        "kms:Decrypt",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
