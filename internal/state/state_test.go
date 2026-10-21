package state

import (
	"strings"
	"testing"
)

func sampleTFState() []byte {
	return []byte(`{
  "version": 4,
  "terraform_version": "1.9.0",
  "resources": [
    {
      "type": "aws_s3_bucket",
      "name": "assets",
      "instances": [
        {
          "attributes": {
            "arn": "arn:aws:s3:::my-production-assets-bucket",
            "bucket": "my-production-assets-bucket"
          }
        }
      ]
    },
    {
      "type": "aws_dynamodb_table",
      "name": "users",
      "instances": [
        {
          "attributes": {
            "arn": "arn:aws:dynamodb:us-east-1:123456789012:table/production-users",
            "name": "production-users"
          }
        }
      ]
    }
  ]
}`)
}

func TestResolvePolicyWithState(t *testing.T) {
	policyWithPlaceholders := `
data "aws_iam_policy_document" "generated" {
  statement {
    actions = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.bucket_name}"]
  }
  statement {
    actions = ["dynamodb:PutItem"]
    resources = ["arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}"]
  }
}
`

	resolved, count, err := ResolvePolicyWithState(policyWithPlaceholders, sampleTFState())
	if err != nil {
		t.Fatalf("ResolvePolicyWithState failed: %v", err)
	}

	if count != 2 {
		t.Errorf("Expected 2 replacements, got %d", count)
	}

	if !strings.Contains(resolved, `"arn:aws:s3:::my-production-assets-bucket"`) {
		t.Errorf("Expected actual S3 bucket ARN in resolved policy, got:\n%s", resolved)
	}

	if !strings.Contains(resolved, `"arn:aws:dynamodb:us-east-1:123456789012:table/production-users"`) {
		t.Errorf("Expected actual DynamoDB table ARN in resolved policy, got:\n%s", resolved)
	}

	if strings.Contains(resolved, "${var.bucket_name}") || strings.Contains(resolved, "${var.table_name}") {
		t.Errorf("Unresolved placeholders remained in policy:\n%s", resolved)
	}
}
