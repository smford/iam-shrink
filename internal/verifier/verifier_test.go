package verifier

import (
	"testing"
)

func TestVerifySubsetSuccess(t *testing.T) {
	baseJSON := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*", "dynamodb:GetItem", "dynamodb:PutItem"],
      "Resource": "*"
    }
  ]
}`)

	targetJSON := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetObject", "dynamodb:GetItem"],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}`)

	res, err := VerifyPolicyBytes(baseJSON, targetJSON)
	if err != nil {
		t.Fatalf("VerifyPolicyBytes failed: %v", err)
	}

	if !res.IsSubset {
		t.Errorf("Expected target to be recognized as a strict subset, got expansions: %+v", res.Expansions)
	}
}

func TestVerifySubsetDetectsExpansion(t *testing.T) {
	baseJSON := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}`)

	// Target policy adds sqs:SendMessage which is NOT in base!
	targetJSON := []byte(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "sqs:SendMessage"],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}`)

	res, err := VerifyPolicyBytes(baseJSON, targetJSON)
	if err != nil {
		t.Fatalf("VerifyPolicyBytes failed: %v", err)
	}

	if res.IsSubset {
		t.Errorf("Expected verification to fail due to unauthorized sqs:SendMessage expansion")
	}

	if len(res.Expansions) != 1 || res.Expansions[0].Action != "sqs:sendmessage" {
		t.Errorf("Unexpected expansions: %+v", res.Expansions)
	}
}
