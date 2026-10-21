package optimizer

import (
	"testing"

	"github.com/smford/iam-shrink/internal/render"
)

func TestOptimizeStatementsMergesSharedResources(t *testing.T) {
	stmts := []render.Statement{
		{
			Sid:          "S3First",
			Effect:       "Allow",
			Actions:      []render.ActionItem{{Action: "s3:GetObject"}},
			ResourceARNs: []string{"arn:aws:s3:::my-bucket/*"},
		},
		{
			Sid:          "S3Second",
			Effect:       "Allow",
			Actions:      []render.ActionItem{{Action: "s3:PutObject"}},
			ResourceARNs: []string{"arn:aws:s3:::my-bucket/*"},
		},
	}

	opt := OptimizeStatements(stmts)
	if len(opt) != 1 {
		t.Fatalf("Expected 2 statements with identical resources to merge into 1, got %d", len(opt))
	}

	if len(opt[0].Actions) != 2 {
		t.Errorf("Expected 2 merged actions, got %d: %v", len(opt[0].Actions), opt[0].Actions)
	}
}

func TestOptimizePolicyJSON(t *testing.T) {
	indentJSON := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}`
	res, err := OptimizePolicyJSON(indentJSON)
	if err != nil {
		t.Fatalf("OptimizePolicyJSON failed: %v", err)
	}

	if res.SavedBytes <= 0 {
		t.Errorf("Expected saved bytes from minification, got %d", res.SavedBytes)
	}

	if res.ExceedsInline {
		t.Errorf("Expected small policy not to exceed inline limit")
	}
}
