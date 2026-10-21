package diff

import (
	"strings"
	"testing"
)

func TestDiffCompareAndReport(t *testing.T) {
	existingJSON := `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "sqs:SendMessage"
      ],
      "Resource": "*"
    }
  ]
}
`
	existing, err := ParseActions([]byte(existingJSON))
	if err != nil {
		t.Fatalf("ParseActions failed: %v", err)
	}

	captured := []string{
		"dynamodb:PutItem",
		"s3:ListBucket",
		"s3:GetObject",
	}

	res := Compare(existing, captured)

	// Unused should be s3:*, dynamodb:GetItem, sqs:SendMessage
	if len(res.UnusedActions) != 3 {
		t.Errorf("Expected 3 unused actions, got %d: %v", len(res.UnusedActions), res.UnusedActions)
	}

	// Retained should be dynamodb:PutItem
	if len(res.RetainedActions) != 1 || res.RetainedActions[0] != "dynamodb:PutItem" {
		t.Errorf("Expected retained dynamodb:PutItem, got %v", res.RetainedActions)
	}

	// Missing should be s3:ListBucket, s3:GetObject
	if len(res.MissingActions) != 2 {
		t.Errorf("Expected 2 missing actions, got %d: %v", len(res.MissingActions), res.MissingActions)
	}

	// Reduction percentage: 3/4 = 75.0%
	if res.ReductionPct != 75.0 {
		t.Errorf("Expected 75.0%% reduction, got %.1f%%", res.ReductionPct)
	}

	report := res.Report()
	if !strings.Contains(report, "Privilege Attack Surface Reduction: 75.0%") {
		t.Errorf("Expected reduction percentage in report: %s", report)
	}
}
