package advisor

import (
	"strings"
	"testing"
)

func TestPrunePolicy(t *testing.T) {
	origJSON := `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3Ops",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:DeleteBucket"
      ],
      "Resource": "*"
    },
    {
      "Sid": "UnusedDynamo",
      "Effect": "Allow",
      "Action": [
        "dynamodb:DeleteTable"
      ],
      "Resource": "*"
    }
  ]
}
`
	active := []string{
		"s3:ListBucket",
		"s3:GetObject",
	}

	res, err := PrunePolicy([]byte(origJSON), active)
	if err != nil {
		t.Fatalf("PrunePolicy failed: %v", err)
	}

	// s3:DeleteBucket and dynamodb:DeleteTable should be pruned
	if len(res.PrunedActions) != 2 {
		t.Errorf("Expected 2 pruned actions, got %d: %v", len(res.PrunedActions), res.PrunedActions)
	}

	// Active retained should be 2
	if len(res.ActiveActions) != 2 {
		t.Errorf("Expected 2 active retained actions, got %d", len(res.ActiveActions))
	}

	// Reduction: 2 pruned / 4 original = 50.0%
	if res.ReductionPct != 50.0 {
		t.Errorf("Expected 50.0%% reduction, got %.1f%%", res.ReductionPct)
	}

	// Pruned JSON should eliminate UnusedDynamo statement entirely
	prunedStr := string(res.PrunedPolicyDoc)
	if strings.Contains(prunedStr, "UnusedDynamo") || strings.Contains(prunedStr, "dynamodb:DeleteTable") {
		t.Errorf("Expected unused DynamoDB statement to be eliminated")
	}
	if !strings.Contains(prunedStr, "s3:ListBucket") || !strings.Contains(prunedStr, "s3:GetObject") {
		t.Errorf("Expected active S3 actions to be retained")
	}
}
