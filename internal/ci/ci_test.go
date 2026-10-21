package ci

import (
	"strings"
	"testing"

	"github.com/smford/iam-shrink/internal/diff"
	"github.com/smford/iam-shrink/internal/linter"
)

func TestEvaluateGate(t *testing.T) {
	actions := []string{"s3:*", "dynamodb:PutItem"}
	issues := []linter.Issue{
		{
			Severity: linter.SeverityCritical,
			RuleID:   "NO_FULL_WILDCARD_ACTION",
			Action:   "*",
		},
	}

	opts := GateOptions{
		FailOnWildcard: true,
	}

	res := EvaluateGate(actions, issues, nil, opts)
	if res.Passed {
		t.Errorf("Expected gate to fail on s3:* wildcard action")
	}

	if len(res.Reasons) != 2 {
		t.Errorf("Expected 2 failure reasons, got %d: %v", len(res.Reasons), res.Reasons)
	}
}

func TestFormatPRComment(t *testing.T) {
	diffRes := &diff.Result{
		ExistingActions: []string{"s3:*", "dynamodb:*"},
		CapturedActions: []string{"s3:GetObject"},
		UnusedActions:   []string{"dynamodb:*"},
		MissingActions:  []string{"s3:GetObject"},
		RetainedActions: nil,
		ReductionPct:    50.0,
	}

	comment := FormatPRComment(diffRes, nil)
	if !strings.Contains(comment, "Reduced Permission Attack Surface by **50.0%**") {
		t.Errorf("Expected reduction percentage in PR comment, got:\n%s", comment)
	}
	if !strings.Contains(comment, "<details>") {
		t.Errorf("Expected collapsible section in PR comment")
	}
}
