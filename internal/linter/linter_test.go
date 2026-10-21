package linter

import (
	"strings"
	"testing"
)

func TestLinterDetectsPrivilegeEscalationAndWildcards(t *testing.T) {
	riskyPolicyJSON := `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminWildcard",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "RiskyPassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*"
    },
    {
      "Sid": "ServiceWildcard",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
`
	issues, err := LintPolicyJSON([]byte(riskyPolicyJSON))
	if err != nil {
		t.Fatalf("LintPolicyJSON failed: %v", err)
	}

	if len(issues) != 3 {
		t.Fatalf("Expected 3 issues, got %d: %+v", len(issues), issues)
	}

	// 1st issue should be CRITICAL (Action: *)
	if issues[0].Severity != SeverityCritical || issues[0].RuleID != "NO_FULL_WILDCARD_ACTION" {
		t.Errorf("Unexpected issue 0: %+v", issues[0])
	}

	// 2nd issue should be HIGH (iam:PassRole with *)
	if issues[1].Severity != SeverityHigh || issues[1].RuleID != "PRIV_ESC_PASS_ROLE" {
		t.Errorf("Unexpected issue 1: %+v", issues[1])
	}

	// 3rd issue should be MEDIUM (s3:*)
	if issues[2].Severity != SeverityMedium || issues[2].RuleID != "SERVICE_WILDCARD_ACTION" {
		t.Errorf("Unexpected issue 2: %+v", issues[2])
	}

	report := FormatIssues(issues)
	if !strings.Contains(report, "[CRITICAL]") || !strings.Contains(report, "[HIGH]") {
		t.Errorf("Unexpected report content:\n%s", report)
	}
}

func TestLinterCleanPolicy(t *testing.T) {
	cleanPolicyJSON := `
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SafeS3",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
`
	issues, err := LintPolicyJSON([]byte(cleanPolicyJSON))
	if err != nil {
		t.Fatalf("LintPolicyJSON failed: %v", err)
	}

	if len(issues) != 0 {
		t.Errorf("Expected 0 issues for clean policy, got %d", len(issues))
	}

	report := FormatIssues(issues)
	if !strings.Contains(report, "No security issues") {
		t.Errorf("Expected clean report message, got:\n%s", report)
	}
}
