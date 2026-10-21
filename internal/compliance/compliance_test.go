package compliance

import (
	"strings"
	"testing"
)

func TestComplianceEvaluationCIS(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	actions := []string{
		"iam:PassRole",
		"s3:ListBucket",
		"s3:*",
	}

	resourcesByAction := map[string][]string{
		"iam:passrole":  {"*"},
		"s3:listbucket": {"arn:aws:s3:::my-bucket"},
		"s3:*":          {"*"},
	}

	rep, err := reg.Evaluate("cis", actions, resourcesByAction)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if rep.FailedRules != 2 {
		t.Errorf("Expected 2 failed CIS rules (unconstrained passrole & s3:*), got %d failed out of %d", rep.FailedRules, rep.TotalRules)
	}

	if rep.ComplianceScore >= 100.0 {
		t.Errorf("Expected compliance score < 100%%, got %.1f%%", rep.ComplianceScore)
	}

	terminalOutput := rep.FormatTerminal()
	if !strings.Contains(terminalOutput, "[FAIL]") || !strings.Contains(terminalOutput, "1.20") {
		t.Errorf("Expected 1.20 failure in output:\n%s", terminalOutput)
	}

	mdOutput := rep.FormatMarkdown()
	if !strings.Contains(mdOutput, "### 🛡️ Compliance Audit") || !strings.Contains(mdOutput, "❌ FAIL") {
		t.Errorf("Expected Markdown PR table formatting:\n%s", mdOutput)
	}
}

func TestComplianceEvaluationCleanPolicy(t *testing.T) {
	reg, err := NewRegistry("")
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	actions := []string{
		"s3:ListBucket",
		"s3:GetObject",
		"dynamodb:PutItem",
	}

	resourcesByAction := map[string][]string{
		"s3:listbucket":    {"arn:aws:s3:::my-bucket"},
		"s3:getobject":     {"arn:aws:s3:::my-bucket/*"},
		"dynamodb:putitem": {"arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"},
	}

	rep, err := reg.Evaluate("nist", actions, resourcesByAction)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if rep.FailedRules != 0 || rep.ComplianceScore != 100.0 {
		t.Errorf("Expected 100%% compliance, got %.1f%% (%d failed)", rep.ComplianceScore, rep.FailedRules)
	}
}
