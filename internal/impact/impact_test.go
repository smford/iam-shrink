package impact

import (
	"strings"
	"testing"

	"github.com/smford/iam-shrink/internal/cloudtrail"
	"github.com/smford/iam-shrink/internal/csm"
)

func TestImpactAnalysisAllAllowed(t *testing.T) {
	events := []cloudtrail.IngestedEvent{
		{
			Event: csm.Event{
				Service: "s3",
				Api:     "ListObjectsV2",
			},
		},
		{
			Event: csm.Event{
				Service: "s3",
				Api:     "GetObject",
			},
		},
	}

	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3:ListBucket", "s3:GetObject"],
				"Resource": "*"
			}
		]
	}`)

	report, err := AnalyzeEvents(events, policyJSON, nil)
	if err != nil {
		t.Fatalf("AnalyzeEvents failed: %v", err)
	}

	if report.SafetyScore != 100.0 {
		t.Errorf("Expected 100%% safety, got %.1f%%", report.SafetyScore)
	}
	if report.SeveredCalls != 0 {
		t.Errorf("Expected 0 severed calls, got %d", report.SeveredCalls)
	}
	if report.RiskLevel != "MINIMAL" {
		t.Errorf("Expected MINIMAL risk, got %s", report.RiskLevel)
	}

	term := report.FormatTerminal()
	if !strings.Contains(term, "0 broken calls") {
		t.Errorf("Expected '0 broken calls' in terminal output:\n%s", term)
	}
}

func TestImpactAnalysisDetectsSeveredCalls(t *testing.T) {
	events := []cloudtrail.IngestedEvent{
		{
			Event: csm.Event{
				Service: "s3",
				Api:     "GetObject",
			},
		},
		{
			Event: csm.Event{
				Service: "dynamodb",
				Api:     "DeleteItem",
			},
		},
		{
			Event: csm.Event{
				Service: "dynamodb",
				Api:     "DeleteItem",
			},
		},
	}

	// Policy only permits s3:GetObject
	policyJSON := []byte(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "*"
			}
		]
	}`)

	report, err := AnalyzeEvents(events, policyJSON, nil)
	if err != nil {
		t.Fatalf("AnalyzeEvents failed: %v", err)
	}

	if report.TotalEventsSeen != 3 {
		t.Errorf("Expected 3 total events, got %d", report.TotalEventsSeen)
	}
	if report.AllowedCalls != 1 {
		t.Errorf("Expected 1 allowed call, got %d", report.AllowedCalls)
	}
	if report.SeveredCalls != 2 {
		t.Errorf("Expected 2 severed calls, got %d", report.SeveredCalls)
	}
	if len(report.SeveredBreakdown) != 1 {
		t.Fatalf("Expected 1 severed breakdown item, got %d", len(report.SeveredBreakdown))
	}

	sev := report.SeveredBreakdown[0]
	if sev.Count != 2 || sev.Action != "dynamodb:DeleteItem" {
		t.Errorf("Expected 2 DeleteItem calls severed, got %+v", sev)
	}

	term := report.FormatTerminal()
	if !strings.Contains(term, "dynamodb:DeleteItem") {
		t.Errorf("Expected severed call dynamodb:DeleteItem in terminal output:\n%s", term)
	}

	jsonStr, err := report.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	if !strings.Contains(jsonStr, `"safety_score"`) {
		t.Errorf("Expected safety_score in JSON output:\n%s", jsonStr)
	}
}
