package render

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleActionItems() []ActionItem {
	return []ActionItem{
		{
			Action:       "s3:ListBucket",
			Service:      "s3",
			ResourceARNs: []string{"arn:aws:s3:::my-bucket"},
			IsFallback:   false,
		},
		{
			Action:       "s3:PutObject",
			Service:      "s3",
			ResourceARNs: []string{"arn:aws:s3:::my-bucket/*"},
			IsFallback:   false,
		},
		{
			Action:       "dynamodb:PutItem",
			Service:      "dynamodb",
			ResourceARNs: []string{"arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"},
			IsFallback:   false,
		},
		{
			Action:       "custom:CustomMethod",
			Service:      "custom",
			ResourceARNs: nil,
			IsFallback:   true,
		},
	}
}

func TestRenderJSON(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatJSON,
		GroupByService: true,
		StrictARNs:     false,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	// Verify valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("Invalid JSON produced: %v\nOutput was:\n%s", err, out)
	}

	if parsed["Version"] != "2012-10-17" {
		t.Errorf("Expected Version 2012-10-17, got %v", parsed["Version"])
	}

	// Check statements order
	stmts, ok := parsed["Statement"].([]interface{})
	if !ok || len(stmts) != 3 {
		t.Fatalf("Expected 3 statements, got %v", len(stmts))
	}

	// First statement should be custom, second dynamodb, third s3 (alphabetical Sids)
	first := stmts[0].(map[string]interface{})
	second := stmts[1].(map[string]interface{})
	third := stmts[2].(map[string]interface{})

	if first["Sid"] != "Custom" || second["Sid"] != "Dynamodb" || third["Sid"] != "S3" {
		t.Errorf("Unexpected Sids order: %v, %v, %v", first["Sid"], second["Sid"], third["Sid"])
	}

	// Check wildcard resource when strict-arns=false
	resSlice := third["Resource"].([]interface{})
	if len(resSlice) != 1 || resSlice[0] != "*" {
		t.Errorf("Expected resource '*', got %v", resSlice)
	}
}

func TestRenderTerraform(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatTF,
		GroupByService: true,
		StrictARNs:     true,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	// Check data block
	if !strings.Contains(out, `data "aws_iam_policy_document" "generated" {`) {
		t.Errorf("Expected Terraform data source header")
	}

	// Check fallback comment
	if !strings.Contains(out, `"custom:CustomMethod", # unmapped fallback from SDK call`) {
		t.Errorf("Expected fallback comment in Terraform output, got:\n%s", out)
	}

	// Check strict arns for S3
	if !strings.Contains(out, `"arn:aws:s3:::my-bucket"`) || !strings.Contains(out, `"arn:aws:s3:::my-bucket/*"`) {
		t.Errorf("Expected strict ARNs in Terraform output, got:\n%s", out)
	}
}

func TestRenderCDK(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatCDK,
		GroupByService: true,
		StrictARNs:     false,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if !strings.Contains(out, `import * as iam from 'aws-cdk-lib/aws-iam';`) {
		t.Errorf("Expected CDK import statement")
	}
	if !strings.Contains(out, `new iam.PolicyStatement({`) {
		t.Errorf("Expected new iam.PolicyStatement")
	}
	if !strings.Contains(out, `'custom:CustomMethod', // unmapped fallback from SDK call`) {
		t.Errorf("Expected fallback comment in CDK output, got:\n%s", out)
	}
}

func TestRenderNonGrouped(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatTF,
		GroupByService: false,
		StrictARNs:     false,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	// Should only have 1 statement
	count := strings.Count(out, "statement {")
	if count != 1 {
		t.Errorf("Expected exactly 1 statement, got %d", count)
	}
}
