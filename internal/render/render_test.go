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
			AccessLevel:  "List",
			ResourceARNs: []string{"arn:aws:s3:::my-bucket"},
			IsFallback:   false,
		},
		{
			Action:       "s3:PutObject",
			Service:      "s3",
			AccessLevel:  "Write",
			ResourceARNs: []string{"arn:aws:s3:::${var.bucket_name}/*"},
			IsFallback:   false,
		},
		{
			Action:       "dynamodb:PutItem",
			Service:      "dynamodb",
			AccessLevel:  "Write",
			ResourceARNs: []string{"arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}"},
			IsFallback:   false,
		},
		{
			Action:       "custom:CustomMethod",
			Service:      "custom",
			AccessLevel:  "Write",
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

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("Invalid JSON produced: %v\nOutput was:\n%s", err, out)
	}

	if parsed["Version"] != "2012-10-17" {
		t.Errorf("Expected Version 2012-10-17, got %v", parsed["Version"])
	}
}

func TestRenderTerraformWithVars(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatTF,
		GroupByService: true,
		StrictARNs:     true,
		EmitVars:       true,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if !strings.Contains(out, `data "aws_iam_policy_document" "generated" {`) {
		t.Errorf("Expected Terraform data source header")
	}

	if !strings.Contains(out, `variable "bucket_name" {`) {
		t.Errorf("Expected variable bucket_name block, got:\n%s", out)
	}
	if !strings.Contains(out, `variable "table_name" {`) {
		t.Errorf("Expected variable table_name block, got:\n%s", out)
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
}

func TestRenderPulumi(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatPulumi,
		GroupByService: true,
		StrictARNs:     false,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if !strings.Contains(out, `import * as aws from "@pulumi/aws";`) {
		t.Errorf("Expected Pulumi import statement")
	}
	if !strings.Contains(out, `aws.iam.getPolicyDocumentOutput`) {
		t.Errorf("Expected getPolicyDocumentOutput in Pulumi output")
	}
}

func TestRenderCloudFormation(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:         FormatCFN,
		GroupByService: true,
		StrictARNs:     false,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("Invalid CloudFormation template: %v\nOutput was:\n%s", err, out)
	}

	if parsed["AWSTemplateFormatVersion"] != "2010-09-09" {
		t.Errorf("Expected AWSTemplateFormatVersion, got %v", parsed["AWSTemplateFormatVersion"])
	}
}

func TestRenderSplitByAccessLevel(t *testing.T) {
	items := sampleActionItems()
	opts := RenderOptions{
		Format:             FormatJSON,
		GroupByService:     true,
		SplitByAccessLevel: true,
		StrictARNs:         false,
	}

	out, err := Render(items, opts)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if !strings.Contains(out, "S3List") || !strings.Contains(out, "S3Write") {
		t.Errorf("Expected S3List and S3Write Sids, got:\n%s", out)
	}
}
