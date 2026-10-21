package patcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchTerraformContentReplace(t *testing.T) {
	orig := `
# Provider configuration
provider "aws" {
  region = "us-east-1"
}

data "aws_iam_policy_document" "app_policy" {
  statement {
    sid    = "Old"
    effect = "Allow"
    actions = ["s3:*"]
    resources = ["*"]
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
}
`
	newHCL := `data "aws_iam_policy_document" "app_policy" {
  statement {
    sid    = "Shrunk"
    effect = "Allow"
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::my-bucket/*",
    ]
  }
}`

	patched, err := PatchTerraformContent(orig, "app_policy", newHCL)
	if err != nil {
		t.Fatalf("PatchTerraformContent failed: %v", err)
	}

	if !strings.Contains(patched, `sid    = "Shrunk"`) {
		t.Errorf("Expected new block in patched content, got:\n%s", patched)
	}
	if strings.Contains(patched, `sid    = "Old"`) {
		t.Errorf("Expected old block to be removed from patched content")
	}
	if !strings.Contains(patched, `resource "aws_s3_bucket" "b"`) {
		t.Errorf("Expected surrounding resources to be preserved")
	}
}

func TestPatchTerraformFileWithBackup(t *testing.T) {
	tempDir := t.TempDir()
	tfFile := filepath.Join(tempDir, "main.tf")

	initial := `data "aws_iam_policy_document" "generated" {
  statement {
    actions = ["*"]
  }
}`
	if err := os.WriteFile(tfFile, []byte(initial), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	newHCL := `data "aws_iam_policy_document" "generated" {
  statement {
    actions = ["s3:ListBucket"]
  }
}`

	opts := PatchOptions{
		FilePath:     tfFile,
		TargetName:   "generated",
		NewHCL:       newHCL,
		CreateBackup: true,
	}

	if err := PatchTerraformFile(opts); err != nil {
		t.Fatalf("PatchTerraformFile failed: %v", err)
	}

	// Verify backup exists
	bakData, err := os.ReadFile(tfFile + ".bak")
	if err != nil {
		t.Fatalf("Backup file not created: %v", err)
	}
	if !strings.Contains(string(bakData), `actions = ["*"]`) {
		t.Errorf("Backup file missing original content")
	}

	// Verify updated file
	updatedData, err := os.ReadFile(tfFile)
	if err != nil {
		t.Fatalf("Reading updated file failed: %v", err)
	}
	if !strings.Contains(string(updatedData), `actions = ["s3:ListBucket"]`) {
		t.Errorf("Updated file missing new content")
	}
}
