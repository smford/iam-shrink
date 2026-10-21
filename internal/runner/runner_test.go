package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smford/iam-shrink/internal/render"
)

func TestRunnerEndToEndWithMockAWSApp(t *testing.T) {
	mockAppPath, err := filepath.Abs("../../testdata/mock_aws_app.go")
	if err != nil {
		t.Fatalf("Resolving mock app path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	opts := Options{
		Command:        []string{"go", "run", mockAppPath},
		Format:         render.FormatJSON,
		IncludeFailed:  true,
		GroupByService: true,
		StrictARNs:     false,
		Stdout:         &stdoutBuf,
		Stderr:         &stderrBuf,
	}

	res, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d. Stderr: %s", res.ExitCode, stderrBuf.String())
	}

	// 1. Verify child process stdout was redirected to stderr so stdout is clean policy
	if !strings.Contains(stderrBuf.String(), "Mock AWS application execution completed successfully.") {
		t.Errorf("Expected child message in stderr, got: %s", stderrBuf.String())
	}

	// 2. Parse stdout JSON policy
	policyJSON := stdoutBuf.String()
	var policy struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid      string   `json:"Sid"`
			Effect   string   `json:"Effect"`
			Action   []string `json:"Action"`
			Resource []string `json:"Resource"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		t.Fatalf("Failed to parse generated JSON policy: %v\nOutput was:\n%s", err, policyJSON)
	}

	actionMap := make(map[string]bool)
	for _, stmt := range policy.Statement {
		for _, act := range stmt.Action {
			actionMap[act] = true
		}
	}

	if !actionMap["s3:ListBucket"] {
		t.Errorf("Expected s3:ListBucket in policy, actions found: %v", actionMap)
	}
	if !actionMap["dynamodb:PutItem"] {
		t.Errorf("Expected dynamodb:PutItem in policy, actions found: %v", actionMap)
	}
	if !actionMap["kms:Decrypt"] {
		t.Errorf("Expected kms:Decrypt in policy when IncludeFailed=true, actions found: %v", actionMap)
	}
}

func TestRunnerExcludeFailedCalls(t *testing.T) {
	mockAppPath, err := filepath.Abs("../../testdata/mock_aws_app.go")
	if err != nil {
		t.Fatalf("Resolving mock app path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	opts := Options{
		Command:        []string{"go", "run", mockAppPath},
		Format:         render.FormatJSON,
		IncludeFailed:  false,
		GroupByService: true,
		StrictARNs:     false,
		Stdout:         &stdoutBuf,
		Stderr:         &stderrBuf,
	}

	res, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d", res.ExitCode)
	}

	policyJSON := stdoutBuf.String()
	if strings.Contains(policyJSON, "kms:Decrypt") {
		t.Errorf("kms:Decrypt was expected to be excluded when IncludeFailed=false, but was present in:\n%s", policyJSON)
	}
	if !strings.Contains(policyJSON, "s3:ListBucket") {
		t.Errorf("s3:ListBucket expected in policy")
	}
}

func TestRunnerTerraformOutputToFile(t *testing.T) {
	mockAppPath, err := filepath.Abs("../../testdata/mock_aws_app.go")
	if err != nil {
		t.Fatalf("Resolving mock app path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "policy.tf")

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	opts := Options{
		Command:        []string{"go", "run", mockAppPath},
		Format:         render.FormatTF,
		OutputFile:     outFile,
		IncludeFailed:  true,
		GroupByService: true,
		StrictARNs:     true,
		EmitVars:       true,
		Stdout:         &stdoutBuf,
		Stderr:         &stderrBuf,
	}

	res, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d", res.ExitCode)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("Reading output file %q: %v", outFile, err)
	}

	tfContent := string(data)
	if !strings.Contains(tfContent, `data "aws_iam_policy_document" "generated" {`) {
		t.Errorf("Expected Terraform block in file, got:\n%s", tfContent)
	}
	if !strings.Contains(tfContent, `variable "bucket_name" {`) {
		t.Errorf("Expected companion variable definition in file")
	}
}

func TestRunnerSplitByAccessLevel(t *testing.T) {
	mockAppPath, err := filepath.Abs("../../testdata/mock_aws_app.go")
	if err != nil {
		t.Fatalf("Resolving mock app path: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	opts := Options{
		Command:            []string{"go", "run", mockAppPath},
		Format:             render.FormatJSON,
		IncludeFailed:      true,
		GroupByService:     true,
		SplitByAccessLevel: true,
		StrictARNs:         false,
		Stdout:             &stdoutBuf,
		Stderr:             &stderrBuf,
	}

	res, err := Run(ctx, opts)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d", res.ExitCode)
	}

	policyJSON := stdoutBuf.String()
	// Should have S3List and DynamoDBWrite Sids
	if !strings.Contains(policyJSON, "S3List") || !strings.Contains(policyJSON, "DynamodbWrite") {
		t.Errorf("Expected S3List and DynamodbWrite Sids, got:\n%s", policyJSON)
	}
}
