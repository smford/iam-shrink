package otel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smford/iam-shrink/internal/csm"
)

func TestConvertEventsToSpansAndExport(t *testing.T) {
	events := []csm.Event{
		{
			Service:        "S3",
			Api:            "ListObjectsV2",
			Region:         "us-east-1",
			HttpStatusCode: 200,
		},
		{
			Service:             "KMS",
			Api:                 "Decrypt",
			Region:              "us-east-1",
			FinalHttpStatusCode: 403,
			AwsException:        "AccessDenied",
		},
	}

	spans := ConvertEventsToSpans(events)
	if len(spans) != 2 {
		t.Fatalf("Expected 2 spans, got %d", len(spans))
	}

	if spans[0].Name != "aws.s3.ListObjectsV2" || spans[0].Status != "OK" {
		t.Errorf("Unexpected span 0: %+v", spans[0])
	}

	if spans[1].Name != "aws.kms.Decrypt" || spans[1].Status != "ERROR" {
		t.Errorf("Unexpected span 1: %+v", spans[1])
	}

	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "traces.json")

	if err := ExportToFile(outPath, events); err != nil {
		t.Fatalf("ExportToFile failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	str := string(data)
	if !strings.Contains(str, "aws.s3.ListObjectsV2") || !strings.Contains(str, "iam-shrink") {
		t.Errorf("Expected OTel trace data in output:\n%s", str)
	}
}
