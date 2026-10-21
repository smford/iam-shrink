package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func sampleCloudTrailJSON() []byte {
	return []byte(`{
  "Records": [
    {
      "eventVersion": "1.08",
      "eventTime": "2026-10-21T12:00:00Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "ListObjectsV2",
      "awsRegion": "us-east-1",
      "requestParameters": {
        "bucketName": "production-data-lake"
      },
      "resources": [
        {
          "ARN": "arn:aws:s3:::production-data-lake",
          "type": "AWS::S3::Bucket"
        }
      ]
    },
    {
      "eventVersion": "1.08",
      "eventTime": "2026-10-21T12:01:00Z",
      "eventSource": "dynamodb.amazonaws.com",
      "eventName": "PutItem",
      "awsRegion": "us-east-1",
      "resources": [
        {
          "ARN": "arn:aws:dynamodb:us-east-1:123456789012:table/Orders",
          "type": "AWS::DynamoDB::Table"
        }
      ]
    },
    {
      "eventVersion": "1.08",
      "eventTime": "2026-10-21T12:02:00Z",
      "eventSource": "kms.amazonaws.com",
      "eventName": "Decrypt",
      "awsRegion": "us-east-1",
      "errorCode": "AccessDenied"
    }
  ]
}`)
}

func TestParseReader(t *testing.T) {
	events, err := ParseReader(bytes.NewReader(sampleCloudTrailJSON()))
	if err != nil {
		t.Fatalf("ParseReader failed: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(events))
	}

	// 1. S3 ListObjectsV2
	if events[0].Event.Service != "s3" || events[0].Event.Api != "ListObjectsV2" {
		t.Errorf("Unexpected event 0: %+v", events[0].Event)
	}
	if len(events[0].ResourceARNs) == 0 || events[0].ResourceARNs[0] != "arn:aws:s3:::production-data-lake" {
		t.Errorf("Expected S3 bucket ARN, got: %v", events[0].ResourceARNs)
	}

	// 2. DynamoDB PutItem
	if events[1].Event.Service != "dynamodb" || events[1].Event.Api != "PutItem" {
		t.Errorf("Unexpected event 1: %+v", events[1].Event)
	}
	if len(events[1].ResourceARNs) == 0 || events[1].ResourceARNs[0] != "arn:aws:dynamodb:us-east-1:123456789012:table/Orders" {
		t.Errorf("Expected DynamoDB table ARN, got: %v", events[1].ResourceARNs)
	}

	// 3. KMS Decrypt AccessDenied
	if events[2].Event.Service != "kms" || events[2].Event.Api != "Decrypt" {
		t.Errorf("Unexpected event 2: %+v", events[2].Event)
	}
	if !events[2].Event.IsFailed() {
		t.Errorf("Expected event 2 to be failed (AccessDenied)")
	}
}

func TestParseGzipFile(t *testing.T) {
	tempDir := t.TempDir()
	gzPath := filepath.Join(tempDir, "cloudtrail_log.json.gz")

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	if _, err := gzWriter.Write(sampleCloudTrailJSON()); err != nil {
		t.Fatalf("Gzip write failed: %v", err)
	}
	gzWriter.Close()

	if err := os.WriteFile(gzPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("Write gz file failed: %v", err)
	}

	events, err := ParsePath(gzPath)
	if err != nil {
		t.Fatalf("ParsePath failed for gzip: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("Expected 3 events from gzip file, got %d", len(events))
	}
}
