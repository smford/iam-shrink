package cloudtrail

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/smford/iam-shrink/internal/csm"
)

// Record represents a single AWS CloudTrail event structure.
type Record struct {
	EventVersion      string                 `json:"eventVersion"`
	EventTime         string                 `json:"eventTime"`
	EventSource       string                 `json:"eventSource"`
	EventName         string                 `json:"eventName"`
	AwsRegion         string                 `json:"awsRegion"`
	ErrorCode         string                 `json:"errorCode,omitempty"`
	ErrorMessage      string                 `json:"errorMessage,omitempty"`
	RequestParameters map[string]interface{} `json:"requestParameters,omitempty"`
	Resources         []ResourceItem         `json:"resources,omitempty"`
	UserIdentity      map[string]interface{} `json:"userIdentity,omitempty"`
}

// ResourceItem describes an AWS resource referenced in a CloudTrail record.
type ResourceItem struct {
	ARN       string `json:"ARN"`
	AccountId string `json:"accountId"`
	Type      string `json:"type"`
}

// LogFile represents the root wrapper of a CloudTrail log file.
type LogFile struct {
	Records []Record `json:"Records"`
}

// IngestedEvent captures the extracted telemetry from a CloudTrail event.
type IngestedEvent struct {
	Event        csm.Event
	ResourceARNs []string
}

// NormalizeEventSource converts "s3.amazonaws.com" -> "s3", "dynamodb.amazonaws.com" -> "dynamodb".
func NormalizeEventSource(source string) string {
	s := strings.ToLower(strings.TrimSpace(source))
	if idx := strings.Index(s, "."); idx != -1 {
		s = s[:idx]
	}
	return s
}

// ParseReader parses CloudTrail JSON from an io.Reader.
func ParseReader(r io.Reader) ([]IngestedEvent, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading CloudTrail data: %w", err)
	}

	// Try parsing as {"Records": [...]}
	var logFile LogFile
	if err := json.Unmarshal(data, &logFile); err == nil && len(logFile.Records) > 0 {
		return processRecords(logFile.Records), nil
	}

	// Try parsing as a single Record or array of Records
	var singleRecord Record
	if err := json.Unmarshal(data, &singleRecord); err == nil && singleRecord.EventSource != "" {
		return processRecords([]Record{singleRecord}), nil
	}

	var records []Record
	if err := json.Unmarshal(data, &records); err == nil && len(records) > 0 {
		return processRecords(records), nil
	}

	return nil, fmt.Errorf("unable to parse CloudTrail JSON schema")
}

// ParseFile parses a CloudTrail file (.json or .json.gz).
func ParseFile(path string) ([]IngestedEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file %s: %w", path, err)
	}
	defer f.Close()

	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gzReader, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader for %s: %w", path, err)
		}
		defer gzReader.Close()
		return ParseReader(gzReader)
	}

	return ParseReader(f)
}

// ParsePath parses a single CloudTrail file or all log files in a directory.
func ParsePath(targetPath string) ([]IngestedEvent, error) {
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("stat path %s: %w", targetPath, err)
	}

	if !info.IsDir() {
		return ParseFile(targetPath)
	}

	var allEvents []IngestedEvent
	err = filepath.Walk(targetPath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".json.gz") || strings.HasSuffix(lower, ".gz") {
			events, err := ParseFile(path)
			if err == nil {
				allEvents = append(allEvents, events...)
			}
		}
		return nil
	})

	return allEvents, err
}

func processRecords(records []Record) []IngestedEvent {
	var results []IngestedEvent
	for _, rec := range records {
		svc := NormalizeEventSource(rec.EventSource)
		if svc == "" || rec.EventName == "" {
			continue
		}

		httpStatus := 200
		if rec.ErrorCode != "" {
			httpStatus = 403
		}

		evt := csm.Event{
			Type:           "ApiCall",
			Service:        svc,
			Api:            rec.EventName,
			Region:         rec.AwsRegion,
			HttpStatusCode: httpStatus,
			AwsException:   rec.ErrorCode,
		}

		var arns []string
		for _, r := range rec.Resources {
			if r.ARN != "" {
				arns = append(arns, r.ARN)
			}
		}

		// Additional parameter extraction (e.g. S3 bucket, DynamoDB table)
		if len(arns) == 0 && rec.RequestParameters != nil {
			if b, ok := rec.RequestParameters["bucketName"].(string); ok && b != "" {
				arns = append(arns, fmt.Sprintf("arn:aws:s3:::%s", b))
			}
			if t, ok := rec.RequestParameters["tableName"].(string); ok && t != "" {
				arns = append(arns, fmt.Sprintf("arn:aws:dynamodb:%s:*:table/%s", rec.AwsRegion, t))
			}
		}

		results = append(results, IngestedEvent{
			Event:        evt,
			ResourceARNs: arns,
		})
	}
	return results
}
