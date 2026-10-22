package otel

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/smford/iam-shrink/internal/csm"
)

// SpanAttribute represents a key-value attribute in an OpenTelemetry span.
type SpanAttribute struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// Span represents an OpenTelemetry trace span.
type Span struct {
	TraceID    string          `json:"trace_id"`
	SpanID     string          `json:"span_id"`
	Name       string          `json:"name"`
	StartTime  time.Time       `json:"start_time"`
	EndTime    time.Time       `json:"end_time"`
	Status     string          `json:"status"`
	Attributes []SpanAttribute `json:"attributes"`
}

// TraceBatch represents a collection of spans in OTLP JSON format.
type TraceBatch struct {
	ResourceSpans []ResourceSpan `json:"resource_spans"`
}

// ResourceSpan bundles spans with service attributes.
type ResourceSpan struct {
	Resource map[string]string `json:"resource"`
	Spans    []Span            `json:"spans"`
}

// ConvertEventsToSpans converts captured CSM events into OpenTelemetry spans.
func ConvertEventsToSpans(events []csm.Event) []Span {
	var spans []Span

	for _, e := range events {
		if e.Service == "" || e.Api == "" {
			continue
		}

		traceID := generateHex(16)
		spanID := generateHex(8)

		status := "OK"
		if e.IsFailed() {
			status = "ERROR"
		}

		attrs := []SpanAttribute{
			{Key: "rpc.system", Value: "aws-api"},
			{Key: "rpc.service", Value: strings.ToLower(e.Service)},
			{Key: "rpc.method", Value: e.Api},
		}

		if e.Region != "" {
			attrs = append(attrs, SpanAttribute{Key: "aws.region", Value: e.Region})
		}
		if code := e.StatusCode(); code != 0 {
			attrs = append(attrs, SpanAttribute{Key: "http.status_code", Value: code})
		}
		if e.AwsException != "" {
			attrs = append(attrs, SpanAttribute{Key: "aws.exception", Value: e.AwsException})
		}

		now := time.Now()
		spans = append(spans, Span{
			TraceID:    traceID,
			SpanID:     spanID,
			Name:       fmt.Sprintf("aws.%s.%s", strings.ToLower(e.Service), e.Api),
			StartTime:  now.Add(-50 * time.Millisecond),
			EndTime:    now,
			Status:     status,
			Attributes: attrs,
		})
	}

	return spans
}

// ExportToFile serializes the spans as formatted OTLP JSON to destination file.
func ExportToFile(path string, events []csm.Event) error {
	spans := ConvertEventsToSpans(events)
	batch := TraceBatch{
		ResourceSpans: []ResourceSpan{
			{
				Resource: map[string]string{
					"service.name":       "iam-shrink",
					"telemetry.sdk.name": "iam-shrink-csm",
				},
				Spans: spans,
			},
		},
	}

	data, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(data, '\n'), 0644)
}

func generateHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
