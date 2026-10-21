package mapper

import (
	"strings"
	"testing"
)

func TestMapperResolve(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	tests := []struct {
		service         string
		api             string
		expectedActions []string
		isFallback      bool
		hasResourceARNs bool
	}{
		{
			service:         "S3",
			api:             "ListObjectsV2",
			expectedActions: []string{"s3:ListBucket"},
			isFallback:      false,
			hasResourceARNs: true,
		},
		{
			service:         "s3",
			api:             "PutObject",
			expectedActions: []string{"s3:PutObject"},
			isFallback:      false,
			hasResourceARNs: true,
		},
		{
			service:         "DynamoDB",
			api:             "Query",
			expectedActions: []string{"dynamodb:Query"},
			isFallback:      false,
			hasResourceARNs: true,
		},
		{
			service:         "kms",
			api:             "Decrypt",
			expectedActions: []string{"kms:Decrypt"},
			isFallback:      false,
			hasResourceARNs: true,
		},
		{
			service:         "CloudWatchLogs",
			api:             "CreateLogGroup",
			expectedActions: []string{"logs:CreateLogGroup"},
			isFallback:      false,
			hasResourceARNs: true,
		},
		{
			service:         "CustomService",
			api:             "DoSomethingSpecial",
			expectedActions: []string{"customservice:DoSomethingSpecial"},
			isFallback:      true,
			hasResourceARNs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.service+":"+tt.api, func(t *testing.T) {
			res := m.Resolve(tt.service, tt.api)
			if res.IsFallback != tt.isFallback {
				t.Errorf("expected IsFallback=%v, got %v", tt.isFallback, res.IsFallback)
			}
			if len(res.Actions) != len(tt.expectedActions) {
				t.Fatalf("expected actions %v, got %v", tt.expectedActions, res.Actions)
			}
			for i, act := range tt.expectedActions {
				if res.Actions[i] != act {
					t.Errorf("action[%d]: expected %q, got %q", i, act, res.Actions[i])
				}
			}
			if tt.hasResourceARNs && len(res.ResourceARNs) == 0 {
				t.Errorf("expected resource ARNs to be present")
			}
		})
	}
}

func TestMapperExplain(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	res, err := m.Explain("s3:ListObjectsV2")
	if err != nil {
		t.Fatalf("Explain failed: %v", err)
	}
	if len(res.Actions) != 1 || res.Actions[0] != "s3:ListBucket" {
		t.Errorf("expected s3:ListBucket, got %v", res.Actions)
	}
	if res.IsFallback {
		t.Errorf("expected known mapping, got fallback")
	}

	// Invalid query
	_, err = m.Explain("invalidQueryFormat")
	if err == nil {
		t.Errorf("expected error for invalid query format")
	}
}

func TestMapperOverrides(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	overrideYAML := `
version: 1
mappings:
  - service: S3
    api: ListObjectsV2
    actions:
      - s3:CustomListBucketAction
    resource_arns:
      - "arn:aws:s3:::custom-bucket"
  - service: CustomNewService
    api: NewMethod
    actions:
      - custom:NewMethodAction
`
	if err := m.LoadOverrides([]byte(overrideYAML)); err != nil {
		t.Fatalf("LoadOverrides failed: %v", err)
	}

	res := m.Resolve("S3", "ListObjectsV2")
	if len(res.Actions) != 1 || res.Actions[0] != "s3:CustomListBucketAction" {
		t.Errorf("expected overridden action, got %v", res.Actions)
	}

	resCustom := m.Resolve("CustomNewService", "NewMethod")
	if resCustom.IsFallback {
		t.Errorf("expected custom mapping to be resolved, got fallback")
	}
	if len(resCustom.Actions) != 1 || resCustom.Actions[0] != "custom:NewMethodAction" {
		t.Errorf("expected custom:NewMethodAction, got %v", resCustom.Actions)
	}
}

func TestMapperExportYAML(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	out, err := m.ExportYAML()
	if err != nil {
		t.Fatalf("ExportYAML failed: %v", err)
	}

	yamlStr := string(out)
	if !strings.Contains(yamlStr, "ListObjectsV2") || !strings.Contains(yamlStr, "s3:ListBucket") {
		t.Errorf("exported YAML missing expected mappings: %s", yamlStr[:200])
	}
}
