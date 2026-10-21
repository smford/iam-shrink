package multicloud

import (
	"strings"
	"testing"

	"github.com/smford/iam-shrink/internal/render"
)

func sampleItems() []render.ActionItem {
	return []render.ActionItem{
		{Action: "s3:GetObject", Service: "s3"},
		{Action: "s3:PutObject", Service: "s3"},
		{Action: "kms:Decrypt", Service: "kms"},
		{Action: "dynamodb:PutItem", Service: "dynamodb"},
	}
}

func TestRenderGCPIAMCustomRole(t *testing.T) {
	out, err := RenderGCPIAMCustomRole(sampleItems())
	if err != nil {
		t.Fatalf("RenderGCPIAMCustomRole failed: %v", err)
	}

	if !strings.Contains(out, "storage.objects.get") || !strings.Contains(out, "cloudkms.cryptoKeyVersions.useToDecrypt") {
		t.Errorf("Expected GCP permissions in output:\n%s", out)
	}
}

func TestRenderAzureRBAC(t *testing.T) {
	out, err := RenderAzureRBAC(sampleItems())
	if err != nil {
		t.Fatalf("RenderAzureRBAC failed: %v", err)
	}

	if !strings.Contains(out, "Microsoft.Storage") || !strings.Contains(out, "Microsoft.KeyVault") {
		t.Errorf("Expected Azure permissions in output:\n%s", out)
	}
}

func TestRenderK8sRBAC(t *testing.T) {
	out := RenderK8sRBAC(sampleItems())
	if !strings.Contains(out, "kind: Role") || !strings.Contains(out, "resources: [\"s3\"]") {
		t.Errorf("Expected Kubernetes RBAC manifest in output:\n%s", out)
	}
}

func TestRenderVaultSecretRole(t *testing.T) {
	out := RenderVaultSecretRole(`{"Version": "2012-10-17"}`)
	if !strings.Contains(out, "vault write aws/roles/least-privilege-app") {
		t.Errorf("Expected Vault CLI command in output:\n%s", out)
	}
}
