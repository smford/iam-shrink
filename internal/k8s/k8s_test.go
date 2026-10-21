package k8s

import (
	"strings"
	"testing"
)

func TestGeneratePodSidecarYAML(t *testing.T) {
	opts := ManifestOptions{
		DeploymentName: "payment-service",
		Namespace:      "production",
		CSMPort:        31000,
		ProxyPort:      31001,
		EnableProxy:    true,
	}

	manifest := GeneratePodSidecarYAML(opts)

	if !strings.Contains(manifest, "name: payment-service") {
		t.Errorf("Expected deployment name payment-service")
	}
	if !strings.Contains(manifest, "name: AWS_CSM_ENABLED") {
		t.Errorf("Expected AWS_CSM_ENABLED env var")
	}
	if !strings.Contains(manifest, "name: iam-shrink-collector") {
		t.Errorf("Expected sidecar container name iam-shrink-collector")
	}
	if !strings.Contains(manifest, "containerPort: 31000") {
		t.Errorf("Expected UDP port 31000")
	}
	if !strings.Contains(manifest, "HTTP_PROXY") {
		t.Errorf("Expected HTTP_PROXY env var when EnableProxy is true")
	}
}
