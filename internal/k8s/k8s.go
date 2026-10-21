package k8s

import (
	"bytes"
	"fmt"
)

// ManifestOptions defines settings for Kubernetes IRSA and pod telemetry generation.
type ManifestOptions struct {
	DeploymentName string
	Namespace      string
	CSMPort        int
	ProxyPort      int
	EnableProxy    bool
	Image          string
}

// GeneratePodSidecarYAML generates a Kubernetes Deployment manifest with an iam-shrink sidecar and IRSA telemetry env vars.
func GeneratePodSidecarYAML(opts ManifestOptions) string {
	if opts.CSMPort <= 0 {
		opts.CSMPort = 31000
	}
	if opts.ProxyPort <= 0 {
		opts.ProxyPort = 31001
	}
	if opts.DeploymentName == "" {
		opts.DeploymentName = "my-service"
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.Image == "" {
		opts.Image = "ghcr.io/smford/iam-shrink:latest"
	}

	var buf bytes.Buffer
	buf.WriteString("apiVersion: apps/v1\n")
	buf.WriteString("kind: Deployment\n")
	buf.WriteString("metadata:\n")
	buf.WriteString(fmt.Sprintf("  name: %s\n", opts.DeploymentName))
	buf.WriteString(fmt.Sprintf("  namespace: %s\n", opts.Namespace))
	buf.WriteString("spec:\n")
	buf.WriteString("  replicas: 1\n")
	buf.WriteString("  selector:\n")
	buf.WriteString("    matchLabels:\n")
	buf.WriteString(fmt.Sprintf("      app: %s\n", opts.DeploymentName))
	buf.WriteString("  template:\n")
	buf.WriteString("    metadata:\n")
	buf.WriteString("      labels:\n")
	buf.WriteString(fmt.Sprintf("        app: %s\n", opts.DeploymentName))
	buf.WriteString("    spec:\n")
	buf.WriteString("      containers:\n")
	buf.WriteString("        # Main Application Container\n")
	buf.WriteString(fmt.Sprintf("        - name: %s\n", opts.DeploymentName))
	buf.WriteString("          image: your-app-image:latest\n")
	buf.WriteString("          env:\n")
	buf.WriteString("            - name: AWS_CSM_ENABLED\n")
	buf.WriteString("              value: \"true\"\n")
	buf.WriteString("            - name: AWS_CSM_PORT\n")
	buf.WriteString(fmt.Sprintf("              value: %q\n", fmt.Sprintf("%d", opts.CSMPort)))
	buf.WriteString("            - name: AWS_CSM_HOST\n")
	buf.WriteString("              value: \"127.0.0.1\"\n")

	if opts.EnableProxy {
		buf.WriteString("            - name: HTTP_PROXY\n")
		buf.WriteString(fmt.Sprintf("              value: \"http://127.0.0.1:%d\"\n", opts.ProxyPort))
		buf.WriteString("            - name: HTTPS_PROXY\n")
		buf.WriteString(fmt.Sprintf("              value: \"http://127.0.0.1:%d\"\n", opts.ProxyPort))
		buf.WriteString("            - name: AWS_CA_BUNDLE\n")
		buf.WriteString("              value: \"/etc/iam-shrink/ca.pem\"\n")
	}

	buf.WriteString("        # iam-shrink CSM Telemetry Collector Sidecar\n")
	buf.WriteString("        - name: iam-shrink-collector\n")
	buf.WriteString(fmt.Sprintf("          image: %s\n", opts.Image))
	buf.WriteString("          args:\n")
	buf.WriteString("            - \"session\"\n")
	buf.WriteString("            - \"start\"\n")
	if opts.EnableProxy {
		buf.WriteString("            - \"--proxy\"\n")
	}
	buf.WriteString("          ports:\n")
	buf.WriteString(fmt.Sprintf("            - containerPort: %d\n", opts.CSMPort))
	buf.WriteString("              protocol: UDP\n")
	if opts.EnableProxy {
		buf.WriteString(fmt.Sprintf("            - containerPort: %d\n", opts.ProxyPort))
		buf.WriteString("              protocol: TCP\n")
	}

	return buf.String()
}
