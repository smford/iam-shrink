package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/smford/iam-shrink/internal/compliance"
	"gopkg.in/yaml.v3"
)

// ProwlerBenchmark mirrors the upstream Prowler CIS AWS JSON structure.
type ProwlerBenchmark struct {
	Framework    string               `json:"Framework"`
	Name         string               `json:"Name"`
	Version      string               `json:"Version"`
	Provider     string               `json:"Provider"`
	Description  string               `json:"Description"`
	Requirements []ProwlerRequirement `json:"Requirements"`
}

type ProwlerRequirement struct {
	ID          string             `json:"Id"`
	Description string             `json:"Description"`
	Checks      []string           `json:"Checks"`
	Attributes  []ProwlerAttribute `json:"Attributes"`
}

type ProwlerAttribute struct {
	Section              string `json:"Section"`
	Profile              string `json:"Profile"`
	Description          string `json:"Description"`
	RationaleStatement   string `json:"RationaleStatement"`
	RemediationProcedure string `json:"RemediationProcedure"`
}

func main() {
	outDir := flag.String("out-dir", "internal/compliance/embedded", "Directory to write embedded compliance YAML files")
	prowlerURL := flag.String("prowler-url", "https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/compliance/aws/cis_3.0_aws.json", "Upstream Prowler CIS AWS Benchmark JSON URL")
	flag.Parse()

	fmt.Printf("Fetching upstream CIS AWS benchmark from %s...\n", *prowlerURL)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(*prowlerURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to fetch upstream Prowler JSON: %v. Using canonical baseline.\n", err)
	}

	var prowlerData ProwlerBenchmark
	if resp != nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &prowlerData)
		fmt.Printf("Successfully loaded %d requirements from upstream %s v%s\n", len(prowlerData.Requirements), prowlerData.Framework, prowlerData.Version)
	}

	// Index Prowler requirements by Control ID for enriched descriptions and remediations
	reqByID := make(map[string]ProwlerRequirement)
	for _, req := range prowlerData.Requirements {
		reqByID[req.ID] = req
	}

	cisStandard := buildCISStandard(reqByID)
	if err := writeYAMLFile(filepath.Join(*outDir, "cis_v3.yaml"), cisStandard); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing cis_v3.yaml: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Successfully synced %s (%d rules)\n", filepath.Join(*outDir, "cis_v3.yaml"), len(cisStandard.Rules))

	nistStandard := buildNISTStandard()
	if err := writeYAMLFile(filepath.Join(*outDir, "nist_800_53.yaml"), nistStandard); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing nist_800_53.yaml: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Successfully synced %s (%d rules)\n", filepath.Join(*outDir, "nist_800_53.yaml"), len(nistStandard.Rules))
}

func buildCISStandard(prowlerReqs map[string]ProwlerRequirement) compliance.Standard {
	rules := []compliance.Rule{
		{
			ID:          "CIS-1.16-NO-WILDCARD-ADMIN",
			ControlID:   "1.16",
			Title:       getReqTitle(prowlerReqs, "1.16", "Ensure IAM policies that allow full administrative privileges are not created"),
			Severity:    "CRITICAL",
			DenyActions: []string{"*"},
			Remediation: getReqRemediation(prowlerReqs, "1.16", "Remove full administrative Action '*' and scope down to specific least-privilege actions."),
		},
		{
			ID:                             "CIS-1.20-NO-UNCONSTRAINED-PASSROLE",
			ControlID:                      "1.20",
			Title:                          "Ensure iam:PassRole access is not granted on wildcard resource '*'",
			Severity:                       "HIGH",
			DenyWildcardResourcesOnActions: []string{"iam:passrole"},
			Remediation:                    "Restrict iam:PassRole to specific, authorized role ARNs instead of '*'.",
		},
		{
			ID:                             "CIS-1.21-NO-UNCONSTRAINED-ASSUMEROLE",
			ControlID:                      "1.21",
			Title:                          "Ensure sts:AssumeRole access is not granted on wildcard resource '*'",
			Severity:                       "HIGH",
			DenyWildcardResourcesOnActions: []string{"sts:assumerole"},
			Remediation:                    "Restrict sts:AssumeRole to specific role ARNs.",
		},
		{
			ID:        "CIS-1.22-NO-SERVICE-WILDCARD",
			ControlID: "1.22",
			Title:     "Ensure service-level wildcard actions are not used",
			Severity:  "MEDIUM",
			DenyActions: []string{
				"s3:*",
				"dynamodb:*",
				"iam:*",
				"kms:*",
				"sqs:*",
				"ec2:*",
			},
			Remediation: "Scope down service wildcards (e.g. s3:*) to the exact APIs exercised at runtime.",
		},
	}

	return compliance.Standard{
		Name:        "CIS AWS Foundations Benchmark",
		Version:     "v3.0.0",
		Description: "Security guidelines and baseline controls for AWS IAM policies",
		Rules:       rules,
	}
}

func buildNISTStandard() compliance.Standard {
	rules := []compliance.Rule{
		{
			ID:          "NIST-AC-6-LEAST-PRIVILEGE-ADMIN",
			ControlID:   "AC-6",
			Title:       "Least Privilege - Prevent Uncontrolled Administrative Privileges",
			Severity:    "CRITICAL",
			DenyActions: []string{"*"},
			Remediation: "Implement least privilege by strictly removing wildcard actions.",
		},
		{
			ID:        "NIST-AC-6-LEAST-PRIVILEGE-RESOURCES",
			ControlID: "AC-6",
			Title:     "Least Privilege - Scope Resource Boundaries for Sensitive APIs",
			Severity:  "HIGH",
			DenyWildcardResourcesOnActions: []string{
				"iam:passrole",
				"iam:createpolicyversion",
				"iam:attachrolepolicy",
				"iam:putrolepolicy",
				"sts:assumerole",
			},
			Remediation: "Define explicit resource ARNs for delegation and policy attachment actions.",
		},
		{
			ID:        "NIST-AC-3-ACCESS-ENFORCEMENT",
			ControlID: "AC-3",
			Title:     "Access Enforcement - Avoid Unbounded Service Grants",
			Severity:  "MEDIUM",
			DenyActions: []string{
				"s3:*",
				"dynamodb:*",
				"kms:*",
				"iam:*",
			},
			Remediation: "Restrict permissions to verified operational calls.",
		},
		{
			ID:                             "NIST-SC-12-CRYPTOGRAPHIC-PROTECTION",
			ControlID:                      "SC-12",
			Title:                          "Cryptographic Key Management - Constrain KMS Decrypt/Encrypt Keys",
			Severity:                       "HIGH",
			DenyWildcardResourcesOnActions: []string{"kms:decrypt"},
			Remediation:                    "Restrict kms:Decrypt to designated key ARNs instead of '*'.",
		},
	}

	return compliance.Standard{
		Name:        "NIST SP 800-53",
		Version:     "Rev 5",
		Description: "Security and Privacy Controls for Information Systems and Organizations",
		Rules:       rules,
	}
}

func getReqTitle(reqs map[string]ProwlerRequirement, id string, fallback string) string {
	if req, ok := reqs[id]; ok && req.Description != "" {
		return req.Description
	}
	return fallback
}

func getReqRemediation(reqs map[string]ProwlerRequirement, id string, fallback string) string {
	if req, ok := reqs[id]; ok && len(req.Attributes) > 0 {
		proc := strings.TrimSpace(req.Attributes[0].RemediationProcedure)
		if proc != "" && !strings.HasPrefix(proc, "From Console") && !strings.HasPrefix(proc, "This activity") {
			return proc
		}
	}
	return fallback
}

func writeYAMLFile(path string, std compliance.Standard) error {
	data, err := yaml.Marshal(std)
	if err != nil {
		return fmt.Errorf("marshaling YAML: %w", err)
	}

	// Verify roundtrip parsing against compliance.Standard
	var verify compliance.Standard
	if err := yaml.Unmarshal(data, &verify); err != nil {
		return fmt.Errorf("validating roundtrip YAML: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}
