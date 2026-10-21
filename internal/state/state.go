package state

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TFState represents the top-level Terraform / OpenTofu state JSON.
type TFState struct {
	Version   int          `json:"version"`
	Resources []TFResource `json:"resources"`
}

// TFResource represents a managed resource in state.
type TFResource struct {
	Type      string       `json:"type"`
	Name      string       `json:"name"`
	Instances []TFInstance `json:"instances"`
}

// TFInstance holds the instance attributes of a resource.
type TFInstance struct {
	Attributes map[string]interface{} `json:"attributes"`
}

// DiscoveredResource holds details of an actual resource found in state.
type DiscoveredResource struct {
	Type string
	Name string
	ARN  string
}

// ParseState extracts all AWS resources with ARNs from a terraform.tfstate file or bytes.
func ParseState(data []byte) ([]DiscoveredResource, error) {
	var s TFState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decoding terraform.tfstate JSON: %w", err)
	}

	var results []DiscoveredResource
	for _, res := range s.Resources {
		if !strings.HasPrefix(res.Type, "aws_") {
			continue
		}
		for _, inst := range res.Instances {
			if inst.Attributes == nil {
				continue
			}
			arn, _ := inst.Attributes["arn"].(string)
			if arn != "" {
				results = append(results, DiscoveredResource{
					Type: res.Type,
					Name: res.Name,
					ARN:  arn,
				})
			}
		}
	}
	return results, nil
}

// ResolvePolicyWithState substitutes ARN placeholders in policyText with actual ARNs from tfstate.
func ResolvePolicyWithState(policyText string, stateData []byte) (string, int, error) {
	resources, err := ParseState(stateData)
	if err != nil {
		return policyText, 0, err
	}

	replacements := 0
	result := policyText

	for _, r := range resources {
		switch r.Type {
		case "aws_s3_bucket":
			// Replace arn:aws:s3:::${var.bucket_name} with actual bucket ARN
			if strings.Contains(result, "arn:aws:s3:::${var.bucket_name}") {
				result = strings.ReplaceAll(result, "arn:aws:s3:::${var.bucket_name}", r.ARN)
				replacements++
			}
		case "aws_dynamodb_table":
			// Replace DynamoDB table ARN placeholder
			target := "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.table_name}"
			if strings.Contains(result, target) {
				result = strings.ReplaceAll(result, target, r.ARN)
				replacements++
			}
		case "aws_sqs_queue":
			target := "arn:aws:sqs:${var.region}:${var.account_id}:${var.queue_name}"
			if strings.Contains(result, target) {
				result = strings.ReplaceAll(result, target, r.ARN)
				replacements++
			}
		case "aws_kms_key":
			target := "arn:aws:kms:${var.region}:${var.account_id}:key/${var.key_id}"
			if strings.Contains(result, target) {
				result = strings.ReplaceAll(result, target, r.ARN)
				replacements++
			}
		case "aws_lambda_function":
			target := "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.function_name}"
			if strings.Contains(result, target) {
				result = strings.ReplaceAll(result, target, r.ARN)
				replacements++
			}
		}
	}

	return result, replacements, nil
}

// ResolvePolicyFile reads a policy file and resolves placeholders using a tfstate file.
func ResolvePolicyFile(policyPath, statePath string) (string, int, error) {
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return "", 0, fmt.Errorf("reading policy file %s: %w", policyPath, err)
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		return "", 0, fmt.Errorf("reading state file %s: %w", statePath, err)
	}
	return ResolvePolicyWithState(string(policyBytes), stateBytes)
}
