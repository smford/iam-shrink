package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// FormatType defines supported output formats.
type FormatType string

const (
	FormatJSON   FormatType = "json"
	FormatTF     FormatType = "tf"
	FormatCDK    FormatType = "cdk"
	FormatPulumi FormatType = "pulumi"
	FormatCFN    FormatType = "cfn"
)

// ActionItem represents a resolved IAM action with metadata for rendering.
type ActionItem struct {
	Action       string
	Service      string
	ResourceARNs []string
	AccessLevel  string
	IsFallback   bool
	FallbackNote string
}

// Statement represents an aggregated IAM policy statement.
type Statement struct {
	Sid          string
	Service      string
	AccessLevel  string
	Actions      []ActionItem
	ResourceARNs []string
}

// RenderOptions configures policy generation.
type RenderOptions struct {
	Format             FormatType
	GroupByService     bool
	SplitByAccessLevel bool
	StrictARNs         bool
	EmitVars           bool
}

// BuildStatements aggregates and deduplicates ActionItems according to options.
func BuildStatements(items []ActionItem, opts RenderOptions) []Statement {
	if len(items) == 0 {
		return nil
	}

	// Deduplicate items by action name, merging resource ARNs
	merged := make(map[string]*ActionItem)
	for _, item := range items {
		existing, ok := merged[item.Action]
		if !ok {
			copyItem := item
			// copy resource ARNs slice
			if len(item.ResourceARNs) > 0 {
				copyItem.ResourceARNs = append([]string(nil), item.ResourceARNs...)
			}
			merged[item.Action] = &copyItem
		} else {
			// Merge resource ARNs
			existing.ResourceARNs = append(existing.ResourceARNs, item.ResourceARNs...)
			if item.IsFallback {
				existing.IsFallback = true
			}
		}
	}

	// Normalise actions
	var deduped []ActionItem
	for _, item := range merged {
		item.ResourceARNs = uniqueSortedStrings(item.ResourceARNs)
		deduped = append(deduped, *item)
	}

	sort.Slice(deduped, func(i, j int) bool {
		return deduped[i].Action < deduped[j].Action
	})

	if !opts.GroupByService && !opts.SplitByAccessLevel {
		var allActions []ActionItem
		var allResources []string
		for _, it := range deduped {
			allActions = append(allActions, it)
			if opts.StrictARNs && len(it.ResourceARNs) > 0 {
				allResources = append(allResources, it.ResourceARNs...)
			}
		}

		resources := []string{"*"}
		if opts.StrictARNs && len(allResources) > 0 {
			resources = uniqueSortedStrings(allResources)
		}

		return []Statement{
			{
				Sid:          "AllowPolicyActions",
				Service:      "All",
				Actions:      allActions,
				ResourceARNs: resources,
			},
		}
	}

	// Grouping
	groups := make(map[string][]ActionItem)
	for _, it := range deduped {
		var groupKey string
		svc := serviceFromAction(it.Action)
		access := it.AccessLevel
		if access == "" {
			access = "General"
		}

		if opts.GroupByService && opts.SplitByAccessLevel {
			groupKey = sanitizeSid(svc) + sanitizeSid(access)
		} else if opts.SplitByAccessLevel {
			groupKey = sanitizeSid(access) + "Permissions"
		} else {
			groupKey = sanitizeSid(svc)
		}

		groups[groupKey] = append(groups[groupKey], it)
	}

	var groupKeys []string
	for k := range groups {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)

	var statements []Statement
	for _, k := range groupKeys {
		actions := groups[k]
		var resources []string
		if opts.StrictARNs {
			for _, act := range actions {
				resources = append(resources, act.ResourceARNs...)
			}
			resources = uniqueSortedStrings(resources)
		}
		if len(resources) == 0 {
			resources = []string{"*"}
		}

		statements = append(statements, Statement{
			Sid:          k,
			Actions:      actions,
			ResourceARNs: resources,
		})
	}

	return statements
}

// Render formats statements into the requested format (json, tf, cdk, pulumi, cfn).
func Render(items []ActionItem, opts RenderOptions) (string, error) {
	statements := BuildStatements(items, opts)
	switch opts.Format {
	case FormatTF:
		return RenderTerraform(statements, opts.EmitVars), nil
	case FormatCDK:
		return RenderCDK(statements), nil
	case FormatPulumi:
		return RenderPulumi(statements), nil
	case FormatCFN:
		return RenderCloudFormation(statements), nil
	case FormatJSON, "":
		return RenderJSON(statements)
	default:
		return "", fmt.Errorf("unsupported format %q (allowed: json, tf, cdk, pulumi, cfn)", opts.Format)
	}
}

// RenderJSON formats statements as canonical AWS IAM JSON.
func RenderJSON(statements []Statement) (string, error) {
	type jsonStatement struct {
		Sid      string   `json:"Sid,omitempty"`
		Effect   string   `json:"Effect"`
		Action   []string `json:"Action"`
		Resource []string `json:"Resource"`
	}

	type jsonPolicy struct {
		Version   string          `json:"Version"`
		Statement []jsonStatement `json:"Statement"`
	}

	var policy jsonPolicy
	policy.Version = "2012-10-17"

	for _, stmt := range statements {
		var actionNames []string
		for _, act := range stmt.Actions {
			actionNames = append(actionNames, act.Action)
		}
		sort.Strings(actionNames)

		policy.Statement = append(policy.Statement, jsonStatement{
			Sid:      stmt.Sid,
			Effect:   "Allow",
			Action:   actionNames,
			Resource: stmt.ResourceARNs,
		})
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// RenderTerraform formats statements as Terraform HCL data aws_iam_policy_document block.
func RenderTerraform(statements []Statement, emitVars bool) string {
	var buf bytes.Buffer
	buf.WriteString("data \"aws_iam_policy_document\" \"generated\" {\n")

	var allResources []string

	for i, stmt := range statements {
		if i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString("  statement {\n")
		buf.WriteString(fmt.Sprintf("    sid    = %q\n", stmt.Sid))
		buf.WriteString("    effect = \"Allow\"\n")

		// actions
		buf.WriteString("    actions = [\n")
		for _, act := range stmt.Actions {
			if act.IsFallback {
				buf.WriteString(fmt.Sprintf("      %q, # unmapped fallback from SDK call\n", act.Action))
			} else {
				buf.WriteString(fmt.Sprintf("      %q,\n", act.Action))
			}
		}
		buf.WriteString("    ]\n")

		// resources
		buf.WriteString("    resources = [\n")
		for _, r := range stmt.ResourceARNs {
			buf.WriteString(fmt.Sprintf("      %q,\n", r))
			allResources = append(allResources, r)
		}
		buf.WriteString("    ]\n")

		buf.WriteString("  }\n")
	}

	buf.WriteString("}\n")

	if emitVars {
		vars := extractTerraformVars(allResources)
		if len(vars) > 0 {
			buf.WriteString("\n# Companion Terraform variable definitions:\n")
			for _, v := range vars {
				buf.WriteString(fmt.Sprintf("variable %q {\n  type        = string\n  description = %q\n}\n\n", v, "Auto-extracted IAM ARN placeholder"))
			}
		}
	}

	return buf.String()
}

func extractTerraformVars(resources []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, r := range resources {
		idx := 0
		for {
			start := strings.Index(r[idx:], "${var.")
			if start == -1 {
				break
			}
			startPos := idx + start + len("${var.")
			end := strings.Index(r[startPos:], "}")
			if end == -1 {
				break
			}
			varName := r[startPos : startPos+end]
			if !seen[varName] {
				seen[varName] = true
				out = append(out, varName)
			}
			idx = startPos + end + 1
		}
	}
	sort.Strings(out)
	return out
}

// RenderPulumi formats statements as TypeScript Pulumi aws.iam.getPolicyDocumentOutput definitions.
func RenderPulumi(statements []Statement) string {
	var buf bytes.Buffer
	buf.WriteString("import * as aws from \"@pulumi/aws\";\n\n")
	buf.WriteString("export const generatedPolicy = aws.iam.getPolicyDocumentOutput({\n")
	buf.WriteString("    statements: [\n")

	for _, stmt := range statements {
		buf.WriteString("        {\n")
		buf.WriteString(fmt.Sprintf("            sid: %q,\n", stmt.Sid))
		buf.WriteString("            effect: \"Allow\",\n")

		// actions
		buf.WriteString("            actions: [\n")
		for _, act := range stmt.Actions {
			if act.IsFallback {
				buf.WriteString(fmt.Sprintf("                %q, // unmapped fallback from SDK call\n", act.Action))
			} else {
				buf.WriteString(fmt.Sprintf("                %q,\n", act.Action))
			}
		}
		buf.WriteString("            ],\n")

		// resources
		buf.WriteString("            resources: [\n")
		for _, r := range stmt.ResourceARNs {
			buf.WriteString(fmt.Sprintf("                %q,\n", r))
		}
		buf.WriteString("            ],\n")

		buf.WriteString("        },\n")
	}

	buf.WriteString("    ],\n")
	buf.WriteString("});\n")
	return buf.String()
}

// RenderCloudFormation formats statements as a CloudFormation IAM ManagedPolicy template.
func RenderCloudFormation(statements []Statement) string {
	type cfnStatement struct {
		Sid      string   `json:"Sid"`
		Effect   string   `json:"Effect"`
		Action   []string `json:"Action"`
		Resource []string `json:"Resource"`
	}

	type cfnPolicyDoc struct {
		Version   string         `json:"Version"`
		Statement []cfnStatement `json:"Statement"`
	}

	type cfnProperties struct {
		PolicyDocument cfnPolicyDoc `json:"PolicyDocument"`
	}

	type cfnResource struct {
		Type       string        `json:"Type"`
		Properties cfnProperties `json:"Properties"`
	}

	type cfnTemplate struct {
		AWSTemplateFormatVersion string                 `json:"AWSTemplateFormatVersion"`
		Description              string                 `json:"Description"`
		Resources                map[string]cfnResource `json:"Resources"`
	}

	var stmts []cfnStatement
	for _, stmt := range statements {
		var actions []string
		for _, act := range stmt.Actions {
			actions = append(actions, act.Action)
		}
		sort.Strings(actions)
		stmts = append(stmts, cfnStatement{
			Sid:      stmt.Sid,
			Effect:   "Allow",
			Action:   actions,
			Resource: stmt.ResourceARNs,
		})
	}

	template := cfnTemplate{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              "Generated least-privilege IAM policy by iam-shrink",
		Resources: map[string]cfnResource{
			"GeneratedIamPolicy": {
				Type: "AWS::IAM::ManagedPolicy",
				Properties: cfnProperties{
					PolicyDocument: cfnPolicyDoc{
						Version:   "2012-10-17",
						Statement: stmts,
					},
				},
			},
		},
	}

	data, _ := json.MarshalIndent(template, "", "  ")
	return string(data) + "\n"
}

// RenderCDK formats statements as TypeScript AWS CDK iam.PolicyStatement constructs.
func RenderCDK(statements []Statement) string {
	var buf bytes.Buffer
	buf.WriteString("import * as iam from 'aws-cdk-lib/aws-iam';\n\n")
	buf.WriteString("export const generatedStatements = [\n")

	for _, stmt := range statements {
		buf.WriteString("  new iam.PolicyStatement({\n")
		buf.WriteString(fmt.Sprintf("    sid: '%s',\n", escapeSingleQuote(stmt.Sid)))
		buf.WriteString("    effect: iam.Effect.ALLOW,\n")

		// actions
		buf.WriteString("    actions: [\n")
		for _, act := range stmt.Actions {
			if act.IsFallback {
				buf.WriteString(fmt.Sprintf("      '%s', // unmapped fallback from SDK call\n", escapeSingleQuote(act.Action)))
			} else {
				buf.WriteString(fmt.Sprintf("      '%s',\n", escapeSingleQuote(act.Action)))
			}
		}
		buf.WriteString("    ],\n")

		// resources
		buf.WriteString("    resources: [\n")
		for _, r := range stmt.ResourceARNs {
			buf.WriteString(fmt.Sprintf("      '%s',\n", escapeSingleQuote(r)))
		}
		buf.WriteString("    ],\n")

		buf.WriteString("  }),\n")
	}

	buf.WriteString("];\n")
	return buf.String()
}

func escapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

func serviceFromAction(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return "custom"
}

func sanitizeSid(service string) string {
	var b strings.Builder
	nextUpper := true
	for _, r := range service {
		if r == '-' || r == '_' || r == '.' {
			nextUpper = true
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if nextUpper {
				b.WriteRune(unicode.ToUpper(r))
				nextUpper = false
			} else {
				b.WriteRune(r)
			}
		}
	}
	res := b.String()
	if res == "" {
		return "Default"
	}
	return res
}

func uniqueSortedStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}
