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
	FormatCDKTF  FormatType = "cdktf"
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
	Effect       string
	Service      string
	AccessLevel  string
	Principal    string
	Actions      []ActionItem
	NotActions   []string
	ResourceARNs []string
	Conditions   map[string]map[string][]string
}

// PolicyType defines whether to generate identity policies, boundaries, SCPs, or resource policies.
type PolicyType string

const (
	PolicyTypeIdentity PolicyType = "identity"
	PolicyTypeBoundary PolicyType = "boundary"
	PolicyTypeSCP      PolicyType = "scp"
	PolicyTypeResource PolicyType = "resource"
)

// RenderOptions configures policy generation.
type RenderOptions struct {
	Format               FormatType
	PolicyType           PolicyType
	GroupByService       bool
	SplitByAccessLevel   bool
	StrictARNs           bool
	EmitVars             bool
	SynthesizeConditions bool
	SynthesizeNotAction  bool
	PrincipalARN         string
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

	var statements []Statement

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

		statements = []Statement{
			{
				Sid:          "AllowPolicyActions",
				Service:      "All",
				Actions:      allActions,
				ResourceARNs: resources,
			},
		}
	} else {
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
	}

	var finalStatements []Statement
	for _, s := range statements {
		stmt := s
		if opts.PolicyType == PolicyTypeSCP {
			stmt.ResourceARNs = []string{"*"}
		}
		if opts.PolicyType == PolicyTypeResource {
			if opts.PrincipalARN != "" {
				stmt.Principal = opts.PrincipalARN
			} else {
				stmt.Principal = "arn:aws:iam::${var.account_id}:root"
			}
		}
		if opts.SynthesizeConditions {
			stmt.Conditions = map[string]map[string][]string{
				"StringEquals": {
					"aws:RequestedRegion": []string{"${var.region}"},
				},
			}
		}
		if opts.SynthesizeNotAction {
			stmt.Effect = "Deny"
			for _, act := range stmt.Actions {
				stmt.NotActions = append(stmt.NotActions, act.Action)
			}
			stmt.Actions = nil
			stmt.ResourceARNs = []string{"*"}
		} else {
			stmt.Effect = "Allow"
		}
		finalStatements = append(finalStatements, stmt)
	}

	return finalStatements
}

// Render formats statements into the requested format (json, tf, cdk, cdktf, pulumi, cfn).
func Render(items []ActionItem, opts RenderOptions) (string, error) {
	statements := BuildStatements(items, opts)
	switch opts.Format {
	case FormatTF:
		return RenderTerraform(statements, opts.EmitVars), nil
	case FormatCDK:
		return RenderCDK(statements), nil
	case FormatCDKTF:
		return RenderCDKTF(statements), nil
	case FormatPulumi:
		return RenderPulumi(statements), nil
	case FormatCFN:
		return RenderCloudFormation(statements), nil
	case FormatJSON, "":
		return RenderJSON(statements)
	default:
		return "", fmt.Errorf("unsupported format %q (allowed: json, tf, cdk, cdktf, pulumi, cfn)", opts.Format)
	}
}

// RenderJSON formats statements as canonical AWS IAM JSON.
func RenderJSON(statements []Statement) (string, error) {
	type jsonPrincipal struct {
		AWS string `json:"AWS,omitempty"`
	}

	type jsonStatement struct {
		Sid       string                         `json:"Sid,omitempty"`
		Effect    string                         `json:"Effect"`
		Principal *jsonPrincipal                 `json:"Principal,omitempty"`
		Action    []string                       `json:"Action,omitempty"`
		NotAction []string                       `json:"NotAction,omitempty"`
		Resource  []string                       `json:"Resource"`
		Condition map[string]map[string][]string `json:"Condition,omitempty"`
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

		var notActions []string
		if len(stmt.NotActions) > 0 {
			notActions = append([]string(nil), stmt.NotActions...)
			sort.Strings(notActions)
		}

		var principal *jsonPrincipal
		if stmt.Principal != "" {
			principal = &jsonPrincipal{AWS: stmt.Principal}
		}

		eff := stmt.Effect
		if eff == "" {
			eff = "Allow"
		}

		policy.Statement = append(policy.Statement, jsonStatement{
			Sid:       stmt.Sid,
			Effect:    eff,
			Principal: principal,
			Action:    actionNames,
			NotAction: notActions,
			Resource:  stmt.ResourceARNs,
			Condition: stmt.Conditions,
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
		eff := stmt.Effect
		if eff == "" {
			eff = "Allow"
		}

		buf.WriteString("  statement {\n")
		buf.WriteString(fmt.Sprintf("    sid    = %q\n", stmt.Sid))
		buf.WriteString(fmt.Sprintf("    effect = %q\n", eff))

		if stmt.Principal != "" {
			buf.WriteString("    principals {\n")
			buf.WriteString("      type        = \"AWS\"\n")
			buf.WriteString(fmt.Sprintf("      identifiers = [%q]\n", stmt.Principal))
			buf.WriteString("    }\n")
		}

		// actions or not_actions
		if len(stmt.NotActions) > 0 {
			buf.WriteString("    not_actions = [\n")
			for _, na := range stmt.NotActions {
				buf.WriteString(fmt.Sprintf("      %q,\n", na))
			}
			buf.WriteString("    ]\n")
		} else {
			buf.WriteString("    actions = [\n")
			for _, act := range stmt.Actions {
				if act.IsFallback {
					buf.WriteString(fmt.Sprintf("      %q, # unmapped fallback from SDK call\n", act.Action))
				} else {
					buf.WriteString(fmt.Sprintf("      %q,\n", act.Action))
				}
			}
			buf.WriteString("    ]\n")
		}

		// resources
		buf.WriteString("    resources = [\n")
		for _, r := range stmt.ResourceARNs {
			buf.WriteString(fmt.Sprintf("      %q,\n", r))
			allResources = append(allResources, r)
		}
		buf.WriteString("    ]\n")

		if len(stmt.Conditions) > 0 {
			for test, varMap := range stmt.Conditions {
				for varName, vals := range varMap {
					buf.WriteString("    condition {\n")
					buf.WriteString(fmt.Sprintf("      test     = %q\n", test))
					buf.WriteString(fmt.Sprintf("      variable = %q\n", varName))
					buf.WriteString("      values   = [\n")
					for _, val := range vals {
						buf.WriteString(fmt.Sprintf("        %q,\n", val))
						allResources = append(allResources, val)
					}
					buf.WriteString("      ]\n")
					buf.WriteString("    }\n")
				}
			}
		}

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

// RenderCDKTF formats statements as TypeScript CDKTF DataAwsIamPolicyDocument.
func RenderCDKTF(statements []Statement) string {
	var buf bytes.Buffer
	buf.WriteString("import { DataAwsIamPolicyDocument } from \"@cdktf/provider-aws/lib/data-aws-iam-policy-document\";\n")
	buf.WriteString("import { Construct } from \"constructs\";\n\n")
	buf.WriteString("export function createGeneratedPolicy(scope: Construct, id: string): DataAwsIamPolicyDocument {\n")
	buf.WriteString("  return new DataAwsIamPolicyDocument(scope, id, {\n")
	buf.WriteString("    statement: [\n")

	for _, stmt := range statements {
		eff := stmt.Effect
		if eff == "" {
			eff = "Allow"
		}
		buf.WriteString("      {\n")
		buf.WriteString(fmt.Sprintf("        sid: %q,\n", stmt.Sid))
		buf.WriteString(fmt.Sprintf("        effect: %q,\n", eff))

		if len(stmt.NotActions) > 0 {
			buf.WriteString("        notActions: [\n")
			for _, na := range stmt.NotActions {
				buf.WriteString(fmt.Sprintf("          %q,\n", na))
			}
			buf.WriteString("        ],\n")
		} else {
			buf.WriteString("        actions: [\n")
			for _, act := range stmt.Actions {
				if act.IsFallback {
					buf.WriteString(fmt.Sprintf("          %q, // unmapped fallback\n", act.Action))
				} else {
					buf.WriteString(fmt.Sprintf("          %q,\n", act.Action))
				}
			}
			buf.WriteString("        ],\n")
		}

		buf.WriteString("        resources: [\n")
		for _, r := range stmt.ResourceARNs {
			buf.WriteString(fmt.Sprintf("          %q,\n", r))
		}
		buf.WriteString("        ],\n")
		buf.WriteString("      },\n")
	}

	buf.WriteString("    ],\n")
	buf.WriteString("  });\n")
	buf.WriteString("}\n")
	return buf.String()
}
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
