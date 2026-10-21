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
	FormatJSON FormatType = "json"
	FormatTF   FormatType = "tf"
	FormatCDK  FormatType = "cdk"
)

// ActionItem represents a resolved IAM action with metadata for rendering.
type ActionItem struct {
	Action       string
	Service      string
	ResourceARNs []string
	IsFallback   bool
	FallbackNote string
}

// Statement represents an aggregated IAM policy statement.
type Statement struct {
	Sid          string
	Service      string
	Actions      []ActionItem
	ResourceARNs []string
}

// RenderOptions configures policy generation.
type RenderOptions struct {
	Format         FormatType
	GroupByService bool
	StrictARNs     bool
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

	if !opts.GroupByService {
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

	// Group by Service
	groups := make(map[string][]ActionItem)
	for _, it := range deduped {
		svc := serviceFromAction(it.Action)
		groups[svc] = append(groups[svc], it)
	}

	var services []string
	for svc := range groups {
		services = append(services, svc)
	}
	sort.Strings(services)

	var statements []Statement
	for _, svc := range services {
		actions := groups[svc]
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

		sid := sanitizeSid(svc)
		statements = append(statements, Statement{
			Sid:          sid,
			Service:      svc,
			Actions:      actions,
			ResourceARNs: resources,
		})
	}

	return statements
}

// Render formats statements into the requested format (json, tf, cdk).
func Render(items []ActionItem, opts RenderOptions) (string, error) {
	statements := BuildStatements(items, opts)
	switch opts.Format {
	case FormatTF:
		return RenderTerraform(statements), nil
	case FormatCDK:
		return RenderCDK(statements), nil
	case FormatJSON, "":
		return RenderJSON(statements)
	default:
		return "", fmt.Errorf("unsupported format %q (allowed: json, tf, cdk)", opts.Format)
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
func RenderTerraform(statements []Statement) string {
	var buf bytes.Buffer
	buf.WriteString("data \"aws_iam_policy_document\" \"generated\" {\n")

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
		}
		buf.WriteString("    ]\n")

		buf.WriteString("  }\n")
	}

	buf.WriteString("}\n")
	return buf.String()
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
