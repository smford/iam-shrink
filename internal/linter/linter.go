package linter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Severity indicates the risk level of an identified issue.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Issue represents a security vulnerability or anti-pattern detected in an IAM policy.
type Issue struct {
	Severity       Severity `json:"severity"`
	RuleID         string   `json:"rule_id"`
	Action         string   `json:"action"`
	Resource       string   `json:"resource"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
}

// StatementInput represents a generalized IAM statement to lint.
type StatementInput struct {
	Sid       string
	Effect    string
	Actions   []string
	Resources []string
}

// LintStatements checks a slice of StatementInput against IAM security rules.
func LintStatements(stmts []StatementInput) []Issue {
	var issues []Issue

	for _, stmt := range stmts {
		if strings.ToLower(stmt.Effect) == "deny" {
			continue // Deny statements with wildcards are generally fine
		}

		for _, action := range stmt.Actions {
			actLower := strings.ToLower(strings.TrimSpace(action))

			// Rule 1: Full Wildcard Action
			if actLower == "*" {
				issues = append(issues, Issue{
					Severity:       SeverityCritical,
					RuleID:         "NO_FULL_WILDCARD_ACTION",
					Action:         "*",
					Resource:       strings.Join(stmt.Resources, ", "),
					Description:    "Full administrator access granted via 'Action: *'.",
					Recommendation: "Specify exact service actions instead of a wildcard.",
				})
			}

			// Rule 2: Service-level Wildcard
			if strings.HasSuffix(actLower, ":*") {
				issues = append(issues, Issue{
					Severity:       SeverityMedium,
					RuleID:         "SERVICE_WILDCARD_ACTION",
					Action:         action,
					Resource:       strings.Join(stmt.Resources, ", "),
					Description:    fmt.Sprintf("Service-level wildcard '%s' grants all current and future APIs of this service.", action),
					Recommendation: "Scope down permissions to individual APIs invoked by the application.",
				})
			}

			// Rule 3: Privilege Escalation with Wildcard Resource
			for _, r := range stmt.Resources {
				rTrim := strings.TrimSpace(r)
				if rTrim == "*" {
					switch actLower {
					case "iam:passrole":
						issues = append(issues, Issue{
							Severity:       SeverityHigh,
							RuleID:         "PRIV_ESC_PASS_ROLE",
							Action:         action,
							Resource:       "*",
							Description:    "iam:PassRole granted on wildcard resource '*'. Allows passing any privileged role to a compute resource (EC2/Lambda/ECS).",
							Recommendation: "Constrain Resource to the specific role ARN(s) needed.",
						})
					case "iam:createpolicyversion":
						issues = append(issues, Issue{
							Severity:       SeverityHigh,
							RuleID:         "PRIV_ESC_CREATE_POLICY_VERSION",
							Action:         action,
							Resource:       "*",
							Description:    "iam:CreatePolicyVersion with Resource '*' allows privilege escalation by modifying policy versions.",
							Recommendation: "Restrict policy modification to specific policy ARNs.",
						})
					case "iam:attachrolepolicy", "iam:putrolepolicy", "iam:attachuserpolicy", "iam:putuserpolicy":
						issues = append(issues, Issue{
							Severity:       SeverityHigh,
							RuleID:         "PRIV_ESC_ATTACH_POLICY",
							Action:         action,
							Resource:       "*",
							Description:    fmt.Sprintf("%s with Resource '*' allows granting administrator permissions to roles or users.", action),
							Recommendation: "Restrict policy attachment actions to specific designated roles.",
						})
					case "sts:assumerole":
						issues = append(issues, Issue{
							Severity:       SeverityHigh,
							RuleID:         "PRIV_ESC_ASSUME_ROLE",
							Action:         action,
							Resource:       "*",
							Description:    "sts:AssumeRole with Resource '*' allows assuming any reachable role in the account or cross-account.",
							Recommendation: "Specify explicit role ARNs that the principal is authorized to assume.",
						})
					}
				}
			}
		}
	}

	sort.Slice(issues, func(i, j int) bool {
		sevOrder := map[Severity]int{
			SeverityCritical: 0,
			SeverityHigh:     1,
			SeverityMedium:   2,
			SeverityLow:      3,
		}
		if sevOrder[issues[i].Severity] != sevOrder[issues[j].Severity] {
			return sevOrder[issues[i].Severity] < sevOrder[issues[j].Severity]
		}
		return issues[i].Action < issues[j].Action
	})

	return issues
}

// LintPolicyJSON parses IAM policy JSON and runs security linter rules.
func LintPolicyJSON(data []byte) ([]Issue, error) {
	type rawStatement struct {
		Sid      string      `json:"Sid"`
		Effect   string      `json:"Effect"`
		Action   interface{} `json:"Action"`
		Resource interface{} `json:"Resource"`
	}

	type rawPolicy struct {
		Statement []rawStatement `json:"Statement"`
	}

	var pol rawPolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("decoding policy JSON: %w", err)
	}

	var stmts []StatementInput
	for _, s := range pol.Statement {
		eff := s.Effect
		if eff == "" {
			eff = "Allow"
		}

		var actions []string
		switch a := s.Action.(type) {
		case string:
			actions = append(actions, a)
		case []interface{}:
			for _, it := range a {
				if str, ok := it.(string); ok {
					actions = append(actions, str)
				}
			}
		}

		var resources []string
		switch r := s.Resource.(type) {
		case string:
			resources = append(resources, r)
		case []interface{}:
			for _, it := range r {
				if str, ok := it.(string); ok {
					resources = append(resources, str)
				}
			}
		}

		stmts = append(stmts, StatementInput{
			Sid:       s.Sid,
			Effect:    eff,
			Actions:   actions,
			Resources: resources,
		})
	}

	return LintStatements(stmts), nil
}

// LintFile reads an IAM policy file and analyzes it.
func LintFile(path string) ([]Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}
	return LintPolicyJSON(data)
}

// FormatIssues formats issues into a readable terminal report.
func FormatIssues(issues []Issue) string {
	if len(issues) == 0 {
		return "✓ No security issues or privilege escalation patterns detected.\n"
	}

	var sb strings.Builder
	sb.WriteString("============================================================\n")
	sb.WriteString(fmt.Sprintf("          IAM Security Linter Report (%d issues found)      \n", len(issues)))
	sb.WriteString("============================================================\n\n")

	for i, iss := range issues {
		sb.WriteString(fmt.Sprintf("[%s] #%d: %s (%s)\n", iss.Severity, i+1, iss.RuleID, iss.Action))
		sb.WriteString(fmt.Sprintf("  Resource:       %s\n", iss.Resource))
		sb.WriteString(fmt.Sprintf("  Description:    %s\n", iss.Description))
		sb.WriteString(fmt.Sprintf("  Recommendation: %s\n\n", iss.Recommendation))
	}

	return sb.String()
}
