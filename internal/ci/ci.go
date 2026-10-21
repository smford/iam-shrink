package ci

import (
	"fmt"
	"strings"

	"github.com/smford/iam-shrink/internal/compliance"
	"github.com/smford/iam-shrink/internal/diff"
	"github.com/smford/iam-shrink/internal/linter"
)

// GateOptions configures the CI/CD quality gate enforcement.
type GateOptions struct {
	FailOnWildcard bool
	MinCompliance  float64 // e.g. 100.0 or 80.0
	MaxSeverity    string  // e.g. "CRITICAL", "HIGH"
}

// GateResult holds the evaluation decision of the quality gate.
type GateResult struct {
	Passed  bool
	Reasons []string
}

// EvaluateGate checks actions, issues, and compliance scores against quality gate thresholds.
func EvaluateGate(actions []string, issues []linter.Issue, compReport *compliance.Report, opts GateOptions) GateResult {
	var reasons []string

	if opts.FailOnWildcard {
		for _, a := range actions {
			if strings.TrimSpace(a) == "*" || strings.HasSuffix(a, ":*") {
				reasons = append(reasons, fmt.Sprintf("Wildcard action disallowed: %s", a))
			}
		}
	}

	for _, iss := range issues {
		if iss.Severity == linter.SeverityCritical {
			reasons = append(reasons, fmt.Sprintf("Critical security risk: %s (%s)", iss.RuleID, iss.Action))
		}
		if opts.MaxSeverity == "HIGH" && iss.Severity == linter.SeverityHigh {
			reasons = append(reasons, fmt.Sprintf("High security risk: %s (%s)", iss.RuleID, iss.Action))
		}
	}

	if compReport != nil && opts.MinCompliance > 0 {
		if compReport.ComplianceScore < opts.MinCompliance {
			reasons = append(reasons, fmt.Sprintf("Compliance score %.1f%% below required minimum %.1f%%", compReport.ComplianceScore, opts.MinCompliance))
		}
	}

	return GateResult{
		Passed:  len(reasons) == 0,
		Reasons: reasons,
	}
}

// FormatPRComment produces a formatted GitHub/GitLab PR comment.
func FormatPRComment(diffRes *diff.Result, compReport *compliance.Report) string {
	var sb strings.Builder
	sb.WriteString("## 🛡️ `iam-shrink` Least-Privilege & Compliance Analysis\n\n")

	if diffRes != nil {
		badge := "🟢 Least-Privilege Enforced"
		if diffRes.ReductionPct > 0 {
			badge = fmt.Sprintf("📉 Reduced Permission Attack Surface by **%.1f%%**", diffRes.ReductionPct)
		}
		sb.WriteString(fmt.Sprintf("%s\n\n", badge))

		sb.WriteString("<details>\n<summary><b>📊 Permission Diff (Click to expand)</b></summary>\n\n")
		sb.WriteString(fmt.Sprintf("- **Existing Actions:** %d\n", len(diffRes.ExistingActions)))
		sb.WriteString(fmt.Sprintf("- **Runtime Actions Exercised:** %d\n", len(diffRes.CapturedActions)))
		sb.WriteString(fmt.Sprintf("- **Retained Actions:** %d\n", len(diffRes.RetainedActions)))
		sb.WriteString(fmt.Sprintf("- **Unused Permissions (Pruned):** %d\n", len(diffRes.UnusedActions)))
		sb.WriteString(fmt.Sprintf("- **Missing Permissions (Added):** %d\n\n", len(diffRes.MissingActions)))

		if len(diffRes.UnusedActions) > 0 {
			sb.WriteString("```diff\n# Unused Permissions Recommended for Pruning:\n")
			for _, a := range diffRes.UnusedActions {
				sb.WriteString(fmt.Sprintf("- %s\n", a))
			}
			sb.WriteString("```\n")
		}

		if len(diffRes.MissingActions) > 0 {
			sb.WriteString("```diff\n# Required Permissions Observed at Runtime:\n")
			for _, a := range diffRes.MissingActions {
				sb.WriteString(fmt.Sprintf("+ %s\n", a))
			}
			sb.WriteString("```\n")
		}

		sb.WriteString("</details>\n\n")
	}

	if compReport != nil {
		sb.WriteString(compReport.FormatMarkdown())
	}

	sb.WriteString("\n_Generated automatically by [iam-shrink](https://github.com/smford/iam-shrink)_ 🚀\n")
	return sb.String()
}
