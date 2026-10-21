package compliance

import (
	"embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed embedded/*.yaml
var embeddedFS embed.FS

// Standard defines a set of compliance rules (e.g. CIS or NIST).
type Standard struct {
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description" json:"description"`
	Rules       []Rule `yaml:"rules" json:"rules"`
}

// Rule defines an individual compliance check against an IAM policy.
type Rule struct {
	ID                             string   `yaml:"id" json:"id"`
	ControlID                      string   `yaml:"control_id" json:"control_id"`
	Title                          string   `yaml:"title" json:"title"`
	Severity                       string   `yaml:"severity" json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	DenyActions                    []string `yaml:"deny_actions,omitempty" json:"deny_actions,omitempty"`
	DenyWildcardResourcesOnActions []string `yaml:"deny_wildcard_resources_on_actions,omitempty" json:"deny_wildcard_resources_on_actions,omitempty"`
	Remediation                    string   `yaml:"remediation" json:"remediation"`
}

// EvaluationResult records the outcome of a rule check.
type EvaluationResult struct {
	RuleID      string `json:"rule_id"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Passed      bool   `json:"passed"`
	Violations  []string `json:"violations,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Report aggregates compliance findings across evaluated standards.
type Report struct {
	StandardName    string             `json:"standard_name"`
	StandardVersion string             `json:"standard_version"`
	TotalRules      int                `json:"total_rules"`
	PassedRules     int                `json:"passed_rules"`
	FailedRules     int                `json:"failed_rules"`
	ComplianceScore float64            `json:"compliance_score"`
	Results         []EvaluationResult `json:"results"`
}

// Registry manages loaded compliance standards.
type Registry struct {
	standards map[string]Standard
}

// NewRegistry initializes the registry with embedded standards (CIS, NIST) and optional local overrides.
func NewRegistry(customRulesPath string) (*Registry, error) {
	r := &Registry{
		standards: make(map[string]Standard),
	}

	// 1. Load embedded standards
	cisData, err := embeddedFS.ReadFile("embedded/cis_v3.yaml")
	if err != nil {
		return nil, fmt.Errorf("reading embedded CIS rules: %w", err)
	}
	var cisStd Standard
	if err := yaml.Unmarshal(cisData, &cisStd); err == nil {
		r.standards["cis"] = cisStd
	}

	nistData, err := embeddedFS.ReadFile("embedded/nist_800_53.yaml")
	if err != nil {
		return nil, fmt.Errorf("reading embedded NIST rules: %w", err)
	}
	var nistStd Standard
	if err := yaml.Unmarshal(nistData, &nistStd); err == nil {
		r.standards["nist"] = nistStd
	}

	// 2. Check local cached rules in ~/.iam-shrink/rules/
	home, _ := os.UserHomeDir()
	if home != "" {
		rulesDir := filepath.Join(home, ".iam-shrink", "rules")
		_ = r.loadDir(rulesDir)
	}

	// 3. Load explicit custom rule file if specified
	if customRulesPath != "" {
		data, err := os.ReadFile(customRulesPath)
		if err != nil {
			return nil, fmt.Errorf("reading custom rules %s: %w", customRulesPath, err)
		}
		var customStd Standard
		if err := yaml.Unmarshal(data, &customStd); err != nil {
			return nil, fmt.Errorf("parsing custom rules: %w", err)
		}
		key := strings.ToLower(customStd.Name)
		if key == "" {
			key = "custom"
		}
		r.standards[key] = customStd
	}

	return r, nil
}

func (r *Registry) loadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err == nil {
				var std Standard
				if err := yaml.Unmarshal(data, &std); err == nil {
					key := strings.ToLower(std.Name)
					if strings.Contains(key, "cis") {
						key = "cis"
					} else if strings.Contains(key, "nist") {
						key = "nist"
					}
					r.standards[key] = std
				}
			}
		}
	}
	return nil
}

// EvaluateStatementInput runs compliance checks against policy statements.
func (r *Registry) Evaluate(standardName string, actions []string, resourcesByAction map[string][]string) (*Report, error) {
	stdKey := strings.ToLower(strings.TrimSpace(standardName))
	std, ok := r.standards[stdKey]
	if !ok {
		return nil, fmt.Errorf("compliance standard %q not found (available: cis, nist)", standardName)
	}

	actionSet := make(map[string]bool)
	for _, a := range actions {
		actionSet[strings.ToLower(strings.TrimSpace(a))] = true
	}

	var results []EvaluationResult
	passedCount := 0

	for _, rule := range std.Rules {
		res := EvaluationResult{
			RuleID:      rule.ID,
			ControlID:   rule.ControlID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			Passed:      true,
			Remediation: rule.Remediation,
		}

		// Check DenyActions
		for _, deny := range rule.DenyActions {
			denyLower := strings.ToLower(deny)
			if actionSet[denyLower] {
				res.Passed = false
				res.Violations = append(res.Violations, fmt.Sprintf("Action '%s' violates rule", deny))
			}
		}

		// Check DenyWildcardResourcesOnActions
		for _, sensitiveAct := range rule.DenyWildcardResourcesOnActions {
			sensitiveLower := strings.ToLower(sensitiveAct)
			if actionSet[sensitiveLower] {
				resources := resourcesByAction[sensitiveLower]
				for _, r := range resources {
					if strings.TrimSpace(r) == "*" {
						res.Passed = false
						res.Violations = append(res.Violations, fmt.Sprintf("Action '%s' is granted with wildcard resource '*'", sensitiveAct))
					}
				}
			}
		}

		if res.Passed {
			passedCount++
		}
		results = append(results, res)
	}

	total := len(std.Rules)
	score := 100.0
	if total > 0 {
		score = (float64(passedCount) / float64(total)) * 100.0
	}

	return &Report{
		StandardName:    std.Name,
		StandardVersion: std.Version,
		TotalRules:      total,
		PassedRules:     passedCount,
		FailedRules:     total - passedCount,
		ComplianceScore: score,
		Results:         results,
	}, nil
}

// FormatTerminal outputs the report for CLI viewing.
func (rep *Report) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("============================================================\n")
	sb.WriteString(fmt.Sprintf("       Compliance Report: %s (%s)\n", rep.StandardName, rep.StandardVersion))
	sb.WriteString("============================================================\n\n")

	sb.WriteString(fmt.Sprintf("Compliance Score: %.1f%%  (%d/%d Controls Passed)\n\n", rep.ComplianceScore, rep.PassedRules, rep.TotalRules))

	sort.Slice(rep.Results, func(i, j int) bool {
		if rep.Results[i].Passed != rep.Results[j].Passed {
			return !rep.Results[i].Passed // Failed first
		}
		return rep.Results[i].ControlID < rep.Results[j].ControlID
	})

	for _, res := range rep.Results {
		if res.Passed {
			sb.WriteString(fmt.Sprintf("[PASS] Control %s: %s\n", res.ControlID, res.Title))
		} else {
			sb.WriteString(fmt.Sprintf("[FAIL] [%s] Control %s: %s\n", res.Severity, res.ControlID, res.Title))
			for _, v := range res.Violations {
				sb.WriteString(fmt.Sprintf("  - %s\n", v))
			}
			if res.Remediation != "" {
				sb.WriteString(fmt.Sprintf("  Remediation: %s\n", res.Remediation))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatMarkdown outputs the report formatted for GitHub/GitLab PR comments.
func (rep *Report) FormatMarkdown() string {
	var sb strings.Builder
	statusBadge := "🟢 Compliant"
	if rep.ComplianceScore < 100.0 {
		statusBadge = "🟡 Action Required"
	}
	if rep.ComplianceScore < 75.0 {
		statusBadge = "🔴 Non-Compliant"
	}

	sb.WriteString(fmt.Sprintf("### 🛡️ Compliance Audit: %s (%s) — %s\n\n", rep.StandardName, rep.StandardVersion, statusBadge))
	sb.WriteString(fmt.Sprintf("**Compliance Score:** `%.1f%%` (%d/%d checks passed)\n\n", rep.ComplianceScore, rep.PassedRules, rep.TotalRules))

	sb.WriteString("| Control | Severity | Status | Details |\n")
	sb.WriteString("| :--- | :--- | :---: | :--- |\n")

	for _, res := range rep.Results {
		status := "✅ PASS"
		details := "-"
		if !res.Passed {
			status = "❌ FAIL"
			details = strings.Join(res.Violations, "<br>")
			if res.Remediation != "" {
				details += fmt.Sprintf("<br>_Fix: %s_", res.Remediation)
			}
		}
		sb.WriteString(fmt.Sprintf("| **%s** %s | `%s` | %s | %s |\n", res.ControlID, res.Title, res.Severity, status, details))
	}
	sb.WriteString("\n")
	return sb.String()
}

// UpdateRules fetches fresh rules from a remote URL or updates ~/.iam-shrink/rules/.
func UpdateRules(sourceURL string) (string, error) {
	if sourceURL == "" {
		sourceURL = "https://raw.githubusercontent.com/smford/iam-shrink/main/internal/compliance/embedded/cis_v3.yaml"
	}

	resp, err := http.Get(sourceURL)
	if err != nil {
		return "", fmt.Errorf("downloading rules from %s: %w", sourceURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with HTTP %d from %s", resp.StatusCode, sourceURL)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	var std Standard
	if err := yaml.Unmarshal(data, &std); err != nil {
		return "", fmt.Errorf("validating downloaded rule schema: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}

	destDir := filepath.Join(home, ".iam-shrink", "rules")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("creating directory %s: %w", destDir, err)
	}

	filename := "updated_rules.yaml"
	if strings.Contains(strings.ToLower(std.Name), "cis") {
		filename = "cis_v3.yaml"
	} else if strings.Contains(strings.ToLower(std.Name), "nist") {
		filename = "nist_800_53.yaml"
	}

	destPath := filepath.Join(destDir, filename)
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return "", fmt.Errorf("saving rules to %s: %w", destPath, err)
	}

	return destPath, nil
}
