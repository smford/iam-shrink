package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// PolicyDocument represents the standard IAM Policy JSON structure.
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents an individual statement in IAM policy JSON.
type PolicyStatement struct {
	Sid      string      `json:"Sid,omitempty"`
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"` // string or []string
	Resource interface{} `json:"Resource"`
}

// Result holds the comparison metrics between an existing policy and a captured policy.
type Result struct {
	ExistingActions []string
	CapturedActions []string
	UnusedActions   []string // Present in existing, but never invoked (candidates to prune)
	MissingActions  []string // Invoked at runtime, but missing from existing policy
	RetainedActions []string // Invoked and present in existing policy
	ReductionPct    float64
}

// ParseActions extracts all unique normalized actions from IAM policy JSON bytes.
func ParseActions(data []byte) ([]string, error) {
	var doc PolicyDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing IAM policy JSON: %w", err)
	}

	seen := make(map[string]bool)
	var actions []string

	for _, stmt := range doc.Statement {
		switch val := stmt.Action.(type) {
		case string:
			act := strings.TrimSpace(val)
			if act != "" && !seen[act] {
				seen[act] = true
				actions = append(actions, act)
			}
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok {
					act := strings.TrimSpace(s)
					if act != "" && !seen[act] {
						seen[act] = true
						actions = append(actions, act)
					}
				}
			}
		}
	}

	sort.Strings(actions)
	return actions, nil
}

// ParseActionsFile reads a policy JSON file from disk and extracts actions.
func ParseActionsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}
	return ParseActions(data)
}

// Compare computes the difference between existing policy actions and captured actions.
func Compare(existing []string, captured []string) *Result {
	existingMap := make(map[string]bool)
	for _, a := range existing {
		existingMap[strings.ToLower(a)] = true
	}

	capturedMap := make(map[string]bool)
	for _, a := range captured {
		capturedMap[strings.ToLower(a)] = true
	}

	var unused []string
	var retained []string
	var missing []string

	for _, a := range existing {
		if !capturedMap[strings.ToLower(a)] {
			unused = append(unused, a)
		} else {
			retained = append(retained, a)
		}
	}

	for _, a := range captured {
		if !existingMap[strings.ToLower(a)] {
			missing = append(missing, a)
		}
	}

	sort.Strings(unused)
	sort.Strings(retained)
	sort.Strings(missing)

	reduction := 0.0
	if len(existing) > 0 {
		reduction = (float64(len(unused)) / float64(len(existing))) * 100.0
	}

	return &Result{
		ExistingActions: existing,
		CapturedActions: captured,
		UnusedActions:   unused,
		MissingActions:  missing,
		RetainedActions: retained,
		ReductionPct:    reduction,
	}
}

// Report formats the diff result into a human-readable summary.
func (r *Result) Report() string {
	var sb strings.Builder
	sb.WriteString("============================================================\n")
	sb.WriteString("                  IAM Policy Diff & Shrink Report           \n")
	sb.WriteString("============================================================\n\n")

	sb.WriteString(fmt.Sprintf("Existing Policy Actions: %d\n", len(r.ExistingActions)))
	sb.WriteString(fmt.Sprintf("Captured Runtime Actions:%d\n", len(r.CapturedActions)))
	sb.WriteString(fmt.Sprintf("Retained (Used) Actions: %d\n", len(r.RetainedActions)))
	sb.WriteString(fmt.Sprintf("Unused (Prunable) Actions:%d\n", len(r.UnusedActions)))
	sb.WriteString(fmt.Sprintf("Missing (Needed) Actions: %d\n", len(r.MissingActions)))
	sb.WriteString(fmt.Sprintf("Privilege Attack Surface Reduction: %.1f%%\n\n", r.ReductionPct))

	if len(r.UnusedActions) > 0 {
		sb.WriteString("--- UNUSED PERMISSIONS (Recommended to Prune) ---\n")
		for _, a := range r.UnusedActions {
			sb.WriteString(fmt.Sprintf("  - %s\n", a))
		}
		sb.WriteString("\n")
	}

	if len(r.MissingActions) > 0 {
		sb.WriteString("+++ MISSING PERMISSIONS (Observed at runtime, not in existing) +++\n")
		for _, a := range r.MissingActions {
			sb.WriteString(fmt.Sprintf("  + %s\n", a))
		}
		sb.WriteString("\n")
	}

	if len(r.RetainedActions) > 0 {
		sb.WriteString("=== RETAINED PERMISSIONS (Verified in use) ===\n")
		for _, a := range r.RetainedActions {
			sb.WriteString(fmt.Sprintf("    %s\n", a))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
