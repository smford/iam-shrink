package verifier

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ExpansionDetail describes an unintended permission granted by target that was not in base.
type ExpansionDetail struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Reason   string `json:"reason"`
}

// Result holds the outcome of formal subset and equivalence analysis.
type Result struct {
	IsSubset          bool              `json:"is_subset"`
	IsEquivalent      bool              `json:"is_equivalent"`
	Expansions        []ExpansionDetail `json:"expansions,omitempty"`
	BaseActionCount   int               `json:"base_action_count"`
	TargetActionCount int               `json:"target_action_count"`
}

type rawPolicy struct {
	Statement []rawStatement `json:"Statement"`
}

type rawStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

// VerifyPolicyBytes evaluates whether targetJSON is a strict mathematical subset of baseJSON.
func VerifyPolicyBytes(baseJSON, targetJSON []byte) (*Result, error) {
	baseMap, err := extractEffectiveGrants(baseJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing base policy: %w", err)
	}

	targetMap, err := extractEffectiveGrants(targetJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing target policy: %w", err)
	}

	var expansions []ExpansionDetail

	for targetAct, targetResources := range targetMap {
		baseResources, allowedInBase := baseMap[targetAct]
		if !allowedInBase {
			// Check if base has wildcard covering this action (e.g. "*" or "s3:*")
			coveredByWildcard := false
			if baseMap["*"] != nil {
				coveredByWildcard = true
				baseResources = baseMap["*"]
			} else {
				prefix := strings.Split(targetAct, ":")[0] + ":*"
				if baseMap[prefix] != nil {
					coveredByWildcard = true
					baseResources = baseMap[prefix]
				}
			}

			if !coveredByWildcard {
				expansions = append(expansions, ExpansionDetail{
					Action:   targetAct,
					Resource: strings.Join(targetResources, ", "),
					Reason:   "Action not permitted by base policy",
				})
				continue
			}
		}

		// Check resource coverage
		for _, tr := range targetResources {
			if !isResourceCovered(tr, baseResources) {
				expansions = append(expansions, ExpansionDetail{
					Action:   targetAct,
					Resource: tr,
					Reason:   "Resource scope exceeds base policy constraints",
				})
			}
		}
	}

	isSubset := len(expansions) == 0
	isEquivalent := isSubset && len(baseMap) == len(targetMap)

	return &Result{
		IsSubset:          isSubset,
		IsEquivalent:      isEquivalent,
		Expansions:        expansions,
		BaseActionCount:   len(baseMap),
		TargetActionCount: len(targetMap),
	}, nil
}

func extractEffectiveGrants(data []byte) (map[string][]string, error) {
	var pol rawPolicy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, err
	}

	grants := make(map[string][]string)

	for _, stmt := range pol.Statement {
		eff := stmt.Effect
		if eff == "" {
			eff = "Allow"
		}
		if strings.ToLower(eff) != "allow" {
			continue // Focus on allowed privileges for subset verification
		}

		var actions []string
		switch a := stmt.Action.(type) {
		case string:
			actions = append(actions, a)
		case []interface{}:
			for _, it := range a {
				if s, ok := it.(string); ok {
					actions = append(actions, s)
				}
			}
		}

		var resources []string
		switch r := stmt.Resource.(type) {
		case string:
			resources = append(resources, r)
		case []interface{}:
			for _, it := range r {
				if s, ok := it.(string); ok {
					resources = append(resources, s)
				}
			}
		}

		for _, act := range actions {
			actLower := strings.ToLower(strings.TrimSpace(act))
			grants[actLower] = append(grants[actLower], resources...)
		}
	}

	for k, v := range grants {
		grants[k] = uniqueSorted(v)
	}

	return grants, nil
}

func isResourceCovered(targetResource string, baseResources []string) bool {
	for _, br := range baseResources {
		if br == "*" {
			return true
		}
		if br == targetResource {
			return true
		}
		if strings.HasSuffix(br, "/*") {
			prefix := strings.TrimSuffix(br, "/*")
			if strings.HasPrefix(targetResource, prefix) {
				return true
			}
		}
	}
	return false
}

func uniqueSorted(in []string) []string {
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

// FormatReport outputs the verification analysis as a clean CLI report.
func (r *Result) FormatReport() string {
	var sb strings.Builder
	sb.WriteString("============================================================\n")
	sb.WriteString("              IAM Policy Verification Report                \n")
	sb.WriteString("============================================================\n\n")

	if r.IsSubset {
		sb.WriteString("✅ VERIFICATION PASSED: Shrunk policy is a strict subset of base policy.\n")
		sb.WriteString("   Zero unauthorized privilege boundaries or shadow expansions detected.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("❌ VERIFICATION FAILED: Detected %d privilege expansion(s)!\n", len(r.Expansions)))
		sb.WriteString("   The target policy grants access not authorized by the base policy:\n\n")
		for i, exp := range r.Expansions {
			sb.WriteString(fmt.Sprintf("   [%d] Action:   %s\n", i+1, exp.Action))
			sb.WriteString(fmt.Sprintf("       Resource: %s\n", exp.Resource))
			sb.WriteString(fmt.Sprintf("       Reason:   %s\n\n", exp.Reason))
		}
	}

	sb.WriteString(fmt.Sprintf("Base Actions: %d | Target Actions: %d\n", r.BaseActionCount, r.TargetActionCount))
	return sb.String()
}
