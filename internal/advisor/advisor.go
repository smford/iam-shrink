package advisor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// PruneResult holds the results of pruning unaccessed actions from a policy.
type PruneResult struct {
	OriginalActions []string
	ActiveActions   []string
	PrunedActions   []string
	PrunedPolicyDoc []byte
	ReductionPct    float64
}

// PrunePolicy removes unaccessed actions from an IAM policy JSON based on active actions.
func PrunePolicy(policyJSON []byte, activeActions []string) (*PruneResult, error) {
	activeMap := make(map[string]bool)
	for _, a := range activeActions {
		activeMap[strings.ToLower(strings.TrimSpace(a))] = true
	}

	type jsonStatement struct {
		Sid       string                         `json:"Sid,omitempty"`
		Effect    string                         `json:"Effect"`
		Action    interface{}                    `json:"Action"`
		Resource  interface{}                    `json:"Resource"`
		Condition map[string]map[string][]string `json:"Condition,omitempty"`
	}

	type jsonPolicy struct {
		Version   string          `json:"Version"`
		Statement []jsonStatement `json:"Statement"`
	}

	var pol jsonPolicy
	if err := json.Unmarshal(policyJSON, &pol); err != nil {
		return nil, fmt.Errorf("parsing policy JSON: %w", err)
	}

	var origActions []string
	var retainedActions []string
	var prunedActions []string

	var updatedStatements []jsonStatement

	for _, stmt := range pol.Statement {
		var actionList []string
		switch a := stmt.Action.(type) {
		case string:
			actionList = append(actionList, a)
		case []interface{}:
			for _, it := range a {
				if s, ok := it.(string); ok {
					actionList = append(actionList, s)
				}
			}
		}

		var keptInStmt []string
		for _, act := range actionList {
			origActions = append(origActions, act)
			actLower := strings.ToLower(act)

			// If action was observed active
			if activeMap[actLower] {
				keptInStmt = append(keptInStmt, act)
				retainedActions = append(retainedActions, act)
			} else {
				prunedActions = append(prunedActions, act)
			}
		}

		if len(keptInStmt) > 0 {
			sort.Strings(keptInStmt)
			stmtCopy := stmt
			stmtCopy.Action = keptInStmt
			updatedStatements = append(updatedStatements, stmtCopy)
		}
	}

	origActions = uniqueSorted(origActions)
	prunedActions = uniqueSorted(prunedActions)
	retainedActions = uniqueSorted(retainedActions)

	reduction := 0.0
	if len(origActions) > 0 {
		reduction = (float64(len(prunedActions)) / float64(len(origActions))) * 100.0
	}

	pol.Statement = updatedStatements
	prunedJSON, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializing pruned policy: %w", err)
	}
	prunedJSON = append(prunedJSON, '\n')

	return &PruneResult{
		OriginalActions: origActions,
		ActiveActions:   retainedActions,
		PrunedActions:   prunedActions,
		PrunedPolicyDoc: prunedJSON,
		ReductionPct:    reduction,
	}, nil
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
