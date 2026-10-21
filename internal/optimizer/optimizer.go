package optimizer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/smford/iam-shrink/internal/render"
)

// Quota limits in bytes for AWS IAM policies.
const (
	LimitManagedPolicy = 10240
	LimitInlinePolicy  = 2048
)

// OptimizationResult holds the outcome of statement merging and compression.
type OptimizationResult struct {
	OriginalBytes  int
	OptimizedBytes int
	SavedBytes     int
	SavedPct       float64
	ExceedsInline  bool
	ExceedsManaged bool
	OptimizedJSON  string
}

// OptimizeStatements merges statements with identical resources to reduce character count.
func OptimizeStatements(statements []render.Statement) []render.Statement {
	if len(statements) <= 1 {
		return statements
	}

	// Group by Resource Key + Effect + Principal
	type groupKey struct {
		Effect    string
		Principal string
		Resources string
	}

	groups := make(map[groupKey][]render.ActionItem)

	for _, stmt := range statements {
		eff := stmt.Effect
		if eff == "" {
			eff = "Allow"
		}
		var rCopy []string
		rCopy = append(rCopy, stmt.ResourceARNs...)
		sort.Strings(rCopy)
		rKey := strings.Join(rCopy, ";")

		k := groupKey{
			Effect:    eff,
			Principal: stmt.Principal,
			Resources: rKey,
		}

		groups[k] = append(groups[k], stmt.Actions...)
	}

	var optimized []render.Statement
	idx := 1

	for k, actions := range groups {
		deduped := deduplicateActions(actions)
		rList := strings.Split(k.Resources, ";")

		sid := fmt.Sprintf("OptimizedStatement%d", idx)
		idx++

		optimized = append(optimized, render.Statement{
			Sid:          sid,
			Effect:       k.Effect,
			Principal:    k.Principal,
			Actions:      deduped,
			ResourceARNs: rList,
		})
	}

	sort.Slice(optimized, func(i, j int) bool {
		return optimized[i].Sid < optimized[j].Sid
	})

	return optimized
}

// OptimizePolicyJSON compresses and minifies an IAM policy JSON string to fit under AWS limits.
func OptimizePolicyJSON(policyJSON string) (*OptimizationResult, error) {
	origBytes := len(policyJSON)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &parsed); err != nil {
		return nil, fmt.Errorf("decoding policy JSON: %w", err)
	}

	// Minify by re-marshaling without indentation
	minified, err := json.Marshal(parsed)
	if err != nil {
		return nil, err
	}

	optBytes := len(minified)
	saved := origBytes - optBytes
	savedPct := 0.0
	if origBytes > 0 {
		savedPct = (float64(saved) / float64(origBytes)) * 100.0
	}

	return &OptimizationResult{
		OriginalBytes:  origBytes,
		OptimizedBytes: optBytes,
		SavedBytes:     saved,
		SavedPct:       savedPct,
		ExceedsInline:  optBytes > LimitInlinePolicy,
		ExceedsManaged: optBytes > LimitManagedPolicy,
		OptimizedJSON:  string(minified),
	}, nil
}

func deduplicateActions(actions []render.ActionItem) []render.ActionItem {
	seen := make(map[string]bool)
	var out []render.ActionItem
	for _, act := range actions {
		if !seen[act.Action] {
			seen[act.Action] = true
			out = append(out, act)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Action < out[j].Action
	})
	return out
}
