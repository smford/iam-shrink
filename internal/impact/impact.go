package impact

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/smford/iam-shrink/internal/cloudtrail"
	"github.com/smford/iam-shrink/internal/mapper"
)

// SeveredCall captures an API operation observed in CloudTrail that is not permitted by the policy.
type SeveredCall struct {
	Service   string `json:"service"`
	Api       string `json:"api"`
	Action    string `json:"action"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}

// Report holds the operational blast radius risk analysis.
type Report struct {
	TotalEventsSeen  int           `json:"total_events_seen"`
	AllowedCalls     int           `json:"allowed_calls"`
	SeveredCalls     int           `json:"severed_calls"`
	SafetyScore      float64       `json:"safety_score"`
	RiskLevel        string        `json:"risk_level"`
	SeveredBreakdown []SeveredCall `json:"severed_breakdown,omitempty"`
}

type rawPolicy struct {
	Statement []rawStatement `json:"Statement"`
}

type rawStatement struct {
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	NotAction interface{} `json:"NotAction,omitempty"`
	Resource  interface{} `json:"Resource"`
}

// AnalyzeEvents evaluates historical CloudTrail events against the candidate policy JSON.
func AnalyzeEvents(events []cloudtrail.IngestedEvent, policyJSON []byte, m *mapper.Mapper) (*Report, error) {
	if m == nil {
		var err error
		m, err = mapper.New()
		if err != nil {
			return nil, fmt.Errorf("initializing mapper: %w", err)
		}
	}

	var pol rawPolicy
	if err := json.Unmarshal(policyJSON, &pol); err != nil {
		return nil, fmt.Errorf("parsing policy JSON: %w", err)
	}

	total := len(events)
	allowedCount := 0
	severedMap := make(map[string]*SeveredCall)

	for _, evt := range events {
		res := m.Resolve(evt.Event.Service, evt.Event.Api)
		actions := res.Actions
		if len(actions) == 0 {
			actions = []string{fmt.Sprintf("%s:%s", strings.ToLower(evt.Event.Service), evt.Event.Api)}
		}

		callAllowed := true
		var ungrantedAction string

		for _, act := range actions {
			if !isActionAllowed(act, pol.Statement) {
				callAllowed = false
				ungrantedAction = act
				break
			}
		}

		if callAllowed {
			allowedCount++
		} else {
			key := fmt.Sprintf("%s:%s", strings.ToLower(evt.Event.Service), strings.ToLower(evt.Event.Api))
			if existing, ok := severedMap[key]; ok {
				existing.Count++
			} else {
				severedMap[key] = &SeveredCall{
					Service: strings.ToLower(evt.Event.Service),
					Api:     evt.Event.Api,
					Action:  ungrantedAction,
					Count:   1,
				}
			}
		}
	}

	var severedList []SeveredCall
	severedTotal := 0
	for _, call := range severedMap {
		severedList = append(severedList, *call)
		severedTotal += call.Count
	}

	sort.Slice(severedList, func(i, j int) bool {
		if severedList[i].Count != severedList[j].Count {
			return severedList[i].Count > severedList[j].Count
		}
		return severedList[i].Action < severedList[j].Action
	})

	score := 100.0
	if total > 0 {
		score = (float64(allowedCount) / float64(total)) * 100.0
	}

	risk := "MINIMAL"
	if score < 75.0 {
		risk = "CRITICAL"
	} else if score < 90.0 {
		risk = "HIGH"
	} else if score < 98.0 {
		risk = "MEDIUM"
	} else if severedTotal > 0 {
		risk = "LOW"
	}

	return &Report{
		TotalEventsSeen:  total,
		AllowedCalls:     allowedCount,
		SeveredCalls:     severedTotal,
		SafetyScore:      score,
		RiskLevel:        risk,
		SeveredBreakdown: severedList,
	}, nil
}

// AnalyzePath reads all CloudTrail log files in a directory or file and evaluates against policy.
func AnalyzePath(path string, policyJSON []byte) (*Report, error) {
	events, err := cloudtrail.ParsePath(path)
	if err != nil {
		return nil, fmt.Errorf("reading CloudTrail logs from %s: %w", path, err)
	}
	m, err := mapper.New()
	if err != nil {
		return nil, err
	}
	return AnalyzeEvents(events, policyJSON, m)
}

func isActionAllowed(action string, stmts []rawStatement) bool {
	actLower := strings.ToLower(action)
	actSvc := ""
	if parts := strings.Split(actLower, ":"); len(parts) == 2 {
		actSvc = parts[0]
	}

	allowed := false

	for _, stmt := range stmts {
		eff := strings.ToLower(stmt.Effect)
		if eff == "" {
			eff = "allow"
		}

		actions := extractStrings(stmt.Action)

		matches := false
		for _, a := range actions {
			aLower := strings.ToLower(a)
			if aLower == "*" {
				matches = true
				break
			}
			if strings.HasSuffix(aLower, ":*") {
				svcPrefix := strings.TrimSuffix(aLower, ":*")
				if svcPrefix == actSvc {
					matches = true
					break
				}
			}
			if aLower == actLower {
				matches = true
				break
			}
		}

		if eff == "deny" && matches {
			return false
		}
		if eff == "allow" && matches {
			allowed = true
		}
	}

	return allowed
}

func extractStrings(val interface{}) []string {
	var out []string
	switch v := val.(type) {
	case string:
		out = append(out, v)
	case []interface{}:
		for _, it := range v {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}

// FormatTerminal generates human-readable terminal output.
func (r *Report) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("\n=== Operational Blast Radius & Impact Analysis ===\n\n")
	sb.WriteString(fmt.Sprintf("  Historical Events Analyzed: %d\n", r.TotalEventsSeen))
	sb.WriteString(fmt.Sprintf("  Permitted by Shrunk Policy: %d (%.2f%%)\n", r.AllowedCalls, r.SafetyScore))
	sb.WriteString(fmt.Sprintf("  Potentially Severed Calls:  %d\n", r.SeveredCalls))
	sb.WriteString(fmt.Sprintf("  Operational Safety Score:   %.1f%% [%s RISK]\n\n", r.SafetyScore, r.RiskLevel))

	if len(r.SeveredBreakdown) == 0 {
		sb.WriteString("✓ All historical operations are fully permitted by the candidate policy. (0 broken calls)\n")
	} else {
		sb.WriteString("⚠️  The following historical calls would be SEVERED if this policy is applied:\n")
		sb.WriteString(fmt.Sprintf("    %-20s %-30s %-10s\n", "SERVICE / API", "IAM ACTION", "OCCURRENCES"))
		sb.WriteString("    --------------------------------------------------------------------\n")
		for _, call := range r.SeveredBreakdown {
			callKey := fmt.Sprintf("%s:%s", call.Service, call.Api)
			sb.WriteString(fmt.Sprintf("    %-20s %-30s %-10d\n", callKey, call.Action, call.Count))
		}
		sb.WriteString("\nRecommendation: Verify if severed operations represent periodic background jobs, DR drills, or legitimate application workflows before deploying.\n")
	}

	return sb.String()
}

// FormatJSON outputs the report in JSON format.
func (r *Report) FormatJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
