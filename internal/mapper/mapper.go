package mapper

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed embedded_mappings.yaml
var defaultMappingsYAML []byte

// MappingFile represents the structure of the mappings YAML file.
type MappingFile struct {
	Version  int            `yaml:"version" json:"version"`
	Mappings []MappingEntry `yaml:"mappings" json:"mappings"`
}

// MappingEntry defines the SDK method to IAM action and ARN mappings.
type MappingEntry struct {
	Service          string   `yaml:"service" json:"service"`
	Api              string   `yaml:"api" json:"api"`
	Actions          []string `yaml:"actions" json:"actions"`
	ResourceARNs     []string `yaml:"resource_arns,omitempty" json:"resource_arns,omitempty"`
	DependentActions []string `yaml:"dependent_actions,omitempty" json:"dependent_actions,omitempty"`
	Comment          string   `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// ResolvedMapping holds the translated IAM action details.
type ResolvedMapping struct {
	Service          string
	Api              string
	ServicePrefix    string
	Actions          []string
	ResourceARNs     []string
	DependentActions []string
	IsFallback       bool
}

// Mapper manages SDK-to-IAM mappings.
type Mapper struct {
	entries map[string]MappingEntry
	rawYAML []byte
}

// New creates a new Mapper initialized with embedded default mappings.
func New() (*Mapper, error) {
	m := &Mapper{
		entries: make(map[string]MappingEntry),
		rawYAML: defaultMappingsYAML,
	}

	if err := m.loadYAML(defaultMappingsYAML); err != nil {
		return nil, fmt.Errorf("failed to load default mappings: %w", err)
	}

	return m, nil
}

// LoadOverridesFile reads an external YAML file and merges mappings into the mapper.
func (m *Mapper) LoadOverridesFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading override file %q: %w", path, err)
	}
	return m.LoadOverrides(data)
}

// LoadOverrides parses external YAML bytes and merges or overrides mappings.
func (m *Mapper) LoadOverrides(data []byte) error {
	return m.loadYAML(data)
}

func (m *Mapper) loadYAML(data []byte) error {
	var file MappingFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return err
	}

	for _, entry := range file.Mappings {
		key := makeKey(entry.Service, entry.Api)
		m.entries[key] = entry
	}
	return nil
}

// NormalizeServicePrefix maps SDK/CSM service names to standard IAM prefix.
func NormalizeServicePrefix(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	switch s {
	case "cloudwatchlogs":
		return "logs"
	case "cloudwatchevents", "eventbridge":
		return "events"
	case "cognitoidentityprovider":
		return "cognito-idp"
	default:
		return s
	}
}

func makeKey(service, api string) string {
	svc := NormalizeServicePrefix(service)
	a := strings.ToLower(strings.TrimSpace(api))
	return svc + ":" + a
}

// Resolve looks up a (Service, Api) pair. If unmapped, it falls back to <servicePrefix>:<Api>.
func (m *Mapper) Resolve(service, api string) ResolvedMapping {
	svcPrefix := NormalizeServicePrefix(service)
	trimmedApi := strings.TrimSpace(api)
	key := makeKey(svcPrefix, trimmedApi)

	if entry, found := m.entries[key]; found && len(entry.Actions) > 0 {
		actions := make([]string, len(entry.Actions))
		copy(actions, entry.Actions)
		sort.Strings(actions)

		var rARNs []string
		if len(entry.ResourceARNs) > 0 {
			rARNs = make([]string, len(entry.ResourceARNs))
			copy(rARNs, entry.ResourceARNs)
		}

		var depActions []string
		if len(entry.DependentActions) > 0 {
			depActions = make([]string, len(entry.DependentActions))
			copy(depActions, entry.DependentActions)
			sort.Strings(depActions)
		}

		return ResolvedMapping{
			Service:          entry.Service,
			Api:              entry.Api,
			ServicePrefix:    svcPrefix,
			Actions:          actions,
			ResourceARNs:     rARNs,
			DependentActions: depActions,
			IsFallback:       false,
		}
	}

	// Deterministic fallback: <servicePrefix>:<Api>
	fallbackAction := fmt.Sprintf("%s:%s", svcPrefix, trimmedApi)
	return ResolvedMapping{
		Service:          service,
		Api:              trimmedApi,
		ServicePrefix:    svcPrefix,
		Actions:          []string{fallbackAction},
		ResourceARNs:     []string{"*"},
		DependentActions: nil,
		IsFallback:       true,
	}
}

// Explain looks up an entry by "service:api" or "service Api" and returns the mapping details.
func (m *Mapper) Explain(query string) (ResolvedMapping, error) {
	var service, api string
	if idx := strings.Index(query, ":"); idx != -1 {
		service = query[:idx]
		api = query[idx+1:]
	} else if idx := strings.Index(query, " "); idx != -1 {
		service = query[:idx]
		api = query[idx+1:]
	} else {
		return ResolvedMapping{}, fmt.Errorf("invalid query %q: expected format '<service>:<api>' (e.g. 's3:ListObjectsV2')", query)
	}

	return m.Resolve(service, api), nil
}

// ExportYAML exports the default or loaded mappings as YAML.
func (m *Mapper) ExportYAML() ([]byte, error) {
	// Reconstruct structured mapping sorted deterministically by service and API
	var entries []MappingEntry
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		si := strings.ToLower(entries[i].Service)
		sj := strings.ToLower(entries[j].Service)
		if si == sj {
			return strings.ToLower(entries[i].Api) < strings.ToLower(entries[j].Api)
		}
		return si < sj
	})

	out := MappingFile{
		Version:  1,
		Mappings: entries,
	}

	return yaml.Marshal(&out)
}
