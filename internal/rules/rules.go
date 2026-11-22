// Package rules loads, validates, and evaluates opt-in path-qualification rules
// that emit traversable CanExecuteOn and CanAssumePrincipal edges only when all
// six evidence criteria in docs/02-graph-model.md are satisfied.
package rules

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	extrules "github.com/0x3df/LLMHound/extension/rules"
	"github.com/0x3df/LLMHound/internal/graph"
)

const (
	// CapabilityHostCodeExec is the host code-execution qualification class.
	CapabilityHostCodeExec = "host_code_execution"
	// CapabilityPrincipalAssumption is the credential-exposure-to-principal
	// assumption qualification class.
	CapabilityPrincipalAssumption = "principal_assumption"
)

// Rule defines an opt-in path-qualification rule loaded from extension/rules.
type Rule struct {
	ID                      string         `json:"id"`
	Version                 string         `json:"version"`
	CapabilityClass         string         `json:"capability_class"`
	EdgeKind                string         `json:"edge_kind,omitempty"`
	Surface                 string         `json:"surface"`
	NodeKind                string         `json:"node_kind"`
	VersionRange            string         `json:"version_range"`
	RequiredChecksAny       []string       `json:"required_checks_any,omitempty"`
	RequiredNodeProps       map[string]any `json:"required_node_props,omitempty"`
	RequiredExecSurfacesAny []string       `json:"required_exec_surfaces_any,omitempty"`
	StartFromProperty       string         `json:"start_from_property,omitempty"`
	StartKind               string         `json:"start_kind,omitempty"`
	TargetFromProperty      string         `json:"target_from_property,omitempty"`
	TargetKind              string         `json:"target_kind,omitempty"`
	FanoutHostProperty      string         `json:"fanout_host_property,omitempty"`
	Docs                    []string       `json:"docs"`
	Confidence              string         `json:"confidence"`
	ExecIdentity            string         `json:"exec_identity"`
}

// EffectiveEdgeKind returns the opt-in traversable edge kind emitted by the rule.
func (r Rule) EffectiveEdgeKind() graph.EdgeKind {
	if strings.TrimSpace(r.EdgeKind) == "" {
		return graph.CanExecuteOn
	}
	return graph.EdgeKind(strings.TrimSpace(r.EdgeKind))
}

// Validate enforces closed capability classes, edge kinds, and required rule metadata.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Version) == "" {
		return fmt.Errorf("rule requires non-empty id and version")
	}
	switch r.CapabilityClass {
	case CapabilityHostCodeExec, CapabilityPrincipalAssumption:
	default:
		return fmt.Errorf("rule %s has unsupported capability_class %q", r.ID, r.CapabilityClass)
	}
	switch r.EffectiveEdgeKind() {
	case graph.CanExecuteOn, graph.CanAssumePrincipal:
	default:
		return fmt.Errorf("rule %s has unsupported edge_kind %q", r.ID, r.EdgeKind)
	}
	if strings.TrimSpace(r.Surface) == "" {
		return fmt.Errorf("rule %s requires non-empty surface (or *)", r.ID)
	}
	if r.NodeKind != "*" && !graph.Kind(r.NodeKind).IsService() {
		return fmt.Errorf("rule %s references non-service node_kind %q", r.ID, r.NodeKind)
	}
	if strings.TrimSpace(r.VersionRange) == "" {
		return fmt.Errorf("rule %s requires non-empty version_range (or *)", r.ID)
	}
	if r.VersionRange != "*" {
		if _, err := ParseRange(r.VersionRange); err != nil {
			return fmt.Errorf("rule %s invalid version_range: %w", r.ID, err)
		}
	}
	if len(r.RequiredChecksAny) == 0 && len(r.RequiredNodeProps) == 0 &&
		len(r.RequiredExecSurfacesAny) == 0 && strings.TrimSpace(r.TargetFromProperty) == "" {
		return fmt.Errorf("rule %s must define at least one qualifying evidence criterion", r.ID)
	}
	if r.ID == "jupyter-auth-disabled" {
		for _, c := range r.RequiredChecksAny {
			if c == "jupyter_version" {
				return fmt.Errorf("rule %s must never qualify on jupyter_version alone", r.ID)
			}
		}
	}
	if (r.StartFromProperty != "" && r.StartKind == "") || (r.StartFromProperty == "" && r.StartKind != "") {
		return fmt.Errorf("rule %s must set both start_from_property and start_kind together", r.ID)
	}
	if (r.TargetFromProperty != "" && r.TargetKind == "") || (r.TargetFromProperty == "" && r.TargetKind != "") {
		return fmt.Errorf("rule %s must set both target_from_property and target_kind together", r.ID)
	}
	if len(r.Docs) == 0 {
		return fmt.Errorf("rule %s must cite at least one upstream documentation URL", r.ID)
	}
	if strings.TrimSpace(r.Confidence) == "" || strings.TrimSpace(r.ExecIdentity) == "" {
		return fmt.Errorf("rule %s requires confidence and exec_identity", r.ID)
	}
	return nil
}

// BuiltinRules loads and validates all shipped path-qualification rules from
// extension/rules/.
func BuiltinRules() ([]Rule, error) {
	entries, err := fs.ReadDir(extrules.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []Rule
	seen := make(map[string]bool)
	for _, name := range names {
		raw, err := fs.ReadFile(extrules.FS, name)
		if err != nil {
			return nil, fmt.Errorf("read rule %s: %w", name, err)
		}
		var r Rule
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", name, err)
		}
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
}
