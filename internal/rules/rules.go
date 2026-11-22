// Package rules loads, validates, and evaluates opt-in path-qualification
// rules that emit traversable CanExecuteOn edges only when all six evidence
// criteria in docs/02-graph-model.md are satisfied.
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	extrules "github.com/0x3df/LLMHound/extension/rules"
	"github.com/0x3df/LLMHound/internal/graph"
)

const CapabilityHostCodeExec = "host_code_execution"

// Rule defines an opt-in path-qualification rule loaded from extension/rules.
type Rule struct {
	ID                string         `json:"id"`
	Version           string         `json:"version"`
	CapabilityClass   string         `json:"capability_class"`
	Surface           string         `json:"surface"`
	NodeKind          string         `json:"node_kind"`
	VersionRange      string         `json:"version_range"`
	RequiredChecksAny []string       `json:"required_checks_any"`
	RequiredNodeProps map[string]any `json:"required_node_props,omitempty"`
	Docs              []string       `json:"docs"`
	Confidence        string         `json:"confidence"`
	ExecIdentity      string         `json:"exec_identity"`
}

// Validate enforces the closed capability class and required rule metadata.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Version) == "" {
		return errors.New("rule requires non-empty id and version")
	}
	if r.CapabilityClass != CapabilityHostCodeExec {
		return fmt.Errorf("rule %s: capability_class %q not allowed (must be %q)", r.ID, r.CapabilityClass, CapabilityHostCodeExec)
	}
	if strings.TrimSpace(r.Surface) == "" {
		return fmt.Errorf("rule %s: surface is required", r.ID)
	}
	if !graph.Kind(r.NodeKind).IsService() {
		return fmt.Errorf("rule %s: node_kind %q must be a concrete service kind", r.ID, r.NodeKind)
	}
	if _, err := ParseRange(r.VersionRange); err != nil {
		return fmt.Errorf("rule %s: invalid version_range: %w", r.ID, err)
	}
	if len(r.RequiredChecksAny) == 0 {
		return fmt.Errorf("rule %s: required_checks_any must be non-empty", r.ID)
	}
	for _, chk := range r.RequiredChecksAny {
		if strings.TrimSpace(chk) == "" {
			return fmt.Errorf("rule %s: required_checks_any cannot contain empty check IDs", r.ID)
		}
	}
	if len(r.Docs) == 0 {
		return fmt.Errorf("rule %s: docs reference is required", r.ID)
	}
	if strings.TrimSpace(r.Confidence) == "" {
		return fmt.Errorf("rule %s: confidence is required", r.ID)
	}
	if strings.TrimSpace(r.ExecIdentity) == "" {
		return fmt.Errorf("rule %s: exec_identity is required", r.ID)
	}
	return nil
}

// BuiltinRules loads and validates all shipped path-qualification rules from
// extension/rules/.
func BuiltinRules() ([]Rule, error) {
	entries, err := fs.ReadDir(extrules.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules: %w", err)
	}
	var out []Rule
	seen := make(map[string]bool)
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		data, err := fs.ReadFile(extrules.FS, ent.Name())
		if err != nil {
			return nil, fmt.Errorf("read rule %s: %w", ent.Name(), err)
		}
		var r Rule
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", ent.Name(), err)
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
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
