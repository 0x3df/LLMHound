package rules_test

import (
	"encoding/json"
	"io/fs"
	"testing"

	"github.com/0x3df/LLMHound/extension/rules"
	"github.com/0x3df/LLMHound/internal/graph"
)

type ruleDoc struct {
	ID                string         `json:"id"`
	Version           string         `json:"version"`
	CapabilityClass   string         `json:"capability_class"`
	Surface           string         `json:"surface"`
	NodeKind          string         `json:"node_kind"`
	VersionRange      string         `json:"version_range"`
	RequiredChecksAny []string       `json:"required_checks_any"`
	RequiredNodeProps map[string]any `json:"required_node_props"`
	Docs              []string       `json:"docs"`
	Confidence        string         `json:"confidence"`
	ExecIdentity      string         `json:"exec_identity"`
}

func TestEmbeddedRuleFiles(t *testing.T) {
	entries, err := fs.ReadDir(rules.FS, ".")
	if err != nil {
		t.Fatalf("read embedded rules dir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 embedded rule files, got %d", len(entries))
	}
	seenIDs := map[string]bool{}
	for _, ent := range entries {
		data, err := fs.ReadFile(rules.FS, ent.Name())
		if err != nil {
			t.Fatalf("read %s: %v", ent.Name(), err)
		}
		var doc ruleDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("unmarshal %s: %v", ent.Name(), err)
		}
		if doc.ID == "" || doc.Version == "" || doc.VersionRange == "" || doc.Surface == "" {
			t.Errorf("%s missing required identity/version fields", ent.Name())
		}
		if seenIDs[doc.ID] {
			t.Errorf("duplicate rule id %q", doc.ID)
		}
		seenIDs[doc.ID] = true
		if doc.CapabilityClass != "host_code_execution" {
			t.Errorf("%s capability_class = %q, want host_code_execution", ent.Name(), doc.CapabilityClass)
		}
		if !graph.Kind(doc.NodeKind).IsService() {
			t.Errorf("%s node_kind %q is not a service kind", ent.Name(), doc.NodeKind)
		}
		if len(doc.RequiredChecksAny) == 0 {
			t.Errorf("%s must require at least one check", ent.Name())
		}
		if doc.ID == "jupyter-auth-disabled" {
			for _, chk := range doc.RequiredChecksAny {
				if chk == "jupyter_version" {
					t.Errorf("jupyter rule must never qualify on version metadata alone")
				}
			}
		}
		if len(doc.Docs) == 0 {
			t.Errorf("%s must cite official documentation", ent.Name())
		}
	}
}
