package extension_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/graph"
)

type SchemaDefinition struct {
	Schema struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Version     string `json:"version"`
		Namespace   string `json:"namespace"`
	} `json:"schema"`
	NodeKinds []struct {
		Name          string `json:"name"`
		DisplayName   string `json:"display_name"`
		Description   string `json:"description"`
		IsDisplayKind bool   `json:"is_display_kind"`
		Icon          string `json:"icon"`
		Color         string `json:"color"`
	} `json:"node_kinds"`
	RelationshipKinds []struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		IsTraversable bool   `json:"is_traversable"`
	} `json:"relationship_kinds"`
}

func TestExtensionSchema(t *testing.T) {
	data, err := os.ReadFile("schema.json")
	if err != nil {
		t.Fatalf("failed to read extension/schema.json: %v", err)
	}

	var schemaDef SchemaDefinition
	if err := json.Unmarshal(data, &schemaDef); err != nil {
		t.Fatalf("failed to parse extension/schema.json: %v", err)
	}

	// 1. Verify schema metadata
	if schemaDef.Schema.Name != "LLMHound" {
		t.Errorf("expected schema.name LLMHound, got %q", schemaDef.Schema.Name)
	}
	if schemaDef.Schema.Namespace != "LLMHound" {
		t.Errorf("expected schema.namespace LLMHound, got %q", schemaDef.Schema.Namespace)
	}
	semverPattern := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	if !semverPattern.MatchString(schemaDef.Schema.Version) {
		t.Errorf("schema.version %q does not match vX.Y.Z", schemaDef.Schema.Version)
	}
	if strings.TrimSpace(schemaDef.Schema.DisplayName) == "" {
		t.Errorf("schema.display_name must be non-empty")
	}

	// 2. Verify all graph.NodeKinds() are declared
	expectedNodeKinds := make(map[string]bool)
	for _, k := range graph.NodeKinds() {
		emitted, err := k.Emitted()
		if err != nil {
			t.Fatalf("failed to get emitted kind for %s: %v", k, err)
		}
		expectedNodeKinds[emitted] = true
	}

	foundNodeKinds := make(map[string]bool)
	tagPattern := regexp.MustCompile(`(?i)^tag_`)
	for _, nk := range schemaDef.NodeKinds {
		if tagPattern.MatchString(nk.Name) {
			t.Errorf("node kind %q uses reserved tag_ prefix", nk.Name)
		}
		if !strings.HasPrefix(nk.Name, "LLMHound_") {
			t.Errorf("node kind %q missing namespace prefix LLMHound_", nk.Name)
		}
		if foundNodeKinds[nk.Name] {
			t.Errorf("duplicate node kind in schema: %s", nk.Name)
		}
		foundNodeKinds[nk.Name] = true

		if strings.TrimSpace(nk.DisplayName) == "" {
			t.Errorf("node kind %s has empty display_name", nk.Name)
		}
		if strings.TrimSpace(nk.Description) == "" {
			t.Errorf("node kind %s has empty description", nk.Name)
		}
	}

	for exp := range expectedNodeKinds {
		if !foundNodeKinds[exp] {
			t.Errorf("expected node kind %s not found in schema.json", exp)
		}
	}
	if len(foundNodeKinds) != len(expectedNodeKinds) {
		t.Errorf("expected %d node kinds, got %d", len(expectedNodeKinds), len(foundNodeKinds))
	}

	// 3. Verify all graph.EdgeKinds() are declared and non-traversable
	expectedEdgeKinds := make(map[string]bool)
	for _, k := range graph.EdgeKinds() {
		emitted, err := k.Emitted()
		if err != nil {
			t.Fatalf("failed to get emitted kind for %s: %v", k, err)
		}
		expectedEdgeKinds[emitted] = true
	}

	foundEdgeKinds := make(map[string]bool)
	for _, rk := range schemaDef.RelationshipKinds {
		if tagPattern.MatchString(rk.Name) {
			t.Errorf("relationship kind %q uses reserved tag_ prefix", rk.Name)
		}
		if !strings.HasPrefix(rk.Name, "LLMHound_") {
			t.Errorf("relationship kind %q missing namespace prefix LLMHound_", rk.Name)
		}
		if foundEdgeKinds[rk.Name] {
			t.Errorf("duplicate relationship kind in schema: %s", rk.Name)
		}
		foundEdgeKinds[rk.Name] = true

		// CRITICAL: M0 Q4 and graph-model constraint: all edges must be non-traversable!
		if rk.IsTraversable {
			t.Errorf("relationship kind %s is declared traversable (must be false in v1)", rk.Name)
		}
		if strings.TrimSpace(rk.Description) == "" {
			t.Errorf("relationship kind %s has empty description", rk.Name)
		}
	}

	for exp := range expectedEdgeKinds {
		if !foundEdgeKinds[exp] {
			t.Errorf("expected relationship kind %s not found in schema.json", exp)
		}
	}
	if len(foundEdgeKinds) != len(expectedEdgeKinds) {
		t.Errorf("expected %d relationship kinds, got %d", len(expectedEdgeKinds), len(foundEdgeKinds))
	}
}
