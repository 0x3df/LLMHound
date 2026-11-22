package rules

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/0x3df/LLMHound/internal/graph"
)

type schemaDoc struct {
	Schema struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Version     string `json:"version"`
		Namespace   string `json:"namespace"`
	} `json:"schema"`
	NodeKinds         []json.RawMessage `json:"node_kinds"`
	RelationshipKinds []relKindDoc      `json:"relationship_kinds"`
}

type relKindDoc struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	IsTraversable bool   `json:"is_traversable"`
}

// SchemaWithCanExecuteOn augments the default non-traversable extension schema
// with the opt-in traversable relationship kinds (LLMHound_CanExecuteOn and
// LLMHound_CanAssumePrincipal) without making any base edge kind traversable.
func SchemaWithCanExecuteOn(baseSchemaJSON []byte) ([]byte, error) {
	var doc schemaDoc
	if err := json.Unmarshal(baseSchemaJSON, &doc); err != nil {
		return nil, fmt.Errorf("parse base schema: %w", err)
	}
	ruleDescs := map[graph.EdgeKind]string{
		graph.CanExecuteOn:       "Opt-in rule-gated host code execution transition from assumed-reach principals to a mapped native host node.",
		graph.CanAssumePrincipal: "Opt-in rule-gated principal assumption transition from an assumed-reach principal to a cloud/directory identity whose credential was exposed.",
	}
	for _, k := range graph.RuleEdgeKinds() {
		emitted, err := k.Emitted()
		if err != nil {
			return nil, err
		}
		found := false
		for i, rk := range doc.RelationshipKinds {
			if rk.Name == emitted {
				doc.RelationshipKinds[i].IsTraversable = true
				found = true
				break
			}
		}
		if !found {
			doc.RelationshipKinds = append(doc.RelationshipKinds, relKindDoc{
				Name:          emitted,
				Description:   ruleDescs[k],
				IsTraversable: true,
			})
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode augmented schema: %w", err)
	}
	return buf.Bytes(), nil
}
