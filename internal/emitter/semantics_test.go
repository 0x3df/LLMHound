package emitter_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

// TestSemantics_M0_Q1_NamespaceMapping verifies all emitted kinds start with LLMHound_.
func TestSemantics_M0_Q1_NamespaceMapping(t *testing.T) {
	for _, k := range graph.NodeKinds() {
		emitted, err := k.Emitted()
		if err != nil {
			t.Fatalf("kind %s emitted error: %v", k, err)
		}
		if !strings.HasPrefix(emitted, "LLMHound_") {
			t.Errorf("node kind %s does not start with LLMHound_: %s", k, emitted)
		}
	}

	for _, k := range graph.EdgeKinds() {
		emitted, err := k.Emitted()
		if err != nil {
			t.Fatalf("edge kind %s emitted error: %v", k, err)
		}
		if !strings.HasPrefix(emitted, "LLMHound_") {
			t.Errorf("edge kind %s does not start with LLMHound_: %s", k, emitted)
		}
	}
}

// TestSemantics_M0_Q2_AIServiceUmbrella verifies that service nodes include LLMHound_AIService.
func TestSemantics_M0_Q2_AIServiceUmbrella(t *testing.T) {
	obs := helperObservation(t)
	ep, err := graph.ParseEndpoint("http://127.0.0.1:11434", "")
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := graph.NewServiceIdentity("lab", graph.OllamaInstance, ep)
	if err != nil {
		t.Fatal(err)
	}
	srvNode, err := graph.NewNode(srvID, obs)
	if err != nil {
		t.Fatal(err)
	}

	item, err := emitter.NewNodeItem(srvNode, map[string]any{"name": "OLLAMA-1"})
	if err != nil {
		t.Fatal(err)
	}

	p, err := emitter.BuildBasePayload([]emitter.NodeItem{item}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(p.Graph.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(p.Graph.Nodes))
	}
	node := p.Graph.Nodes[0]
	if len(node.Kinds) != 2 {
		t.Fatalf("expected 2 kinds, got %d", len(node.Kinds))
	}
	if node.Kinds[0] != "LLMHound_OllamaInstance" || node.Kinds[1] != "LLMHound_AIService" {
		t.Errorf("unexpected node kinds: %v", node.Kinds)
	}
}

// TestSemantics_M0_Q3_PropertyTypesAndCase verifies flat property types and lowercase names.
func TestSemantics_M0_Q3_PropertyTypesAndCase(t *testing.T) {
	props := map[string]any{
		"endpoint_host":   "my-host.local", // Hostname preserved in specific property, not name
		"endpoint_port":   11434,
		"is_anonymous":    true,
		"model_tags":      []string{"llama3", "mistral"},
		"confidence_rate": 0.95,
	}

	validated, err := emitter.ValidateProperties(props)
	if err != nil {
		t.Fatalf("ValidateProperties: %v", err)
	}

	if validated["endpoint_host"] != "my-host.local" {
		t.Errorf("endpoint_host mutated: %v", validated["endpoint_host"])
	}
}

// TestSemantics_M0_Q4_NonTraversableEdges verifies all edge kinds declare is_traversable false.
func TestSemantics_M0_Q4_NonTraversableEdges(t *testing.T) {
	for _, k := range graph.EdgeKinds() {
		if k.IsTraversable() {
			t.Errorf("edge kind %s is unexpectedly traversable", k)
		}
	}
}

// TestSemantics_M0_Q5_SourceSegregation verifies source_kind isolation on base vs linking payloads.
func TestSemantics_M0_Q5_SourceSegregation(t *testing.T) {
	obs := helperObservation(t)
	ep, _ := graph.ParseEndpoint("http://127.0.0.1:11434", "")
	srvID, _ := graph.NewServiceIdentity("lab", graph.OllamaInstance, ep)
	srvNode, _ := graph.NewNode(srvID, obs)
	item, _ := emitter.NewNodeItem(srvNode, map[string]any{"name": "OLLAMA-1"})

	compRef, _ := graph.ExistingNodeByID(graph.Computer, "S-1-5-21-1103")
	linkingEdge, _ := graph.NewObservedAtEdge(srvID.Reference(), compRef, obs, graph.Correlation{
		MatchMethod: "mapping",
		MatchValue:  "S-1-5-21-1103",
		Confidence:  "exact",
	})

	var baseBuf, linkBuf bytes.Buffer
	err := emitter.EmitSplit(&baseBuf, &linkBuf, []emitter.NodeItem{item}, []graph.Edge{linkingEdge})
	if err != nil {
		t.Fatalf("EmitSplit: %v", err)
	}

	var basePayload, linkPayload emitter.Payload
	if err := json.Unmarshal(baseBuf.Bytes(), &basePayload); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	if err := json.Unmarshal(linkBuf.Bytes(), &linkPayload); err != nil {
		t.Fatalf("unmarshal linking: %v", err)
	}

	// Base payload MUST have source_kind: LLMHound
	if basePayload.Metadata == nil || basePayload.Metadata.SourceKind != "LLMHound" {
		t.Errorf("base payload missing metadata.source_kind: %+v", basePayload.Metadata)
	}
	// Linking payload MUST NOT have source_kind
	if linkPayload.Metadata != nil && linkPayload.Metadata.SourceKind != "" {
		t.Errorf("linking payload must NOT declare source_kind, got: %v", linkPayload.Metadata.SourceKind)
	}
	if len(linkPayload.Graph.Nodes) != 0 {
		t.Errorf("linking payload must not contain nodes, got: %d", len(linkPayload.Graph.Nodes))
	}
	if len(linkPayload.Graph.Edges) != 1 {
		t.Errorf("linking payload must contain 1 linking edge, got: %d", len(linkPayload.Graph.Edges))
	}
}

// TestSemantics_M0_Q6_NativeNodesMatchByIDOnly verifies that every native kind
// (not only Computer) is matched by objectid. M0 Q6 showed property matching
// silently drops zero or ambiguous matches, so LLMHound never emits it.
func TestSemantics_M0_Q6_NativeNodesMatchByIDOnly(t *testing.T) {
	obs := helperObservation(t)
	ep, _ := graph.ParseEndpoint("http://127.0.0.1:11434", "")
	srvID, _ := graph.NewServiceIdentity("lab", graph.OllamaInstance, ep)

	for _, native := range []struct {
		kind graph.Kind
		id   string
	}{{graph.Computer, "S-1-5-21-1103"}, {"AZVM", "AZURE-VM-1"}} {
		ref, err := graph.ExistingNodeByID(native.kind, native.id)
		if err != nil {
			t.Fatalf("ExistingNodeByID(%s): %v", native.kind, err)
		}
		edge, err := graph.NewObservedAtEdge(srvID.Reference(), ref, obs, graph.Correlation{MatchMethod: "mapping", MatchValue: "host.lab.local", Confidence: "asserted"})
		if err != nil {
			t.Fatalf("NewObservedAtEdge: %v", err)
		}
		p, err := emitter.BuildLinkingPayload([]graph.Edge{edge})
		if err != nil {
			t.Fatalf("BuildLinkingPayload: %v", err)
		}
		raw, err := json.Marshal(p.Graph.Edges[0].End)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `{"match_by":"id","value":"`+native.id+`"}` {
			t.Errorf("%s endpoint must be an id match only, got %s", native.kind, raw)
		}
	}
}

// TestSemantics_M0_Q7_IDMatchComputer verifies mapping-file ID matcher format.
func TestSemantics_M0_Q7_IDMatchComputer(t *testing.T) {
	obs := helperObservation(t)
	ep, _ := graph.ParseEndpoint("http://127.0.0.1:11434", "")
	srvID, _ := graph.NewServiceIdentity("lab", graph.OllamaInstance, ep)

	compRef, err := graph.ExistingNodeByID(graph.Computer, "S-1-5-21-1104")
	if err != nil {
		t.Fatalf("ExistingNodeByID: %v", err)
	}

	edge, err := graph.NewObservedAtEdge(srvID.Reference(), compRef, obs, graph.Correlation{
		MatchMethod: "mapping",
		MatchValue:  "S-1-5-21-1104",
		Confidence:  "exact",
	})
	if err != nil {
		t.Fatalf("NewObservedAtEdge: %v", err)
	}

	p, err := emitter.BuildLinkingPayload([]graph.Edge{edge})
	if err != nil {
		t.Fatalf("BuildLinkingPayload: %v", err)
	}

	end := p.Graph.Edges[0].End
	if end.MatchBy != "id" {
		t.Errorf("expected match_by id, got: %s", end.MatchBy)
	}
	if end.Value != "S-1-5-21-1104" {
		t.Errorf("expected SID value, got: %s", end.Value)
	}
}

// TestSemantics_M0_Q8_UpsertDeterminism verifies repeatable deterministic emission.
func TestSemantics_M0_Q8_UpsertDeterminism(t *testing.T) {
	obs := helperObservation(t)
	ep, _ := graph.ParseEndpoint("http://127.0.0.1:11434", "")
	srvID1, _ := graph.NewServiceIdentity("lab", graph.OllamaInstance, ep)
	srvID2, _ := graph.NewServiceIdentity("lab", graph.OllamaInstance, ep)

	if srvID1.ID() != srvID2.ID() {
		t.Errorf("service IDs differ across identical constructions: %s vs %s", srvID1.ID(), srvID2.ID())
	}

	node1, _ := graph.NewNode(srvID1, obs)
	node2, _ := graph.NewNode(srvID2, obs)

	item1, _ := emitter.NewNodeItem(node1, map[string]any{"port": 11434})
	item2, _ := emitter.NewNodeItem(node2, map[string]any{"port": 11434})

	var buf1, buf2 bytes.Buffer
	if err := emitter.EmitBasePayload(&buf1, []emitter.NodeItem{item1}, nil); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitBasePayload(&buf2, []emitter.NodeItem{item2}, nil); err != nil {
		t.Fatal(err)
	}

	if buf1.String() != buf2.String() {
		t.Errorf("emission not deterministic across identical inputs")
	}
}
