package emitter_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

func TestFilterAttackPathGraph(t *testing.T) {
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-1",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-1",
		Source:           "http://10.0.0.1:8080/mcp",
		Surface:          "mcp",
		ObservedAt:       time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC),
		DeploymentScope:  "corp",
		VantageKey:       "v1",
		Coverage:         graph.CoverageComplete,
	}

	ep, _ := graph.ParseEndpoint("http://10.0.0.1:8080", "")
	srvID, _ := graph.NewServiceIdentity("corp", graph.MCPServer, ep)
	srvNode, _ := graph.NewNode(srvID, obs)
	srvItem, _ := emitter.NewNodeItem(srvNode, map[string]any{"name": "mcp"})

	highToolID, _ := graph.NewResourceIdentity("corp", graph.MCPTool, srvID, "run_shell")
	highToolNode, _ := graph.NewNode(highToolID, obs)
	highToolItem, _ := emitter.NewNodeItem(highToolNode, map[string]any{
		"name":            "run_shell",
		"capability_hint": []any{"shell"},
	})

	lowToolID, _ := graph.NewResourceIdentity("corp", graph.MCPTool, srvID, "get_weather")
	lowToolNode, _ := graph.NewNode(lowToolID, obs)
	lowToolItem, _ := emitter.NewNodeItem(lowToolNode, map[string]any{
		"name":            "get_weather",
		"capability_hint": []string{"network"},
	})

	modelID, _ := graph.NewResourceIdentity("corp", graph.AIModel, srvID, "llama3")
	modelNode, _ := graph.NewNode(modelID, obs)
	modelItem, _ := emitter.NewNodeItem(modelNode, map[string]any{"name": "llama3"})

	tgt, _ := graph.ParseTarget("10.0.0.1")
	nepID, _ := graph.NewNetworkEndpointIdentity("corp", tgt)
	nepNode, _ := graph.NewNode(nepID, obs)
	nepItem, _ := emitter.NewNodeItem(nepNode, map[string]any{"name": "10.0.0.1"})

	nativeRef, _ := graph.ExistingNodeByID(graph.Computer, "S-1-5-21-99")

	mustEdge := func(e graph.Edge, err error) graph.Edge {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	eHighTool := mustEdge(graph.NewTopologyEdge(graph.ProvidesTool, srvID.Reference(), highToolID.Reference(), obs))
	eLowTool := mustEdge(graph.NewTopologyEdge(graph.ProvidesTool, srvID.Reference(), lowToolID.Reference(), obs))
	eModel := mustEdge(graph.NewTopologyEdge(graph.ProvidesModel, srvID.Reference(), modelID.Reference(), obs))
	eObsNep := mustEdge(graph.NewObservedAtEdge(srvID.Reference(), nepID.Reference(), obs, graph.Correlation{FallbackReason: "no_mapping_entry"}))
	eObsNative := mustEdge(graph.NewObservedAtEdge(srvID.Reference(), nativeRef, obs, graph.Correlation{MatchMethod: "mapping", MatchValue: "10.0.0.1", Confidence: "asserted"}))

	nodes := []emitter.NodeItem{srvItem, highToolItem, lowToolItem, modelItem, nepItem}
	edges := []graph.Edge{eHighTool, eLowTool, eModel, eObsNep, eObsNative}

	keptNodes, keptEdges := emitter.FilterAttackPathGraph(nodes, edges, emitter.FilterOptions{CompactAttackPath: true, MappedOnly: false})
	if len(keptNodes) != 3 { // srv + highTool + nep
		t.Fatalf("keptNodes = %d, want 3", len(keptNodes))
	}
	if len(keptEdges) != 3 { // eHighTool + eObsNep + eObsNative
		t.Fatalf("keptEdges = %d, want 3", len(keptEdges))
	}

	mappedNodes, mappedEdges := emitter.FilterAttackPathGraph(nodes, edges, emitter.FilterOptions{CompactAttackPath: true, MappedOnly: true})
	if len(mappedNodes) != 2 { // srv + highTool (nep dropped)
		t.Fatalf("mappedNodes = %d, want 2", len(mappedNodes))
	}
	if len(mappedEdges) != 2 { // eHighTool + eObsNative
		t.Fatalf("mappedEdges = %d, want 2", len(mappedEdges))
	}

	// Full graph mode keeps every node, but an edge to an owned node that is
	// not emitted (here: the model node is withheld) must still be dropped so
	// CE never creates a source-tagged stub for it.
	fullNodes := []emitter.NodeItem{srvItem, highToolItem, lowToolItem, nepItem}
	gotNodes, gotEdges := emitter.FilterAttackPathGraph(fullNodes, edges, emitter.FilterOptions{})
	if len(gotNodes) != 4 {
		t.Fatalf("full mode nodes = %d, want 4", len(gotNodes))
	}
	for _, e := range gotEdges {
		if e.Kind() == graph.ProvidesModel {
			t.Fatal("dangling edge to a non-emitted owned node survived full mode")
		}
	}
	if len(gotEdges) != 4 { // eHighTool + eLowTool + eObsNep + eObsNative
		t.Fatalf("full mode edges = %d, want 4", len(gotEdges))
	}
}

func TestEmitCompactOmitsIndentation(t *testing.T) {
	p := emitter.Payload{
		Metadata: &emitter.Metadata{SourceKind: "LLMHound"},
		Graph:    emitter.GraphPayload{Nodes: []emitter.NodePayload{}, Edges: []emitter.EdgePayload{}},
	}
	var compact, pretty bytes.Buffer
	if err := emitter.EmitCompact(&compact, p); err != nil {
		t.Fatal(err)
	}
	if err := emitter.Emit(&pretty, p); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compact.String(), "\n  ") {
		t.Fatalf("compact output contains indentation: %q", compact.String())
	}
	if compact.Len() >= pretty.Len() {
		t.Fatalf("compact (%d) not smaller than pretty (%d)", compact.Len(), pretty.Len())
	}
}
