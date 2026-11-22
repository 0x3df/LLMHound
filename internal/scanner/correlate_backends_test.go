package scanner_test

import (
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/scanner"
)

func TestResolveBackendEdges(t *testing.T) {
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-1",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-1",
		Source:           "scanner",
		Surface:          "litellm",
		ObservedAt:       time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC),
		DeploymentScope:  "corp",
		VantageKey:       "v1",
		Coverage:         graph.CoverageComplete,
	}

	mkSvc := func(kind graph.Kind, rawEP string, backends []string) emitter.NodeItem {
		ep, err := graph.ParseEndpoint(rawEP, "")
		if err != nil {
			t.Fatal(err)
		}
		id, err := graph.NewServiceIdentity("corp", kind, ep)
		if err != nil {
			t.Fatal(err)
		}
		n, err := graph.NewNode(id, obs)
		if err != nil {
			t.Fatal(err)
		}
		props := map[string]any{
			"name":          string(kind),
			"endpoint":      ep.String(),
			"endpoint_host": ep.Host(),
			"endpoint_port": int(ep.Port()),
		}
		if len(backends) > 0 {
			props["backend_refs"] = backends
		}
		item, err := emitter.NewNodeItem(n, props)
		if err != nil {
			t.Fatal(err)
		}
		return item
	}

	// Gateway scans on IP 10.0.0.10:4000, points to DNS alias gpu01.corp.internal:11434
	// and to direct IP 10.0.0.20:6333.
	// Ollama backend was scanned via IP 10.0.0.21:11434; both DNS alias & IP map to S-1-5-21-GPU01.
	gateway := mkSvc(graph.LiteLLMGateway, "http://10.0.0.10:4000", []string{
		"http://gpu01.corp.internal:11434/v1",
		"http://10.0.0.10:4000", // self-reference must be ignored
		"https://unknown.corp.internal:8443",
	})
	ollama := mkSvc(graph.OllamaInstance, "http://10.0.0.21:11434", nil)

	resolver, err := correlate.New([]correlate.Mapping{
		{Target: "10.0.0.21", ObjectID: "S-1-5-21-GPU01", Kind: graph.Computer},
		{Target: "gpu01.corp.internal", ObjectID: "S-1-5-21-GPU01", Kind: graph.Computer},
	})
	if err != nil {
		t.Fatal(err)
	}

	edges := scanner.ResolveBackendEdges("corp", []emitter.NodeItem{gateway, ollama}, resolver, obs)
	if len(edges) != 1 {
		t.Fatalf("got %d UsesBackend edges, want 1", len(edges))
	}
	if edges[0].Kind() != graph.UsesBackend ||
		edges[0].Start().ID() != gateway.Node.Identity().ID() ||
		edges[0].End().ID() != ollama.Node.Identity().ID() {
		t.Fatalf("unexpected UsesBackend edge: %+v", edges[0])
	}
}
