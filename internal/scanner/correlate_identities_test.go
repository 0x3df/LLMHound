package scanner

import (
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

func TestResolveIdentityEdges(t *testing.T) {
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-1",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-1",
		Source:           "https://ai.corp.local",
		Surface:          "open_webui",
		ObservedAt:       time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC),
		DeploymentScope:  "lab",
		VantageKey:       "corp-vpn",
		Coverage:         graph.CoverageComplete,
	}
	ep, _ := graph.ParseEndpoint("https://ai.corp.local:3000", "")
	srvID, _ := graph.NewServiceIdentity("lab", graph.OpenWebUIInstance, ep)
	srvNode, _ := graph.NewNode(srvID, obs)

	azClient := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	azSecretApp := "11111111-2222-3333-4444-555555555555"
	item, err := emitter.NewNodeItem(srvNode, map[string]any{
		"endpoint":          ep.String(),
		"vantage_key":       "corp-vpn",
		"exposed_azapp_ids": []string{azSecretApp, azSecretApp},
		"entra_client_id":   azClient,
		"entra_tenant_id":   "99999999-8888-7777-6666-555555555555",
	})
	if err != nil {
		t.Fatalf("NewNodeItem: %v", err)
	}

	edges, evs, err := ResolveIdentityEdges("lab", []emitter.NodeItem{item}, obs)
	if err != nil {
		t.Fatalf("ResolveIdentityEdges: %v", err)
	}
	if len(edges) != 2 || len(evs) != 2 {
		t.Fatalf("got %d edges / %d evs, want 2 / 2", len(edges), len(evs))
	}
	if edges[0].Kind() != graph.ExposesCredentialFor || !edges[0].TouchesNative() || edges[0].IsTraversable() {
		t.Errorf("unexpected credential edge: %+v", edges[0])
	}
	if edges[0].End().Kind() != graph.Kind("AZApp") || edges[0].End().ID() != azSecretApp {
		t.Errorf("unexpected cred target: %+v", edges[0].End())
	}
	if edges[1].Kind() != graph.AuthenticatesVia || !edges[1].TouchesNative() || edges[1].IsTraversable() {
		t.Errorf("unexpected oidc edge: %+v", edges[1])
	}
	if edges[1].End().Kind() != graph.Kind("AZApp") || edges[1].End().ID() != "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" {
		t.Errorf("unexpected oidc target: %+v", edges[1].End())
	}
}
