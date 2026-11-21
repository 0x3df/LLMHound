package emitter_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

func helperObservation(t *testing.T) graph.Observation {
	t.Helper()
	return graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-001",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-001",
		Source:           "http://127.0.0.1:11434",
		Surface:          "ollama",
		ObservedAt:       time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC),
		DeploymentScope:  "lab",
		VantageKey:       "vantage-test",
		Coverage:         graph.CoverageComplete,
	}
}

func TestConformance_PropertyValidation(t *testing.T) {
	tests := []struct {
		name    string
		props   map[string]any
		wantErr string
	}{
		{
			name: "valid primitive properties",
			props: map[string]any{
				"name":         "TEST-NODE",
				"port":         11434,
				"active":       true,
				"float_val":    3.14,
				"string_slice": []string{"a", "b", "c"},
				"int_slice":    []int{1, 2, 3},
			},
			wantErr: "",
		},
		{
			name: "uppercase property key rejected",
			props: map[string]any{
				"Port": 11434,
			},
			wantErr: "must be lowercase",
		},
		{
			name: "reserved objectid property rejected",
			props: map[string]any{
				"objectid": "test",
			},
			wantErr: "reserved property 'objectid'",
		},
		{
			name: "nested object rejected",
			props: map[string]any{
				"nested": map[string]any{"key": "value"},
			},
			wantErr: "nested object",
		},
		{
			name: "heterogeneous array rejected",
			props: map[string]any{
				"mixed": []any{"string", 123},
			},
			wantErr: "heterogeneous array",
		},
		{
			name: "null property value rejected",
			props: map[string]any{
				"empty": nil,
			},
			wantErr: "cannot have null value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := emitter.ValidateProperties(tt.props)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestConformance_PayloadRules(t *testing.T) {
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

	nodeItem, err := emitter.NewNodeItem(srvNode, map[string]any{
		"endpoint_host": "127.0.0.1",
		"endpoint_port": 11434,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Base payload must reject native edges
	compRef, err := graph.ExistingNodeByID(graph.Computer, "S-1-5-21-1103")
	if err != nil {
		t.Fatal(err)
	}
	linkingEdge, err := graph.NewObservedAtEdge(srvID.Reference(), compRef, obs, graph.Correlation{
		MatchMethod: "mapping",
		MatchValue:  "S-1-5-21-1103",
		Confidence:  "exact",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = emitter.BuildBasePayload([]emitter.NodeItem{nodeItem}, []graph.Edge{linkingEdge})
	if err == nil || !strings.Contains(err.Error(), "M0 Q5") {
		t.Fatalf("expected base payload to reject linking edge, got: %v", err)
	}

	// Linking payload must reject non-native edges
	tgt, err := graph.ParseTarget("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	netID, err := graph.NewNetworkEndpointIdentity("lab", tgt)
	if err != nil {
		t.Fatal(err)
	}
	nonLinkingEdge, err := graph.NewObservedAtEdge(srvID.Reference(), netID.Reference(), obs, graph.Correlation{
		FallbackReason: "unresolved",
		MatchValue:     "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = emitter.BuildLinkingPayload([]graph.Edge{nonLinkingEdge})
	if err == nil || !strings.Contains(err.Error(), "linking payload can only contain edges that touch native") {
		t.Fatalf("expected linking payload to reject non-native edge, got: %v", err)
	}

	// EmitBasePayload succeeds with non-native edges
	var buf bytes.Buffer
	if err := emitter.EmitBasePayload(&buf, []emitter.NodeItem{nodeItem}, []graph.Edge{nonLinkingEdge}); err != nil {
		t.Fatalf("EmitBasePayload: %v", err)
	}
	if !strings.Contains(buf.String(), `"source_kind": "LLMHound"`) {
		t.Errorf("base payload missing source_kind")
	}

	// EmitLinkingPayload succeeds with native edges
	buf.Reset()
	if err := emitter.EmitLinkingPayload(&buf, []graph.Edge{linkingEdge}); err != nil {
		t.Fatalf("EmitLinkingPayload: %v", err)
	}
	if strings.Contains(buf.String(), `"source_kind"`) {
		t.Errorf("linking payload must NOT have source_kind")
	}
}
