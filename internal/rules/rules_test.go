package rules_test

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/rules"
)

func testObs(surface string) graph.Observation {
	return graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-1",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-1",
		Source:           "http://127.0.0.1:8888",
		Surface:          surface,
		ObservedAt:       time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
		DeploymentScope:  "lab",
		VantageKey:       "scanner-a",
		Coverage:         graph.CoverageComplete,
	}
}

func makeServiceAndHost(
	t *testing.T,
	kind graph.Kind,
	surface string,
	endpoint string,
	props map[string]any,
	mapped bool,
	checkIDs []string,
) ([]emitter.NodeItem, []graph.Edge, []evidence.Record, graph.Observation) {
	t.Helper()
	obs := testObs(surface)
	ep, err := graph.ParseEndpoint(endpoint, "")
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := graph.NewServiceIdentity("lab", kind, ep)
	if err != nil {
		t.Fatal(err)
	}
	srvNode, err := graph.NewNode(srvID, obs)
	if err != nil {
		t.Fatal(err)
	}
	item, err := emitter.NewNodeItem(srvNode, props)
	if err != nil {
		t.Fatal(err)
	}

	var targetRef graph.Reference
	var corr graph.Correlation
	if mapped {
		targetRef, err = graph.ExistingNodeByID(graph.Computer, "S-1-5-21-1-2-3-1103")
		if err != nil {
			t.Fatal(err)
		}
		corr = graph.Correlation{MatchMethod: "mapping", MatchValue: ep.Host(), Confidence: "asserted"}
	} else {
		tgt, err := graph.ParseTarget(ep.Host())
		if err != nil {
			t.Fatal(err)
		}
		fb, err := graph.NewNetworkEndpointIdentity("lab", tgt)
		if err != nil {
			t.Fatal(err)
		}
		targetRef = fb.Reference()
		corr = graph.Correlation{MatchValue: ep.Host(), FallbackReason: "no_mapping_entry"}
	}
	obsEdge, err := graph.NewObservedAtEdge(srvID.Reference(), targetRef, obs, corr)
	if err != nil {
		t.Fatal(err)
	}

	var evRecs []evidence.Record
	for _, cid := range checkIDs {
		cObs := obs
		cObs.EvidenceID = "ev-" + cid
		rec, err := evidence.NewAccessEvidenceRecord(graph.AccessEvidence{
			Observation:   cObs,
			CheckID:       cid,
			Operation:     cid,
			TargetID:      srvID.ID(),
			Outcome:       graph.OutcomeSuccess,
			Reason:        "anonymous success",
			Anonymous:     true,
			OperationKind: graph.EnumerationOperation,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		evRecs = append(evRecs, rec)
	}

	return []emitter.NodeItem{item}, []graph.Edge{obsEdge}, evRecs, obs
}

func TestBuiltinRulesAndSemver(t *testing.T) {
	loaded, err := rules.BuiltinRules()
	if err != nil {
		t.Fatalf("BuiltinRules: %v", err)
	}
	if len(loaded) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(loaded))
	}

	for _, tc := range []struct {
		ver  string
		rng  string
		want bool
	}{
		{"2.14.0", ">=1.0.0, <4.0.0", true},
		{"v2.37.0", ">=2.0.0, <3.0.0", true},
		{"1.0.19", ">=1.0.0, <2.0.0", true},
		{"4.0.0", ">=1.0.0, <4.0.0", false},
		{"", ">=1.0.0, <4.0.0", false},
		{"unknown", ">=1.0.0, <4.0.0", false},
		{"2.0.0-rc1", ">=2.0.0, <3.0.0", false},
	} {
		got, err := rules.MatchVersion(tc.ver, tc.rng)
		if err != nil {
			t.Fatalf("MatchVersion(%q, %q) unexpected err: %v", tc.ver, tc.rng, err)
		}
		if got != tc.want {
			t.Errorf("MatchVersion(%q, %q) = %v, want %v", tc.ver, tc.rng, got, tc.want)
		}
	}
}

func TestEvaluate_AllThreeRulesAndFailClosedCases(t *testing.T) {
	principals := []config.ReachPrincipal{{ObjectID: "S-1-5-21-1-2-3-513", Kind: "Group"}}

	// 1. Disabled by default: emits zero edges even when service would qualify.
	nodes, edges, evs, obs := makeServiceAndHost(t, graph.JupyterServer, "jupyter", "http://127.0.0.1:8888", map[string]any{
		"software_version": "2.14.0",
		"auth_required":    false,
		"anon_operations":  []string{"jupyter_sessions"},
	}, true, []string{"jupyter_sessions"})
	outEdges, outEvs, err := rules.Evaluate(config.PathQualification{}, nodes, edges, evs, obs)
	if err != nil || len(outEdges) != 0 || len(outEvs) != 0 {
		t.Fatalf("disabled rules must emit 0 edges, got %d (%v)", len(outEdges), err)
	}

	// 2. Jupyter true positive -> emits CanExecuteOn with full provenance in sourceless form.
	cfgJup := config.PathQualification{
		EnabledRules:           []string{"jupyter-auth-disabled"},
		AssumedReachPrincipals: principals,
	}
	outEdges, outEvs, err = rules.Evaluate(cfgJup, nodes, edges, evs, obs)
	if err != nil || len(outEdges) != 1 || len(outEvs) != 1 {
		t.Fatalf("expected 1 CanExecuteOn edge for Jupyter, got %d edges (%v)", len(outEdges), err)
	}
	e := outEdges[0]
	if e.Kind() != graph.CanExecuteOn || !e.IsTraversable() || !e.TouchesNative() || e.SourceKind() != "" {
		t.Fatalf("unexpected edge properties: kind=%s trav=%v native=%v src=%q", e.Kind(), e.IsTraversable(), e.TouchesNative(), e.SourceKind())
	}
	prov, ok := e.RuleProvenance()
	if !ok || prov.RuleID != "jupyter-auth-disabled" || prov.Basis != graph.BasisInferred || prov.ReachBasis != "scanner_vantage" || prov.ExecIdentity != "unknown" {
		t.Fatalf("unexpected provenance: %+v", prov)
	}
	if !reflect.DeepEqual(prov.Operations, []string{"jupyter_sessions"}) || !reflect.DeepEqual(prov.EvidenceIDs, []string{"ev-jupyter_sessions"}) {
		t.Fatalf("unexpected ops/evidence: %+v", prov)
	}

	// 3. Ray true positive.
	rNodes, rEdges, rEvs, rObs := makeServiceAndHost(t, graph.RayDashboard, "ray", "http://127.0.0.1:8265", map[string]any{
		"software_version": "2.37.0",
		"anon_operations":  []string{"ray_jobs"},
	}, true, []string{"ray_jobs"})
	outEdges, _, err = rules.Evaluate(config.PathQualification{
		EnabledRules:           []string{"ray-anonymous-jobs"},
		AssumedReachPrincipals: principals,
	}, rNodes, rEdges, rEvs, rObs)
	if err != nil || len(outEdges) != 1 {
		t.Fatalf("expected 1 Ray CanExecuteOn edge, got %d (%v)", len(outEdges), err)
	}

	// 4. Langflow true positive.
	lNodes, lEdges, lEvs, lObs := makeServiceAndHost(t, graph.LangflowInstance, "langflow", "http://127.0.0.1:7860", map[string]any{
		"software_version":   "1.0.19",
		"auto_login_enabled": true,
		"anon_operations":    []string{"langflow_auto_login", "langflow_flows"},
	}, true, []string{"langflow_auto_login", "langflow_flows"})
	outEdges, _, err = rules.Evaluate(config.PathQualification{
		EnabledRules:           []string{"langflow-unauthenticated-exec"},
		AssumedReachPrincipals: principals,
	}, lNodes, lEdges, lEvs, lObs)
	if err != nil || len(outEdges) != 1 {
		t.Fatalf("expected 1 Langflow CanExecuteOn edge, got %d (%v)", len(outEdges), err)
	}

	// 5. Fail-closed negative cases:
	allEnabled := config.PathQualification{
		EnabledRules:           []string{"jupyter-auth-disabled", "ray-anonymous-jobs", "langflow-unauthenticated-exec"},
		AssumedReachPrincipals: principals,
	}
	negativeCases := []struct {
		name  string
		kind  graph.Kind
		surf  string
		ep    string
		props map[string]any
		mapd  bool
		chks  []string
	}{
		{
			name: "jupyter missing software_version (api_version alone must fail closed)",
			kind: graph.JupyterServer, surf: "jupyter", ep: "http://127.0.0.1:8888",
			props: map[string]any{"api_version": "2.14.0", "auth_required": false, "anon_operations": []string{"jupyter_sessions"}},
			mapd:  true, chks: []string{"jupyter_sessions"},
		},
		{
			name: "jupyter version metadata check alone does not qualify",
			kind: graph.JupyterServer, surf: "jupyter", ep: "http://127.0.0.1:8888",
			props: map[string]any{"software_version": "2.14.0", "auth_required": false, "anon_operations": []string{"jupyter_version"}},
			mapd:  true, chks: []string{"jupyter_version"},
		},
		{
			name: "jupyter unmapped NetworkEndpoint fails closed",
			kind: graph.JupyterServer, surf: "jupyter", ep: "http://127.0.0.1:8888",
			props: map[string]any{"software_version": "2.14.0", "auth_required": false, "anon_operations": []string{"jupyter_sessions"}},
			mapd:  false, chks: []string{"jupyter_sessions"},
		},
		{
			name: "ray out-of-range version fails closed",
			kind: graph.RayDashboard, surf: "ray", ep: "http://127.0.0.1:8265",
			props: map[string]any{"software_version": "3.0.0", "anon_operations": []string{"ray_jobs"}},
			mapd:  true, chks: []string{"ray_jobs"},
		},
		{
			name: "langflow auto_login disabled fails closed",
			kind: graph.LangflowInstance, surf: "langflow", ep: "http://127.0.0.1:7860",
			props: map[string]any{"software_version": "1.0.19", "auto_login_enabled": false, "anon_operations": []string{"langflow_flows"}},
			mapd:  true, chks: []string{"langflow_flows"},
		},
		{
			name: "non-qualifying surface ollama never qualifies",
			kind: graph.OllamaInstance, surf: "ollama", ep: "http://127.0.0.1:11434",
			props: map[string]any{"software_version": "1.5.0", "anon_operations": []string{"ollama_tags"}},
			mapd:  true, chks: []string{"ollama_tags"},
		},
	}

	for _, nc := range negativeCases {
		t.Run(nc.name, func(t *testing.T) {
			n, ed, ev, ob := makeServiceAndHost(t, nc.kind, nc.surf, nc.ep, nc.props, nc.mapd, nc.chks)
			got, _, err := rules.Evaluate(allEnabled, n, ed, ev, ob)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("expected 0 edges (fail closed), got %d", len(got))
			}
		})
	}
}

func TestSchemaWithCanExecuteOn(t *testing.T) {
	base, err := os.ReadFile("../../extension/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	aug, err := rules.SchemaWithCanExecuteOn(base)
	if err != nil {
		t.Fatalf("SchemaWithCanExecuteOn: %v", err)
	}
	if !contains(string(aug), `"LLMHound_CanExecuteOn"`) {
		t.Errorf("augmented schema missing LLMHound_CanExecuteOn")
	}
}

func TestEvaluate_PartialCoveragePreservesCoverageReason(t *testing.T) {
	nodes, edges, evs, obs := makeServiceAndHost(t, graph.JupyterServer, "jupyter", "http://127.0.0.1:8888", map[string]any{
		"software_version": "2.14.0",
		"auth_required":    false,
		"anon_operations":  []string{"jupyter_sessions"},
	}, true, []string{"jupyter_sessions"})

	partObs := nodes[0].Node.Observation()
	partObs.Coverage = graph.CoveragePartial
	partObs.CoverageReason = "root directory listing skipped nested subdirectories"
	partNode, err := graph.NewNode(nodes[0].Node.Identity(), partObs)
	if err != nil {
		t.Fatal(err)
	}
	nodes[0].Node = partNode

	cfg := config.PathQualification{
		EnabledRules:           []string{"jupyter-auth-disabled"},
		AssumedReachPrincipals: []config.ReachPrincipal{{ObjectID: "S-1-5-21-1-2-3-513", Kind: "Group"}},
	}
	outEdges, outEvs, err := rules.Evaluate(cfg, nodes, edges, evs, obs)
	if err != nil {
		t.Fatalf("Evaluate failed on partial-coverage service: %v", err)
	}
	if len(outEdges) != 1 || len(outEvs) != 1 {
		t.Fatalf("expected 1 CanExecuteOn edge and 1 evidence record, got %d / %d", len(outEdges), len(outEvs))
	}
	if outEdges[0].Observation().Coverage != graph.CoveragePartial || outEdges[0].Observation().CoverageReason == "" {
		t.Fatalf("expected partial coverage reason preserved, got %+v", outEdges[0].Observation())
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
