package graph_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/graph"
)

func observation(t *testing.T) graph.Observation {
	t.Helper()
	return graph.Observation{SchemaVersion: "1", ScanID: "scan-1", CollectorVersion: "0.1.0", EvidenceID: "evidence-1", Source: "metadata-list", Surface: "mcp-resources", ObservedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), DeploymentScope: "scope", VantageKey: "scanner-network", Coverage: graph.CoverageComplete}
}

func resource(t *testing.T, kind graph.Kind, owner graph.Identity) graph.Identity {
	t.Helper()
	id, err := graph.NewResourceIdentity(owner.Scope(), kind, owner, "stable-key")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOwnedNodesCannotEmitNativeComputers(t *testing.T) {
	id := service(t, "scope", graph.MCPServer, "https://example.com/mcp")
	obs := observation(t)
	n, err := graph.NewNode(id, obs)
	if err != nil {
		t.Fatal(err)
	}
	if n.Identity() != id || n.SourceKind() != "LLMHound" || !reflect.DeepEqual(n.Kinds(), []graph.Kind{graph.MCPServer, graph.AIService}) {
		t.Fatal("wrong owned node")
	}
	if !reflect.DeepEqual(n.Observation(), obs) {
		t.Fatal("provenance changed")
	}
	kinds := n.Kinds()
	kinds[0] = graph.Computer
	if n.Kinds()[0] == graph.Computer {
		t.Fatal("mutable kind slice")
	}
	if _, err := graph.NewNode(graph.Identity{}, obs); err == nil {
		t.Fatal("empty/native identity accepted")
	}
	for _, owned := range []graph.Identity{resource(t, graph.MCPResource, id)} {
		n, err := graph.NewNode(owned, obs)
		if err != nil {
			t.Fatal(err)
		}
		if len(n.Kinds()) != 1 || n.Kinds()[0] != owned.Kind() {
			t.Fatal("umbrella on non-service")
		}
	}
	// Changing run, version or time changes provenance only, never identity.
	newObs := obs
	newObs.ScanID = "scan-2"
	newObs.CollectorVersion = "2.0"
	newObs.ObservedAt = obs.ObservedAt.Add(time.Hour)
	n2, err := graph.NewNode(id, newObs)
	if err != nil {
		t.Fatal(err)
	}
	if n2.Identity().ID() != n.Identity().ID() || n.Observation().ObservedAt != obs.ObservedAt {
		t.Fatal("identity/provenance refreshed")
	}
}

func TestNativeReferencesAndLinkingPayloadSafety(t *testing.T) {
	const nativeID = "S-1-5-21-123-456-789-1103"
	c, err := graph.ExistingNodeByID(graph.Computer, nativeID)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != nativeID || c.Kind() != graph.Computer || !c.IsNative() {
		t.Fatal("native id/kind changed")
	}
	mixed, err := graph.ExistingNodeByID(graph.Computer, "Native-MixedCase")
	if err != nil {
		t.Fatal(err)
	}
	if mixed.ID() != "Native-MixedCase" {
		t.Fatal("native ID rewritten")
	}
	// Any native kind already in the graph is attachable, not only Computer.
	vm, err := graph.ExistingNodeByID("AZVM", "AZURE-VM-OBJECT-ID")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Kind() != "AZVM" || !vm.IsNative() || vm.ID() != "AZURE-VM-OBJECT-ID" {
		t.Fatal("native non-Computer kind lost")
	}
	s := service(t, "scope", graph.MCPServer, "https://host.lab.local/mcp")
	for _, native := range []graph.Reference{c, vm} {
		edge, err := graph.NewObservedAtEdge(s.Reference(), native, observation(t), graph.Correlation{MatchMethod: "mapping", MatchValue: "host.lab.local", Confidence: "exact"})
		if err != nil {
			t.Fatal(err)
		}
		if edge.SourceKind() != "" || !edge.TouchesNative() || edge.End().ID() != native.ID() || edge.IsTraversable() || edge.Kind() != graph.ObservedAt {
			t.Fatal("unsafe native linking edge")
		}
	}
	for _, id := range []string{"", " ", "id\n", " id"} {
		if _, err := graph.ExistingNodeByID(graph.Computer, id); err == nil {
			t.Fatal("invalid native reference")
		}
	}
	// Owned kinds, the umbrella label, the extension namespace, and malformed
	// kind names can never be native references.
	for _, kind := range []graph.Kind{"", graph.MCPServer, graph.OllamaInstance, graph.MCPTool, graph.NetworkEndpoint, graph.AIService, "LLMHound_Thing", "llmhound", "Bad Kind", "1Kind", "Kind-Dash"} {
		if _, err := graph.ExistingNodeByID(kind, nativeID); err == nil {
			t.Fatalf("native kind %q accepted", kind)
		}
	}
}

func TestTopologyDirectionsAndNoPlacementInference(t *testing.T) {
	obs := observation(t)
	mcp := service(t, "scope", graph.MCPServer, "https://example.com/mcp")
	a2a := service(t, "scope", graph.A2AAgent, "https://example.com/a2a")
	other := service(t, "scope", graph.OllamaInstance, "https://example.com/ollama")
	for _, tc := range []struct {
		kind  graph.EdgeKind
		start graph.Identity
		end   graph.Identity
	}{
		{graph.ProvidesTool, mcp, resource(t, graph.MCPTool, mcp)},
		{graph.ProvidesResource, mcp, resource(t, graph.MCPResource, mcp)},
		{graph.ProvidesPrompt, mcp, resource(t, graph.MCPPrompt, mcp)},
		{graph.ProvidesModel, other, resource(t, graph.AIModel, other)},
		{graph.AdvertisesSkill, a2a, resource(t, graph.A2ASkill, a2a)},
		{graph.Contains, other, resource(t, graph.VectorCollection, other)},
		{graph.Contains, other, resource(t, graph.WorkspaceFile, other)},
		{graph.Contains, other, resource(t, graph.ModelArtifact, other)},
		{graph.Contains, other, resource(t, graph.ArtifactStore, other)},
		{graph.UsesBackend, mcp, other},
	} {
		t.Run(string(tc.kind)+string(tc.end.Kind()), func(t *testing.T) {
			e, err := graph.NewTopologyEdge(tc.kind, tc.start.Reference(), tc.end.Reference(), obs)
			if err != nil {
				t.Fatal(err)
			}
			if e.IsTraversable() || e.SourceKind() != "LLMHound" || e.TouchesNative() {
				t.Fatal("incorrect topology semantics")
			}
			if _, err := graph.NewTopologyEdge(tc.kind, tc.end.Reference(), tc.start.Reference(), obs); err == nil && tc.kind != graph.UsesBackend {
				t.Fatal("reversed edge accepted")
			}
		})
	}
	target, _ := graph.ParseTarget("example.com")
	fallback, _ := graph.NewNetworkEndpointIdentity("scope", target)
	e, err := graph.NewObservedAtEdge(mcp.Reference(), fallback.Reference(), obs, graph.Correlation{FallbackReason: "unresolved"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind() != graph.ObservedAt || e.IsTraversable() {
		t.Fatal("endpoint observation implies runtime placement")
	}
	if _, err := graph.NewTopologyEdge(graph.RunsOn, mcp.Reference(), fallback.Reference(), obs); err == nil {
		t.Fatal("network observation allowed RunsOn")
	}
	if _, err := graph.NewTopologyEdge(graph.ObservedAt, mcp.Reference(), fallback.Reference(), obs); err == nil {
		t.Fatal("observation missing correlation evidence")
	}
	if _, err := graph.NewTopologyEdge("unknown", mcp.Reference(), fallback.Reference(), obs); err == nil {
		t.Fatal("unknown edge")
	}
	if _, err := graph.NewTopologyEdge(graph.ProvidesResource, mcp.Reference(), resource(t, graph.MCPResource, other).Reference(), obs); err == nil {
		t.Fatal("resource owned by different service")
	}
}

func TestSummarizeAccessIsOperationScopedAndNeverClaimsAbsence(t *testing.T) {
	obs := observation(t)
	ev := func(check string, outcome graph.Outcome, anonymous bool) graph.AccessEvidence {
		return graph.AccessEvidence{Observation: obs, CheckID: check, Operation: check, TargetID: "T", Outcome: outcome, Reason: "r", Anonymous: anonymous, OperationKind: graph.EnumerationOperation}
	}
	for _, tc := range []struct {
		name     string
		evidence []graph.AccessEvidence
		ops      []string
		auth     string
	}{
		{"none", nil, nil, "unknown"},
		{"anonymous success only", []graph.AccessEvidence{ev("tools-list", graph.OutcomeSuccess, true), ev("initialize", graph.OutcomeSuccess, true)}, []string{"initialize", "tools-list"}, "anonymous"},
		{"duplicate check collapses", []graph.AccessEvidence{ev("initialize", graph.OutcomeSuccess, true), ev("initialize", graph.OutcomeSuccess, true)}, []string{"initialize"}, "anonymous"},
		{"denied only", []graph.AccessEvidence{ev("tools-list", graph.OutcomeDenied, false)}, nil, "denied"},
		{"mixed", []graph.AccessEvidence{ev("initialize", graph.OutcomeSuccess, true), ev("tools-list", graph.OutcomeDenied, false)}, []string{"initialize"}, "mixed"},
		{"non-anonymous success is not anonymous access", []graph.AccessEvidence{ev("initialize", graph.OutcomeSuccess, false)}, nil, "unknown"},
		{"failed/skipped/unsupported say nothing", []graph.AccessEvidence{ev("a", graph.OutcomeFailed, true), ev("b", graph.OutcomeSkipped, true), ev("c", graph.OutcomeUnsupported, true)}, nil, "unknown"},
	} {
		got := graph.SummarizeAccess(tc.evidence)
		if !reflect.DeepEqual(got.Operations, tc.ops) && !(len(got.Operations) == 0 && len(tc.ops) == 0) {
			t.Fatalf("%s: operations %v, want %v", tc.name, got.Operations, tc.ops)
		}
		if got.AuthObserved != tc.auth {
			t.Fatalf("%s: auth %q, want %q", tc.name, got.AuthObserved, tc.auth)
		}
		props := got.Properties()
		if props["auth_observed"] != tc.auth {
			t.Fatalf("%s: auth property %v", tc.name, props["auth_observed"])
		}
		if _, has := props["anon_operations"]; has != (len(tc.ops) > 0) {
			t.Fatalf("%s: anon_operations presence wrong (empty must be omitted)", tc.name)
		}
	}
	// The returned slice is a copy.
	got := graph.SummarizeAccess([]graph.AccessEvidence{ev("x", graph.OutcomeSuccess, true)})
	got.Properties()["anon_operations"].([]string)[0] = "mutated"
	if got.Operations[0] != "x" {
		t.Fatal("property slice aliases summary")
	}
}

func TestCorrelationEvidenceAndEdgeValidation(t *testing.T) {
	obs := observation(t)
	s := service(t, "scope", graph.MCPServer, "https://example.com")
	c, _ := graph.ExistingNodeByID(graph.Computer, "native-existing")
	fallbackTarget, _ := graph.ParseTarget("example.com")
	fallback, _ := graph.NewNetworkEndpointIdentity("scope", fallbackTarget)
	for _, tc := range []struct {
		start, end graph.Reference
		decision   graph.Correlation
	}{
		{s.Reference(), c, graph.Correlation{}},
		{s.Reference(), c, graph.Correlation{MatchMethod: "mapping", MatchValue: "example.com", Confidence: "exact", FallbackReason: "ambiguous"}},
		{s.Reference(), fallback.Reference(), graph.Correlation{}},
		{s.Reference(), fallback.Reference(), graph.Correlation{FallbackReason: "unresolved", MatchMethod: "mapping"}},
		{fallback.Reference(), c, graph.Correlation{MatchMethod: "mapping", MatchValue: "example.com", Confidence: "exact"}},
	} {
		if _, err := graph.NewObservedAtEdge(tc.start, tc.end, obs, tc.decision); err == nil {
			t.Fatal("invalid correlation edge accepted")
		}
	}
	decision := graph.Correlation{FallbackReason: "ambiguous", CandidateIDs: []string{"candidate-a", "candidate-b"}}
	e, err := graph.NewObservedAtEdge(s.Reference(), fallback.Reference(), obs, decision)
	if err != nil {
		t.Fatal(err)
	}
	decision.CandidateIDs[0] = "mutated"
	copy, ok := e.Correlation()
	if !ok || copy.CandidateIDs[0] != "candidate-a" {
		t.Fatal("input correlation slice not copied")
	}
	copy.CandidateIDs[0] = "mutated"
	original, _ := e.Correlation()
	if original.CandidateIDs[0] != "candidate-a" {
		t.Fatal("output correlation slice not copied")
	}
	if !reflect.DeepEqual(e.Observation(), obs) {
		t.Fatal("edge provenance changed")
	}
	backend := service(t, "scope", graph.OllamaInstance, "https://example.com/other")
	topology, err := graph.NewTopologyEdge(graph.UsesBackend, s.Reference(), backend.Reference(), obs)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := topology.Correlation(); ok {
		t.Fatal("unrelated topology has correlation claim")
	}
	otherScope := service(t, "other", graph.MCPServer, "https://example.com")
	if _, err := graph.NewTopologyEdge(graph.UsesBackend, s.Reference(), otherScope.Reference(), obs); err == nil {
		t.Fatal("cross-scope edge accepted")
	}
	bad := obs
	bad.ScanID = ""
	if _, err := graph.NewTopologyEdge(graph.UsesBackend, s.Reference(), backend.Reference(), bad); err == nil {
		t.Fatal("missing edge provenance accepted")
	}
	if _, err := graph.NewObservedAtEdge(s.Reference(), fallback.Reference(), bad, graph.Correlation{FallbackReason: "unresolved"}); err == nil {
		t.Fatal("missing correlation provenance accepted")
	}
}

func TestCoverageAndOriginalProvenance(t *testing.T) {
	obs := observation(t)
	id := service(t, "scope", graph.MCPServer, "https://example.com/mcp")
	for _, coverage := range []graph.Coverage{graph.CoverageComplete, graph.CoveragePartial, graph.CoverageFailed, graph.CoverageTruncated} {
		current := obs
		current.Coverage = coverage
		current.CoverageReason = "original attempt outcome"
		n, err := graph.NewNode(id, current)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(n.Observation(), current) || n.Identity() != id {
			t.Fatal("resume refreshed observation or failure changed identity")
		}
	}
	for _, mutate := range []func(*graph.Observation){
		func(o *graph.Observation) { o.SchemaVersion = "unknown" }, func(o *graph.Observation) { o.ScanID = "" },
		func(o *graph.Observation) { o.CollectorVersion = "" }, func(o *graph.Observation) { o.EvidenceID = "" },
		func(o *graph.Observation) { o.Source = "" }, func(o *graph.Observation) { o.Surface = "" },
		func(o *graph.Observation) { o.ObservedAt = time.Time{} }, func(o *graph.Observation) { o.VantageKey = "" },
		func(o *graph.Observation) { o.Coverage = "unknown" },
		func(o *graph.Observation) { o.ObservedAt = o.ObservedAt.In(time.FixedZone("offset", 3600)) }, func(o *graph.Observation) { o.Coverage = graph.CoverageFailed },
		func(o *graph.Observation) { o.DeploymentScope = "other" },
	} {
		bad := obs
		mutate(&bad)
		if _, err := graph.NewNode(id, bad); err == nil {
			t.Fatal("invalid provenance accepted")
		}
	}
	for _, outcome := range []graph.Outcome{graph.OutcomeSuccess, graph.OutcomeDenied, graph.OutcomeUnsupported, graph.OutcomeFailed, graph.OutcomeSkipped} {
		result := graph.CheckResult{CheckID: "list", Operation: "resources/list", TargetID: id.ID(), Outcome: outcome, Reason: "explicit outcome reason", Observation: obs}
		result.Observation.Coverage = graph.CoverageTruncated
		result.Observation.CoverageReason = "page bound"
		if err := result.Validate("scope"); err != nil {
			t.Fatal(err)
		}
	}
}
