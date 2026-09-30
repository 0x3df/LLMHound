package graph_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/graph"
)

func observation(t *testing.T) graph.Observation {
	t.Helper()
	v, err := graph.NewVantageIdentity("scope", "scanner-network")
	if err != nil {
		t.Fatal(err)
	}
	return graph.Observation{SchemaVersion: "1", ScanID: "scan-1", CollectorVersion: "0.1.0", EvidenceID: "evidence-1", Source: "metadata-list", Surface: "mcp-resources", ObservedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), Vantage: v, Coverage: graph.CoverageComplete}
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
	for _, owned := range []graph.Identity{resource(t, graph.MCPResource, id), obs.Vantage} {
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
	c, err := graph.ExistingComputerByID(nativeID)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID() != nativeID || c.Kind() != graph.Computer || !c.IsNative() || c.MatchBy() != graph.MatchByID {
		t.Fatal("native id/ownership changed")
	}
	mixed, err := graph.ExistingComputerByID("Native-MixedCase")
	if err != nil {
		t.Fatal(err)
	}
	if mixed.ID() != "Native-MixedCase" {
		t.Fatal("native ID rewritten")
	}
	p, err := graph.ExistingComputerByName(nativeID, "HOST.LAB.LOCAL")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != nativeID || p.MatchBy() != graph.MatchByProperty || p.Property() != "name" || p.MatchValue() != "HOST.LAB.LOCAL" {
		t.Fatal("wrong M0 property reference")
	}
	s := service(t, "scope", graph.MCPServer, "https://host.lab.local/mcp")
	edge, err := graph.NewObservedAtEdge(s.Reference(), c, observation(t), graph.Correlation{MatchMethod: "mapping", MatchValue: "host.lab.local", Confidence: "exact"})
	if err != nil {
		t.Fatal(err)
	}
	if edge.SourceKind() != "" || !edge.TouchesNative() || edge.End().ID() != nativeID || edge.IsTraversable() || edge.Kind() != graph.ObservedAt {
		t.Fatal("unsafe native linking edge")
	}
	for _, id := range []string{"", " ", "id\n", " id"} {
		if _, err := graph.ExistingComputerByID(id); err == nil {
			t.Fatal("invalid native reference")
		}
	}
	if _, err := graph.ExistingComputerByName(nativeID, "host.lab.local"); err == nil {
		t.Fatal("lowercase matcher would silently fail in CE")
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

func TestAccessIsOperationScopedVantageToTarget(t *testing.T) {
	obs := observation(t)
	s := service(t, "scope", graph.MCPServer, "https://example.com/mcp")
	r := resource(t, graph.MCPResource, s)
	for _, tc := range []struct {
		kind          graph.EdgeKind
		target        graph.Identity
		operationKind graph.OperationKind
	}{
		{graph.UnauthenticatedAccess, s, graph.EnumerationOperation},
		{graph.PublicAccess, r, graph.ResourceReadOperation},
	} {
		evidence := graph.AccessEvidence{Observation: obs, CheckID: "resources-list", Operation: "resources/list", TargetID: tc.target.ID(), Outcome: graph.OutcomeSuccess, Reason: "validated intended response", Anonymous: true, OperationKind: tc.operationKind}
		e, err := graph.NewAccessEdge(tc.kind, obs.Vantage.Reference(), tc.target.Reference(), evidence)
		if err != nil {
			t.Fatal(err)
		}
		if e.Start().Kind() != graph.CollectionVantage || e.End().ID() != tc.target.ID() || e.IsTraversable() {
			t.Fatal("wrong access direction")
		}
		got, ok := e.AccessEvidence()
		if !ok || !reflect.DeepEqual(got, evidence) {
			t.Fatal("operation provenance lost")
		}
		if _, err := graph.NewAccessEdge(tc.kind, tc.target.Reference(), obs.Vantage.Reference(), evidence); err == nil {
			t.Fatal("host/service-origin access accepted")
		}
		if _, err := graph.NewTopologyEdge(tc.kind, obs.Vantage.Reference(), tc.target.Reference(), obs); err == nil {
			t.Fatal("access without operation evidence")
		}
		for _, outcome := range []graph.Outcome{graph.OutcomeDenied, graph.OutcomeUnsupported, graph.OutcomeFailed, graph.OutcomeSkipped, "unknown"} {
			bad := evidence
			bad.Outcome = outcome
			if _, err := graph.NewAccessEdge(tc.kind, obs.Vantage.Reference(), tc.target.Reference(), bad); err == nil {
				t.Fatal("negative/unknown result became positive access")
			}
		}
		for _, mutate := range []func(*graph.AccessEvidence){
			func(a *graph.AccessEvidence) { a.Anonymous = false },
			func(a *graph.AccessEvidence) { a.TargetID = s.ID() + "wrong" },
			func(a *graph.AccessEvidence) { a.Operation = "" },
			func(a *graph.AccessEvidence) { a.CheckID = "" },
			func(a *graph.AccessEvidence) { a.Reason = "" },
			func(a *graph.AccessEvidence) { a.OperationKind = "tcp-probe" },
			func(a *graph.AccessEvidence) { a.OperationKind = "advertisement" },
		} {
			bad := evidence
			mutate(&bad)
			if _, err := graph.NewAccessEdge(tc.kind, obs.Vantage.Reference(), tc.target.Reference(), bad); err == nil {
				t.Fatal("invalid access evidence accepted")
			}
		}
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
		func(o *graph.Observation) { o.ObservedAt = time.Time{} }, func(o *graph.Observation) { o.Vantage = graph.Identity{} },
		func(o *graph.Observation) { o.Coverage = "unknown" }, func(o *graph.Observation) { o.Coverage = graph.CoverageFailed },
		func(o *graph.Observation) { o.Vantage, _ = graph.NewVantageIdentity("other", "scanner") },
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
