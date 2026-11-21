package correlate_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/graph"
)

const scope = "scope"

func resolver(t *testing.T, m ...correlate.Mapping) *correlate.Resolver {
	t.Helper()
	r, err := correlate.New(m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMappedTargetAttachesToExistingNodeOfAnyKind(t *testing.T) {
	r := resolver(t,
		correlate.Mapping{Target: "AI1.Corp.Example.", ObjectID: "S-1-5-21-1-2-3-1103", Kind: graph.Computer},
		correlate.Mapping{Target: "10.1.2.3", ObjectID: "azure-vm-object-id", Kind: "AZVM"},
	)
	for _, tc := range []struct {
		raw, id string
		kind    graph.Kind
	}{
		{"ai1.corp.example", "S-1-5-21-1-2-3-1103", graph.Computer},
		{"AI1.CORP.EXAMPLE", "S-1-5-21-1-2-3-1103", graph.Computer}, // DNS case is canonicalized
		{"10.1.2.3", "azure-vm-object-id", "AZVM"},
	} {
		res, err := r.Resolve(scope, tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Target().IsNative() || res.Target().ID() != tc.id || res.Target().Kind() != tc.kind {
			t.Fatalf("%s attached to %v", tc.raw, res.Target())
		}
		if _, hasFallback := res.FallbackIdentity(); hasFallback {
			t.Fatal("attached target must not also create a NetworkEndpoint")
		}
		ev := res.Evidence()
		if ev.NativeKind != tc.kind || ev.Correlation.MatchMethod != "mapping" || ev.Correlation.FallbackReason != "" {
			t.Fatalf("evidence %+v", ev)
		}
	}
}

func TestUnmappedAndAmbiguousTargetsFallBackWithoutGuessing(t *testing.T) {
	r := resolver(t,
		correlate.Mapping{Target: "dup.corp.example", ObjectID: "id-a", Kind: graph.Computer},
		correlate.Mapping{Target: "dup.corp.example", ObjectID: "id-b", Kind: graph.Computer},
		correlate.Mapping{Target: "same.corp.example", ObjectID: "id-c", Kind: graph.Computer},
		correlate.Mapping{Target: "same.corp.example", ObjectID: "id-c", Kind: graph.Computer}, // identical duplicate collapses
	)
	cases := []struct {
		raw, reason string
		candidates  []string
		attached    bool
	}{
		{"unknown.corp.example", correlate.NoMappingEntry, nil, false},
		{"192.0.2.9", correlate.NoMappingEntry, nil, false},
		// No suffix, name, or reverse-DNS inference: a sibling of a mapped name is unmapped.
		{"other.corp.example", correlate.NoMappingEntry, nil, false},
		{"dup.corp.example", correlate.MappingAmbiguous, []string{"id-a", "id-b"}, false},
		{"same.corp.example", "", nil, true},
	}
	for _, tc := range cases {
		res, err := r.Resolve(scope, tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if res.Target().IsNative() != tc.attached {
			t.Fatalf("%s attached=%v", tc.raw, res.Target().IsNative())
		}
		if tc.attached {
			continue
		}
		fb, ok := res.FallbackIdentity()
		if !ok || fb.Kind() != graph.NetworkEndpoint || fb.Scope() != scope || res.Target().ID() != fb.ID() {
			t.Fatalf("%s: no scoped NetworkEndpoint fallback", tc.raw)
		}
		c := res.Evidence().Correlation
		if c.FallbackReason != tc.reason || c.MatchMethod != "" || !reflect.DeepEqual(c.CandidateIDs, tc.candidates) {
			t.Fatalf("%s: correlation %+v", tc.raw, c)
		}
	}
}

func TestFallbackIdentityDoesNotDependOnMapping(t *testing.T) {
	// Service and endpoint identity never change because a mapping appears later.
	without := resolver(t)
	a, _ := without.Resolve(scope, "x.corp.example")
	b, _ := without.Resolve("other-scope", "x.corp.example")
	fa, _ := a.FallbackIdentity()
	fb, _ := b.FallbackIdentity()
	if fa.ID() == fb.ID() {
		t.Fatal("fallback identity must be scoped to the deployment")
	}
}

func TestNewRejectsInvalidMappings(t *testing.T) {
	for _, m := range []correlate.Mapping{
		{Target: "", ObjectID: "id", Kind: graph.Computer},
		{Target: "http://host/path", ObjectID: "id", Kind: graph.Computer},
		{Target: "ok.example", ObjectID: "", Kind: graph.Computer},
		{Target: "ok.example", ObjectID: " id", Kind: graph.Computer},
		{Target: "ok.example", ObjectID: "id", Kind: ""},
		{Target: "ok.example", ObjectID: "id", Kind: graph.OllamaInstance},
		{Target: "ok.example", ObjectID: "id", Kind: "LLMHound_Computer"},
	} {
		if _, err := correlate.New([]correlate.Mapping{m}); err == nil {
			t.Fatalf("accepted %+v", m)
		}
	}
}

func TestResolvedEdgeIsNativeLinkingAndNonTraversable(t *testing.T) {
	r := resolver(t, correlate.Mapping{Target: "ai1.corp.example", ObjectID: "native-1", Kind: "AZVM"})
	res, _ := r.Resolve(scope, "ai1.corp.example")
	ep, err := graph.ParseEndpoint("https://ai1.corp.example/mcp", "")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := graph.NewServiceIdentity(scope, graph.MCPServer, ep)
	if err != nil {
		t.Fatal(err)
	}
	obs := graph.Observation{SchemaVersion: "1", ScanID: "s", CollectorVersion: "0", EvidenceID: "e", Source: "src", Surface: "mcp", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), DeploymentScope: scope, VantageKey: "v", Coverage: graph.CoverageComplete}
	edge, err := res.ObservedAt(svc, obs)
	if err != nil {
		t.Fatal(err)
	}
	if !edge.TouchesNative() || edge.SourceKind() != "" || edge.IsTraversable() || edge.End().Kind() != "AZVM" {
		t.Fatal("native attachment must be a sourceless, non-traversable linking edge")
	}
	other, _ := graph.NewServiceIdentity("different-scope", graph.MCPServer, ep)
	if _, err := res.ObservedAt(other, obs); err == nil {
		t.Fatal("scope mismatch accepted")
	}
	// A nil resolver is an empty mapping: the target falls back, never an error.
	var nilResolver *correlate.Resolver
	nr, err := nilResolver.Resolve(scope, "x.example")
	if err != nil || nr.Target().IsNative() || nr.Evidence().Correlation.FallbackReason != correlate.NoMappingEntry {
		t.Fatal("nil resolver must behave as an empty mapping")
	}
}
