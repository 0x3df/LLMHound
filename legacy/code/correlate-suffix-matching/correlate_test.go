//go:build ignore

// ARCHIVED. Not compiled. See legacy/README.md.
// Retired: AD-suffix property matching against a caller-supplied verified
// inventory (superseded by mapping-file-only attachment of any native kind).

package correlate_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/graph"
)

const computerA = "S-1-5-21-123-456-789-1103"
const computerB = "S-1-5-21-123-456-789-1104"

func resolver(t *testing.T, cfg correlate.Config) *correlate.Resolver {
	t.Helper()
	r, err := correlate.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func resolve(t *testing.T, r *correlate.Resolver, raw string, computers ...correlate.Computer) correlate.Result {
	t.Helper()
	result, err := r.Resolve("deployment", raw, computers)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertFallback(t *testing.T, r correlate.Result, reason string, candidates ...string) {
	t.Helper()
	id, ok := r.FallbackIdentity()
	if !ok || id.Kind() != graph.NetworkEndpoint || r.Target().IsNative() || r.Target().ID() != id.ID() {
		t.Fatal("fallback is not a source-owned NetworkEndpoint")
	}
	e := r.Evidence()
	if e.Correlation.FallbackReason != reason || e.Verified || e.Correlation.MatchMethod != "" || e.Correlation.Confidence != "" {
		t.Fatalf("dishonest fallback: %#v", e)
	}
	if !reflect.DeepEqual(e.Correlation.CandidateIDs, candidates) {
		t.Fatalf("candidates %v want %v", e.Correlation.CandidateIDs, candidates)
	}
}

func TestVerifiedMappingPrecedenceAndNativeIDPreservation(t *testing.T) {
	r := resolver(t, correlate.Config{Mappings: []correlate.Mapping{{Target: "HOST.LAB.LOCAL.", ComputerID: computerB}}, ADSuffixes: []string{"lab.local"}, PropertyMatchSupported: true})
	result := resolve(t, r, "host.lab.local", correlate.Computer{ObjectID: computerA, Name: "HOST.LAB.LOCAL"}, correlate.Computer{ObjectID: computerB, Name: "OTHER.LAB.LOCAL"})
	if result.Target().ID() != computerB || result.Target().Kind() != graph.Computer || result.Target().MatchBy() != graph.MatchByID {
		t.Fatal("mapping did not win or native id rewritten")
	}
	if _, fallback := result.FallbackIdentity(); fallback {
		t.Fatal("correlated Computer created fallback node")
	}
	e := result.Evidence()
	if !e.Verified || e.Correlation.MatchMethod != "mapping" || e.Correlation.MatchValue != "host.lab.local" || e.Correlation.Confidence != "exact" {
		t.Fatalf("missing mapping provenance: %#v", e)
	}
	mixed := resolver(t, correlate.Config{Mappings: []correlate.Mapping{{Target: "192.0.2.1", ComputerID: "Native-MixedCase"}}})
	if got := resolve(t, mixed, "192.0.2.1", correlate.Computer{ObjectID: "Native-MixedCase"}).Target().ID(); got != "Native-MixedCase" {
		t.Fatal("rewrote native id")
	}
}

func TestUnverifiedOrAmbiguousMappingNeverFallsThrough(t *testing.T) {
	cfg := correlate.Config{Mappings: []correlate.Mapping{{Target: "host.lab.local", ComputerID: computerB}}, ADSuffixes: []string{"lab.local"}, PropertyMatchSupported: true}
	known := correlate.Computer{ObjectID: computerA, Name: "HOST.LAB.LOCAL"}
	assertFallback(t, resolve(t, resolver(t, cfg), "host.lab.local", known), correlate.MappingUnverified, computerB)
	cfg.Mappings = append(cfg.Mappings, correlate.Mapping{Target: "HOST.LAB.LOCAL.", ComputerID: computerA})
	assertFallback(t, resolve(t, resolver(t, cfg), "host.lab.local", known), correlate.MappingAmbiguous, computerA, computerB)
	// Repeated identical mappings/verified records do not invent ambiguity.
	cfg.Mappings = []correlate.Mapping{{Target: "host.lab.local", ComputerID: computerA}, {Target: "HOST.LAB.LOCAL", ComputerID: computerA}}
	got := resolve(t, resolver(t, cfg), "host.lab.local", known, known)
	if got.Target().ID() != computerA {
		t.Fatal("duplicate identical mapping/record became ambiguous")
	}
}

func TestADSuffixPropertyMatchRequiresUniqueVerifiedComputer(t *testing.T) {
	r := resolver(t, correlate.Config{ADSuffixes: []string{"LAB.LOCAL."}, PropertyMatchSupported: true, ComputerProperty: "name"})
	known := correlate.Computer{ObjectID: computerA, Name: "HOST.LAB.LOCAL"}
	result := resolve(t, r, "Host.Lab.Local.", known)
	ref, evidence := result.Target(), result.Evidence()
	if ref.ID() != computerA || ref.MatchBy() != graph.MatchByProperty || ref.Property() != "name" || ref.MatchValue() != "HOST.LAB.LOCAL" {
		t.Fatal("incorrect M0 matcher")
	}
	if !evidence.Verified || evidence.Correlation.MatchMethod != "ad_suffix_name" || evidence.Correlation.Confidence != "unique_property_match" || evidence.OriginalTarget != "Host.Lab.Local." || evidence.NormalizedTarget != "host.lab.local" {
		t.Fatalf("wrong match evidence: %#v", evidence)
	}
	assertFallback(t, resolve(t, r, "host.lab.local"), correlate.NameUnresolved)
	assertFallback(t, resolve(t, r, "host.lab.local", correlate.Computer{ObjectID: computerA, Name: "host.lab.local"}), correlate.NameUnresolved)
	assertFallback(t, resolve(t, r, "host.lab.local", known, correlate.Computer{ObjectID: computerB, Name: "HOST.LAB.LOCAL"}), correlate.NameAmbiguous, computerA, computerB)
	// No fan-out and evidence cannot mutate the resolver's original result.
	ambiguous := resolve(t, r, "host.lab.local", known, correlate.Computer{ObjectID: computerB, Name: "HOST.LAB.LOCAL"})
	e := ambiguous.Evidence()
	e.Correlation.CandidateIDs[0] = "changed"
	if ambiguous.Evidence().Correlation.CandidateIDs[0] != computerA {
		t.Fatal("mutable evidence alias")
	}
}

func TestADSuffixBoundaries(t *testing.T) {
	r := resolver(t, correlate.Config{ADSuffixes: []string{"lab.local"}, PropertyMatchSupported: true})
	for _, host := range []string{"lab.local", "notlab.local", "host.notlab.local", "host.lab.local.attacker.example", "hostlab.local", "host.other.local"} {
		t.Run(host, func(t *testing.T) { assertFallback(t, resolve(t, r, host), correlate.OutsideADSuffix) })
	}
	for _, host := range []string{"host.lab.local", "deep.host.lab.local"} {
		assertFallback(t, resolve(t, r, host), correlate.NameUnresolved)
	}
	assertFallback(t, resolve(t, resolver(t, correlate.Config{}), "host.lab.local"), correlate.NoADSuffixes)
	assertFallback(t, resolve(t, resolver(t, correlate.Config{ADSuffixes: []string{"lab.local"}}), "host.lab.local", correlate.Computer{ObjectID: computerA, Name: "HOST.LAB.LOCAL"}), correlate.PropertyMatchDisabled)
}

func TestIPOnlyNeverUsesNameMatchOrInventsReverseDNS(t *testing.T) {
	r := resolver(t, correlate.Config{ADSuffixes: []string{"lab.local"}, PropertyMatchSupported: true})
	for _, raw := range []string{"192.0.2.1", "[2001:0db8::1]"} {
		assertFallback(t, resolve(t, r, raw, correlate.Computer{ObjectID: computerA, Name: "HOST.LAB.LOCAL"}), correlate.IPRequiresMapping)
	}
	mapped := resolver(t, correlate.Config{Mappings: []correlate.Mapping{{Target: "2001:db8::1", ComputerID: computerA}}})
	if result := resolve(t, mapped, "[2001:0db8::1]", correlate.Computer{ObjectID: computerA}); !result.Target().IsNative() {
		t.Fatal("exact mapped IP did not correlate")
	}
}

func TestMalformedConfigAndInputs(t *testing.T) {
	for _, cfg := range []correlate.Config{
		{Mappings: []correlate.Mapping{{Target: "http://host", ComputerID: computerA}}},
		{Mappings: []correlate.Mapping{{Target: "host", ComputerID: ""}}},
		{ADSuffixes: []string{""}}, {ADSuffixes: []string{".lab.local"}}, {ADSuffixes: []string{"192.0.2.1"}},
		{ComputerProperty: "domain", PropertyMatchSupported: true}, {ComputerProperty: "dNSHostName", PropertyMatchSupported: true},
	} {
		if _, err := correlate.New(cfg); err == nil {
			t.Fatalf("accepted invalid cfg %#v", cfg)
		}
	}
	r := resolver(t, correlate.Config{})
	for _, tc := range []struct {
		scope, target string
		inventory     []correlate.Computer
	}{
		{"", "host.lab.local", nil}, {"deployment", "", nil}, {"deployment", "https://host.lab.local", nil},
		{"deployment", "host.lab.local", []correlate.Computer{{ObjectID: ""}}},
		{"deployment", "host.lab.local", []correlate.Computer{{ObjectID: computerA, Name: "A.LAB.LOCAL"}, {ObjectID: computerA, Name: "B.LAB.LOCAL"}}},
	} {
		if _, err := r.Resolve(tc.scope, tc.target, tc.inventory); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	// Config slices are copied; mutation cannot change subsequent resolutions.
	cfg := correlate.Config{Mappings: []correlate.Mapping{{Target: "host.lab.local", ComputerID: computerA}}}
	r = resolver(t, cfg)
	cfg.Mappings[0].ComputerID = computerB
	if resolve(t, r, "host.lab.local", correlate.Computer{ObjectID: computerA}).Target().ID() != computerA {
		t.Fatal("resolver retained mutable config")
	}
}

func TestCorrelationAddedOnRescanPreservesServiceAndProvenance(t *testing.T) {
	ep, _ := graph.ParseEndpoint("https://host.lab.local/mcp", "")
	service, _ := graph.NewServiceIdentity("deployment", graph.MCPServer, ep)
	vantage, _ := graph.NewVantageIdentity("deployment", "scanner")
	obs := graph.Observation{SchemaVersion: "1", ScanID: "original-scan", CollectorVersion: "0.1.0", EvidenceID: "correlation-evidence", Source: "explicit-inventory", Surface: "mcp", ObservedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), Vantage: vantage, Coverage: graph.CoveragePartial, CoverageReason: "bounded failed check"}
	r := resolver(t, correlate.Config{ADSuffixes: []string{"lab.local"}, PropertyMatchSupported: true})
	first := resolve(t, r, "host.lab.local")
	before, err := first.ObservedAt(service, obs)
	if err != nil {
		t.Fatal(err)
	}
	second := resolve(t, r, "host.lab.local", correlate.Computer{ObjectID: computerA, Name: "HOST.LAB.LOCAL"})
	after, err := second.ObservedAt(service, obs)
	if err != nil {
		t.Fatal(err)
	}
	if before.Start().ID() != after.Start().ID() || before.Kind() != graph.ObservedAt || after.Kind() != graph.ObservedAt || after.End().ID() != computerA {
		t.Fatal("rescan merged/changed identity or inferred RunsOn")
	}
	if before.SourceKind() != "LLMHound" || after.SourceKind() != "" || !after.TouchesNative() {
		t.Fatal("unsafe cleanup ownership")
	}
	if !reflect.DeepEqual(after.Observation(), obs) || before.IsTraversable() || after.IsTraversable() {
		t.Fatal("refreshed provenance or traversal semantics")
	}
	decision, ok := after.Correlation()
	if !ok || decision.MatchValue != "HOST.LAB.LOCAL" {
		t.Fatal("edge missing decision metadata")
	}
	// The earlier fallback remains a valid owned identity; no deletion is inferred.
	if _, ok := first.FallbackIdentity(); !ok {
		t.Fatal("previous observation mutated on rescan")
	}
	wrongScope, _ := graph.NewServiceIdentity("other", graph.MCPServer, ep)
	if _, err := second.ObservedAt(wrongScope, obs); err == nil {
		t.Fatal("native edge escaped deployment scope")
	}
}
