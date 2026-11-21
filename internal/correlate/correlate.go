// Package correlate attaches observed targets to existing BloodHound nodes
// using the asset mapping supplied by the normalization program.
//
// Attribution is not LLMHound's job: this package performs no DNS, CE lookups,
// name or suffix matching, and it never guesses. A target is attached only when
// the mapping names exactly one existing node (objectid and native kind, e.g.
// Computer or AZVM). Anything else falls back to a scoped NetworkEndpoint that
// the normalizer can attribute later.
//
// A mapping entry is the normalizer's assertion. Existence in the graph is
// re-verified at upload time, because an edge to a missing objectid makes CE
// create an empty stub node.
package correlate

import (
	"errors"
	"sort"

	"github.com/0x3df/LLMHound/internal/graph"
)

// Mapping asserts that Target is the existing BloodHound node ObjectID of Kind.
type Mapping struct {
	Target   string
	ObjectID string
	Kind     graph.Kind
}

// Fallback reasons recorded in evidence when a target is not attached.
const (
	NoMappingEntry   = "no_mapping_entry"
	MappingAmbiguous = "ambiguous_mapping"
)

type nativeNode struct {
	id   string
	kind graph.Kind
}

// Resolver is immutable after construction; inputs are normalized and copied.
type Resolver struct {
	mappings map[graph.Target][]nativeNode
}

// New validates and indexes mapping entries. Duplicate identical entries
// collapse; differing entries for one target make that target ambiguous.
func New(mappings []Mapping) (*Resolver, error) {
	r := &Resolver{mappings: make(map[graph.Target][]nativeNode)}
	for _, m := range mappings {
		target, err := graph.ParseTarget(m.Target)
		if err != nil {
			return nil, errors.New("mapping requires a canonicalizable bare target")
		}
		if _, err := graph.ExistingNodeByID(m.Kind, m.ObjectID); err != nil {
			return nil, err
		}
		r.mappings[target] = append(r.mappings[target], nativeNode{m.ObjectID, m.Kind})
	}
	for target, nodes := range r.mappings {
		r.mappings[target] = uniqueNodes(nodes)
	}
	return r, nil
}

// Evidence preserves the original accepted target and the decision made.
type Evidence struct {
	OriginalTarget   string
	NormalizedTarget string
	TargetType       graph.TargetType
	// NativeKind is the kind of the existing node attached to, empty on fallback.
	NativeKind  graph.Kind
	Correlation graph.Correlation
}

// Result carries either a source-owned fallback or a native reference, never a
// source-owned native node. Native linking edges belong in a sourceless payload.
type Result struct {
	scope    string
	target   graph.Reference
	fallback graph.Identity
	evidence Evidence
}

func (r Result) Target() graph.Reference                  { return r.target }
func (r Result) FallbackIdentity() (graph.Identity, bool) { return r.fallback, r.fallback.ID() != "" }
func (r Result) Evidence() Evidence {
	e := r.evidence
	e.Correlation.CandidateIDs = append([]string(nil), e.Correlation.CandidateIDs...)
	return e
}

// ObservedAt adds only network-observation evidence, never RunsOn or cleanup.
func (r Result) ObservedAt(service graph.Identity, observation graph.Observation) (graph.Edge, error) {
	if service.Scope() != r.scope {
		return graph.Edge{}, errors.New("correlation and service must share deployment scope")
	}
	return graph.NewObservedAtEdge(service.Reference(), r.target, observation, r.evidence.Correlation)
}

// Resolve attaches rawTarget to the single existing node the mapping names, or
// returns a scoped NetworkEndpoint fallback with the reason. Several entries
// for one target are never resolved by choosing one. A nil Resolver behaves as
// an empty mapping, so collectors need no separate "no resolver" path.
func (r *Resolver) Resolve(scope, rawTarget string) (Result, error) {
	target, err := graph.ParseTarget(rawTarget)
	if err != nil {
		return Result{}, err
	}
	fallback, err := graph.NewNetworkEndpointIdentity(scope, target)
	if err != nil {
		return Result{}, err
	}
	result := Result{scope: scope, evidence: Evidence{OriginalTarget: rawTarget, NormalizedTarget: target.Value(), TargetType: target.Type()}}
	unresolved := func(reason string, candidates []string) (Result, error) {
		result.target, result.fallback = fallback.Reference(), fallback
		result.evidence.Correlation = graph.Correlation{MatchValue: target.Value(), FallbackReason: reason, CandidateIDs: sortedIDs(candidates)}
		return result, nil
	}
	var nodes []nativeNode
	if r != nil { // a nil Resolver is an empty mapping: every target falls back
		nodes = r.mappings[target]
	}
	switch len(nodes) {
	case 0:
		return unresolved(NoMappingEntry, nil)
	case 1:
		ref, err := graph.ExistingNodeByID(nodes[0].kind, nodes[0].id)
		if err != nil {
			return Result{}, err
		}
		result.target = ref
		result.evidence.NativeKind = nodes[0].kind
		result.evidence.Correlation = graph.Correlation{MatchMethod: "mapping", MatchValue: target.Value(), Confidence: "asserted"}
		return result, nil
	default:
		ids := make([]string, 0, len(nodes))
		for _, n := range nodes {
			ids = append(ids, n.id)
		}
		return unresolved(MappingAmbiguous, ids)
	}
}

func uniqueNodes(nodes []nativeNode) []nativeNode {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].id != nodes[j].id {
			return nodes[i].id < nodes[j].id
		}
		return nodes[i].kind < nodes[j].kind
	})
	out := nodes[:0]
	for _, n := range nodes {
		if len(out) == 0 || out[len(out)-1] != n {
			out = append(out, n)
		}
	}
	return out
}

func sortedIDs(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
