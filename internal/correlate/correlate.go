// Package correlate resolves observed targets using explicit mapping data and
// a caller-supplied, externally verified inventory of existing AD Computers.
// It does not read mapping files, resolve DNS, look up CE, or emit graph data.
package correlate

import (
	"errors"
	"sort"
	"strings"

	"github.com/0x3df/LLMHound/internal/graph"
)

// Mapping is an operator assertion, not proof that the destination exists.
type Mapping struct {
	Target     string
	ComputerID string
}

// Computer must describe an existing native Computer verified by the caller.
// Name is the exact stored CE property value, not a synthesized DNS alias. An
// empty inventory means no match is proven; no remote lookup is fabricated.
type Computer struct {
	ObjectID string
	Name     string
}

// Config enables only M0-validated property semantics. PropertyMatchSupported
// must be explicitly asserted by the adapter/operator. Only "name" is supported;
// dNSHostName and other properties were not validated by the M0 spike.
type Config struct {
	Mappings               []Mapping
	ADSuffixes             []string
	PropertyMatchSupported bool
	ComputerProperty       string
}

const (
	MappingUnverified     = "mapping_destination_unverified"
	MappingAmbiguous      = "ambiguous_mapping"
	NameUnresolved        = "computer_name_unresolved"
	NameAmbiguous         = "computer_name_ambiguous"
	OutsideADSuffix       = "outside_ad_suffix"
	NoADSuffixes          = "no_ad_suffixes"
	PropertyMatchDisabled = "property_match_not_enabled"
	IPRequiresMapping     = "ip_requires_explicit_mapping"
)

// Resolver is immutable after construction; inputs are normalized and copied.
type Resolver struct {
	mappings               map[graph.Target][]string
	suffixes               []string
	propertyMatchSupported bool
}

func New(config Config) (*Resolver, error) {
	if config.ComputerProperty != "" && config.ComputerProperty != "name" {
		return nil, errors.New("only M0-validated Computer name matching is supported")
	}
	r := &Resolver{mappings: make(map[graph.Target][]string), propertyMatchSupported: config.PropertyMatchSupported}
	for _, mapping := range config.Mappings {
		target, err := graph.ParseTarget(mapping.Target)
		if err != nil {
			return nil, errors.New("mapping requires a canonicalizable bare target")
		}
		if _, err := graph.ExistingComputerByID(mapping.ComputerID); err != nil {
			return nil, err
		}
		r.mappings[target] = append(r.mappings[target], mapping.ComputerID)
	}
	for target, ids := range r.mappings {
		r.mappings[target] = sortedUnique(ids)
	}
	for _, suffix := range config.ADSuffixes {
		target, err := graph.ParseTarget(suffix)
		if err != nil || target.Type() != graph.DNSTarget {
			return nil, errors.New("AD suffix must be a DNS domain, not an IP or URL")
		}
		r.suffixes = append(r.suffixes, target.Value())
	}
	r.suffixes = sortedUnique(r.suffixes)
	return r, nil
}

// Evidence preserves the original accepted target and the normalized decision.
// Verified applies to the supplied inventory, not a lookup performed here.
type Evidence struct {
	OriginalTarget   string
	NormalizedTarget string
	TargetType       graph.TargetType
	Verified         bool
	Correlation      graph.Correlation
}

// Result carries either a source-owned fallback or a native reference, never a
// source-owned Computer. Native linking edges must go in a sourceless payload.
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

// Resolve requires a complete verified candidate inventory for the relevant
// target/matcher, not an arbitrary subset. Only a unique existing record can
// correlate. Mapping precedence is terminal even when unresolved/ambiguous.
// Missing, incomplete or stale inventory must not be presented as proof of a
// unique match by the caller; this package does not establish remote freshness.
func (r *Resolver) Resolve(scope, rawTarget string, computers []Computer) (Result, error) {
	if r == nil {
		return Result{}, errors.New("correlation resolver is not initialized")
	}
	target, err := graph.ParseTarget(rawTarget)
	if err != nil {
		return Result{}, err
	}
	fallback, err := graph.NewNetworkEndpointIdentity(scope, target)
	if err != nil {
		return Result{}, err
	}
	inventory := make(map[string]Computer)
	for _, computer := range computers {
		if _, err := graph.ExistingComputerByID(computer.ObjectID); err != nil {
			return Result{}, err
		}
		if previous, ok := inventory[computer.ObjectID]; ok && previous != computer {
			return Result{}, errors.New("conflicting verified records for the same native Computer ID")
		}
		inventory[computer.ObjectID] = computer
	}
	result := Result{scope: scope, evidence: Evidence{OriginalTarget: rawTarget, NormalizedTarget: target.Value(), TargetType: target.Type()}}
	unresolved := func(reason string, candidates []string) (Result, error) {
		result.target, result.fallback = fallback.Reference(), fallback
		result.evidence.Correlation = graph.Correlation{MatchValue: target.Value(), FallbackReason: reason, CandidateIDs: sortedUnique(candidates)}
		return result, nil
	}
	if ids := r.mappings[target]; len(ids) > 0 {
		if len(ids) > 1 {
			return unresolved(MappingAmbiguous, ids)
		}
		if _, verified := inventory[ids[0]]; !verified {
			return unresolved(MappingUnverified, ids)
		}
		ref, err := graph.ExistingComputerByID(ids[0])
		if err != nil {
			return Result{}, err
		}
		result.target = ref
		result.evidence.Verified = true
		result.evidence.Correlation = graph.Correlation{MatchMethod: "mapping", MatchValue: target.Value(), Confidence: "exact"}
		return result, nil
	}
	if target.Type() == graph.IPTarget {
		return unresolved(IPRequiresMapping, nil)
	}
	if len(r.suffixes) == 0 {
		return unresolved(NoADSuffixes, nil)
	}
	inADDomain := false
	for _, suffix := range r.suffixes {
		// A child hostname must be inside the suffix, not equal to it or merely
		// share its trailing bytes (e.g. host.notlab.local).
		if strings.HasSuffix(target.Value(), "."+suffix) {
			inADDomain = true
			break
		}
	}
	if !inADDomain {
		return unresolved(OutsideADSuffix, nil)
	}
	if !r.propertyMatchSupported {
		return unresolved(PropertyMatchDisabled, nil)
	}
	name := strings.ToUpper(target.Value())
	var candidates []string
	for id, computer := range inventory {
		// CE matching is case-sensitive, and native name is upper-cased at
		// ingest. Never normalize an unverified stored value into a match.
		if computer.Name == name {
			candidates = append(candidates, id)
		}
	}
	candidates = sortedUnique(candidates)
	if len(candidates) == 0 {
		return unresolved(NameUnresolved, nil)
	}
	if len(candidates) > 1 {
		return unresolved(NameAmbiguous, candidates)
	}
	ref, err := graph.ExistingComputerByName(candidates[0], name)
	if err != nil {
		return Result{}, err
	}
	result.target = ref
	result.evidence.Verified = true
	result.evidence.Correlation = graph.Correlation{MatchMethod: "ad_suffix_name", MatchValue: name, Confidence: "unique_property_match"}
	return result, nil
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
