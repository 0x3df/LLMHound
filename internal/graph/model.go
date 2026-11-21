package graph

import (
	"errors"
	"strings"
)

// Node is always source-owned. A native Computer can only be a Reference, never
// a Node. Properties and payload serialization are left to the emitter.
type Node struct {
	identity    Identity
	observation Observation
}

func NewNode(identity Identity, observation Observation) (Node, error) {
	if identity.id == "" {
		return Node{}, errors.New("node requires a source-owned identity")
	}
	if err := observation.Validate(identity.scope); err != nil {
		return Node{}, err
	}
	return Node{identity, observation}, nil
}

func (n Node) Identity() Identity       { return n.identity }
func (n Node) Observation() Observation { return n.observation }
func (n Node) SourceKind() string       { return SourceKind }
func (n Node) Kinds() []Kind {
	if n.identity.kind.IsService() {
		return []Kind{n.identity.kind, AIService}
	}
	return []Kind{n.identity.kind}
}

// Reference is either a source-owned endpoint or an existing native node of
// any kind already in the BloodHound graph (Computer, AZVM, ...). Native
// references are matched by objectid only. Constructors require that existence
// was asserted by the caller (the normalizer's asset mapping); they do not
// prove presence in CE, and the upload pre-flight re-verifies it.
type Reference struct {
	identity   Identity
	nativeID   string
	nativeKind Kind
}

func (i Identity) Reference() Reference { return Reference{identity: i} }
func (r Reference) ID() string {
	if r.IsNative() {
		return r.nativeID
	}
	return r.identity.id
}
func (r Reference) Kind() Kind {
	if r.IsNative() {
		return r.nativeKind
	}
	return r.identity.kind
}
func (r Reference) Scope() string   { return r.identity.scope }
func (r Reference) OwnerID() string { return r.identity.ownerID }
func (r Reference) IsNative() bool  { return r.nativeID != "" }

// ExistingNodeByID preserves the native objectid verbatim and records the
// native kind (for example "Computer" or "AZVM"). A source-owned kind, the
// umbrella label, or a malformed kind name is rejected.
func ExistingNodeByID(kind Kind, objectID string) (Reference, error) {
	if !validStableText(objectID) {
		return Reference{}, errors.New("existing node requires an exact native objectid")
	}
	if !validNativeKind(kind) {
		return Reference{}, errors.New("existing node requires a native kind that LLMHound does not own")
	}
	return Reference{nativeID: objectID, nativeKind: kind}, nil
}

func validNativeKind(kind Kind) bool {
	k := string(kind)
	if k == "" || k[0] < 'A' || (k[0] > 'Z' && k[0] < 'a') || k[0] > 'z' {
		return false
	}
	for _, c := range k {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	if kind.IsService() || kind.IsResource() || kind == NetworkEndpoint || kind == AIService {
		return false
	}
	return !strings.HasPrefix(strings.ToLower(k), strings.ToLower(SourceKind))
}

// Correlation records a decision, not an identity merge. Candidate IDs stay in
// structured evidence, rather than becoming guessed native endpoints.
type Correlation struct {
	MatchMethod    string
	MatchValue     string
	Confidence     string
	FallbackReason string
	CandidateIDs   []string
}

func cloneCorrelation(c Correlation) Correlation {
	c.CandidateIDs = append([]string(nil), c.CandidateIDs...)
	return c
}

// Edge never carries a configurable traversal flag. SourceKind is deliberately
// empty on native-touching edges: M0 Q5 requires a separate sourceless linking
// payload to avoid tagging and deleting existing native nodes on source cleanup.
type Edge struct {
	kind        EdgeKind
	start       Reference
	end         Reference
	observation Observation
	correlation *Correlation
}

func (e Edge) Kind() EdgeKind           { return e.kind }
func (e Edge) Start() Reference         { return e.start }
func (e Edge) End() Reference           { return e.end }
func (e Edge) Observation() Observation { return e.observation }
func (e Edge) IsTraversable() bool      { return false }
func (e Edge) TouchesNative() bool      { return e.start.IsNative() || e.end.IsNative() }
func (e Edge) SourceKind() string {
	if e.TouchesNative() {
		return ""
	}
	return SourceKind
}
func (e Edge) Correlation() (Correlation, bool) {
	if e.correlation == nil {
		return Correlation{}, false
	}
	return cloneCorrelation(*e.correlation), true
}

func newEdge(kind EdgeKind, start, end Reference, observation Observation) (Edge, error) {
	if start.ID() == "" || end.ID() == "" || start.IsNative() {
		return Edge{}, errors.New("edge requires a source-owned start and valid endpoints")
	}
	if !end.IsNative() && start.Scope() != end.Scope() {
		return Edge{}, errors.New("edge endpoints must share deployment scope")
	}
	if err := observation.Validate(start.Scope()); err != nil {
		return Edge{}, err
	}
	return Edge{kind: kind, start: start, end: end, observation: observation}, nil
}

// NewObservedAtEdge records endpoint observation, never runtime placement.
func NewObservedAtEdge(service, target Reference, observation Observation, correlation Correlation) (Edge, error) {
	if !service.Kind().IsService() || !(target.IsNative() || target.Kind() == NetworkEndpoint) {
		return Edge{}, errors.New("ObservedAt requires service to an existing native node or NetworkEndpoint")
	}
	if target.IsNative() {
		if !validStableText(correlation.MatchMethod) || !validStableText(correlation.MatchValue) || !validStableText(correlation.Confidence) || correlation.FallbackReason != "" {
			return Edge{}, errors.New("native correlation requires explicit match provenance")
		}
	} else if !validStableText(correlation.FallbackReason) || correlation.MatchMethod != "" || correlation.Confidence != "" {
		return Edge{}, errors.New("fallback requires unresolved reason without a successful match claim")
	}
	e, err := newEdge(ObservedAt, service, target, observation)
	if err != nil {
		return Edge{}, err
	}
	c := cloneCorrelation(correlation)
	e.correlation = &c
	return e, nil
}

func NewTopologyEdge(kind EdgeKind, start, end Reference, observation Observation) (Edge, error) {
	valid := false
	switch kind {
	case ProvidesTool:
		valid = start.Kind() == MCPServer && end.Kind() == MCPTool
	case ProvidesResource:
		valid = start.Kind() == MCPServer && end.Kind() == MCPResource
	case ProvidesPrompt:
		valid = start.Kind() == MCPServer && end.Kind() == MCPPrompt
	case ProvidesModel:
		valid = start.Kind().IsService() && end.Kind() == AIModel
	case AdvertisesSkill:
		valid = start.Kind() == A2AAgent && end.Kind() == A2ASkill
	case Contains:
		valid = start.Kind().IsService() && (end.Kind() == VectorCollection || end.Kind() == WorkspaceFile || end.Kind() == ModelArtifact || end.Kind() == ArtifactStore)
	case UsesBackend:
		valid = start.Kind().IsService() && end.Kind().IsService()
	case RunsOn:
		return Edge{}, errors.New("RunsOn is reserved for supported runtime placement, not network observation")
	default:
		return Edge{}, errors.New("kind requires a dedicated evidence constructor or is unknown")
	}
	if !valid || (end.Kind().IsResource() && end.identity.ownerID != start.ID()) {
		return Edge{}, errors.New("invalid topology direction, kind or resource owner")
	}
	return newEdge(kind, start, end, observation)
}
