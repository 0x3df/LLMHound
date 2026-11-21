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

type MatchBy string

const (
	MatchByID       MatchBy = "id"
	MatchByProperty MatchBy = "property"
)

// Reference is either a source-owned endpoint or an existing native Computer.
// Native constructors require existence already verified by the caller; they
// do not prove presence in CE and must not be used with unchecked mappings.
type Reference struct {
	identity   Identity
	nativeID   string
	matchBy    MatchBy
	property   string
	matchValue string
}

func (i Identity) Reference() Reference { return Reference{identity: i, matchBy: MatchByID} }
func (r Reference) ID() string {
	if r.IsNative() {
		return r.nativeID
	}
	return r.identity.id
}
func (r Reference) Kind() Kind {
	if r.IsNative() {
		return Computer
	}
	return r.identity.kind
}
func (r Reference) Scope() string      { return r.identity.scope }
func (r Reference) OwnerID() string    { return r.identity.ownerID }
func (r Reference) IsNative() bool     { return r.nativeID != "" }
func (r Reference) MatchBy() MatchBy   { return r.matchBy }
func (r Reference) Property() string   { return r.property }
func (r Reference) MatchValue() string { return r.matchValue }

// ExistingComputerByID preserves the verified native objectid verbatim.
func ExistingComputerByID(objectID string) (Reference, error) {
	if !validStableText(objectID) {
		return Reference{}, errors.New("existing Computer requires an exact verified native ID")
	}
	return Reference{nativeID: objectID, matchBy: MatchByID}, nil
}

// ExistingComputerByName uses only M0's verified, exact upper-case name matcher.
// objectID records the unique existing Computer whose name was verified.
func ExistingComputerByName(objectID, name string) (Reference, error) {
	r, err := ExistingComputerByID(objectID)
	if err != nil {
		return Reference{}, err
	}
	target, err := ParseTarget(name)
	if err != nil || target.typ != DNSTarget || name != strings.ToUpper(target.value) {
		return Reference{}, errors.New("Computer name matcher requires canonical upper-case DNS name")
	}
	r.matchBy, r.property, r.matchValue = MatchByProperty, "name", name
	return r, nil
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
// payload to avoid tagging/deleting existing AD Computers during cleanup.
type Edge struct {
	kind        EdgeKind
	start       Reference
	end         Reference
	observation Observation
	access      *AccessEvidence
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
func (e Edge) AccessEvidence() (AccessEvidence, bool) {
	if e.access == nil {
		return AccessEvidence{}, false
	}
	return *e.access, true
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
	if !service.Kind().IsService() || (target.Kind() != Computer && target.Kind() != NetworkEndpoint) {
		return Edge{}, errors.New("ObservedAt requires service to Computer or NetworkEndpoint")
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

// NewAccessEdge accepts only validated anonymous success at the exact target,
// with operation-level evidence. No denied control request is required.
func NewAccessEdge(kind EdgeKind, vantage, target Reference, evidence AccessEvidence) (Edge, error) {
	if vantage.Kind() != CollectionVantage || vantage.identity != evidence.Observation.Vantage || target.ID() != evidence.TargetID {
		return Edge{}, errors.New("access requires the recorded vantage and exact operation target")
	}
	check := CheckResult{Observation: evidence.Observation, CheckID: evidence.CheckID, Operation: evidence.Operation, TargetID: evidence.TargetID, Outcome: evidence.Outcome, Reason: evidence.Reason}
	if err := check.Validate(vantage.Scope()); err != nil {
		return Edge{}, err
	}
	if !evidence.Anonymous || evidence.Outcome != OutcomeSuccess {
		return Edge{}, errors.New("positive access edge requires validated anonymous success")
	}
	valid := kind == UnauthenticatedAccess && target.Kind().IsService() && evidence.OperationKind == EnumerationOperation
	if kind == PublicAccess && evidence.OperationKind == ResourceReadOperation {
		switch target.Kind() {
		case MCPResource, WorkspaceFile, ModelArtifact, ArtifactStore, VectorCollection:
			valid = true
		}
	}
	if !valid {
		return Edge{}, errors.New("access kind requires the correct target and metadata/read operation")
	}
	e, err := newEdge(kind, vantage, target, evidence.Observation)
	if err != nil {
		return Edge{}, err
	}
	e.access = &evidence
	return e, nil
}
