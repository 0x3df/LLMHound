package checkpoint

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

const (
	SchemaVersion = "1"
)

// EntryType defines the kind of record in the journal.
type EntryType string

const (
	EntryHeader   EntryType = "header"
	EntryTarget   EntryType = "target"
	EntryResult   EntryType = "result"
	EntryNode     EntryType = "node"
	EntryEdge     EntryType = "edge"
	EntryEvidence EntryType = "evidence"
)

// Header contains scan-level provenance and configuration recorded at journal creation.
type Header struct {
	SchemaVersion    string `json:"schema_version"`
	DeploymentScope  string `json:"deployment_scope"`
	ScanID           string `json:"scan_id"`
	CollectorVersion string `json:"collector_version"`
	VantageKey       string `json:"vantage_key"`
	CreatedAt        string `json:"created_at"` // RFC3339 UTC
}

func (h Header) Validate() error {
	if h.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported journal schema_version %q (expected %q)", h.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(h.DeploymentScope) == "" {
		return errors.New("journal header requires non-empty deployment_scope")
	}
	if strings.TrimSpace(h.ScanID) == "" {
		return errors.New("journal header requires non-empty scan_id")
	}
	if strings.TrimSpace(h.CollectorVersion) == "" {
		return errors.New("journal header requires non-empty collector_version")
	}
	if strings.TrimSpace(h.VantageKey) == "" {
		return errors.New("journal header requires non-empty vantage_key")
	}
	if h.CreatedAt == "" {
		return errors.New("journal header requires non-empty created_at")
	}
	t, err := time.Parse(time.RFC3339, h.CreatedAt)
	if err != nil {
		return fmt.Errorf("created_at must be RFC3339: %w", err)
	}
	if _, offset := t.Zone(); offset != 0 {
		return errors.New("created_at must be in UTC")
	}
	return nil
}

// TargetStatus tracks target scanning progress.
type TargetStatus string

const (
	TargetStatusStarted   TargetStatus = "started"
	TargetStatusCompleted TargetStatus = "completed"
	TargetStatusFailed    TargetStatus = "failed"
	TargetStatusSkipped   TargetStatus = "skipped"
)

// TargetRecord represents target-level scanning progress and outcome.
type TargetRecord struct {
	Target      string             `json:"target"`
	Surface     string             `json:"surface,omitempty"`
	Status      TargetStatus       `json:"status"`
	Observation *ObservationRecord `json:"observation,omitempty"`
	Error       string             `json:"error,omitempty"`
	Details     map[string]any     `json:"details,omitempty"`
}

// Result is the composite record that collectors produce when evaluating a target and surface.
type Result struct {
	Target      string             `json:"target"`
	Surface     string             `json:"surface"`
	Observation graph.Observation  `json:"observation"`
	Status      TargetStatus       `json:"status,omitempty"`
	Nodes       []emitter.NodeItem `json:"nodes,omitempty"`
	Edges       []graph.Edge       `json:"edges,omitempty"`
	Evidence    []evidence.Record  `json:"evidence,omitempty"`
	Error       string             `json:"error,omitempty"`
	Details     map[string]any     `json:"details,omitempty"`
}

// Validate checks that the result has required fields and valid provenance.
func (r Result) Validate(scope string) error {
	if strings.TrimSpace(r.Target) == "" {
		return errors.New("result requires target")
	}
	if strings.TrimSpace(r.Surface) == "" {
		return errors.New("result requires surface")
	}
	if err := r.Observation.Validate(scope); err != nil {
		return fmt.Errorf("result observation: %w", err)
	}
	for i, n := range r.Nodes {
		if n.Node.Identity().ID() == "" {
			return fmt.Errorf("result node %d requires identity", i)
		}
	}
	for i, e := range r.Edges {
		if e.Kind() == "" {
			return fmt.Errorf("result edge %d requires kind", i)
		}
	}
	for i, ev := range r.Evidence {
		if err := ev.Validate(); err != nil {
			return fmt.Errorf("result evidence %d: %w", i, err)
		}
	}
	return nil
}

// JournalEntry is the top-level wire format for line-delimited JSON entries in the journal.
type JournalEntry struct {
	EntryType EntryType        `json:"entry_type"`
	Header    *Header          `json:"header,omitempty"`
	Target    *TargetRecord    `json:"target,omitempty"`
	Result    *ResultRecord    `json:"result,omitempty"`
	Node      *NodeRecord      `json:"node,omitempty"`
	Edge      *EdgeRecord      `json:"edge,omitempty"`
	Evidence  *evidence.Record `json:"evidence,omitempty"`
}

// ResultRecord is the serialized wire representation of a Result.
type ResultRecord struct {
	Target      string            `json:"target"`
	Surface     string            `json:"surface"`
	Observation ObservationRecord `json:"observation"`
	Status      TargetStatus      `json:"status,omitempty"`
	Nodes       []NodeRecord      `json:"nodes,omitempty"`
	Edges       []EdgeRecord      `json:"edges,omitempty"`
	Evidence    []evidence.Record `json:"evidence,omitempty"`
	Error       string            `json:"error,omitempty"`
	Details     map[string]any    `json:"details,omitempty"`
}

// IdentityRecord serializes graph.Identity.
type IdentityRecord struct {
	ID      string `json:"id"`
	Scope   string `json:"scope"`
	Kind    string `json:"kind"`
	OwnerID string `json:"owner_id,omitempty"`
}

// ObservationRecord serializes graph.Observation with UTC RFC3339 time.
type ObservationRecord struct {
	SchemaVersion    string `json:"schema_version"`
	ScanID           string `json:"scan_id"`
	CollectorVersion string `json:"collector_version"`
	EvidenceID       string `json:"evidence_id"`
	Source           string `json:"source"`
	Surface          string `json:"surface"`
	ObservedAt       string `json:"observed_at"` // RFC3339 UTC
	VantageKey       string `json:"vantage_key"`
	Coverage         string `json:"coverage"`
	CoverageReason   string `json:"coverage_reason,omitempty"`
}

// ReferenceRecord serializes graph.Reference.
type ReferenceRecord struct {
	IsNative   bool            `json:"is_native"`
	NativeID   string          `json:"native_id,omitempty"`
	MatchBy    string          `json:"match_by"`
	Property   string          `json:"property,omitempty"`
	MatchValue string          `json:"match_value,omitempty"`
	Identity   *IdentityRecord `json:"identity,omitempty"`
}

// NodeRecord serializes an emitter.NodeItem.
type NodeRecord struct {
	Identity    IdentityRecord    `json:"identity"`
	Observation ObservationRecord `json:"observation"`
	Properties  map[string]any    `json:"properties"`
}

// EdgeRecord serializes graph.Edge.
type EdgeRecord struct {
	Kind        string                `json:"kind"`
	Start       ReferenceRecord       `json:"start"`
	End         ReferenceRecord       `json:"end"`
	Observation ObservationRecord     `json:"observation"`
	Access      *AccessEvidenceRecord `json:"access,omitempty"`
	Correlation *CorrelationRecord    `json:"correlation,omitempty"`
}

// AccessEvidenceRecord serializes graph.AccessEvidence.
type AccessEvidenceRecord struct {
	CheckID       string            `json:"check_id"`
	Operation     string            `json:"operation"`
	TargetID      string            `json:"target_id"`
	Outcome       string            `json:"outcome"`
	Reason        string            `json:"reason"`
	Anonymous     bool              `json:"anonymous"`
	OperationKind string            `json:"operation_kind"`
	Observation   ObservationRecord `json:"observation"`
}

// CorrelationRecord serializes graph.Correlation.
type CorrelationRecord struct {
	MatchMethod    string   `json:"match_method,omitempty"`
	MatchValue     string   `json:"match_value,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	FallbackReason string   `json:"fallback_reason,omitempty"`
	CandidateIDs   []string `json:"candidate_ids,omitempty"`
}

// Helper converters

func toObservationRecord(obs graph.Observation) ObservationRecord {
	return ObservationRecord{
		SchemaVersion:    obs.SchemaVersion,
		ScanID:           obs.ScanID,
		CollectorVersion: obs.CollectorVersion,
		EvidenceID:       obs.EvidenceID,
		Source:           SanitizeURL(obs.Source),
		Surface:          obs.Surface,
		ObservedAt:       obs.ObservedAt.UTC().Format(time.RFC3339),
		VantageKey:       obs.Vantage.ID(),
		Coverage:         string(obs.Coverage),
		CoverageReason:   obs.CoverageReason,
	}
}

func fromObservationRecord(r ObservationRecord, vantage graph.Identity) (graph.Observation, error) {
	if r.SchemaVersion != SchemaVersion {
		return graph.Observation{}, fmt.Errorf("unsupported observation schema_version %q", r.SchemaVersion)
	}
	t, err := time.Parse(time.RFC3339, r.ObservedAt)
	if err != nil {
		return graph.Observation{}, fmt.Errorf("parse observed_at: %w", err)
	}
	if _, offset := t.Zone(); offset != 0 {
		return graph.Observation{}, errors.New("observed_at must be in UTC")
	}

	obs := graph.Observation{
		SchemaVersion:    r.SchemaVersion,
		ScanID:           r.ScanID,
		CollectorVersion: r.CollectorVersion,
		EvidenceID:       r.EvidenceID,
		Source:           r.Source,
		Surface:          r.Surface,
		ObservedAt:       t.UTC(),
		Vantage:          vantage,
		Coverage:         graph.Coverage(r.Coverage),
		CoverageReason:   r.CoverageReason,
	}
	if err := obs.Validate(vantage.Scope()); err != nil {
		return graph.Observation{}, fmt.Errorf("validate observation: %w", err)
	}
	return obs, nil
}

func toIdentityRecord(id graph.Identity) IdentityRecord {
	return IdentityRecord{
		ID:      id.ID(),
		Scope:   id.Scope(),
		Kind:    string(id.Kind()),
		OwnerID: id.OwnerID(),
	}
}

func fromIdentityRecord(r IdentityRecord) (graph.Identity, error) {
	return graph.RestoreIdentity(r.ID, r.Scope, graph.Kind(r.Kind), r.OwnerID)
}

func toReferenceRecord(ref graph.Reference) ReferenceRecord {
	rec := ReferenceRecord{
		IsNative:   ref.IsNative(),
		MatchBy:    string(ref.MatchBy()),
		Property:   ref.Property(),
		MatchValue: ref.MatchValue(),
	}
	if ref.IsNative() {
		rec.NativeID = ref.ID()
	} else {
		rec.Identity = &IdentityRecord{
			ID:      ref.ID(),
			Scope:   ref.Scope(),
			Kind:    string(ref.Kind()),
			OwnerID: ref.OwnerID(),
		}
	}
	return rec
}


func fromReferenceRecord(r ReferenceRecord) (graph.Reference, error) {
	if r.IsNative {
		if r.MatchBy == string(graph.MatchByProperty) {
			return graph.ExistingComputerByName(r.NativeID, r.MatchValue)
		}
		return graph.ExistingComputerByID(r.NativeID)
	}
	if r.Identity == nil {
		return graph.Reference{}, errors.New("source-owned reference requires identity")
	}
	ident, err := fromIdentityRecord(*r.Identity)
	if err != nil {
		return graph.Reference{}, fmt.Errorf("restore reference identity: %w", err)
	}
	return ident.Reference(), nil
}

func toNodeRecord(item emitter.NodeItem, maxStringLen int) NodeRecord {
	idRec := toIdentityRecord(item.Node.Identity())
	obsRec := toObservationRecord(item.Node.Observation())
	sanitizedProps := SanitizeMap(item.Properties, maxStringLen)
	return NodeRecord{
		Identity:    idRec,
		Observation: obsRec,
		Properties:  sanitizedProps,
	}
}

func fromNodeRecord(r NodeRecord, vantage graph.Identity) (emitter.NodeItem, error) {
	ident, err := fromIdentityRecord(r.Identity)
	if err != nil {
		return emitter.NodeItem{}, fmt.Errorf("restore node identity: %w", err)
	}
	obs, err := fromObservationRecord(r.Observation, vantage)
	if err != nil {
		return emitter.NodeItem{}, fmt.Errorf("restore node observation: %w", err)
	}
	node, err := graph.NewNode(ident, obs)
	if err != nil {
		return emitter.NodeItem{}, fmt.Errorf("create node: %w", err)
	}
	return emitter.NewNodeItem(node, r.Properties)
}

func toEdgeRecord(edge graph.Edge, maxStringLen int) EdgeRecord {
	rec := EdgeRecord{
		Kind:        string(edge.Kind()),
		Start:       toReferenceRecord(edge.Start()),
		End:         toReferenceRecord(edge.End()),
		Observation: toObservationRecord(edge.Observation()),
	}

	if corr, ok := edge.Correlation(); ok {
		rec.Correlation = &CorrelationRecord{
			MatchMethod:    corr.MatchMethod,
			MatchValue:     corr.MatchValue,
			Confidence:     corr.Confidence,
			FallbackReason: corr.FallbackReason,
			CandidateIDs:   append([]string(nil), corr.CandidateIDs...),
		}
	}

	if acc, ok := edge.AccessEvidence(); ok {
		rec.Access = &AccessEvidenceRecord{
			CheckID:       acc.CheckID,
			Operation:     acc.Operation,
			TargetID:      acc.TargetID,
			Outcome:       string(acc.Outcome),
			Reason:        acc.Reason,
			Anonymous:     acc.Anonymous,
			OperationKind: string(acc.OperationKind),
			Observation:   toObservationRecord(acc.Observation),
		}
	}

	return rec
}

func fromEdgeRecord(r EdgeRecord, vantage graph.Identity) (graph.Edge, error) {
	start, err := fromReferenceRecord(r.Start)
	if err != nil {
		return graph.Edge{}, fmt.Errorf("restore edge start: %w", err)
	}
	end, err := fromReferenceRecord(r.End)
	if err != nil {
		return graph.Edge{}, fmt.Errorf("restore edge end: %w", err)
	}
	obs, err := fromObservationRecord(r.Observation, vantage)
	if err != nil {
		return graph.Edge{}, fmt.Errorf("restore edge observation: %w", err)
	}

	kind := graph.EdgeKind(r.Kind)
	if kind == graph.ObservedAt {
		if r.Correlation == nil {
			return graph.Edge{}, errors.New("ObservedAt edge requires correlation")
		}
		corr := graph.Correlation{
			MatchMethod:    r.Correlation.MatchMethod,
			MatchValue:     r.Correlation.MatchValue,
			Confidence:     r.Correlation.Confidence,
			FallbackReason: r.Correlation.FallbackReason,
			CandidateIDs:   append([]string(nil), r.Correlation.CandidateIDs...),
		}
		return graph.NewObservedAtEdge(start, end, obs, corr)
	}

	if kind == graph.UnauthenticatedAccess || kind == graph.PublicAccess {
		if r.Access == nil {
			return graph.Edge{}, fmt.Errorf("%s edge requires access evidence", kind)
		}
		accObs, err := fromObservationRecord(r.Access.Observation, vantage)
		if err != nil {
			return graph.Edge{}, fmt.Errorf("restore access observation: %w", err)
		}
		acc := graph.AccessEvidence{
			Observation:   accObs,
			CheckID:       r.Access.CheckID,
			Operation:     r.Access.Operation,
			TargetID:      r.Access.TargetID,
			Outcome:       graph.Outcome(r.Access.Outcome),
			Reason:        r.Access.Reason,
			Anonymous:     r.Access.Anonymous,
			OperationKind: graph.OperationKind(r.Access.OperationKind),
		}
		return graph.NewAccessEdge(kind, start, end, acc)
	}

	return graph.NewTopologyEdge(kind, start, end, obs)
}

func toResultRecord(res Result, maxStringLen int) ResultRecord {
	nodes := make([]NodeRecord, len(res.Nodes))
	for i, n := range res.Nodes {
		nodes[i] = toNodeRecord(n, maxStringLen)
	}

	edges := make([]EdgeRecord, len(res.Edges))
	for i, e := range res.Edges {
		edges[i] = toEdgeRecord(e, maxStringLen)
	}

	evs := make([]evidence.Record, len(res.Evidence))
	for i, ev := range res.Evidence {
		ev.Details = SanitizeMap(ev.Details, maxStringLen)
		ev.Source = SanitizeURL(ev.Source)
		evs[i] = ev
	}

	return ResultRecord{
		Target:      SanitizeTarget(res.Target),
		Surface:     res.Surface,
		Observation: toObservationRecord(res.Observation),
		Status:      res.Status,
		Nodes:       nodes,
		Edges:       edges,
		Evidence:    evs,
		Error:       boundString(res.Error, maxStringLen),
		Details:     SanitizeMap(res.Details, maxStringLen),
	}
}

func fromResultRecord(r ResultRecord, vantage graph.Identity) (Result, error) {
	obs, err := fromObservationRecord(r.Observation, vantage)
	if err != nil {
		return Result{}, fmt.Errorf("restore result observation: %w", err)
	}

	nodes := make([]emitter.NodeItem, len(r.Nodes))
	for i, nr := range r.Nodes {
		node, err := fromNodeRecord(nr, vantage)
		if err != nil {
			return Result{}, fmt.Errorf("restore node %d: %w", i, err)
		}
		nodes[i] = node
	}

	edges := make([]graph.Edge, len(r.Edges))
	for i, er := range r.Edges {
		edge, err := fromEdgeRecord(er, vantage)
		if err != nil {
			return Result{}, fmt.Errorf("restore edge %d: %w", i, err)
		}
		edges[i] = edge
	}

	evs := make([]evidence.Record, len(r.Evidence))
	for i, ev := range r.Evidence {
		if err := ev.Validate(); err != nil {
			return Result{}, fmt.Errorf("validate evidence %d: %w", i, err)
		}
		evs[i] = ev
	}

	return Result{
		Target:      r.Target,
		Surface:     r.Surface,
		Observation: obs,
		Status:      r.Status,
		Nodes:       nodes,
		Edges:       edges,
		Evidence:    evs,
		Error:       r.Error,
		Details:     r.Details,
	}, nil
}
