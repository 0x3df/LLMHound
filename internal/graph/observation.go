package graph

import (
	"errors"
	"time"
)

// Coverage describes only the configured surface, independently of check outcome.
type Coverage string

const (
	CoverageComplete  Coverage = "complete"
	CoveragePartial   Coverage = "partial"
	CoverageFailed    Coverage = "failed"
	CoverageTruncated Coverage = "truncated"
)

// Observation preserves original provenance on rescan/resume. First/last-seen
// and reconciliation belong to a stateful downstream owner, not these values.
// Source must be a sanitized operation/field reference, never a raw secret URL.
type Observation struct {
	SchemaVersion    string
	ScanID           string
	CollectorVersion string
	EvidenceID       string
	Source           string
	Surface          string
	ObservedAt       time.Time
	Vantage          Identity
	Coverage         Coverage
	CoverageReason   string
}

func (o Observation) Validate(scope string) error {
	if o.SchemaVersion != "1" {
		return errors.New("unsupported observation schema version")
	}
	for _, s := range []string{o.ScanID, o.CollectorVersion, o.EvidenceID, o.Source, o.Surface} {
		if !validStableText(s) {
			return errors.New("observation requires explicit sanitized provenance")
		}
	}
	if o.ObservedAt.IsZero() {
		return errors.New("observation requires its original time")
	}
	_, offset := o.ObservedAt.Zone()
	if offset != 0 {
		return errors.New("observation time must be UTC")
	}
	if o.Vantage.id == "" || o.Vantage.kind != CollectionVantage || o.Vantage.scope != scope {
		return errors.New("observation requires a collection vantage in the same scope")
	}
	switch o.Coverage {
	case CoverageComplete:
	case CoveragePartial, CoverageFailed, CoverageTruncated:
		if !validStableText(o.CoverageReason) {
			return errors.New("incomplete coverage requires a reason")
		}
	default:
		return errors.New("unknown surface coverage")
	}
	return nil
}

// Outcome describes the intended metadata operation, not an HTTP status alone.
type Outcome string

const (
	OutcomeSuccess     Outcome = "success"
	OutcomeDenied      Outcome = "denied"
	OutcomeUnsupported Outcome = "unsupported"
	OutcomeFailed      Outcome = "failed"
	OutcomeSkipped     Outcome = "skipped"
)

type CheckResult struct {
	Observation Observation
	CheckID     string
	Operation   string
	TargetID    string
	Outcome     Outcome
	Reason      string
}

func (r CheckResult) Validate(scope string) error {
	if err := r.Observation.Validate(scope); err != nil {
		return err
	}
	for _, s := range []string{r.CheckID, r.Operation, r.TargetID, r.Reason} {
		if !validStableText(s) {
			return errors.New("check requires operation, target, outcome reason and stable check ID")
		}
	}
	switch r.Outcome {
	case OutcomeSuccess, OutcomeDenied, OutcomeUnsupported, OutcomeFailed, OutcomeSkipped:
		return nil
	}
	return errors.New("unknown check outcome")
}

// OperationKind prevents transport probes or advertised capabilities from being
// mistaken for validated anonymous enumeration or content reads.
type OperationKind string

const (
	EnumerationOperation  OperationKind = "enumeration"
	ResourceReadOperation OperationKind = "resource-read"
)

type AccessEvidence struct {
	Observation   Observation
	CheckID       string
	Operation     string
	TargetID      string
	Outcome       Outcome
	Reason        string
	Anonymous     bool
	OperationKind OperationKind
}
