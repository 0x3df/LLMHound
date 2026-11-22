package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/graph"
)

const (
	SchemaVersion = "1"
	MaxDetailSize = 4096
)

type RecordType string

const (
	RecordCheckResult RecordType = "check_result"
	RecordCorrelation RecordType = "correlation"
	RecordFingerprint RecordType = "fingerprint"
	RecordTLS         RecordType = "tls"
	RecordRedirect    RecordType = "redirect"
)

// Record is a bounded, structured entry for the .evidence.jsonl sidecar.
type Record struct {
	RecordType       RecordType `json:"record_type"`
	SchemaVersion    string     `json:"schema_version"`
	DeploymentScope  string     `json:"deployment_scope"`
	ScanID           string     `json:"scan_id"`
	CollectorVersion string     `json:"collector_version"`
	EvidenceID       string     `json:"evidence_id"`
	Source           string     `json:"source"`
	Surface          string     `json:"surface,omitempty"`
	VantageKey       string     `json:"vantage_key,omitempty"`
	ObservedAt       string     `json:"observed_at"`

	// CheckResult fields
	CheckID        string `json:"check_id,omitempty"`
	Operation      string `json:"operation,omitempty"`
	TargetID       string `json:"target_id,omitempty"`
	Outcome        string `json:"outcome,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Anonymous      *bool  `json:"anonymous,omitempty"`
	OperationKind  string `json:"operation_kind,omitempty"`
	Coverage       string `json:"coverage,omitempty"`
	CoverageReason string `json:"coverage_reason,omitempty"`

	// Correlation fields
	OriginalTarget   string   `json:"original_target,omitempty"`
	NormalizedTarget string   `json:"normalized_target,omitempty"`
	TargetType       string   `json:"target_type,omitempty"`
	NativeKind       string   `json:"native_kind,omitempty"`
	MatchMethod      string   `json:"match_method,omitempty"`
	MatchValue       string   `json:"match_value,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	FallbackReason   string   `json:"fallback_reason,omitempty"`
	CandidateIDs     []string `json:"candidate_ids,omitempty"`
	MappingSource    string   `json:"mapping_source,omitempty"`

	// Fingerprint fields
	Product            string `json:"product,omitempty"`
	Vendor             string `json:"vendor,omitempty"`
	SoftwareVersion    string `json:"software_version,omitempty"`
	SoftwareVersionRaw string `json:"software_version_raw,omitempty"`
	BuildID            string `json:"build_id,omitempty"`
	Commit             string `json:"commit,omitempty"`
	ImageDigest        string `json:"image_digest,omitempty"`
	APIVersion         string `json:"api_version,omitempty"`
	ProtocolVersion    string `json:"protocol_version,omitempty"`
	Method             string `json:"method,omitempty"`

	// TLS fields
	CertFingerprint    string   `json:"cert_fingerprint,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	SANs               []string `json:"sans,omitempty"`
	ValidFrom          string   `json:"valid_from,omitempty"`
	ValidTo            string   `json:"valid_to,omitempty"`
	VerificationResult string   `json:"verification_result,omitempty"`
	VerificationReason string   `json:"verification_reason,omitempty"`
	NegotiatedVersion  string   `json:"negotiated_version,omitempty"`
	InsecureOverride   *bool    `json:"insecure_override,omitempty"`

	// Redirect fields
	FromURL    string `json:"from_url,omitempty"`
	ToURL      string `json:"to_url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Authorized *bool  `json:"authorized,omitempty"`

	// Bounded supporting data
	Details map[string]any `json:"details,omitempty"`
}

func (r Record) Validate() error {
	if r.RecordType == "" {
		return errors.New("record requires record_type")
	}
	if r.SchemaVersion != SchemaVersion {
		return errors.New("record requires schema_version 1")
	}
	if r.DeploymentScope == "" || r.ScanID == "" || r.EvidenceID == "" || r.Source == "" {
		return errors.New("record requires explicit provenance: scope, scan_id, evidence_id, source")
	}
	if r.ObservedAt == "" {
		return errors.New("record requires observed_at time")
	}
	t, err := time.Parse(time.RFC3339, r.ObservedAt)
	if err != nil {
		return fmt.Errorf("observed_at must be RFC3339: %w", err)
	}
	_, offset := t.Zone()
	if offset != 0 {
		return errors.New("observed_at must be UTC")
	}
	return nil
}

func baseRecord(obs graph.Observation, typ RecordType) Record {
	return Record{
		RecordType:       typ,
		SchemaVersion:    SchemaVersion,
		DeploymentScope:  obs.DeploymentScope,
		ScanID:           obs.ScanID,
		CollectorVersion: obs.CollectorVersion,
		EvidenceID:       obs.EvidenceID,
		Source:           SanitizeURL(obs.Source),
		Surface:          obs.Surface,
		VantageKey:       obs.VantageKey,
		ObservedAt:       obs.ObservedAt.UTC().Format(time.RFC3339),
		Coverage:         string(obs.Coverage),
		CoverageReason:   obs.CoverageReason,
	}
}

// NewCheckResultRecord creates an evidence record from a CheckResult.
func NewCheckResultRecord(check graph.CheckResult, details map[string]any) (Record, error) {
	if err := check.Validate(check.Observation.DeploymentScope); err != nil {
		return Record{}, err
	}
	r := baseRecord(check.Observation, RecordCheckResult)
	r.CheckID = check.CheckID
	r.Operation = check.Operation
	r.TargetID = check.TargetID
	r.Outcome = string(check.Outcome)
	r.Reason = check.Reason
	r.Details = sanitizeDetails(details)
	return r, nil
}

// NewAccessEvidenceRecord creates an evidence record from AccessEvidence.
func NewAccessEvidenceRecord(access graph.AccessEvidence, details map[string]any) (Record, error) {
	if err := access.Observation.Validate(access.Observation.DeploymentScope); err != nil {
		return Record{}, err
	}
	r := baseRecord(access.Observation, RecordCheckResult)
	r.CheckID = access.CheckID
	r.Operation = access.Operation
	r.TargetID = access.TargetID
	r.Outcome = string(access.Outcome)
	r.Reason = access.Reason
	anon := access.Anonymous
	r.Anonymous = &anon
	r.OperationKind = string(access.OperationKind)
	r.Details = sanitizeDetails(details)
	return r, nil
}

// NewCorrelationRecord creates an evidence record from a correlation decision.
func NewCorrelationRecord(ev correlate.Evidence, obs graph.Observation) (Record, error) {
	if err := obs.Validate(obs.DeploymentScope); err != nil {
		return Record{}, err
	}
	r := baseRecord(obs, RecordCorrelation)
	r.OriginalTarget = ev.OriginalTarget
	r.NormalizedTarget = ev.NormalizedTarget
	r.TargetType = string(ev.TargetType)
	r.NativeKind = string(ev.NativeKind)
	r.MatchMethod = ev.Correlation.MatchMethod
	r.MatchValue = ev.Correlation.MatchValue
	r.Confidence = ev.Correlation.Confidence
	r.FallbackReason = ev.Correlation.FallbackReason
	r.CandidateIDs = append([]string(nil), ev.Correlation.CandidateIDs...)
	r.MappingSource = ev.Correlation.MappingSource
	return r, nil
}

// NewFingerprintRecord creates an evidence record for component fingerprinting.
type FingerprintInput struct {
	Observation        graph.Observation
	TargetID           string
	Product            string
	Vendor             string
	SoftwareVersion    string
	SoftwareVersionRaw string
	BuildID            string
	Commit             string
	ImageDigest        string
	APIVersion         string
	ProtocolVersion    string
	Method             string
	Confidence         string
	Details            map[string]any
}

func NewFingerprintRecord(input FingerprintInput) (Record, error) {
	if err := input.Observation.Validate(input.Observation.DeploymentScope); err != nil {
		return Record{}, err
	}
	r := baseRecord(input.Observation, RecordFingerprint)
	r.TargetID = input.TargetID
	r.Product = input.Product
	r.Vendor = input.Vendor
	r.SoftwareVersion = input.SoftwareVersion
	r.SoftwareVersionRaw = input.SoftwareVersionRaw
	r.BuildID = input.BuildID
	r.Commit = input.Commit
	r.ImageDigest = input.ImageDigest
	r.APIVersion = input.APIVersion
	r.ProtocolVersion = input.ProtocolVersion
	r.Method = input.Method
	r.Confidence = input.Confidence
	r.Details = sanitizeDetails(input.Details)
	return r, nil
}

// TLSRecordInput contains fields for a TLS observation record.
type TLSRecordInput struct {
	Observation        graph.Observation
	TargetID           string
	CertFingerprint    string
	Issuer             string
	Subject            string
	SANs               []string
	ValidFrom          string
	ValidTo            string
	VerificationResult string
	VerificationReason string
	NegotiatedVersion  string
	InsecureOverride   bool
	Details            map[string]any
}

func NewTLSRecord(input TLSRecordInput) (Record, error) {
	if err := input.Observation.Validate(input.Observation.DeploymentScope); err != nil {
		return Record{}, err
	}
	r := baseRecord(input.Observation, RecordTLS)
	r.TargetID = input.TargetID
	r.CertFingerprint = input.CertFingerprint
	r.Issuer = input.Issuer
	r.Subject = input.Subject
	r.SANs = append([]string(nil), input.SANs...)
	r.ValidFrom = input.ValidFrom
	r.ValidTo = input.ValidTo
	r.VerificationResult = input.VerificationResult
	r.VerificationReason = input.VerificationReason
	r.NegotiatedVersion = input.NegotiatedVersion
	insecure := input.InsecureOverride
	r.InsecureOverride = &insecure
	r.Details = sanitizeDetails(input.Details)
	return r, nil
}

// RedirectRecordInput contains fields for an authorized redirect observation.
type RedirectRecordInput struct {
	Observation graph.Observation
	FromURL     string
	ToURL       string
	StatusCode  int
	Authorized  bool
	Reason      string
	Details     map[string]any
}

func NewRedirectRecord(input RedirectRecordInput) (Record, error) {
	if err := input.Observation.Validate(input.Observation.DeploymentScope); err != nil {
		return Record{}, err
	}
	r := baseRecord(input.Observation, RecordRedirect)
	r.FromURL = SanitizeURL(input.FromURL)
	r.ToURL = SanitizeURL(input.ToURL)
	r.StatusCode = input.StatusCode
	auth := input.Authorized
	r.Authorized = &auth
	r.Reason = input.Reason
	r.Details = sanitizeDetails(input.Details)
	return r, nil
}

// SanitizeURL strips credentials, query strings, and fragments from a URL.
func SanitizeURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[malformed_url]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

var sensitiveKeyFragments = []string{
	"authorization",
	"cookie",
	"api_key",
	"api-key",
	"apikey",
	"passw",
	"secret",
	"bearer",
	"credential",
	"private_key",
}

var (
	evidenceURLPattern    = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	evidenceBearerPattern = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/-]+=*`)
)

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if lower == "auth" || strings.HasSuffix(lower, "token") {
		return true
	}
	for _, f := range sensitiveKeyFragments {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}

func sanitizeDetails(details map[string]any) map[string]any {
	if len(details) == 0 {
		return nil
	}
	return sanitizeMap(details)
}

func sanitizeMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = sanitizeValue(v)
	}
	return out
}

func sanitizeValue(v any) any {
	switch t := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return t
	case string:
		t = evidenceURLPattern.ReplaceAllStringFunc(t, SanitizeURL)
		t = evidenceBearerPattern.ReplaceAllString(t, "${1} [REDACTED]")
		if len(t) > MaxDetailSize {
			cut := MaxDetailSize
			for cut > 0 && !utf8.RuneStart(t[cut]) {
				cut--
			}
			return t[:cut] + "…[truncated]"
		}
		return t
	case map[string]any:
		return sanitizeMap(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sanitizeValue(e)
		}
		return out
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return "[unserializable]"
		}
		var normalized any
		if err := json.Unmarshal(raw, &normalized); err != nil {
			return "[unserializable]"
		}
		return sanitizeValue(normalized)
	}
}
