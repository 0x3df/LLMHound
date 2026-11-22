package emitter

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/graph"
)

var (
	kindPattern      = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	tagPrefixPattern = regexp.MustCompile(`(?i)^tag_`)
)

// Metadata defines OpenGraph top-level ingest metadata.
type Metadata struct {
	SourceKind string `json:"source_kind,omitempty"`
}

// EndpointPayload defines how an edge endpoint is matched. LLMHound matches
// existing native nodes and its own nodes by objectid only: M0 showed property
// matching silently drops zero or ambiguous matches.
type EndpointPayload struct {
	MatchBy string `json:"match_by"`
	Value   string `json:"value"`
}

// NodePayload represents an entity node in an OpenGraph payload.
type NodePayload struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties"`
}

// EdgePayload represents a relationship between two nodes.
type EdgePayload struct {
	Kind       string          `json:"kind"`
	Start      EndpointPayload `json:"start"`
	End        EndpointPayload `json:"end"`
	Properties map[string]any  `json:"properties,omitempty"`
}

// GraphPayload encapsulates nodes and edges.
type GraphPayload struct {
	Nodes []NodePayload `json:"nodes"`
	Edges []EdgePayload `json:"edges"`
}

// Payload represents the top-level OpenGraph JSON document.
type Payload struct {
	Metadata *Metadata    `json:"metadata,omitempty"`
	Graph    GraphPayload `json:"graph"`
}

// NodeItem pairs a domain Node with its flat OpenGraph properties.
type NodeItem struct {
	Node       graph.Node
	Properties map[string]any
}

// NewNodeItem constructs and validates a NodeItem.
func NewNodeItem(node graph.Node, props map[string]any) (NodeItem, error) {
	if node.Identity().ID() == "" {
		return NodeItem{}, errors.New("node requires a valid identity")
	}
	validated, err := ValidateProperties(props)
	if err != nil {
		return NodeItem{}, fmt.Errorf("node %s: %w", node.Identity().ID(), err)
	}

	// Inject default properties from node observation if not already provided
	obs := node.Observation()
	if _, ok := validated["name"]; !ok {
		validated["name"] = strings.ToUpper(node.Identity().ID())
	}
	if _, ok := validated["coverage"]; !ok && obs.Coverage != "" {
		validated["coverage"] = string(obs.Coverage)
	}
	if _, ok := validated["scan_id"]; !ok && obs.ScanID != "" {
		validated["scan_id"] = obs.ScanID
	}
	if _, ok := validated["evidence_id"]; !ok && obs.EvidenceID != "" {
		validated["evidence_id"] = obs.EvidenceID
	}
	if _, ok := validated["observed_at"]; !ok && !obs.ObservedAt.IsZero() {
		validated["observed_at"] = obs.ObservedAt.UTC().Format(time.RFC3339)
	}

	return NodeItem{Node: node, Properties: validated}, nil
}

// ValidateProperties validates that properties conform to BloodHound CE constraints:
// - Lowercase property names
// - Flat primitive values or homogeneous primitive slices
// - No nested objects, arrays of objects, or heterogeneous arrays
// - No null values
// - No reserved "objectid" property
func ValidateProperties(props map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(props))
	for k, v := range props {
		if strings.TrimSpace(k) == "" {
			return nil, errors.New("property key cannot be empty")
		}
		lower := strings.ToLower(k)
		if lower != k {
			return nil, fmt.Errorf("property key %q must be lowercase", k)
		}
		if lower == "objectid" {
			return nil, errors.New("reserved property 'objectid' is not allowed")
		}
		if v == nil {
			return nil, fmt.Errorf("property %q cannot have null value", k)
		}
		if err := validatePropertyValue(lower, v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}

func validatePropertyValue(key string, val any) error {
	v := reflect.ValueOf(val)
	switch v.Kind() {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return nil

	case reflect.Slice, reflect.Array:
		n := v.Len()
		if n == 0 {
			return nil
		}
		var elemKind reflect.Kind
		for i := 0; i < n; i++ {
			elem := v.Index(i)
			if elem.Kind() == reflect.Interface {
				elem = elem.Elem()
			}
			if !elem.IsValid() {
				return fmt.Errorf("property %q has null array element", key)
			}
			curKind := elem.Kind()
			if !isAllowedPrimitiveKind(curKind) {
				return fmt.Errorf("property %q has array of unsupported element kind %s", key, curKind)
			}
			if i == 0 {
				elemKind = curKind
			} else if !isCompatibleSliceKind(elemKind, curKind) {
				return fmt.Errorf("property %q has heterogeneous array elements (%s and %s)", key, elemKind, curKind)
			}
		}
		return nil

	case reflect.Map, reflect.Struct:
		return fmt.Errorf("property %q has nested object value (not supported in OpenGraph)", key)

	default:
		return fmt.Errorf("property %q has unsupported value kind %s", key, v.Kind())
	}
}

func isAllowedPrimitiveKind(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

func isCompatibleSliceKind(a, b reflect.Kind) bool {
	if a == b {
		return true
	}
	// Check numeric compatibility
	isNum := func(k reflect.Kind) bool {
		return (k >= reflect.Int && k <= reflect.Float64)
	}
	return isNum(a) && isNum(b)
}

func formatEndpoint(ref graph.Reference) (EndpointPayload, error) {
	id := ref.ID()
	if id == "" {
		return EndpointPayload{}, errors.New("id matcher requires nonempty value")
	}
	if strings.Contains(id, ":") {
		return EndpointPayload{}, fmt.Errorf("node id %q cannot contain colons", id)
	}
	return EndpointPayload{MatchBy: "id", Value: id}, nil
}

func formatEdge(edge graph.Edge) (EdgePayload, error) {
	emittedKind, err := edge.Kind().Emitted()
	if err != nil {
		return EdgePayload{}, fmt.Errorf("invalid edge kind: %w", err)
	}
	if !kindPattern.MatchString(emittedKind) {
		return EdgePayload{}, fmt.Errorf("edge kind %q does not match ^[A-Za-z0-9_]+$", emittedKind)
	}
	if tagPrefixPattern.MatchString(emittedKind) {
		return EdgePayload{}, fmt.Errorf("edge kind %q uses reserved tag_ prefix", emittedKind)
	}

	start, err := formatEndpoint(edge.Start())
	if err != nil {
		return EdgePayload{}, fmt.Errorf("edge %s start: %w", emittedKind, err)
	}
	end, err := formatEndpoint(edge.End())
	if err != nil {
		return EdgePayload{}, fmt.Errorf("edge %s end: %w", emittedKind, err)
	}

	props := make(map[string]any)
	if corr, ok := edge.Correlation(); ok {
		if corr.MatchMethod != "" {
			props["match_method"] = corr.MatchMethod
		}
		if corr.MatchValue != "" {
			props["match_value"] = corr.MatchValue
		}
		if corr.Confidence != "" {
			props["confidence"] = corr.Confidence
		}
		if corr.FallbackReason != "" {
			props["fallback_reason"] = corr.FallbackReason
		}
		if corr.MappingSource != "" {
			props["mapping_source"] = corr.MappingSource
		}
	}
	if prov, ok := edge.RuleProvenance(); ok {
		props["rule_id"] = prov.RuleID
		props["rule_version"] = prov.RuleVersion
		props["basis"] = prov.Basis
		props["confidence"] = prov.Confidence
		props["capability_class"] = prov.CapabilityClass
		props["reach_basis"] = prov.ReachBasis
		props["exec_identity"] = prov.ExecIdentity
		props["service_id"] = prov.ServiceID
		props["operations"] = prov.Operations
		props["evidence_ids"] = prov.EvidenceIDs
	}

	obs := edge.Observation()
	if obs.ScanID != "" {
		props["scan_id"] = obs.ScanID
	}
	if obs.EvidenceID != "" {
		props["evidence_id"] = obs.EvidenceID
	}
	if !obs.ObservedAt.IsZero() {
		props["observed_at"] = obs.ObservedAt.UTC().Format(time.RFC3339)
	}

	validatedProps, err := ValidateProperties(props)
	if err != nil {
		return EdgePayload{}, fmt.Errorf("edge %s properties: %w", emittedKind, err)
	}

	return EdgePayload{
		Kind:       emittedKind,
		Start:      start,
		End:        end,
		Properties: validatedProps,
	}, nil
}
