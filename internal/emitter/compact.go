package emitter

import (
	"strings"

	"github.com/0x3df/LLMHound/internal/graph"
)

// FilterOptions controls BloodHound CE graph size reduction for attack-path mode.
type FilterOptions struct {
	// CompactAttackPath keeps AIService nodes, NetworkEndpoints (unless MappedOnly),
	// and only high-risk MCPTool nodes (capability_hint in shell/filesystem/secrets/code),
	// moving verbose child inventory strictly to .evidence.jsonl.
	CompactAttackPath bool

	// MappedOnly omits unmapped NetworkEndpoint fallback nodes and their
	// ObservedAt edges from BloodHound payloads (retaining them in .evidence.jsonl).
	MappedOnly bool
}

var highRiskCapabilityHints = map[string]bool{
	"shell":      true,
	"filesystem": true,
	"secrets":    true,
	"code":       true,
}

// FilterAttackPathGraph filters nodes and edges for high-signal, low-bloat
// BloodHound CE ingestion according to opts.
func FilterAttackPathGraph(nodes []NodeItem, edges []graph.Edge, opts FilterOptions) ([]NodeItem, []graph.Edge) {
	if !opts.CompactAttackPath && !opts.MappedOnly {
		return nodes, edges
	}

	keptNodes := make([]NodeItem, 0, len(nodes))
	keptIDs := make(map[string]bool, len(nodes))

	for _, item := range nodes {
		kind := item.Node.Identity().Kind()
		id := strings.ToUpper(item.Node.Identity().ID())

		if opts.MappedOnly && kind == graph.NetworkEndpoint {
			continue
		}

		if opts.CompactAttackPath {
			switch {
			case kind.IsService():
				// Always keep AIService nodes.
			case kind == graph.NetworkEndpoint:
				// Already filtered by MappedOnly above.
			case kind == graph.MCPTool:
				if !hasHighRiskCapabilityHint(item.Properties) {
					continue
				}
			default:
				// Omit verbose inventory child nodes (AIModel, WorkspaceFile,
				// VectorCollection, ModelArtifact, ArtifactStore, A2ASkill,
				// MCPResource, MCPPrompt) from BloodHound graph payload.
				continue
			}
		}

		keptIDs[id] = true
		keptNodes = append(keptNodes, item)
	}

	keptEdges := make([]graph.Edge, 0, len(edges))
	for _, e := range edges {
		if opts.MappedOnly && e.End().Kind() == graph.NetworkEndpoint && !e.End().IsNative() {
			continue
		}
		if !e.Start().IsNative() && !keptIDs[strings.ToUpper(e.Start().ID())] {
			continue
		}
		if !e.End().IsNative() && !keptIDs[strings.ToUpper(e.End().ID())] {
			continue
		}
		keptEdges = append(keptEdges, e)
	}

	return keptNodes, keptEdges
}

func hasHighRiskCapabilityHint(props map[string]any) bool {
	if props == nil {
		return false
	}
	raw, ok := props["capability_hint"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case []string:
		for _, hint := range v {
			if highRiskCapabilityHints[strings.ToLower(strings.TrimSpace(hint))] {
				return true
			}
		}
	case []any:
		for _, elem := range v {
			if s, ok := elem.(string); ok && highRiskCapabilityHints[strings.ToLower(strings.TrimSpace(s))] {
				return true
			}
		}
	}
	return false
}
