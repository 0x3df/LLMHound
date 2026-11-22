package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/targets"
)

// ResolveBackendEdges deterministically links discovered AIService nodes that
// advertise backend_refs (such as LiteLLM proxies, Open WebUI instances, or A2A
// agents) to matching discovered AIService backend nodes in the same scope,
// emitting UsesBackend topology edges without speculative DNS lookups.
func ResolveBackendEdges(
	scope string,
	nodes []emitter.NodeItem,
	resolver *correlate.Resolver,
	obs graph.Observation,
) []graph.Edge {
	byHostPort := make(map[string][]graph.Identity)
	byObjPort := make(map[string][]graph.Identity)

	for _, item := range nodes {
		id := item.Node.Identity()
		if !id.Kind().IsService() || id.Scope() != scope {
			continue
		}
		rawHost, _ := item.Properties["endpoint_host"].(string)
		port, ok := toInt(item.Properties["endpoint_port"])
		if rawHost == "" || !ok || port <= 0 {
			continue
		}
		normHost, err := targets.NormalizeHost(rawHost)
		if err != nil {
			normHost = strings.ToLower(strings.TrimSpace(rawHost))
		}
		hpKey := hostPortKey(normHost, port)
		byHostPort[hpKey] = append(byHostPort[hpKey], id)

		if resolver != nil {
			if objID, mapped := resolver.ObjectIDForTarget(normHost); mapped {
				opKey := hostPortKey(strings.ToUpper(objID), port)
				byObjPort[opKey] = append(byObjPort[opKey], id)
			}
		}
	}

	var out []graph.Edge
	seen := make(map[string]bool)

	for _, item := range nodes {
		srcID := item.Node.Identity()
		if !srcID.Kind().IsService() || srcID.Scope() != scope {
			continue
		}
		refs := toStringSlice(item.Properties["backend_refs"])
		if len(refs) == 0 {
			continue
		}

		for _, rawRef := range refs {
			host, port, ok := parseBackendRefHostPort(rawRef)
			if !ok {
				continue
			}

			candidates := byHostPort[hostPortKey(host, port)]
			if len(candidates) == 0 && resolver != nil {
				if objID, mapped := resolver.ObjectIDForTarget(host); mapped {
					candidates = byObjPort[hostPortKey(strings.ToUpper(objID), port)]
				}
			}
			// Precision over recall: emit UsesBackend only on a unique non-self match.
			if len(candidates) != 1 {
				continue
			}
			dstID := candidates[0]
			if dstID.ID() == srcID.ID() {
				continue
			}
			edgeKey := srcID.ID() + "->" + dstID.ID()
			if seen[edgeKey] {
				continue
			}
			seen[edgeKey] = true

			edgeObs := obs
			sum := sha256.Sum256([]byte(srcID.ID() + "|" + dstID.ID() + "|" + rawRef))
			edgeObs.EvidenceID = "ev-backend-" + hex.EncodeToString(sum[:6])
			edgeObs.Surface = item.Node.Observation().Surface
			if srcEP, _ := item.Properties["endpoint"].(string); srcEP != "" {
				edgeObs.Source = srcEP
			}
			edgeObs.Coverage = graph.CoverageComplete
			edgeObs.CoverageReason = ""

			edge, err := graph.NewTopologyEdge(graph.UsesBackend, srcID.Reference(), dstID.Reference(), edgeObs)
			if err != nil {
				continue
			}
			out = append(out, edge)
		}
	}
	return out
}

func hostPortKey(host string, port int) string {
	return strings.ToLower(strings.TrimSpace(host)) + ":" + strconv.Itoa(port)
}

func parseBackendRefHostPort(raw string) (string, int, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", 0, false
	}
	h := u.Hostname()
	if h == "" {
		return "", 0, false
	}
	normHost, err := targets.NormalizeHost(h)
	if err != nil {
		return "", 0, false
	}
	port := 0
	if ps := u.Port(); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, false
		}
		port = p
	} else {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = 443
		case "http":
			port = 80
		default:
			return "", 0, false
		}
	}
	return normHost, port, true
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	default:
		return 0, false
	}
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, elem := range s {
			if str, ok := elem.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
