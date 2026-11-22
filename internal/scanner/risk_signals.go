package scanner

import (
	"sort"
	"strings"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

var highRiskExecSurfaces = map[string]bool{
	graph.ExecCodeKernel:     true,
	graph.ExecTerminal:       true,
	graph.ExecJobSubmit:      true,
	graph.ExecCodeEval:       true,
	graph.ExecWorkflowExec:   true,
	graph.ExecToolInvocation: true,
}

var highRiskHints = map[string]bool{
	"shell":      true,
	"filesystem": true,
	"secrets":    true,
	"code":       true,
}

// EnrichRiskSignals computes a deterministic flat risk_signals array on each
// AIService node so BloodHound Cypher queries can filter high-value targets
// directly without multi-clause predicates.
func EnrichRiskSignals(nodes []emitter.NodeItem, edges []graph.Edge) {
	toolRisk := make(map[string]bool)
	for _, item := range nodes {
		if item.Node.Identity().Kind() != graph.MCPTool {
			continue
		}
		for _, hint := range toStringSlice(item.Properties["capability_hint"]) {
			if highRiskHints[strings.ToLower(strings.TrimSpace(hint))] {
				toolRisk[strings.ToUpper(item.Node.Identity().ID())] = true
				break
			}
		}
	}

	hasHighRiskTool := make(map[string]bool)
	hasCrossHostBackend := make(map[string]bool)

	for _, e := range edges {
		srcID := strings.ToUpper(e.Start().ID())
		dstID := strings.ToUpper(e.End().ID())
		switch e.Kind() {
		case graph.ProvidesTool:
			if toolRisk[dstID] {
				hasHighRiskTool[srcID] = true
			}
		case graph.UsesBackend:
			if srcID != "" && dstID != "" && srcID != dstID {
				hasCrossHostBackend[srcID] = true
			}
		}
	}

	for i := range nodes {
		item := &nodes[i]
		if !item.Node.Identity().Kind().IsService() {
			continue
		}
		id := strings.ToUpper(item.Node.Identity().ID())
		signals := make(map[string]bool)

		authObs, _ := item.Properties["auth_observed"].(string)
		if authObs == "anonymous" || authObs == "mixed" {
			for _, ex := range toStringSlice(item.Properties["exec_surface"]) {
				if highRiskExecSurfaces[ex] {
					signals["anon_exec_surface"] = true
					break
				}
			}
		}
		if b, _ := item.Properties["has_exposed_secret"].(bool); b {
			signals["exposed_secret"] = true
		}
		if len(toStringSlice(item.Properties["exposed_azapp_ids"])) > 0 || len(toStringSlice(item.Properties["exposed_aws_key_ids"])) > 0 {
			signals["exposed_cloud_identity"] = true
		}
		if cid, _ := item.Properties["entra_client_id"].(string); strings.TrimSpace(cid) != "" {
			signals["entra_sso_linked"] = true
		}
		if hasHighRiskTool[id] {
			signals["high_risk_mcp_tool"] = true
		}
		if hasCrossHostBackend[id] {
			signals["cross_host_backend"] = true
		}
		if b, _ := item.Properties["enable_signup"].(bool); b {
			signals["anon_signup_enabled"] = true
		}
		if b, _ := item.Properties["auto_login_enabled"].(bool); b {
			signals["anon_signup_enabled"] = true
		}
		if len(toStringSlice(item.Properties["store_refs"])) > 0 {
			signals["cloud_artifact_store"] = true
		}

		if len(signals) == 0 {
			continue
		}
		sorted := make([]string, 0, len(signals))
		for s := range signals {
			sorted = append(sorted, s)
		}
		sort.Strings(sorted)
		item.Properties["risk_signals"] = sorted
	}
}
