// Package savedsearch generates the BloodHound saved queries shipped in
// extension/saved_searches. Queries are written once with logical kind names and
// rendered with emitted names (internal/graph/kinds.go) and the traversable path
// kinds snapshotted from the pinned CE (docs/05-ce-compatibility.md, R2).
package savedsearch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0x3df/LLMHound/internal/graph"
)

// Query is the Query Library import shape (M0 Q9).
type Query struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Query       string `json:"query"`
}

// StartPlaceholder marks the one value an analyst must replace in P2.
const StartPlaceholder = "<START_OBJECTID>"

// CutoffPlaceholder marks the ISO-8601 UTC timestamp cutoff in P8.
const CutoffPlaceholder = "<CUTOFF_ISO8601>"

// GenerateOptions controls optional extensions to generated saved searches.
type GenerateOptions struct {
	// IncludeCanExecuteOn includes opt-in rule edge kinds (LLMHound_CanExecuteOn
	// and LLMHound_CanAssumePrincipal) in PATH_KINDS when path-qualification
	// rules are enabled on the target CE instance.
	IncludeCanExecuteOn bool
}

// ParsePathKinds reads a snapshot of traversable CE edge kinds, one per line.
// Blank lines and # comments are ignored; names are validated so that a bad
// snapshot cannot inject Cypher.
func ParsePathKinds(data string) ([]string, error) {
	var kinds []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for i, r := range line {
			isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			isDigit := r >= '0' && r <= '9'
			if i == 0 && !isLetter {
				return nil, fmt.Errorf("invalid edge kind %q", line)
			}
			if !isLetter && !isDigit && r != '_' {
				return nil, fmt.Errorf("invalid edge kind %q", line)
			}
		}
		if strings.HasPrefix(line, graph.SourceKind+"_") {
			return nil, fmt.Errorf("path kinds must not include LLMHound kinds: %q", line)
		}
		if seen[line] {
			return nil, fmt.Errorf("duplicate edge kind %q", line)
		}
		seen[line] = true
		kinds = append(kinds, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan path kinds: %w", err)
	}
	if len(kinds) == 0 {
		return nil, fmt.Errorf("no path kinds")
	}
	return kinds, nil
}

func mustEmit(k graph.Kind) string {
	s, err := k.Emitted()
	if err != nil {
		panic(err)
	}
	return s
}

func mustEmitEdge(k graph.EdgeKind) string {
	s, err := k.Emitted()
	if err != nil {
		panic(err)
	}
	return s
}

// Generate renders every shipped query with default (non-rule) path kinds.
// Kind names come from internal/graph; the shapes follow the CE 9.7.1 rules
// recorded in docs/04-saved-queries.md.
func Generate(pathKinds []string) []Query {
	return GenerateWithOptions(pathKinds, GenerateOptions{})
}

// GenerateWithOptions renders every shipped query (P1–P12 and I1–I7).
func GenerateWithOptions(pathKinds []string, opts GenerateOptions) []Query {
	kinds := append([]string(nil), pathKinds...)
	if opts.IncludeCanExecuteOn {
		for _, rk := range graph.RuleEdgeKinds() {
			ruleEdge := mustEmitEdge(rk)
			found := false
			for _, k := range kinds {
				if k == ruleEdge {
					found = true
					break
				}
			}
			if !found {
				kinds = append(kinds, ruleEdge)
			}
		}
	}
	pk := strings.Join(kinds, "|")
	svc := mustEmit(graph.AIService)
	nep := mustEmit(graph.NetworkEndpoint)
	mcpSrv := mustEmit(graph.MCPServer)
	mcpTool := mustEmit(graph.MCPTool)
	jupSrv := mustEmit(graph.JupyterServer)
	wsFile := mustEmit(graph.WorkspaceFile)
	aiModel := mustEmit(graph.AIModel)
	vecCol := mustEmit(graph.VectorCollection)
	modelArt := mustEmit(graph.ModelArtifact)
	artStore := mustEmit(graph.ArtifactStore)

	obs := mustEmitEdge(graph.ObservedAt)
	usesBackend := mustEmitEdge(graph.UsesBackend)
	providesTool := mustEmitEdge(graph.ProvidesTool)
	providesModel := mustEmitEdge(graph.ProvidesModel)
	contains := mustEmitEdge(graph.Contains)
	exposesCred := mustEmitEdge(graph.ExposesCredentialFor)
	authVia := mustEmitEdge(graph.AuthenticatesVia)

	return []Query{
		{
			Name:        "LLMHound P1: AI hosts reachable from Domain Users",
			Description: "Shortest paths from Domain Users to hosts that run an AI service. Paths use only traversable AD/Azure edges unless opt-in CanExecuteOn rules are enabled.",
			Query: fmt.Sprintf("MATCH p = shortestPath((g:Group)-[:%s*1..]->(h))\n"+
				"WHERE g.objectid ENDS WITH '-513'\n  AND (h)<-[:%s]-(:%s)\nRETURN p\nLIMIT 100", pk, obs, svc),
		},
		{
			Name:        "LLMHound P2: shortest path from an asset to an AI host",
			Description: "Replace " + StartPlaceholder + " with the start node's objectid (upper-case), then run. Paths use only traversable edges.",
			Query: fmt.Sprintf("MATCH p = shortestPath((a {objectid: '%s'})-[:%s*1..]->(h))\n"+
				"WHERE (h)<-[:%s]-(:%s)\nRETURN p\nLIMIT 25", StartPlaceholder, pk, obs, svc),
		},
		{
			Name:        "LLMHound P3: AI hosts one or two hops from tier 0",
			Description: "Attached hosts running an AI service within one or two traversable hops of Tag_Tier_Zero.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(h)\nWHERE NOT h:%s\n"+
				"MATCH p = (h)-[:%s*1..2]->(t:Tag_Tier_Zero)\nRETURN s, h, p\nLIMIT 100", svc, obs, nep, pk),
		},
		{
			Name:        "LLMHound P4: anonymous AI services with an execution surface",
			Description: "Services that answered anonymous enumeration and expose a declared or inferred execution surface. exec_surface_basis says how; nothing was executed.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(h)\n"+
				"WHERE NOT h:%s\n"+
				"  AND s.auth_observed IN ['anonymous', 'mixed']\n"+
				"  AND any(x IN s.exec_surface WHERE x IN ['code_kernel','terminal','job_submit','code_eval','workflow_exec','tool_invocation'])\n"+
				"RETURN s, h\nLIMIT 100", svc, obs, nep),
		},
		{
			Name:        "LLMHound P5: gateways and UIs with backends on different hosts",
			Description: "Gateways or frontends reporting a backend service attached to a different existing BloodHound host.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(b:%s)\n"+
				"MATCH (s)-[:%s]->(hs), (b)-[:%s]->(hb)\n"+
				"WHERE hs <> hb AND NOT hs:%s AND NOT hb:%s\n"+
				"RETURN s, hs, b, hb\nLIMIT 100", svc, usesBackend, svc, obs, obs, nep, nep),
		},
		{
			Name:        "LLMHound P6: unattributed AI services",
			Description: "Hand-off list for the normalization program: services whose target was not in the asset mapping.",
			Query:       fmt.Sprintf("MATCH (s:%s)-[:%s]->(n:%s)\nRETURN s, n\nLIMIT 1000", svc, obs, nep),
		},
		{
			Name:        "LLMHound P7: MCP tools with high-risk capability hints on reachable hosts",
			Description: "Advertised MCP tools whose descriptions/schemas match high-risk capability hints (declared heuristic, not proof of behavior).",
			Query: fmt.Sprintf("MATCH (m:%s)-[:%s]->(t:%s)\n"+
				"WHERE any(x IN t.capability_hint WHERE x IN ['shell','filesystem','secrets','code'])\n"+
				"MATCH (m)-[:%s]->(h)\nWHERE NOT h:%s\nRETURN m, t, h\nLIMIT 100", mcpSrv, providesTool, mcpTool, obs, nep),
		},
		{
			Name:        "LLMHound P8: AI hosts with a confirmed exposed secret on an attack path",
			Description: "Replace " + CutoffPlaceholder + " with an ISO-8601 UTC timestamp (e.g. 2026-11-01T00:00:00Z). Confirmed high-precision matches only; unset never means clean.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(h)\n"+
				"WHERE NOT h:%s\n  AND s.has_exposed_secret = true\n  AND s.secret_last_confirmed >= '%s'\n"+
				"MATCH p = (g:Group)-[:%s*1..4]->(h)\nWHERE g.objectid ENDS WITH '-513'\nRETURN s, h, p\nLIMIT 100",
				svc, obs, nep, CutoffPlaceholder, pk),
		},
		{
			Name:        "LLMHound P9: high-risk AI services near Tier 0",
			Description: "Mapped AI services with anonymous execution surfaces or confirmed exposed secrets within 1–2 traversable hops of Tag_Tier_Zero.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(h)\n"+
				"WHERE NOT h:%s\n  AND ('anon_exec_surface' IN s.risk_signals OR s.has_exposed_secret = true)\n"+
				"MATCH p = (h)-[:%s*1..2]->(t:Tag_Tier_Zero)\nRETURN s, h, p\nLIMIT 100",
				svc, obs, nep, pk),
		},
		{
			Name:        "LLMHound P10: shortest path from Owned principals to AI hosts",
			Description: "Shortest traversable paths from Owned principals (Tag_Owned) to any mapped host running an AI service.",
			Query: fmt.Sprintf("MATCH p = shortestPath((o:Tag_Owned)-[:%s*1..]->(h))\n"+
				"WHERE (h)<-[:%s]-(:%s)\nRETURN p\nLIMIT 100", pk, obs, svc),
		},
		{
			Name:        "LLMHound P11: AI services exposing Entra credentials linked to AZApp",
			Description: "AI services that exposed paired Entra client credentials (without storing secrets), linked to native AZApp nodes and downstream Tier 0 paths.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(a:AZApp)\n"+
				"OPTIONAL MATCH p = (a)-[:%s*1..4]->(t:Tag_Tier_Zero)\nRETURN s, a, p\nLIMIT 100", svc, exposesCred, pk),
		},
		{
			Name:        "LLMHound P12: AI services with Entra SSO AZApp and host execution surface",
			Description: "Execution-capable AI services delegating authentication to an Entra AZApp, highlighting SSO-reachable compute hosts.",
			Query: fmt.Sprintf("MATCH (s:%s)-[:%s]->(a:AZApp)\n"+
				"MATCH (s)-[:%s]->(h)\nWHERE NOT h:%s\n  AND any(e IN coalesce(s.exec_surface, []) WHERE e IN ['code_kernel', 'job_submit', 'code_eval'])\nRETURN s, a, h\nLIMIT 100", svc, authVia, obs, nep),
		},
		{
			Name:        "LLMHound I1: anonymous access to AI services",
			Description: "Inventory of AI services whose enumeration endpoints answered anonymously or with mixed auth outcomes.",
			Query:       fmt.Sprintf("MATCH (s:%s)\nWHERE s.auth_observed IN ['anonymous', 'mixed']\nRETURN s\nLIMIT 500", svc),
		},
		{
			Name:        "LLMHound I2: MCP servers with anonymously listable tools",
			Description: "MCP servers where mcp_tools_list succeeded anonymously and enumerated tool descriptors.",
			Query:       fmt.Sprintf("MATCH (m:%s)-[:%s]->(t:%s)\nWHERE 'mcp_tools_list' IN m.anon_operations\nRETURN m, t\nLIMIT 500", mcpSrv, providesTool, mcpTool),
		},
		{
			Name:        "LLMHound I3: Jupyter servers with anonymous API or contents access",
			Description: "Jupyter servers where jupyter_contents or jupyter_sessions succeeded anonymously (version metadata never counts).",
			Query:       fmt.Sprintf("MATCH (j:%s)\nWHERE 'jupyter_contents' IN j.anon_operations\n   OR 'jupyter_sessions' IN j.anon_operations\nOPTIONAL MATCH (j)-[:%s]->(f:%s)\nRETURN j, f\nLIMIT 500", jupSrv, contains, wsFile),
		},
		{
			Name:        "LLMHound I4: model runtimes with anonymously listed models",
			Description: "AI model servers or gateways advertising models anonymously.",
			Query:       fmt.Sprintf("MATCH (s:%s)-[:%s]->(m:%s)\nWHERE s.auth_observed IN ['anonymous', 'mixed']\nRETURN s, m\nLIMIT 500", svc, providesModel, aiModel),
		},
		{
			Name:        "LLMHound I5: vector stores and registries exposing inventory",
			Description: "Vector collections, registered model artifacts, and artifact store roots associated with AI services.",
			Query:       fmt.Sprintf("MATCH (s:%s)-[:%s]->(r)\nWHERE r:%s OR r:%s OR r:%s\nRETURN s, r\nLIMIT 500", svc, contains, vecCol, modelArt, artStore),
		},
		{
			Name:        "LLMHound I6: AI services with TLS verification failures",
			Description: "AI services where TLS certificate verification failed during observation.",
			Query:       fmt.Sprintf("MATCH (s:%s)\nWHERE s.tls_verification = 'failed'\nRETURN s\nLIMIT 500", svc),
		},
		{
			Name:        "LLMHound I7: AI services grouped by product and software version",
			Description: "Product and software_version counts for downstream CVE joins (unknown versions stay null).",
			Query:       fmt.Sprintf("MATCH (s:%s)\nRETURN s.product, s.software_version, count(s)\nORDER BY count(s) DESC\nLIMIT 100", svc),
		},
	}
}

// FileName is the shipped file name for a query.
func FileName(q Query) string {
	name := strings.ToLower(q.Name)
	if i := strings.Index(name, ":"); i > 0 {
		name = name[:i]
	}
	name = strings.NewReplacer("llmhound ", "llmhound-", " ", "-").Replace(name)
	return name + ".json"
}

// Marshal renders a query as stable, indented JSON.
func Marshal(q Query) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "->" readable in Cypher
	enc.SetIndent("", "  ")
	if err := enc.Encode(q); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
