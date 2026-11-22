package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxStringLen = 4096

func boundString(s string, limit int) string {
	if limit <= 0 {
		limit = maxStringLen
	}
	if len(s) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut] + "…[truncated]"
	}
	return s
}

func isValidResourceKey(key string) bool {
	if key == "" || !utf8.ValidString(key) {
		return false
	}
	for _, c := range key {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func extractCapabilities(caps *mcpsdk.ServerCapabilities) []string {
	if caps == nil {
		return nil
	}
	var out []string
	if caps.Tools != nil {
		out = append(out, "tools")
	}
	if caps.Resources != nil {
		out = append(out, "resources")
	}
	if caps.Prompts != nil {
		out = append(out, "prompts")
	}
	if caps.Logging != nil {
		out = append(out, "logging")
	}
	if caps.Completions != nil {
		out = append(out, "completions")
	}
	for k := range caps.Experimental {
		out = append(out, "experimental:"+strings.ToLower(k))
	}
	for k := range caps.Extensions {
		out = append(out, "extension:"+strings.ToLower(k))
	}
	sort.Strings(out)
	return out
}

func buildServerNode(srvID graph.Identity, ep graph.Endpoint, obs graph.Observation, initResult *mcpsdk.InitializeResult, tlsObs *tlsObservation, access graph.Access, contentSummary *graph.ContentSummary) (emitter.NodeItem, error) {
	node, err := graph.NewNode(srvID, obs)
	if err != nil {
		return emitter.NodeItem{}, fmt.Errorf("create MCPServer node: %w", err)
	}

	displayName := fmt.Sprintf("MCP · %s:%d%s", ep.Host(), ep.Port(), ep.BasePath())
	facts := graph.ServiceFacts{Endpoint: ep, Name: displayName, VantageKey: obs.VantageKey, Access: access, Content: contentSummary}
	if tlsObs != nil {
		facts.TLS = &graph.TLSSummary{
			Result: tlsObs.VerificationResult, Reason: tlsObs.VerificationReason,
			LeafSHA256: tlsObs.CertFingerprint, Issuer: tlsObs.Issuer, NotAfter: tlsObs.ValidTo,
			TLSVersion: tlsObs.NegotiatedVersion, InsecureSet: tlsObs.InsecureOverride,
		}
	}
	// The server advertises a tools capability: tool invocation is a declared
	// execution surface (it was not invoked, and what a tool does is unknown).
	if initResult != nil && initResult.Capabilities != nil && initResult.Capabilities.Tools != nil {
		facts.ExecSurface = []string{graph.ExecToolInvocation}
		facts.ExecSurfaceBasis = graph.BasisDeclared
	}
	props := facts.Properties()

	if initResult != nil {
		if initResult.ServerInfo != nil {
			if initResult.ServerInfo.Name != "" {
				props["product"] = initResult.ServerInfo.Name
				props["vendor"] = initResult.ServerInfo.Name
			}
			if initResult.ServerInfo.Version != "" {
				props["software_version_raw"] = initResult.ServerInfo.Version
			}
			if initResult.ServerInfo.Title != "" {
				props["title"] = initResult.ServerInfo.Title
			}
			if initResult.ServerInfo.Description != "" {
				props["description"] = boundString(initResult.ServerInfo.Description, maxStringLen)
			}
			if initResult.ServerInfo.WebsiteURL != "" {
				props["website_url"] = boundString(initResult.ServerInfo.WebsiteURL, maxStringLen)
			}
		}

		if initResult.ProtocolVersion != "" {
			props["protocol_version"] = initResult.ProtocolVersion
		}

		caps := extractCapabilities(initResult.Capabilities)
		if len(caps) > 0 {
			props["capabilities"] = caps
		}

		if initResult.Instructions != "" {
			props["instructions"] = boundString(initResult.Instructions, maxStringLen)
		}
	}

	return emitter.NewNodeItem(node, props)
}

func buildToolNodesAndEdges(scope string, srvID graph.Identity, obs graph.Observation, tools []*mcpsdk.Tool) ([]emitter.NodeItem, []graph.Edge, error) {
	var nodes []emitter.NodeItem
	var edges []graph.Edge
	seen := make(map[string]bool)

	for _, tool := range tools {
		if tool == nil || !isValidResourceKey(tool.Name) {
			continue
		}
		if seen[tool.Name] {
			continue
		}
		seen[tool.Name] = true

		toolID, err := graph.NewResourceIdentity(scope, graph.MCPTool, srvID, tool.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("create tool identity %q: %w", tool.Name, err)
		}

		toolNode, err := graph.NewNode(toolID, obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create tool node %q: %w", tool.Name, err)
		}

		displayName := tool.Name
		if tool.Title != "" {
			displayName = tool.Title
		}

		props := map[string]any{
			"name":         tool.Name,
			"display_name": displayName,
			"tool_name":    tool.Name,
		}

		if tool.Description != "" {
			props["description"] = boundString(tool.Description, maxStringLen)
		}

		if tool.InputSchema != nil {
			if b, err := json.Marshal(tool.InputSchema); err == nil {
				props["input_schema"] = boundString(string(b), maxStringLen)
			}
		}

		if tool.OutputSchema != nil {
			if b, err := json.Marshal(tool.OutputSchema); err == nil {
				props["output_schema"] = boundString(string(b), maxStringLen)
			}
		}

		if tool.Annotations != nil {
			props["read_only_hint"] = tool.Annotations.ReadOnlyHint
			props["idempotent_hint"] = tool.Annotations.IdempotentHint
			if tool.Annotations.DestructiveHint != nil {
				props["destructive_hint"] = *tool.Annotations.DestructiveHint
			}
			if tool.Annotations.OpenWorldHint != nil {
				props["open_world_hint"] = *tool.Annotations.OpenWorldHint
			}
		}

		item, err := emitter.NewNodeItem(toolNode, props)
		if err != nil {
			return nil, nil, fmt.Errorf("create tool item %q: %w", tool.Name, err)
		}

		edge, err := graph.NewTopologyEdge(graph.ProvidesTool, srvID.Reference(), toolID.Reference(), obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create ProvidesTool edge for %q: %w", tool.Name, err)
		}

		nodes = append(nodes, item)
		edges = append(edges, edge)
	}

	return nodes, edges, nil
}

func buildResourceNodesAndEdges(scope string, srvID graph.Identity, obs graph.Observation, resources []*mcpsdk.Resource, templates []*mcpsdk.ResourceTemplate) ([]emitter.NodeItem, []graph.Edge, error) {
	var nodes []emitter.NodeItem
	var edges []graph.Edge
	seen := make(map[string]bool)

	for _, res := range resources {
		if res == nil {
			continue
		}
		key := res.URI
		if key == "" {
			key = res.Name
		}
		if !isValidResourceKey(key) || seen[key] {
			continue
		}
		seen[key] = true

		resID, err := graph.NewResourceIdentity(scope, graph.MCPResource, srvID, key)
		if err != nil {
			return nil, nil, fmt.Errorf("create resource identity %q: %w", key, err)
		}

		resNode, err := graph.NewNode(resID, obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create resource node %q: %w", key, err)
		}

		displayName := key
		if res.Title != "" {
			displayName = res.Title
		} else if res.Name != "" {
			displayName = res.Name
		}

		props := map[string]any{
			"name":         key,
			"display_name": displayName,
			"uri":          res.URI,
		}

		if res.Name != "" {
			props["resource_name"] = res.Name
		}
		if res.Description != "" {
			props["description"] = boundString(res.Description, maxStringLen)
		}
		if res.MIMEType != "" {
			props["mime_type"] = res.MIMEType
		}
		if res.Size > 0 {
			props["size"] = res.Size
		}

		if res.Annotations != nil {
			if res.Annotations.Priority > 0 {
				props["priority"] = res.Annotations.Priority
			}
			if res.Annotations.LastModified != "" {
				props["last_modified"] = res.Annotations.LastModified
			}
		}

		item, err := emitter.NewNodeItem(resNode, props)
		if err != nil {
			return nil, nil, fmt.Errorf("create resource item %q: %w", key, err)
		}

		edge, err := graph.NewTopologyEdge(graph.ProvidesResource, srvID.Reference(), resID.Reference(), obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create ProvidesResource edge for %q: %w", key, err)
		}

		nodes = append(nodes, item)
		edges = append(edges, edge)
	}

	for _, tmpl := range templates {
		if tmpl == nil || !isValidResourceKey(tmpl.URITemplate) || seen[tmpl.URITemplate] {
			continue
		}
		seen[tmpl.URITemplate] = true

		tmplID, err := graph.NewResourceIdentity(scope, graph.MCPResource, srvID, tmpl.URITemplate)
		if err != nil {
			return nil, nil, fmt.Errorf("create template identity %q: %w", tmpl.URITemplate, err)
		}

		tmplNode, err := graph.NewNode(tmplID, obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create template node %q: %w", tmpl.URITemplate, err)
		}

		displayName := tmpl.URITemplate
		if tmpl.Title != "" {
			displayName = tmpl.Title
		} else if tmpl.Name != "" {
			displayName = tmpl.Name
		}

		props := map[string]any{
			"name":         tmpl.URITemplate,
			"display_name": displayName,
			"uri":          tmpl.URITemplate,
			"uri_template": tmpl.URITemplate,
		}

		if tmpl.Name != "" {
			props["resource_name"] = tmpl.Name
		}
		if tmpl.Description != "" {
			props["description"] = boundString(tmpl.Description, maxStringLen)
		}
		if tmpl.MIMEType != "" {
			props["mime_type"] = tmpl.MIMEType
		}

		item, err := emitter.NewNodeItem(tmplNode, props)
		if err != nil {
			return nil, nil, fmt.Errorf("create template item %q: %w", tmpl.URITemplate, err)
		}

		edge, err := graph.NewTopologyEdge(graph.ProvidesResource, srvID.Reference(), tmplID.Reference(), obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create ProvidesResource template edge for %q: %w", tmpl.URITemplate, err)
		}

		nodes = append(nodes, item)
		edges = append(edges, edge)
	}

	return nodes, edges, nil
}

func buildPromptNodesAndEdges(scope string, srvID graph.Identity, obs graph.Observation, prompts []*mcpsdk.Prompt) ([]emitter.NodeItem, []graph.Edge, error) {
	var nodes []emitter.NodeItem
	var edges []graph.Edge
	seen := make(map[string]bool)

	for _, prompt := range prompts {
		if prompt == nil || !isValidResourceKey(prompt.Name) || seen[prompt.Name] {
			continue
		}
		seen[prompt.Name] = true

		promptID, err := graph.NewResourceIdentity(scope, graph.MCPPrompt, srvID, prompt.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("create prompt identity %q: %w", prompt.Name, err)
		}

		promptNode, err := graph.NewNode(promptID, obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create prompt node %q: %w", prompt.Name, err)
		}

		displayName := prompt.Name
		if prompt.Title != "" {
			displayName = prompt.Title
		}

		props := map[string]any{
			"name":         prompt.Name,
			"display_name": displayName,
			"prompt_name":  prompt.Name,
		}

		if prompt.Description != "" {
			props["description"] = boundString(prompt.Description, maxStringLen)
		}

		if len(prompt.Arguments) > 0 {
			var argNames []string
			for _, arg := range prompt.Arguments {
				if arg != nil && arg.Name != "" {
					argNames = append(argNames, arg.Name)
				}
			}
			if len(argNames) > 0 {
				props["arguments"] = argNames
			}
		}

		item, err := emitter.NewNodeItem(promptNode, props)
		if err != nil {
			return nil, nil, fmt.Errorf("create prompt item %q: %w", prompt.Name, err)
		}

		edge, err := graph.NewTopologyEdge(graph.ProvidesPrompt, srvID.Reference(), promptID.Reference(), obs)
		if err != nil {
			return nil, nil, fmt.Errorf("create ProvidesPrompt edge for %q: %w", prompt.Name, err)
		}

		nodes = append(nodes, item)
		edges = append(edges, edge)
	}

	return nodes, edges, nil
}

func buildCorrelationEdgeAndFallback(
	scope string,
	targetHost string,
	srvID graph.Identity,
	obs graph.Observation,
	correlator *correlate.Resolver,
) (graph.Edge, *emitter.NodeItem, correlate.Evidence, error) {
	corrRes, err := correlator.Resolve(scope, targetHost)
	if err != nil {
		return graph.Edge{}, nil, correlate.Evidence{}, fmt.Errorf("resolve correlation: %w", err)
	}
	edge, err := corrRes.ObservedAt(srvID, obs)
	if err != nil {
		return graph.Edge{}, nil, corrRes.Evidence(), err
	}

	var fallbackItem *emitter.NodeItem
	if fallbackID, ok := corrRes.FallbackIdentity(); ok {
		fallbackNode, err := graph.NewNode(fallbackID, obs)
		if err != nil {
			return graph.Edge{}, nil, corrRes.Evidence(), err
		}
		item, err := emitter.NewNodeItem(fallbackNode, map[string]any{
			"name":         strings.ToUpper(targetHost),
			"target_type":  string(corrRes.Evidence().TargetType),
			"target_value": targetHost,
		})
		if err != nil {
			return graph.Edge{}, nil, corrRes.Evidence(), err
		}
		fallbackItem = &item
	}
	return edge, fallbackItem, corrRes.Evidence(), nil
}
