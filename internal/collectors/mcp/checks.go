package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/0x3df/LLMHound/internal/graph"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	CheckIDInitialize    = "mcp_initialize"
	CheckIDToolsList      = "mcp_tools_list"
	CheckIDResourcesList  = "mcp_resources_list"
	CheckIDPromptsList    = "mcp_prompts_list"
	CheckIDRFC9728        = "mcp_rfc9728_metadata"

	OpInitialize    = "initialize"
	OpToolsList     = "tools/list"
	OpResourcesList = "resources/list"
	OpPromptsList   = "prompts/list"
	OpRFC9728       = "rfc9728_protected_resource"
)

func classifyRPCError(err error, op string) (graph.Outcome, string) {
	if err == nil {
		return graph.OutcomeSuccess, ""
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "-32601") || strings.Contains(s, "method not found") {
		return graph.OutcomeUnsupported, fmt.Sprintf("%s method not supported by server (-32601)", op)
	}
	if strings.Contains(s, "401") || strings.Contains(s, "unauthorized") {
		return graph.OutcomeDenied, "authentication required (HTTP 401)"
	}
	if strings.Contains(s, "403") || strings.Contains(s, "forbidden") {
		return graph.OutcomeDenied, "access forbidden (HTTP 403)"
	}
	return graph.OutcomeFailed, err.Error()
}

func executeToolsList(ctx context.Context, session *mcpsdk.ClientSession, maxPages, maxItems int) ([]*mcpsdk.Tool, bool, string, error) {
	if maxPages <= 0 {
		maxPages = 100
	}
	if maxItems <= 0 {
		maxItems = 10000
	}

	var tools []*mcpsdk.Tool
	cursor := ""
	pageCount := 0
	isTruncated := false
	var truncationReason string

	for {
		pageCount++
		params := &mcpsdk.ListToolsParams{}
		if cursor != "" {
			params.Cursor = cursor
		}

		res, err := session.ListTools(ctx, params)
		if err != nil {
			return tools, isTruncated, truncationReason, err
		}

		tools = append(tools, res.Tools...)
		if len(tools) >= maxItems {
			tools = tools[:maxItems]
			isTruncated = true
			truncationReason = fmt.Sprintf("tools enumeration reached item limit (%d)", maxItems)
			break
		}

		if res.NextCursor == "" {
			break
		}

		if pageCount >= maxPages {
			isTruncated = true
			truncationReason = fmt.Sprintf("tools enumeration reached page limit (%d)", maxPages)
			break
		}

		cursor = res.NextCursor
	}

	return tools, isTruncated, truncationReason, nil
}

func executeResourcesList(ctx context.Context, session *mcpsdk.ClientSession, maxPages, maxItems int) ([]*mcpsdk.Resource, []*mcpsdk.ResourceTemplate, bool, string, error) {
	if maxPages <= 0 {
		maxPages = 100
	}
	if maxItems <= 0 {
		maxItems = 10000
	}

	var resources []*mcpsdk.Resource
	cursor := ""
	pageCount := 0
	isTruncated := false
	var truncationReason string

	for {
		pageCount++
		params := &mcpsdk.ListResourcesParams{}
		if cursor != "" {
			params.Cursor = cursor
		}

		res, err := session.ListResources(ctx, params)
		if err != nil {
			return resources, nil, isTruncated, truncationReason, err
		}

		resources = append(resources, res.Resources...)
		if len(resources) >= maxItems {
			resources = resources[:maxItems]
			isTruncated = true
			truncationReason = fmt.Sprintf("resources enumeration reached item limit (%d)", maxItems)
			break
		}

		if res.NextCursor == "" {
			break
		}

		if pageCount >= maxPages {
			isTruncated = true
			truncationReason = fmt.Sprintf("resources enumeration reached page limit (%d)", maxPages)
			break
		}

		cursor = res.NextCursor
	}

	var templates []*mcpsdk.ResourceTemplate
	if !isTruncated {
		tmplRes, err := session.ListResourceTemplates(ctx, &mcpsdk.ListResourceTemplatesParams{})
		if err == nil && tmplRes != nil {
			templates = tmplRes.ResourceTemplates
		}
	}

	return resources, templates, isTruncated, truncationReason, nil
}

func executePromptsList(ctx context.Context, session *mcpsdk.ClientSession, maxPages, maxItems int) ([]*mcpsdk.Prompt, bool, string, error) {
	if maxPages <= 0 {
		maxPages = 100
	}
	if maxItems <= 0 {
		maxItems = 10000
	}

	var prompts []*mcpsdk.Prompt
	cursor := ""
	pageCount := 0
	isTruncated := false
	var truncationReason string

	for {
		pageCount++
		params := &mcpsdk.ListPromptsParams{}
		if cursor != "" {
			params.Cursor = cursor
		}

		res, err := session.ListPrompts(ctx, params)
		if err != nil {
			return prompts, isTruncated, truncationReason, err
		}

		prompts = append(prompts, res.Prompts...)
		if len(prompts) >= maxItems {
			prompts = prompts[:maxItems]
			isTruncated = true
			truncationReason = fmt.Sprintf("prompts enumeration reached item limit (%d)", maxItems)
			break
		}

		if res.NextCursor == "" {
			break
		}

		if pageCount >= maxPages {
			isTruncated = true
			truncationReason = fmt.Sprintf("prompts enumeration reached page limit (%d)", maxPages)
			break
		}

		cursor = res.NextCursor
	}

	return prompts, isTruncated, truncationReason, nil
}

type rfc9728Response struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

func executeRFC9728(ctx context.Context, httpClient *http.Client, targetURL string, maxBytes int64) (authServers []string, resource string, statusCode int, err error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, "", 0, fmt.Errorf("parse target URL: %w", err)
	}

	wellKnownURL := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", parsed.Scheme, parsed.Host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("create RFC 9728 request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("fetch RFC 9728 metadata: %w", err)
	}
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	limit := maxBytes
	if limit <= 0 {
		limit = 1 << 20
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, "", statusCode, fmt.Errorf("read RFC 9728 body: %w", err)
	}

	if statusCode != http.StatusOK {
		return nil, "", statusCode, fmt.Errorf("RFC 9728 returned HTTP %d", statusCode)
	}

	var meta rfc9728Response
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, "", statusCode, fmt.Errorf("parse RFC 9728 metadata JSON: %w", err)
	}

	return meta.AuthorizationServers, meta.Resource, statusCode, nil
}
