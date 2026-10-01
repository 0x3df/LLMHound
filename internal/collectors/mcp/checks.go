package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/graph"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	CheckIDInitialize    = "mcp_initialize"
	CheckIDToolsList     = "mcp_tools_list"
	CheckIDResourcesList = "mcp_resources_list"
	CheckIDPromptsList   = "mcp_prompts_list"
	CheckIDRFC9728       = "mcp_rfc9728_metadata"

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

func paginate[T any](maxPages, maxItems int, name string, fetch func(cursor string) ([]T, string, error)) ([]T, bool, string, error) {
	if maxPages <= 0 {
		maxPages = 100
	}
	if maxItems <= 0 {
		maxItems = 10000
	}

	var all []T
	cursor := ""
	for page := 1; ; page++ {
		items, next, err := fetch(cursor)
		if err != nil {
			return all, false, "", err
		}
		all = append(all, items...)
		if len(all) > maxItems {
			return all[:maxItems], true, fmt.Sprintf("%s enumeration reached item limit (%d)", name, maxItems), nil
		}
		if next == "" {
			return all, false, "", nil
		}
		if len(all) == maxItems {
			return all, true, fmt.Sprintf("%s enumeration reached item limit (%d)", name, maxItems), nil
		}
		if page >= maxPages {
			return all, true, fmt.Sprintf("%s enumeration reached page limit (%d)", name, maxPages), nil
		}
		cursor = next
	}
}

func callTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func executeToolsList(ctx context.Context, session *mcpsdk.ClientSession, maxPages, maxItems int, timeout time.Duration) ([]*mcpsdk.Tool, bool, string, error) {
	return paginate(maxPages, maxItems, "tools", func(cursor string) ([]*mcpsdk.Tool, string, error) {
		callCtx, cancel := callTimeout(ctx, timeout)
		defer cancel()
		res, err := session.ListTools(callCtx, &mcpsdk.ListToolsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return res.Tools, res.NextCursor, nil
	})
}

func executeResourcesList(ctx context.Context, session *mcpsdk.ClientSession, maxPages, maxItems int, timeout time.Duration) ([]*mcpsdk.Resource, []*mcpsdk.ResourceTemplate, bool, string, error) {
	resources, truncated, reason, err := paginate(maxPages, maxItems, "resources", func(cursor string) ([]*mcpsdk.Resource, string, error) {
		callCtx, cancel := callTimeout(ctx, timeout)
		defer cancel()
		res, err := session.ListResources(callCtx, &mcpsdk.ListResourcesParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return res.Resources, res.NextCursor, nil
	})
	if err != nil {
		return resources, nil, truncated, reason, err
	}

	templates, tmplTruncated, tmplReason, err := paginate(maxPages, maxItems, "resource templates", func(cursor string) ([]*mcpsdk.ResourceTemplate, string, error) {
		callCtx, cancel := callTimeout(ctx, timeout)
		defer cancel()
		res, err := session.ListResourceTemplates(callCtx, &mcpsdk.ListResourceTemplatesParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return res.ResourceTemplates, res.NextCursor, nil
	})
	if err != nil {
		if outcome, _ := classifyRPCError(err, OpResourcesList); outcome != graph.OutcomeUnsupported {
			return resources, templates, truncated, reason, fmt.Errorf("resources/templates/list: %w", err)
		}
	}
	if tmplTruncated {
		truncated = true
		if reason != "" {
			reason += "; "
		}
		reason += tmplReason
	}
	return resources, templates, truncated, reason, nil
}

func executePromptsList(ctx context.Context, session *mcpsdk.ClientSession, maxPages, maxItems int, timeout time.Duration) ([]*mcpsdk.Prompt, bool, string, error) {
	return paginate(maxPages, maxItems, "prompts", func(cursor string) ([]*mcpsdk.Prompt, string, error) {
		callCtx, cancel := callTimeout(ctx, timeout)
		defer cancel()
		res, err := session.ListPrompts(callCtx, &mcpsdk.ListPromptsParams{Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		return res.Prompts, res.NextCursor, nil
	})
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
