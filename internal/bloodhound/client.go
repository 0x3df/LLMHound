// Package bloodhound implements the BloodHound CE API client, read-only
// existence pre-flight, M0 Q5 two-step OpenGraph uploader, saved-query
// importer, and adapter validation gate.
package bloodhound

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxAPIResponseBytes = 16 << 20 // 16 MiB

// ClientConfig configures the BloodHound CE API client.
type ClientConfig struct {
	BaseURL    string
	Auth       AuthConfig
	Timeout    time.Duration
	Insecure   bool
	UserAgent  string
	HTTPClient *http.Client
	Now        func() time.Time
}

// Client communicates with BloodHound CE API v2.
type Client struct {
	baseURL    string
	auth       AuthConfig
	httpClient *http.Client
	userAgent  string
	now        func() time.Time

	mu          sync.Mutex
	bearerToken string
}

// NewClient validates cfg and returns a BloodHound CE API client.
func NewClient(cfg ClientConfig) (*Client, error) {
	rawURL := strings.TrimSpace(cfg.BaseURL)
	if rawURL == "" {
		return nil, errors.New("bloodhound url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid bloodhound url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return nil, errors.New("bloodhound url must be an http or https URL with host")
	}
	if err := cfg.Auth.Validate(); err != nil {
		return nil, err
	}

	cfg.Auth.TokenID = strings.TrimSpace(cfg.Auth.TokenID)
	cfg.Auth.TokenKey = strings.TrimSpace(cfg.Auth.TokenKey)
	cfg.Auth.BearerToken = strings.TrimSpace(cfg.Auth.BearerToken)
	cfg.Auth.Username = strings.TrimSpace(cfg.Auth.Username)

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tr := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			MaxIdleConns:          32,
			IdleConnTimeout:       30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.Insecure,
			},
		}
		hc = &http.Client{
			Transport: tr,
			Timeout:   timeout,
			// Never follow HTTP redirects silently (avoids forwarding auth/HMAC headers off-origin).
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	ua := strings.TrimSpace(cfg.UserAgent)
	if ua == "" {
		ua = "LLMHound/dev"
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	return &Client{
		baseURL:     strings.TrimRight(rawURL, "/"),
		auth:        cfg.Auth,
		httpClient:  hc,
		userAgent:   ua,
		now:         now,
		bearerToken: cfg.Auth.BearerToken,
	}, nil
}

// CloseIdleConnections closes any idle keep-alive sockets held by the CE client.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

// VersionInfo models GET /api/version.
type VersionInfo struct {
	ServerVersion  string `json:"server_version"`
	ProductEdition string `json:"product_edition"`
	APIVersion     string `json:"api_version"`
}

// ExtensionInfo models an entry returned by GET /api/v2/extensions.
type ExtensionInfo struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Version     string `json:"version"`
	Namespace   string `json:"namespace"`
	IsBuiltin   bool   `json:"is_builtin"`
}

// SourceKindInfo models an entry returned by GET /api/v2/graphs/source-kinds.
type SourceKindInfo struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ExtensionEdgeKind models an entry returned by GET /api/v2/extensions-edges.
type ExtensionEdgeKind struct {
	Name          string `json:"name"`
	IsTraversable bool   `json:"is_traversable"`
	SchemaName    string `json:"schema_name"`
	IsBuiltin     bool   `json:"is_builtin"`
}

// CypherNode models a node entry in POST /api/v2/graphs/cypher results.
type CypherNode struct {
	Label      string         `json:"label"`
	Kind       string         `json:"kind"`
	Kinds      []string       `json:"kinds"`
	ObjectID   string         `json:"objectId"`
	Properties map[string]any `json:"properties"`
}

// CypherResult models POST /api/v2/graphs/cypher response data.
type CypherResult struct {
	Nodes map[string]CypherNode `json:"nodes"`
	Edges []json.RawMessage     `json:"edges"`
}

func (c *Client) doRaw(ctx context.Context, method, path, contentType string, body []byte, extraHeaders map[string]string) (int, []byte, error) {
	var lastErr error
	attempts := 1
	if method == http.MethodGet {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
		if err != nil {
			return 0, nil, fmt.Errorf("create request %s %s: %w", method, path, err)
		}
		req.Header.Set("Accept", "application/json")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}

		if c.auth.TokenID != "" && c.auth.TokenKey != "" && c.auth.BearerToken == "" {
			SignRequest(req, c.auth.TokenID, c.auth.TokenKey, body, c.now())
		} else {
			tok, err := c.ensureBearerToken(ctx)
			if err != nil {
				return 0, nil, err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
			continue
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if len(respBody) > maxAPIResponseBytes {
			return resp.StatusCode, nil, fmt.Errorf("response from %s %s exceeds %d byte limit", method, path, maxAPIResponseBytes)
		}
		if resp.StatusCode >= 500 && attempt+1 < attempts {
			lastErr = fmt.Errorf("HTTP %d from %s %s", resp.StatusCode, method, path)
			continue
		}
		return resp.StatusCode, respBody, nil
	}
	return 0, nil, lastErr
}

// Version queries GET /api/version.
func (c *Client) Version(ctx context.Context) (VersionInfo, error) {
	status, body, err := c.doRaw(ctx, http.MethodGet, "/api/version", "", nil, nil)
	if err != nil {
		return VersionInfo{}, err
	}
	if status != http.StatusOK {
		return VersionInfo{}, fmt.Errorf("GET /api/version returned HTTP %d: %s", status, truncateBody(body))
	}
	var env struct {
		Data struct {
			ServerVersion  string `json:"server_version"`
			ProductEdition string `json:"product_edition"`
			API            struct {
				CurrentVersion string `json:"current_version"`
			} `json:"API"`
		} `json:"data"`
		ServerVersion  string `json:"server_version"`
		ProductEdition string `json:"product_edition"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return VersionInfo{}, fmt.Errorf("decode /api/version: %w", err)
	}
	out := VersionInfo{
		ServerVersion:  env.Data.ServerVersion,
		ProductEdition: env.Data.ProductEdition,
		APIVersion:     env.Data.API.CurrentVersion,
	}
	if out.ServerVersion == "" {
		out.ServerVersion = env.ServerVersion
	}
	if out.ProductEdition == "" {
		out.ProductEdition = env.ProductEdition
	}
	return out, nil
}

// ListExtensions queries GET /api/v2/extensions.
func (c *Client) ListExtensions(ctx context.Context) ([]ExtensionInfo, error) {
	status, body, err := c.doRaw(ctx, http.MethodGet, "/api/v2/extensions", "", nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v2/extensions returned HTTP %d: %s", status, truncateBody(body))
	}
	var objEnv struct {
		Data struct {
			Extensions []ExtensionInfo `json:"extensions"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &objEnv) == nil && objEnv.Data.Extensions != nil {
		return objEnv.Data.Extensions, nil
	}
	var arrEnv struct {
		Data []ExtensionInfo `json:"data"`
	}
	if err := json.Unmarshal(body, &arrEnv); err != nil {
		return nil, fmt.Errorf("decode /api/v2/extensions: %w", err)
	}
	return arrEnv.Data, nil
}

// RegisterExtension upserts an OpenGraph extension schema via PUT /api/v2/extensions.
func (c *Client) RegisterExtension(ctx context.Context, schemaJSON []byte) error {
	status, body, err := c.doRaw(ctx, http.MethodPut, "/api/v2/extensions", "application/json", schemaJSON, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("PUT /api/v2/extensions returned HTTP %d: %s", status, truncateBody(body))
	}
	return nil
}

// ListSourceKinds queries GET /api/v2/graphs/source-kinds (hyphenated on CE 9.7.1).
func (c *Client) ListSourceKinds(ctx context.Context) ([]SourceKindInfo, error) {
	status, body, err := c.doRaw(ctx, http.MethodGet, "/api/v2/graphs/source-kinds", "", nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v2/graphs/source-kinds returned HTTP %d: %s", status, truncateBody(body))
	}
	var env struct {
		Data struct {
			Kinds []SourceKindInfo `json:"kinds"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode /api/v2/graphs/source-kinds: %w", err)
	}
	return env.Data.Kinds, nil
}

// ListExtensionEdges queries GET /api/v2/extensions-edges.
func (c *Client) ListExtensionEdges(ctx context.Context) ([]ExtensionEdgeKind, error) {
	status, body, err := c.doRaw(ctx, http.MethodGet, "/api/v2/extensions-edges", "", nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v2/extensions-edges returned HTTP %d: %s", status, truncateBody(body))
	}
	var objEnv struct {
		Data struct {
			Edges []ExtensionEdgeKind `json:"edges"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &objEnv) == nil && objEnv.Data.Edges != nil {
		return objEnv.Data.Edges, nil
	}
	var arrEnv struct {
		Data []ExtensionEdgeKind `json:"data"`
	}
	if err := json.Unmarshal(body, &arrEnv); err != nil {
		return nil, fmt.Errorf("decode /api/v2/extensions-edges: %w", err)
	}
	return arrEnv.Data, nil
}

// Cypher executes a read query against POST /api/v2/graphs/cypher.
// Per M0/R7, HTTP 404 ("resource not found") is treated as zero rows.
func (c *Client) Cypher(ctx context.Context, query string, includeProps bool) (CypherResult, error) {
	reqBody, err := json.Marshal(map[string]any{
		"query":              query,
		"include_properties": includeProps,
	})
	if err != nil {
		return CypherResult{}, err
	}
	status, body, err := c.doRaw(ctx, http.MethodPost, "/api/v2/graphs/cypher", "application/json", reqBody, nil)
	if err != nil {
		return CypherResult{}, err
	}
	if status == http.StatusNotFound {
		return CypherResult{Nodes: map[string]CypherNode{}}, nil
	}
	if status != http.StatusOK {
		return CypherResult{}, fmt.Errorf("POST /api/v2/graphs/cypher returned HTTP %d: %s", status, truncateBody(body))
	}
	var env struct {
		Data CypherResult `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return CypherResult{}, fmt.Errorf("decode cypher response: %w", err)
	}
	if env.Data.Nodes == nil {
		env.Data.Nodes = map[string]CypherNode{}
	}
	return env.Data, nil
}

func truncateBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}
