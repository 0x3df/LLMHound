package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Surface identifies a supported AI infrastructure service.
type Surface string

const (
	SurfaceJupyter Surface = "jupyter"
	SurfaceOllama  Surface = "ollama"
	SurfaceMCP     Surface = "mcp"
)

// MatchFunc inspects an HTTP probe response to verify a service match.
type MatchFunc func(statusCode int, headers http.Header, body []byte) bool

// Definition defines data-driven fingerprinting rules for a surface.
type Definition struct {
	Surface     Surface
	DefaultPort int
	ProbePaths  []string
	Match       MatchFunc
}

// BuiltinDefinitions returns embedded discovery definitions.
func BuiltinDefinitions() []Definition {
	return []Definition{
		JupyterDefinition(),
		OllamaDefinition(),
		MCPDefinition(),
	}
}

// DefinitionForSurface returns the embedded definition for the given surface.
func DefinitionForSurface(surface Surface) (Definition, bool) {
	for _, def := range BuiltinDefinitions() {
		if def.Surface == surface {
			return def, true
		}
	}
	return Definition{}, false
}

// OllamaDefinition returns the fingerprint definition for Ollama LLM server.
func OllamaDefinition() Definition {
	return Definition{
		Surface:     SurfaceOllama,
		DefaultPort: 11434,
		ProbePaths:  []string{"/api/version", "/api/tags", "/"},
		Match: func(status int, headers http.Header, body []byte) bool {
			serverHeader := strings.ToLower(headers.Get("Server"))
			if strings.Contains(serverHeader, "ollama") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status == http.StatusOK {
				if strings.Contains(bodyStr, "ollama is running") {
					return true
				}
				var doc map[string]json.RawMessage
				if json.Unmarshal(body, &doc) == nil {
					if _, ok := doc["version"]; ok && len(doc) == 1 {
						return true
					}
					if _, ok := doc["models"]; ok && len(doc) == 1 {
						return true
					}
				}
			}
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				if strings.Contains(bodyStr, "ollama") {
					return true
				}
			}
			return false
		},
	}
}

// MCPDefinition returns the fingerprint definition for Model Context Protocol servers.
func MCPDefinition() Definition {
	return Definition{
		Surface:     SurfaceMCP,
		DefaultPort: 8080,
		ProbePaths:  []string{"/mcp", "/sse", "/", "/.well-known/oauth-protected-resource"},
		Match: func(status int, headers http.Header, body []byte) bool {
			contentType := strings.ToLower(headers.Get("Content-Type"))
			if strings.Contains(contentType, "text/event-stream") {
				return true
			}
			if headers.Get("Mcp-Session-Id") != "" {
				return true
			}
			authHeader := strings.ToLower(headers.Get("Www-Authenticate"))
			if strings.Contains(authHeader, "resource_metadata") {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			if status >= http.StatusBadRequest && status < http.StatusInternalServerError && strings.Contains(bodyStr, "mcp-session-id") {
				return true
			}
			if strings.Contains(bodyStr, `"jsonrpc"`) {
				return true
			}
			if strings.Contains(bodyStr, `"authorization_servers"`) {
				return true
			}
			return false
		},
	}
}

// BaseURLForHost constructs a canonical base URL from host, port, and security setting.
func BaseURLForHost(host string, port int, secure bool) string {
	scheme := "http"
	if secure {
		scheme = "https"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("%s://[%s]:%d", scheme, host, port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// ProbeHost probes a target host against a definition using its default port.
func ProbeHost(ctx context.Context, client *http.Client, host string, def Definition, secure bool) (ProbeResult, error) {
	baseURL := BaseURLForHost(host, def.DefaultPort, secure)
	return Probe(ctx, client, baseURL, def)
}

// JupyterDefinition returns the fingerprint definition for Jupyter Server / Notebook.
func JupyterDefinition() Definition {
	return Definition{
		Surface:     SurfaceJupyter,
		DefaultPort: 8888,
		ProbePaths:  []string{"/api", "/api/status", "/tree", "/login"},
		Match: func(status int, headers http.Header, body []byte) bool {
			serverHeader := strings.ToLower(headers.Get("Server"))
			if strings.Contains(serverHeader, "jupyter") {
				return true
			}
			if headers.Get("X-Jupyter-Version") != "" {
				return true
			}
			bodyStr := strings.ToLower(string(body))
			// Status 200 with JSON version or status
			if status == http.StatusOK {
				if strings.Contains(bodyStr, `"version"`) && strings.Contains(bodyStr, "jupyter") {
					return true
				}
				if strings.Contains(bodyStr, `"kernels"`) && strings.Contains(bodyStr, `"connections"`) {
					return true
				}
				if strings.Contains(bodyStr, "jupyter notebook") || strings.Contains(bodyStr, "jupyter server") || strings.Contains(bodyStr, "jupyterlab") {
					return true
				}
			}
			// Status 401 / 403
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				if strings.Contains(bodyStr, "jupyter") {
					return true
				}
			}
			// Redirect to login or tree
			if status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect {
				if IsJupyterLoginRedirect(headers.Get("Location")) {
					return true
				}
			}
			return false
		},
	}
}

// IsJupyterLoginRedirect reports whether a Location value is a Jupyter-style login
// redirect: a /login path whose next parameter targets a /tree or /lab page.
func IsJupyterLoginRedirect(location string) bool {
	u, err := url.Parse(location)
	if err != nil || !strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/login") {
		return false
	}
	next := strings.ToLower(u.Query().Get("next"))
	return strings.Contains(next, "/tree") || strings.Contains(next, "/lab")
}

// ProbeResult holds the result of probing a target against a fingerprint definition.
type ProbeResult struct {
	Matched     bool
	Surface     Surface
	MatchedPath string
	StatusCode  int
	Latency     time.Duration
	Reachable   bool
	Reason      string
}

// Probe executes fingerprint probing for a target URL against a definition.
func Probe(ctx context.Context, client *http.Client, baseURL string, def Definition) (ProbeResult, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	probeClient := http.DefaultClient
	if client != nil {
		copyClient := *client
		copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		probeClient = &copyClient
	} else {
		probeClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	reachable := false
	for _, p := range def.ProbePaths {
		targetURL := baseURL + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("create probe request: %w", err)
		}
		req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")

		start := time.Now()
		resp, err := probeClient.Do(req)
		latency := time.Since(start)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ProbeResult{}, ctxErr
			}
			continue
		}

		reachable = true
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		if def.Match != nil && def.Match(resp.StatusCode, resp.Header, body) {
			return ProbeResult{
				Matched:     true,
				Surface:     def.Surface,
				MatchedPath: p,
				StatusCode:  resp.StatusCode,
				Latency:     latency,
				Reachable:   true,
			}, nil
		}
	}

	reason := "no " + string(def.Surface) + "-specific evidence on probed paths"
	if !reachable {
		reason = "target unreachable on all probed paths"
	}
	return ProbeResult{
		Matched:   false,
		Surface:   def.Surface,
		Reachable: reachable,
		Reason:    reason,
	}, nil
}

// DefinitionFileEntry represents a single fingerprint definition in JSON/YAML.
type DefinitionFileEntry struct {
	Surface     string   `json:"surface"`
	DefaultPort int      `json:"default_port"`
	ProbePaths  []string `json:"probe_paths"`
}

// LoadDefinitions parses custom definitions from JSON data. Builtin match functions
// are associated with recognized surface names.
func LoadDefinitions(data []byte) ([]Definition, error) {
	var entries []DefinitionFileEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode definitions: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("definitions file contains no entries")
	}

	var out []Definition
	for _, e := range entries {
		s := Surface(strings.ToLower(strings.TrimSpace(e.Surface)))
		if s == "" {
			return nil, errors.New("definition missing surface")
		}
		port := e.DefaultPort
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("surface %s has invalid default_port %d", s, port)
		}
		paths := e.ProbePaths
		if len(paths) == 0 {
			paths = []string{"/"}
		}

		// Inherit builtin matcher if available
		var match MatchFunc
		if builtin, ok := DefinitionForSurface(s); ok {
			match = builtin.Match
		} else {
			// Generic fallback matcher
			match = func(status int, headers http.Header, body []byte) bool {
				return status >= 200 && status < 300
			}
		}

		out = append(out, Definition{
			Surface:     s,
			DefaultPort: port,
			ProbePaths:  paths,
			Match:       match,
		})
	}
	return out, nil
}

// LoadDefinitionsFile reads and parses a fingerprint definitions JSON file.
func LoadDefinitionsFile(path string) ([]Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read definitions file: %w", err)
	}
	return LoadDefinitions(data)
}

