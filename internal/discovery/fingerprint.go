package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	}
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
				loc := strings.ToLower(headers.Get("Location"))
				if strings.Contains(loc, "/login") || strings.Contains(loc, "/tree") {
					return true
				}
			}
			return false
		},
	}
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
			continue // try next probe path if network error or connection refused
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
