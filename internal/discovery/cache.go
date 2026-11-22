package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type probeCacheKey struct {
	baseURL string
	path    string
}

type cachedHTTPResponse struct {
	reachable  bool
	dialFailed bool
	needsTLS   bool
	status     int
	headers    http.Header
	body       []byte
	latency    time.Duration
}

// PortProbeCache caches raw HTTP probe responses per (baseURL, path) so
// multiple surface definitions sharing a port (such as 8000, 8080, 3000) reuse
// a single HTTP response per path.
type PortProbeCache struct {
	mu      sync.Mutex
	entries map[probeCacheKey]cachedHTTPResponse
	dialBad map[string]bool
	needTLS map[string]bool
}

// NewPortProbeCache allocates an empty PortProbeCache.
func NewPortProbeCache() *PortProbeCache {
	return &PortProbeCache{
		entries: make(map[probeCacheKey]cachedHTTPResponse),
		dialBad: make(map[string]bool),
		needTLS: make(map[string]bool),
	}
}

func (c *PortProbeCache) isDialBad(baseURL string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dialBad[baseURL]
}

func (c *PortProbeCache) needsTLS(baseURL string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.needTLS[baseURL]
}

func (c *PortProbeCache) get(baseURL, path string) (cachedHTTPResponse, bool) {
	if c == nil {
		return cachedHTTPResponse{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[probeCacheKey{baseURL: baseURL, path: path}]
	return v, ok
}

func (c *PortProbeCache) put(baseURL, path string, resp cachedHTTPResponse) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[probeCacheKey{baseURL: baseURL, path: path}] = resp
	if resp.dialFailed {
		c.dialBad[baseURL] = true
	}
	if resp.needsTLS {
		c.needTLS[baseURL] = true
	}
}

// ProbeWithScheme probes host:port according to schemeMode ("auto", "http", or
// "https"), reusing any cached path responses on shared ports and automatically
// upgrading from HTTP to HTTPS when an HTTP->HTTPS mismatch is detected.
func ProbeWithScheme(
	ctx context.Context,
	client *http.Client,
	host string,
	port int,
	schemeMode string,
	def Definition,
	cache *PortProbeCache,
) (ProbeResult, error) {
	var attempts []bool // secure=false -> http, secure=true -> https
	mode := strings.ToLower(strings.TrimSpace(schemeMode))
	switch mode {
	case "https":
		attempts = []bool{true}
	case "http":
		attempts = []bool{false}
	default: // "auto"
		if port == 443 || port == 8443 {
			attempts = []bool{true, false}
		} else {
			attempts = []bool{false}
		}
	}

	var last ProbeResult
	for i := 0; i < len(attempts); i++ {
		secure := attempts[i]
		baseURL := BaseURLForHost(host, port, secure)
		res, err := probeCachedOne(ctx, client, baseURL, def, cache)
		if err != nil {
			return ProbeResult{}, err
		}
		last = res
		if res.Matched {
			return res, nil
		}
		// Auto mode: upgrade from HTTP to HTTPS if HTTP-to-HTTPS mismatch was seen.
		if mode != "http" && mode != "https" && !secure && res.NeedsTLS {
			attempts = append(attempts, true)
		}
	}
	return last, nil
}

func probeCachedOne(ctx context.Context, client *http.Client, baseURL string, def Definition, cache *PortProbeCache) (ProbeResult, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	scheme := "http"
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		scheme = "https"
	}

	if cache != nil {
		if cache.isDialBad(baseURL) {
			return ProbeResult{
				Matched:   false,
				Surface:   def.Surface,
				BaseURL:   baseURL,
				Scheme:    scheme,
				Reachable: false,
				Reason:    "target unreachable on all probed paths",
			}, nil
		}
		if scheme == "http" && cache.needsTLS(baseURL) {
			return ProbeResult{
				Matched:   false,
				Surface:   def.Surface,
				BaseURL:   baseURL,
				Scheme:    scheme,
				Reachable: true,
				NeedsTLS:  true,
				Reason:    "endpoint requires HTTPS",
			}, nil
		}
	}

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
	needsTLS := false

	for _, p := range def.ProbePaths {
		var entry cachedHTTPResponse
		if cached, ok := cache.get(baseURL, p); ok {
			entry = cached
		} else {
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
				if scheme == "http" && isTLSMismatchError(err) {
					entry = cachedHTTPResponse{
						reachable: true,
						needsTLS:  true,
					}
					cache.put(baseURL, p, entry)
					needsTLS = true
					reachable = true
					break
				}
				entry = cachedHTTPResponse{
					reachable:  false,
					dialFailed: !reachable && isDialOrConnectError(err),
				}
				cache.put(baseURL, p, entry)
				if entry.dialFailed {
					break
				}
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			_ = resp.Body.Close()

			tlsMismatch := scheme == "http" && isHTTPToHTTPSMismatch(resp.StatusCode, body)
			entry = cachedHTTPResponse{
				reachable: true,
				needsTLS:  tlsMismatch,
				status:    resp.StatusCode,
				headers:   resp.Header.Clone(),
				body:      body,
				latency:   latency,
			}
			cache.put(baseURL, p, entry)
		}

		if entry.dialFailed && !reachable {
			break
		}
		if !entry.reachable {
			continue
		}
		reachable = true
		if entry.needsTLS {
			needsTLS = true
			break
		}
		if def.Match != nil && def.Match(entry.status, entry.headers, entry.body) {
			return ProbeResult{
				Matched:     true,
				Surface:     def.Surface,
				MatchedPath: p,
				BaseURL:     baseURL,
				Scheme:      scheme,
				StatusCode:  entry.status,
				Latency:     entry.latency,
				Reachable:   true,
			}, nil
		}
	}

	reason := "no " + string(def.Surface) + "-specific evidence on probed paths"
	if !reachable {
		reason = "target unreachable on all probed paths"
	} else if needsTLS {
		reason = "endpoint requires HTTPS"
	}
	return ProbeResult{
		Matched:   false,
		Surface:   def.Surface,
		BaseURL:   baseURL,
		Scheme:    scheme,
		Reachable: reachable,
		NeedsTLS:  needsTLS,
		Reason:    reason,
	}, nil
}
