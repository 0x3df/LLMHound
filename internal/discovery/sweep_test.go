package discovery_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/discovery"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestProbeShortCircuitsOnDialFailure(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		}),
	}
	def := discovery.MCPDefinition() // has 4 probe paths
	res, err := discovery.Probe(context.Background(), client, "http://127.0.0.1:8080", def)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Matched || res.Reachable {
		t.Fatalf("expected unreachable unmatched result, got %+v", res)
	}
	if calls.Load() != 1 {
		t.Fatalf("Probe made %d HTTP attempts across %d ProbePaths on dial failure, want 1", calls.Load(), len(def.ProbePaths))
	}
}

func TestPortProbeCacheSharesPort8000Responses(t *testing.T) {
	var openapiHits atomic.Int32
	var modelsHits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			modelsHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama","owned_by":"org"}]}`))
		case "/openapi.json":
			openapiHits.Add(1)
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cache := discovery.NewPortProbeCache()
	defs := []discovery.Definition{
		discovery.VLLMDefinition(),
		discovery.LangServeDefinition(),
		discovery.ChromaDBDefinition(),
		discovery.OpenAICompatibleDefinition(),
	}

	var matched []discovery.Surface
	for _, def := range defs {
		res, err := discovery.ProbeWithScheme(context.Background(), srv.Client(), host, port, "http", def, cache)
		if err != nil {
			t.Fatal(err)
		}
		if res.Matched {
			matched = append(matched, res.Surface)
		}
	}

	if len(matched) != 1 || matched[0] != discovery.SurfaceOpenAICompatible {
		t.Fatalf("matched = %v, want [openai_compatible]", matched)
	}
	if modelsHits.Load() != 1 {
		t.Fatalf("/v1/models requested %d times across vllm+openai_compatible, want 1", modelsHits.Load())
	}
	if openapiHits.Load() != 1 {
		t.Fatalf("/openapi.json requested %d times, want 1", openapiHits.Load())
	}
}

func TestProbeWithSchemeAutoUpgradesHTTPToHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.4.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cache := discovery.NewPortProbeCache()
	res, err := discovery.ProbeWithScheme(context.Background(), srv.Client(), host, port, "auto", discovery.OllamaDefinition(), cache)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched || res.Scheme != "https" || !strings.HasPrefix(res.BaseURL, "https://") {
		t.Fatalf("expected HTTPS auto-upgrade match, got %+v", res)
	}
}

func TestProbeWithSchemeHTTP400TLSMismatchFallback(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme == "http" {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("Client sent an HTTP request to an HTTPS server.")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Ollama is running")),
			}, nil
		}),
	}
	_ = tls.VersionTLS13
	cache := discovery.NewPortProbeCache()
	res, err := discovery.ProbeWithScheme(context.Background(), client, "192.0.2.10", 11434, "auto", discovery.OllamaDefinition(), cache)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched || res.Scheme != "https" {
		t.Fatalf("expected https fallback match, got %+v", res)
	}
}

type dummyConn struct{ net.Conn }

func (d dummyConn) Close() error { return nil }

func TestSweepOpenPorts(t *testing.T) {
	var dials atomic.Int32
	open := discovery.SweepOpenPorts(
		context.Background(),
		[]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		[]int{8888, 11434},
		4,
		500*time.Millisecond,
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dials.Add(1)
			if addr == "192.0.2.2:8888" {
				return dummyConn{}, nil
			}
			return nil, errors.New("refused")
		},
	)
	if dials.Load() != 6 {
		t.Fatalf("dials = %d, want 6", dials.Load())
	}
	if !open["192.0.2.2"][8888] || len(open) != 1 || len(open["192.0.2.2"]) != 1 {
		t.Fatalf("unexpected open port map: %+v", open)
	}
}
