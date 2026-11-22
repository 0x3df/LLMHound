package scanner_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/scanner"
	"github.com/0x3df/LLMHound/internal/targets"
)

func endpointScan(t *testing.T, targetHosts []string, port int) *scanner.ScanResult {
	t.Helper()
	cfg := config.Defaults()
	cfg.Scope = "ep-scope"
	cfg.VantageKey = "ep-vantage"
	cfg.Targets = targetHosts
	if len(targetHosts) == 0 {
		cfg.EndpointsFiles = []string{"unused-in-test"}
	}
	cfg.Bounds.TCPTimeout = 100 * time.Millisecond
	cfg.Bounds.PerHostRate = 1000
	s, err := scanner.New(cfg,
		scanner.WithDefinitions([]discovery.Definition{discovery.OllamaDefinition()}),
		scanner.WithEndpoints([]targets.EndpointTarget{{Host: "127.0.0.1", Port: port}}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), targetHosts, t.TempDir(), "ep")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

func assertOllamaCollected(t *testing.T, res *scanner.ScanResult) {
	t.Helper()
	rec, ok := res.State.Targets()["127.0.0.1|ollama"]
	if !ok {
		t.Fatalf("endpoint host has no journal record: %+v", res.State.Targets())
	}
	if rec.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("endpoint collection status = %q (%s), want completed", rec.Status, rec.Error)
	}
	for _, ev := range res.State.Evidence() {
		if strings.Contains(ev.Reason, "not authorized") || strings.Contains(ev.Reason, "not in authorized targets") {
			t.Fatalf("endpoint host must be authorized: %s %s", ev.CheckID, ev.Reason)
		}
	}
	var service bool
	for _, n := range res.State.Nodes() {
		if n.Node.Identity().Kind() == graph.OllamaInstance {
			service = true
		}
	}
	if !service {
		t.Fatal("expected an Ollama service node from the endpoint")
	}
}

// Regression: endpoint hosts were missing from the collectors' authorized-host
// list when --targets was also given, so every check failed.
func TestScanner_EndpointsAuthorizedAlongsideTargets(t *testing.T) {
	srv := setupMockOllama(t)
	defer srv.Close()
	res := endpointScan(t, []string{"192.0.2.1"}, parsePort(srv.URL))
	assertOllamaCollected(t, res)
}

func TestScanner_EndpointsOnly(t *testing.T) {
	srv := setupMockOllama(t)
	defer srv.Close()
	res := endpointScan(t, nil, parsePort(srv.URL))
	assertOllamaCollected(t, res)
}

func TestScanner_UntrustedTLSJournaledAsTLSFailureNotUnreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
	}))
	defer srv.Close()
	cfg := config.Defaults()
	cfg.Scope = "tls-scope"
	cfg.VantageKey = "tls-vantage"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Scan.Scheme = config.SchemeHTTPS
	cfg.Bounds.PerHostRate = 1000
	def := discovery.OllamaDefinition()
	def.DefaultPort = parsePort(srv.URL)
	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{def}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "tls")
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := res.State.Targets()["127.0.0.1|ollama"]
	if !ok {
		t.Fatalf("TLS failure must be journaled: %+v", res.State.Targets())
	}
	if rec.Status != checkpoint.TargetStatusFailed || !strings.Contains(rec.Error, "TLS certificate verification failed") {
		t.Fatalf("want failed with TLS reason, got status=%q error=%q", rec.Status, rec.Error)
	}
	if strings.Contains(rec.Error, "unreachable") {
		t.Fatalf("TLS failure must not be reported as unreachable: %q", rec.Error)
	}
	if len(res.State.Nodes()) != 0 {
		t.Fatal("no service may be emitted after a TLS failure")
	}
}

// One target's collector error must not discard every other target's output:
// the failure is journaled (so resume retries it), reported, and the scan
// still emits artifacts.
func TestScanner_TargetErrorDoesNotAbortScan(t *testing.T) {
	srv := setupMockOllama(t)
	defer srv.Close()
	port := parsePort(srv.URL)
	cfg := config.Defaults()
	cfg.Scope = "err-scope"
	cfg.VantageKey = "err-vantage"
	cfg.EndpointsFiles = []string{"unused-in-test"}
	cfg.Bounds.PerHostRate = 1000
	var progress strings.Builder
	s, err := scanner.New(cfg,
		scanner.WithDefinitions([]discovery.Definition{discovery.OllamaDefinition()}),
		scanner.WithEndpoints([]targets.EndpointTarget{{Host: "127.0.0.1", Port: port}, {Host: "localhost", Port: port}}),
		scanner.WithProgress(&lockedWriter{b: &progress}, time.Hour),
		scanner.WithCollectFault(func(_ discovery.Surface, host string) error {
			if host == "localhost" {
				return errors.New("synthetic collector failure")
			}
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), nil, t.TempDir(), "err")
	if err != nil {
		t.Fatalf("a single target error must not abort the scan: %v", err)
	}
	if res.TargetErrorCount != 1 || len(res.TargetErrors) != 1 || !strings.Contains(res.TargetErrors[0], "synthetic collector failure") {
		t.Fatalf("target errors = %d %v", res.TargetErrorCount, res.TargetErrors)
	}
	if res.Artifacts.BasePayloadPath == "" {
		t.Fatal("artifacts must still be emitted")
	}
	if !strings.Contains(progress.String(), "2/2 targets done, 1 services collected, 1 target errors") {
		t.Fatalf("final progress line missing or wrong: %q", progress.String())
	}
	if rec := res.State.Targets()["localhost|ollama"]; rec.Status != checkpoint.TargetStatusFailed {
		t.Fatalf("failed target must be journaled as failed for resume, got %+v", rec)
	}
	if rec := res.State.Targets()["127.0.0.1|ollama"]; rec.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("healthy target must complete, got %+v", rec)
	}
}

type lockedWriter struct {
	mu sync.Mutex
	b  *strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func TestScanner_UnmatchedExtraPortDoesNotOverwriteCompletedSurface(t *testing.T) {
	ollamaSrv := setupMockOllama(t)
	defer ollamaSrv.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("generic web page"))
	}))
	defer other.Close()

	cfg := config.Defaults()
	cfg.Scope = "xp-scope"
	cfg.VantageKey = "xp-vantage"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Scan.ExtraPorts = []int{parsePort(other.URL)}
	cfg.Bounds.PerHostRate = 1000
	def := discovery.OllamaDefinition()
	def.DefaultPort = parsePort(ollamaSrv.URL)
	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{def}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "xp")
	if err != nil {
		t.Fatal(err)
	}
	rec := res.State.Targets()["127.0.0.1|ollama"]
	if rec.Status != checkpoint.TargetStatusCompleted || !res.State.IsCompleted("127.0.0.1", "ollama") {
		t.Fatalf("completed surface overwritten by unmatched extra port: %+v", rec)
	}
}
