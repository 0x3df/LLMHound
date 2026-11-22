package scanner_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/scanner"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
)

type noopConn struct{ net.Conn }

func (noopConn) Close() error { return nil }

func TestScale_TCPSweepCompactJournalAndSecretsOnly(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Zy9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0")
	jupSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			_, _ = w.Write([]byte(`{"version":"2.14.0","jupyter_server_version":"2.14.0"}`))
		case "/api/sessions":
			_, _ = w.Write([]byte(`[{"id":"s1","path":"nb.ipynb","kernel":{"name":"python3","execution_state":"idle"}}]`))
		case "/api/contents":
			_, _ = w.Write([]byte(`{"content":[{"name":"nb.ipynb","path":"nb.ipynb","type":"notebook"}]}`))
		case "/api/contents/nb.ipynb":
			_, _ = w.Write([]byte(`{"name":"nb.ipynb","type":"notebook","content":{"cells":[{"cell_type":"code","source":["TOKEN=\"` + tok + `\""]}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer jupSrv.Close()
	jupPort := parsePort(jupSrv.URL)

	var deadDials atomic.Int32
	var deadHostDials atomic.Int32
	// 50 firewalled hosts + 1 live host (127.0.0.1).
	targets := make([]string, 0, 51)
	for i := 1; i <= 50; i++ {
		targets = append(targets, fmt.Sprintf("192.0.2.%d", i))
	}
	targets = append(targets, "127.0.0.1")

	cfg := config.Defaults()
	cfg.Scope = "scale-scope"
	cfg.VantageKey = "vantage-scale"
	cfg.Targets = targets

	defs := []discovery.Definition{
		{
			Surface:     discovery.SurfaceJupyter,
			DefaultPort: jupPort,
			ProbePaths:  discovery.JupyterDefinition().ProbePaths,
			Match:       discovery.JupyterDefinition().Match,
		},
		discovery.OllamaDefinition(),
		discovery.RayDefinition(),
	}

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == fmt.Sprintf("127.0.0.1:%d", jupPort) {
			return noopConn{}, nil
		}
		deadDials.Add(1)
		if !strings.HasPrefix(addr, "127.0.0.1:") {
			deadHostDials.Add(1)
		}
		return nil, errors.New("connection refused")
	}

	outDir := t.TempDir()
	s, err := scanner.New(cfg, scanner.WithDefinitions(defs), scanner.WithTCPDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), targets, outDir, "scale")
	if err != nil {
		t.Fatal(err)
	}

	if deadDials.Load() != 152 { // 50 dead * 3 ports + 2 closed ports on 127.0.0.1
		t.Fatalf("unexpected TCP dial count = %d, want 152", deadDials.Load())
	}

	// secrets-only default must NOT create .content.jsonl on disk, yet still flag has_exposed_secret!
	if res.ContentPath != "" {
		t.Fatalf("expected empty ContentPath in default secrets-only mode, got %q", res.ContentPath)
	}
	if _, err := os.Stat(outDir + "/scale.content.jsonl"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scale.content.jsonl should not exist in secrets-only mode")
	}

	// Journal must contain compact _tcp_sweep markers (1 per dead host) rather than 3 unmatched results each.
	for i := 1; i <= 50; i++ {
		h := fmt.Sprintf("192.0.2.%d", i)
		if !res.State.IsHostSweptEmpty(h, []int{jupPort, 8265, 11434}) {
			t.Fatalf("expected compact sweep marker for %s", h)
		}
	}

	// Emitted payload must have has_exposed_secret=true and risk_signals on JupyterServer, and zero WorkspaceFile fluff.
	raw, err := os.ReadFile(res.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\n  ") {
		t.Fatalf("expected compact JSON without indentation by default")
	}
	var payload emitter.Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	var jupNode *emitter.NodePayload
	for i := range payload.Graph.Nodes {
		n := &payload.Graph.Nodes[i]
		for _, k := range n.Kinds {
			if k == "LLMHound_WorkspaceFile" {
				t.Fatalf("compact attack-path graph should omit WorkspaceFile fluff")
			}
			if k == "LLMHound_JupyterServer" {
				jupNode = n
			}
		}
	}
	if jupNode == nil || jupNode.Properties["has_exposed_secret"] != true {
		t.Fatalf("expected JupyterServer with has_exposed_secret=true, got %+v", jupNode)
	}

	// Resume must skip already-swept empty hosts with zero dead-host dials.
	deadHostDials.Store(0)
	if _, err := s.Resume(context.Background(), res.JournalPath, targets, outDir, "scale"); err != nil {
		t.Fatal(err)
	}
	if deadHostDials.Load() != 0 {
		t.Fatalf("resume re-dialed %d swept-empty hosts, want 0", deadHostDials.Load())
	}
}

func BenchmarkScale_TCPSweep500Hosts(b *testing.B) {
	targets := make([]string, 500)
	for i := range targets {
		targets[i] = fmt.Sprintf("10.0.%d.%d", i/250, (i%250)+1)
	}
	cfg := config.Defaults()
	cfg.Scope = "bench-scope"
	cfg.VantageKey = "v1"
	cfg.Targets = targets

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	s, err := scanner.New(cfg, scanner.WithTCPDialer(dialer))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Scan(context.Background(), targets, b.TempDir(), fmt.Sprintf("b%d", i)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestUsesBackend_EndToEndCrossHost(t *testing.T) {
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ollamaSrv.Close()
	ollamaURL := ollamaSrv.URL

	litellmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"info":{"title":"LiteLLM Proxy"},"paths":{"/v1/models":{}}}`))
		case "/model/info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"model_name":"gpt","litellm_params":{"model":"ollama/llama3","api_base":"` + ollamaURL + `"}}]}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer litellmSrv.Close()

	resolver, err := correlate.New([]correlate.Mapping{
		{Target: "127.0.0.1", ObjectID: "S-1-5-21-100", Kind: graph.Computer},
	})
	if err != nil {
		t.Fatal(err)
	}

	defs := []discovery.Definition{
		{
			Surface:     discovery.SurfaceLiteLLM,
			DefaultPort: parsePort(litellmSrv.URL),
			ProbePaths:  discovery.LiteLLMDefinition().ProbePaths,
			Match:       discovery.LiteLLMDefinition().Match,
		},
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: parsePort(ollamaSrv.URL),
			ProbePaths:  discovery.OllamaDefinition().ProbePaths,
			Match:       discovery.OllamaDefinition().Match,
		},
	}

	cfg := config.Defaults()
	cfg.Scope = "p5-scope"
	cfg.VantageKey = "v1"
	cfg.Targets = []string{"127.0.0.1"}

	s, err := scanner.New(cfg, scanner.WithDefinitions(defs), scanner.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "p5")
	if err != nil {
		t.Fatal(err)
	}

	baseBytes, err := os.ReadFile(res.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var base emitter.Payload
	if err := json.Unmarshal(baseBytes, &base); err != nil {
		t.Fatal(err)
	}
	var foundUsesBackend bool
	for _, e := range base.Graph.Edges {
		if e.Kind == "LLMHound_UsesBackend" {
			foundUsesBackend = true
		}
	}
	if !foundUsesBackend {
		t.Fatalf("expected LLMHound_UsesBackend edge in base payload, got edges: %+v", base.Graph.Edges)
	}
}

func TestCompact_MCPHighRiskToolFilter(t *testing.T) {
	mcpSrv := setupMockMCP(t)
	defer mcpSrv.Close()
	// setupMockMCP provides a calculator tool; let's build a server with both benign & high-risk tools using setupMCPWithTools pattern,
	// or test discovery + MCP collector directly through FilterAttackPathGraph via EndToEnd check.
	// Using a lightweight inline JSON-RPC/SSE MCP server is quick and deterministic:
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				return
			}
			var req struct {
				JSONRPC string `json:"jsonrpc"`
				ID      any    `json:"id"`
				Method  string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "sess-1")
			switch req.Method {
			case "initialize":
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + rawJSON(req.ID) + `,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-test","version":"1.0.0"}}}`))
			case "tools/list":
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + rawJSON(req.ID) + `,"result":{"tools":[{"name":"exec_bash","description":"Execute shell commands"},{"name":"weather","description":"Get forecast"}]}}`))
			default:
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + rawJSON(req.ID) + `,"result":{}}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := config.Defaults()
	cfg.Scope = "p7-scope"
	cfg.VantageKey = "v1"
	cfg.Targets = []string{"127.0.0.1"}

	defs := []discovery.Definition{{
		Surface:     discovery.SurfaceMCP,
		DefaultPort: parsePort(srv.URL),
		ProbePaths:  discovery.MCPDefinition().ProbePaths,
		Match:       discovery.MCPDefinition().Match,
	}}
	s, err := scanner.New(cfg, scanner.WithDefinitions(defs))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "p7")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(res.Artifacts.BasePayloadPath)
	var base emitter.Payload
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}

	var toolNames []string
	for _, n := range base.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "LLMHound_MCPTool" {
				toolNames = append(toolNames, fmt.Sprint(n.Properties["tool_name"]))
			}
		}
	}
	if len(toolNames) != 1 || toolNames[0] != "exec_bash" {
		t.Fatalf("compact attack-path mode should keep only high-risk MCPTool exec_bash, got %v", toolNames)
	}
}

func rawJSON(v any) string {
	b, _ := json.Marshal(v)
	if len(b) == 0 {
		return "1"
	}
	return string(b)
}

func TestHTTPS_AutoUpgradeAndCollection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.4.1"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	_, portStr, _ := net.SplitHostPort(u.Host)
	var port int
	_, _ = fmt.Sscan(portStr, &port)

	cfg := config.Defaults()
	cfg.Scope = "tls-scope"
	cfg.VantageKey = "v1"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Insecure = true // httptest TLS server uses self-signed cert

	defs := []discovery.Definition{{
		Surface:     discovery.SurfaceOllama,
		DefaultPort: port,
		ProbePaths:  discovery.OllamaDefinition().ProbePaths,
		Match:       discovery.OllamaDefinition().Match,
	}}
	// Use insecure transport so HTTPS collector + prober trust httptest cert.
	_ = tls.VersionTLS13
	s, err := scanner.New(cfg, scanner.WithDefinitions(defs))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "tls")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.State.Nodes()) == 0 {
		t.Fatalf("expected HTTPS service node after auto-upgrade, got 0 nodes; targets=%+v", res.State.Targets())
	}
	if res.State.Targets()["127.0.0.1|ollama"].Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("expected completed HTTPS ollama target, got %+v", res.State.Targets()["127.0.0.1|ollama"])
	}
	_ = time.Second
}
