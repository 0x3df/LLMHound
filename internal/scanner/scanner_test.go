package scanner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/scanner"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestScanner_Plan(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "scanner-01"
	cfg.Targets = []string{"192.0.2.1", "ai.example.test"}

	s, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner.New failed: %v", err)
	}

	targets := []string{"192.0.2.1", "ai.example.test"}
	plans := s.Plan(targets)
	if len(plans) != 2 {
		t.Fatalf("expected 2 target plans, got %d", len(plans))
	}

	for _, tp := range plans {
		if len(tp.Surfaces) != 3 {
			t.Fatalf("target %s expected 3 surfaces, got %d", tp.Target, len(tp.Surfaces))
		}

		surfaceNames := make(map[discovery.Surface]bool)
		for _, sp := range tp.Surfaces {
			surfaceNames[sp.Surface] = true
			if len(sp.Checks) == 0 {
				t.Errorf("surface %s has no checks", sp.Surface)
			}

			if sp.Surface == discovery.SurfaceOllama {
				// Default: ollama_show must be inactive/skipped
				foundShow := false
				for _, chk := range sp.Checks {
					if chk.CheckID == "ollama_show" {
						foundShow = true
						if chk.Active {
							t.Errorf("ollama_show should be inactive by default")
						}
						if chk.SkipReason == "" {
							t.Errorf("ollama_show should have a skip reason")
						}
					}
				}
				if !foundShow {
					t.Errorf("ollama surface missing ollama_show check in plan")
				}
			}
		}

		if !surfaceNames[discovery.SurfaceJupyter] || !surfaceNames[discovery.SurfaceMCP] || !surfaceNames[discovery.SurfaceOllama] {
			t.Errorf("target %s missing expected surfaces in plan: %+v", tp.Target, surfaceNames)
		}
	}

	// Test with opt-in enabled
	cfg.OptIns.Prompts = true
	sOpt, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner.New with opt-ins failed: %v", err)
	}
	plansOpt := sOpt.Plan([]string{"192.0.2.1"})
	for _, sp := range plansOpt[0].Surfaces {
		if sp.Surface == discovery.SurfaceOllama {
			for _, chk := range sp.Checks {
				if chk.CheckID == "ollama_show" && !chk.Active {
					t.Errorf("ollama_show should be active when --prompts is enabled")
				}
			}
		}
	}
}

func setupMockOllama(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "0.3.12"}`))
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"models": [
					{
						"name": "llama3:latest",
						"size": 4661224676,
						"digest": "sha256:abc123def456",
						"details": {"format": "gguf", "family": "llama", "parameter_size": "8B", "quantization_level": "Q4_0"}
					}
				]
			}`))
		case "/api/ps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models": []}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`Ollama is running`))
		}
	}))
}

func setupMockJupyter(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "2.14.0", "jupyter_server_version": "2.14.0"}`))
		case "/api/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"started": "2026-10-01T12:00:00Z", "kernels": 0, "connections": 0}`))
		case "/api/sessions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name": "",
				"path": "",
				"type": "directory",
				"content": [
					{
						"name": "analysis.ipynb",
						"path": "analysis.ipynb",
						"type": "notebook",
						"size": 2048,
						"last_modified": "2026-10-01T12:00:00Z"
					}
				]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func setupMockMCP(t *testing.T) *httptest.Server {
	t.Helper()
	impl := &mcpsdk.Implementation{
		Name:    "test-mcp-server",
		Version: "1.0.0",
		Title:   "Test MCP Server",
	}
	srv := mcpsdk.NewServer(impl, nil)
	srv.AddTool(&mcpsdk.Tool{
		Name:        "echo",
		Description: "Echoes input text",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{"type": "string"},
			},
		},
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		t.Fatal("CallTool must never be called during read-only enumeration")
		return nil, nil
	})

	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)

	return httptest.NewServer(handler)
}

func parsePort(urlStr string) int {
	u, _ := http.NewRequest("GET", urlStr, nil)
	p := u.URL.Port()
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}

func TestScanner_EndToEndScan(t *testing.T) {
	ollamaSrv := setupMockOllama(t)
	defer ollamaSrv.Close()

	jupyterSrv := setupMockJupyter(t)
	defer jupyterSrv.Close()

	mcpSrv := setupMockMCP(t)
	defer mcpSrv.Close()

	ollamaPort := parsePort(ollamaSrv.URL)
	jupyterPort := parsePort(jupyterSrv.URL)
	mcpPort := parsePort(mcpSrv.URL)

	customDefs := []discovery.Definition{
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: ollamaPort,
			ProbePaths:  []string{"/api/version", "/api/tags", "/"},
			Match:       discovery.OllamaDefinition().Match,
		},
		{
			Surface:     discovery.SurfaceJupyter,
			DefaultPort: jupyterPort,
			ProbePaths:  []string{"/api", "/api/status", "/tree", "/login"},
			Match:       discovery.JupyterDefinition().Match,
		},
		{
			Surface:     discovery.SurfaceMCP,
			DefaultPort: mcpPort,
			ProbePaths:  []string{"/mcp", "/sse", "/"},
			Match:       discovery.MCPDefinition().Match,
		},
	}

	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.Scope = "test-scope"
	cfg.VantageKey = "vantage-test"
	cfg.Targets = []string{"127.0.0.1"}

	fixedNow := time.Date(2026, 10, 1, 20, 0, 0, 0, time.UTC)
	s, err := scanner.New(cfg,
		scanner.WithDefinitions(customDefs),
		scanner.WithNow(func() time.Time { return fixedNow }),
		scanner.WithCollectorVersion("0.1.0"),
	)
	if err != nil {
		t.Fatalf("scanner.New failed: %v", err)
	}

	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "test-scan")
	if err != nil {
		t.Fatalf("s.Scan failed: %v", err)
	}

	if res.TargetsCount != 1 {
		t.Errorf("targets count = %d, want 1", res.TargetsCount)
	}
	if res.Artifacts.BasePayloadPath == "" {
		t.Errorf("expected non-empty BasePayloadPath")
	}
	if res.Artifacts.EvidenceSidecarPath == "" {
		t.Errorf("expected non-empty EvidenceSidecarPath")
	}

	// 1. Verify Journal File
	if _, err := os.Stat(res.JournalPath); err != nil {
		t.Fatalf("journal file not found at %s: %v", res.JournalPath, err)
	}

	// 2. Verify Base Payload JSON
	payloadData, err := os.ReadFile(res.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatalf("read base payload: %v", err)
	}

	var payload emitter.Payload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatalf("unmarshal base payload: %v", err)
	}

	if payload.Metadata == nil || payload.Metadata.SourceKind != "LLMHound" {
		t.Errorf("payload metadata source_kind = %v, want LLMHound", payload.Metadata)
	}

	// Verify nodes emitted across all three surfaces
	foundKinds := make(map[string]bool)
	for _, n := range payload.Graph.Nodes {
		for _, k := range n.Kinds {
			foundKinds[k] = true
		}
	}

	expectedKinds := []string{
		"LLMHound_OllamaInstance",
		"LLMHound_AIModel",
		"LLMHound_JupyterServer",
		"LLMHound_WorkspaceFile",
		"LLMHound_MCPServer",
		"LLMHound_MCPTool",
		"LLMHound_NetworkEndpoint",
	}
	for _, ek := range expectedKinds {
		if !foundKinds[ek] {
			t.Errorf("expected kind %s in emitted nodes, got kinds: %+v", ek, foundKinds)
		}
	}

	// Verify edges emitted
	foundEdgeKinds := make(map[string]bool)
	for _, e := range payload.Graph.Edges {
		foundEdgeKinds[e.Kind] = true
	}
	expectedEdges := []string{
		"LLMHound_ProvidesModel",
		"LLMHound_Contains",
		"LLMHound_ProvidesTool",
		"LLMHound_ObservedAt",
	}
	for _, ee := range expectedEdges {
		if !foundEdgeKinds[ee] {
			t.Errorf("expected edge kind %s in emitted edges, got: %+v", ee, foundEdgeKinds)
		}
	}

	// 3. Verify Evidence Sidecar JSONL
	sidecarData, err := os.ReadFile(res.Artifacts.EvidenceSidecarPath)
	if err != nil {
		t.Fatalf("read evidence sidecar: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(sidecarData)), "\n")
	if len(lines) == 0 {
		t.Fatalf("evidence sidecar is empty")
	}

	foundEvidenceTypes := make(map[string]bool)
	for _, l := range lines {
		var rec evidence.Record
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("unmarshal evidence record: %v", err)
		}
		foundEvidenceTypes[string(rec.RecordType)] = true
	}

	for _, et := range []string{string(evidence.RecordCheckResult), string(evidence.RecordFingerprint), string(evidence.RecordCorrelation)} {
		if !foundEvidenceTypes[et] {
			t.Errorf("expected evidence record type %s in sidecar, got: %+v", et, foundEvidenceTypes)
		}
	}
}

func TestScanner_ComputerCorrelationAndLinkingPayload(t *testing.T) {
	ollamaSrv := setupMockOllama(t)
	defer ollamaSrv.Close()
	ollamaPort := parsePort(ollamaSrv.URL)

	customDefs := []discovery.Definition{
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: ollamaPort,
			ProbePaths:  []string{"/api/version", "/api/tags", "/"},
			Match:       discovery.OllamaDefinition().Match,
		},
	}

	tmpDir := t.TempDir()
	mappingPath := filepath.Join(tmpDir, "mapping.json")
	mappingJSON := `[{"target": "127.0.0.1", "computer_id": "S-1-5-21-1111111111-2222222222-3333333333-1001"}]`
	if err := os.WriteFile(mappingPath, []byte(mappingJSON), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "scanner-corp"
	cfg.Correlation.MappingFile = mappingPath
	cfg.Targets = []string{"127.0.0.1"}

	verifiedComputers := []correlate.Computer{
		{
			ObjectID: "S-1-5-21-1111111111-2222222222-3333333333-1001",
			Name:     "CORP-SERVER.CORP.LOCAL",
		},
	}

	s, err := scanner.New(cfg,
		scanner.WithDefinitions(customDefs),
		scanner.WithVerifiedComputers(verifiedComputers),
	)
	if err != nil {
		t.Fatalf("scanner.New failed: %v", err)
	}

	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "corr-scan")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// With native Computer correlation, linking payload must exist!
	if res.Artifacts.LinkingPayloadPath == "" {
		t.Fatalf("expected non-empty LinkingPayloadPath for correlated scan")
	}

	// 1. Linking payload must NOT have source_kind
	linkingData, err := os.ReadFile(res.Artifacts.LinkingPayloadPath)
	if err != nil {
		t.Fatalf("read linking payload: %v", err)
	}
	var linkingPayload emitter.Payload
	if err := json.Unmarshal(linkingData, &linkingPayload); err != nil {
		t.Fatalf("unmarshal linking payload: %v", err)
	}
	if linkingPayload.Metadata != nil {
		t.Errorf("linking payload MUST NOT declare metadata.source_kind (got %+v)", linkingPayload.Metadata)
	}

	// Edges in linking payload must touch native Computer
	if len(linkingPayload.Graph.Edges) == 0 {
		t.Errorf("linking payload has no edges")
	}
	for _, e := range linkingPayload.Graph.Edges {
		if e.End.Value != "S-1-5-21-1111111111-2222222222-3333333333-1001" {
			t.Errorf("linking edge end Value = %q, want S-1-5-21-...", e.End.Value)
		}
	}

	// 2. Base payload must have source_kind: LLMHound
	baseData, err := os.ReadFile(res.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatalf("read base payload: %v", err)
	}
	var basePayload emitter.Payload
	if err := json.Unmarshal(baseData, &basePayload); err != nil {
		t.Fatalf("unmarshal base payload: %v", err)
	}
	if basePayload.Metadata == nil || basePayload.Metadata.SourceKind != "LLMHound" {
		t.Errorf("base payload source_kind = %v, want LLMHound", basePayload.Metadata)
	}
}

func TestScanner_MixedTargetsAndHonestCoverage(t *testing.T) {
	// Server 1: Active Ollama
	ollamaSrv := setupMockOllama(t)
	defer ollamaSrv.Close()
	ollamaPort := parsePort(ollamaSrv.URL)

	// Server 2: Denied Ollama (HTTP 401)
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ollama"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "ollama: unauthorized"}`))
	}))
	defer deniedSrv.Close()
	deniedPort := parsePort(deniedSrv.URL)

	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.Scope = "mixed-scope"
	cfg.VantageKey = "scanner-v"
	cfg.Targets = []string{"127.0.0.1"}

	// Custom def pointing to active Ollama
	sActive, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: ollamaPort,
			ProbePaths:  []string{"/api/version", "/api/tags", "/"},
			Match:       discovery.OllamaDefinition().Match,
		},
	}))
	if err != nil {
		t.Fatal(err)
	}

	resActive, err := sActive.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "active-scan")
	if err != nil {
		t.Fatalf("active scan failed: %v", err)
	}
	if !resActive.State.IsCompleted("127.0.0.1", "ollama") {
		t.Errorf("expected active ollama to be completed")
	}

	// Custom def pointing to denied server
	sDenied, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: deniedPort,
			ProbePaths:  []string{"/api/version", "/api/tags", "/"},
			Match:       discovery.OllamaDefinition().Match,
		},
	}))
	if err != nil {
		t.Fatal(err)
	}

	resDenied, err := sDenied.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "denied-scan")
	if err != nil {
		t.Fatalf("denied scan failed: %v", err)
	}
	// Denied server must NOT be completed! It should be partial/failed with honest coverage
	if resDenied.State.IsCompleted("127.0.0.1", "ollama") {
		t.Errorf("denied ollama must not be completed")
	}
	targets := resDenied.State.Targets()
	targetRec, ok := targets["127.0.0.1|ollama"]
	if !ok {
		t.Fatalf("expected target record for 127.0.0.1|ollama, got: %+v", targets)
	}
	if targetRec.Observation == nil || targetRec.Observation.Coverage != "partial" {
		t.Errorf("denied target coverage = %v, want partial", targetRec.Observation)
	}
	if !strings.Contains(targetRec.Observation.CoverageReason, "authentication required") {
		t.Errorf("denied reason %q should mention authentication required", targetRec.Observation.CoverageReason)
	}

	// Unreachable port
	sUnreachable, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: 54321, // random unused port
			ProbePaths:  []string{"/api/version"},
			Match:       discovery.OllamaDefinition().Match,
		},
	}))
	if err != nil {
		t.Fatal(err)
	}

	resUnreach, err := sUnreachable.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "unreach-scan")
	if err != nil {
		t.Fatalf("unreachable scan failed: %v", err)
	}
	if resUnreach.State.IsCompleted("127.0.0.1", "ollama") {
		t.Errorf("unreachable ollama must not be completed")
	}
	targetsUnreach := resUnreach.State.Targets()
	targetRecUnreach, ok := targetsUnreach["127.0.0.1|ollama"]
	if !ok {
		t.Fatalf("expected target record for 127.0.0.1|ollama")
	}
	if targetRecUnreach.Status != "failed" {
		t.Errorf("unreachable status = %q, want failed", targetRecUnreach.Status)
	}
}

func TestScanner_DefinitionsSelectSurfaces(t *testing.T) {
	ollamaSrv := setupMockOllama(t)
	defer ollamaSrv.Close()
	jupyterSrv := setupMockJupyter(t)
	defer jupyterSrv.Close()

	cfg := config.Defaults()
	cfg.Scope = "select-scope"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Targets = []string{"127.0.0.1"}
	cfg.VantageKey = "vantage-test"

	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{
		{
			Surface:     discovery.SurfaceOllama,
			DefaultPort: parsePort(ollamaSrv.URL),
			ProbePaths:  []string{"/api/version"},
			Match:       discovery.OllamaDefinition().Match,
		},
	}))
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "select-scan")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	targets := res.State.Targets()
	if _, ok := targets["127.0.0.1|ollama"]; !ok {
		t.Errorf("configured ollama surface missing: %+v", targets)
	}
	for key := range targets {
		if key != "127.0.0.1|ollama" {
			t.Errorf("unconfigured surface scanned: %s", key)
		}
	}
}

func TestScanner_ConfiguredProbePathsAndMatchGateCollection(t *testing.T) {
	var paths []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`generic web page`))
	}))
	defer srv.Close()

	cfg := config.Defaults()
	cfg.Scope = "gate-scope"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Targets = []string{"127.0.0.1"}
	cfg.VantageKey = "vantage-test"

	def := discovery.Definition{
		Surface:     discovery.SurfaceOllama,
		DefaultPort: parsePort(srv.URL),
		ProbePaths:  []string{"/custom-probe"},
		Match:       discovery.OllamaDefinition().Match,
	}
	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{def}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "gate-scan")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(res.State.Targets()) != 0 {
		t.Errorf("non-matching reachable service must not be collected: %+v", res.State.Targets())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/custom-probe" {
		t.Errorf("probed paths = %v, want only [/custom-probe]", paths)
	}
}
