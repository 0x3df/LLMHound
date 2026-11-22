package scanner_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
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
		if len(tp.Surfaces) != 15 {
			t.Fatalf("target %s expected 15 surfaces, got %d", tp.Target, len(tp.Surfaces))
		}

		surfaceNames := make(map[discovery.Surface]bool)
		for _, sp := range tp.Surfaces {
			surfaceNames[sp.Surface] = true
			if len(sp.Checks) == 0 {
				t.Errorf("surface %s has no checks", sp.Surface)
			}

			if sp.Surface == discovery.SurfaceOllama {
				// Default: content tier enabled -> ollama_show must be active
				foundShow := false
				for _, chk := range sp.Checks {
					if chk.CheckID == "ollama_show" {
						foundShow = true
						if !chk.Active {
							t.Errorf("ollama_show should be active by default, skip=%q", chk.SkipReason)
						}
					}
				}
				if !foundShow {
					t.Errorf("ollama surface missing ollama_show check in plan")
				}
			}
			if sp.Surface == discovery.SurfaceJupyter {
				foundContent := false
				for _, chk := range sp.Checks {
					if chk.CheckID == "jupyter_file_content" && chk.Active {
						foundContent = true
					}
				}
				if !foundContent {
					t.Errorf("jupyter surface missing active jupyter_file_content check in plan")
				}
			}
			if sp.Surface == discovery.SurfaceMCP {
				foundContent := false
				for _, chk := range sp.Checks {
					if chk.CheckID == "mcp_resources_read" && chk.Active {
						foundContent = true
					}
				}
				if !foundContent {
					t.Errorf("mcp surface missing active mcp_resources_read check in plan")
				}
			}
			if sp.Surface == discovery.SurfaceQdrant {
				foundSample := false
				for _, chk := range sp.Checks {
					if chk.CheckID == "qdrant_points_sample" && chk.Active {
						foundSample = true
					}
				}
				if !foundSample {
					t.Errorf("qdrant surface missing active qdrant_points_sample check in plan")
				}
			}
		}

		for _, wantSurf := range []discovery.Surface{
			discovery.SurfaceJupyter, discovery.SurfaceMCP, discovery.SurfaceOllama,
			discovery.SurfaceA2A, discovery.SurfaceVLLM, discovery.SurfaceQdrant,
			discovery.SurfaceLiteLLM, discovery.SurfaceMLflow, discovery.SurfaceOpenWebUI, discovery.SurfaceLangServe,
			discovery.SurfaceRay, discovery.SurfaceLangflow, discovery.SurfaceFlowise,
			discovery.SurfaceChromaDB, discovery.SurfaceOpenAICompatible,
		} {
			if !surfaceNames[wantSurf] {
				t.Errorf("target %s missing surface %s in plan: %+v", tp.Target, wantSurf, surfaceNames)
			}
		}
	}

	// Test with global content opt-out
	cfgOff := config.Defaults()
	cfgOff.Scope = "corp-scope"
	cfgOff.VantageKey = "scanner-01"
	cfgOff.Targets = []string{"192.0.2.1"}
	cfgOff.Content.Enabled = false
	sOff, err := scanner.New(cfgOff)
	if err != nil {
		t.Fatalf("scanner.New with content disabled failed: %v", err)
	}
	plansOff := sOff.Plan([]string{"192.0.2.1"})
	for _, sp := range plansOff[0].Surfaces {
		for _, chk := range sp.Checks {
			if chk.CheckID == "ollama_show" || chk.CheckID == "jupyter_file_content" || chk.CheckID == "mcp_resources_read" || chk.CheckID == "qdrant_points_sample" {
				if chk.Active || chk.SkipReason == "" {
					t.Errorf("%s should be inactive with skip reason when content disabled, active=%v reason=%q", chk.CheckID, chk.Active, chk.SkipReason)
				}
			}
		}
	}

	// Test per-surface opt-out
	cfgSurf := config.Defaults()
	cfgSurf.Scope = "corp-scope"
	cfgSurf.VantageKey = "scanner-01"
	cfgSurf.Targets = []string{"192.0.2.1"}
	cfgSurf.Content.Surfaces = map[string]bool{"ollama": false, "qdrant": false}
	sSurf, err := scanner.New(cfgSurf)
	if err != nil {
		t.Fatalf("scanner.New with surface disable failed: %v", err)
	}
	plansSurf := sSurf.Plan([]string{"192.0.2.1"})
	for _, sp := range plansSurf[0].Surfaces {
		for _, chk := range sp.Checks {
			if sp.Surface == discovery.SurfaceOllama && chk.CheckID == "ollama_show" && chk.Active {
				t.Errorf("ollama_show should be inactive when content.surfaces[ollama]=false")
			}
			if sp.Surface == discovery.SurfaceQdrant && chk.CheckID == "qdrant_points_sample" && chk.Active {
				t.Errorf("qdrant_points_sample should be inactive when content.surfaces[qdrant]=false")
			}
			if sp.Surface == discovery.SurfaceJupyter && chk.CheckID == "jupyter_file_content" && !chk.Active {
				t.Errorf("jupyter_file_content should remain active when only ollama/qdrant disabled")
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
		case "/api/show":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"license":"MIT","modelfile":"FROM llama3\nSYSTEM SCANNER_OLLAMA_SECRET","template":"{{ .Prompt }}","system":"SCANNER_OLLAMA_SECRET","details":{"parent_model":"llama3:8b","family":"llama"}}`))
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
		case "/api/contents/analysis.ipynb":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"analysis.ipynb","path":"analysis.ipynb","type":"notebook","format":"json","mimetype":"application/x-ipynb+json","content":{"cells":[{"source":["SCANNER_JUPYTER_SECRET"]}]}}`))
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
	srv.AddResource(&mcpsdk.Resource{
		URI:      "file:///app/notes.txt",
		Name:     "notes.txt",
		MIMEType: "text/plain",
	}, func(ctx context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		return &mcpsdk.ReadResourceResult{
			Contents: []*mcpsdk.ResourceContents{
				{URI: "file:///app/notes.txt", MIMEType: "text/plain", Text: "SCANNER_MCP_SECRET\n"},
			},
		}, nil
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
	seenEvidenceIDs := make(map[string]bool)
	for _, l := range lines {
		var rec evidence.Record
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("unmarshal evidence record: %v", err)
		}
		if seenEvidenceIDs[rec.EvidenceID] {
			t.Errorf("duplicate EvidenceID %q in sidecar", rec.EvidenceID)
		}
		seenEvidenceIDs[rec.EvidenceID] = true
		foundEvidenceTypes[string(rec.RecordType)] = true
	}

	for _, et := range []string{string(evidence.RecordCheckResult), string(evidence.RecordFingerprint), string(evidence.RecordCorrelation)} {
		if !foundEvidenceTypes[et] {
			t.Errorf("expected evidence record type %s in sidecar, got: %+v", et, foundEvidenceTypes)
		}
	}

	// 4. Verify restricted content JSONL exists, has 0600 mode, and never leaks bodies to base/sidecar
	if res.ContentPath == "" {
		t.Fatalf("expected non-empty ContentPath on default scan")
	}
	info, err := os.Stat(res.ContentPath)
	if err != nil {
		t.Fatalf("stat content file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("content file permissions = %o, want 0600", info.Mode().Perm())
	}
	contentRaw, err := os.ReadFile(res.ContentPath)
	if err != nil {
		t.Fatalf("read content file: %v", err)
	}
	contentLines := strings.Split(strings.TrimSpace(string(contentRaw)), "\n")
	seenSurfaces := make(map[string]bool)
	for _, l := range contentLines {
		var crec content.Record
		if err := json.Unmarshal([]byte(l), &crec); err != nil {
			t.Fatalf("unmarshal content record: %v", err)
		}
		if err := crec.Validate(); err != nil {
			t.Errorf("invalid content record: %v", err)
		}
		seenSurfaces[crec.Surface] = true
	}
	for _, surf := range []string{"ollama", "jupyter", "mcp"} {
		if !seenSurfaces[surf] {
			t.Errorf("missing content records for surface %s (got %+v)", surf, seenSurfaces)
		}
	}
	for _, leak := range []string{"SCANNER_OLLAMA_SECRET", "SCANNER_JUPYTER_SECRET", "SCANNER_MCP_SECRET"} {
		if strings.Contains(string(payloadData), leak) || strings.Contains(string(sidecarData), leak) {
			t.Errorf("content secret %q leaked into base payload or evidence sidecar", leak)
		}
	}
}

func TestScanner_MappedTargetAttachesToNativeNodeViaLinkingPayload(t *testing.T) {
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
	mappingJSON := `[{"target": "127.0.0.1", "object_id": "S-1-5-21-1111111111-2222222222-3333333333-1001", "kind": "AZVM"}]`
	if err := os.WriteFile(mappingPath, []byte(mappingJSON), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "scanner-corp"
	cfg.Correlation.MappingFile = mappingPath
	cfg.Targets = []string{"127.0.0.1"}

	s, err := scanner.New(cfg,
		scanner.WithDefinitions(customDefs),
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

	// 3. An attached target needs no fallback NetworkEndpoint, and no node of the
	// native kind is ever emitted: the native node already exists in BloodHound.
	for _, n := range basePayload.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "LLMHound_NetworkEndpoint" || k == "AZVM" || k == "Computer" {
				t.Errorf("base payload must not emit %s for an attached target", k)
			}
		}
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

func scanOllamaDefinition(t *testing.T, handler http.HandlerFunc, probePaths []string, match discovery.MatchFunc) (*scanner.ScanResult, *[]string) {
	t.Helper()
	var paths []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	cfg := config.Defaults()
	cfg.Scope = "gate-scope"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.VantageKey = "vantage-test"

	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{{
		Surface:     discovery.SurfaceOllama,
		DefaultPort: parsePort(srv.URL),
		ProbePaths:  probePaths,
		Match:       match,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "gate-scan")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return res, &paths
}

func TestScanner_UnmatchedServiceJournalsFailedCoverageWithoutCollecting(t *testing.T) {
	res, paths := scanOllamaDefinition(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`generic web page`))
	}, []string{"/custom-probe"}, discovery.OllamaDefinition().Match)

	rec, ok := res.State.Targets()["127.0.0.1|ollama"]
	if !ok {
		t.Fatalf("attempted surface must have journal coverage: %+v", res.State.Targets())
	}
	if rec.Status != "failed" || res.State.IsCompleted("127.0.0.1", "ollama") {
		t.Errorf("status = %q, want failed and not completed", rec.Status)
	}
	if !strings.Contains(rec.Error, "not identified as ollama") {
		t.Errorf("reason %q should explain the unmatched fingerprint", rec.Error)
	}
	if len(res.State.Nodes()) != 0 {
		t.Errorf("unmatched service must not emit nodes: %d", len(res.State.Nodes()))
	}
	if len(*paths) != 1 || (*paths)[0] != "/custom-probe" {
		t.Errorf("requests = %v, want exactly [/custom-probe]", *paths)
	}
}

func TestScanner_ConfiguredMatchGatesCollection(t *testing.T) {
	res, paths := scanOllamaDefinition(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			_, _ = w.Write([]byte(`{"version": "0.3.12"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, []string{"/custom-probe"}, func(int, http.Header, []byte) bool { return true })

	seen := map[string]bool{}
	for _, p := range *paths {
		seen[p] = true
	}
	if !seen["/custom-probe"] || !seen["/api/version"] {
		t.Errorf("requests = %v, want configured probe then collector checks", *paths)
	}
	if _, ok := res.State.Targets()["127.0.0.1|ollama"]; !ok {
		t.Errorf("matched surface must be collected and journaled")
	}
}

func TestScanner_UnreachableSurfaceJournaledWithoutCollectorRequests(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	port := parsePort(srv.URL)
	srv.Close()

	cfg := config.Defaults()
	cfg.Scope = "gate-scope"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.VantageKey = "vantage-test"
	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{{
		Surface:     discovery.SurfaceOllama,
		DefaultPort: port,
		ProbePaths:  []string{"/api/version"},
		Match:       discovery.OllamaDefinition().Match,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "unreach")
	if err != nil {
		t.Fatal(err)
	}
	rec := res.State.Targets()["127.0.0.1|ollama"]
	if rec.Status != "failed" || !strings.Contains(rec.Error, "unreachable") {
		t.Errorf("record = %+v, want failed unreachable", rec)
	}
	if len(res.State.Nodes()) != 0 {
		t.Errorf("unreachable surface must not emit nodes")
	}
}

func TestScanner_CancelledContextFailsInsteadOfFabricatingCoverage(t *testing.T) {
	srv := setupMockOllama(t)
	defer srv.Close()

	cfg := config.Defaults()
	cfg.Scope = "cancel-scope"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.VantageKey = "vantage-test"
	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{{
		Surface:     discovery.SurfaceOllama,
		DefaultPort: parsePort(srv.URL),
		ProbePaths:  []string{"/api/version"},
		Match:       discovery.OllamaDefinition().Match,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := s.Scan(ctx, []string{"127.0.0.1"}, t.TempDir(), "cancel-scan")
	if err == nil {
		t.Fatalf("cancelled scan must fail, got result %+v", res)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestScanner_DisabledContentPreservesExistingArtifactAndSkipsFresh(t *testing.T) {
	ollamaSrv := setupMockOllama(t)
	defer ollamaSrv.Close()

	tmpDir := t.TempDir()
	stalePath := filepath.Join(tmpDir, "nocontent.content.jsonl")
	stale := []byte("{\"stale\":true}\n")
	if err := os.WriteFile(stalePath, stale, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Scope = "optout-scope"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.VantageKey = "vantage-test"
	cfg.Content.Enabled = false

	s, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{{
		Surface:     discovery.SurfaceOllama,
		DefaultPort: parsePort(ollamaSrv.URL),
		ProbePaths:  []string{"/api/version"},
		Match:       discovery.OllamaDefinition().Match,
	}}))
	if err != nil {
		t.Fatalf("scanner.New: %v", err)
	}
	if res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "nocontent"); err == nil {
		t.Fatalf("scan must reject an existing content prefix, got %+v", res)
	}
	got, err := os.ReadFile(stalePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(stale) {
		t.Fatalf("collision changed content artifact: got %q want %q", got, stale)
	}

	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "fresh-nocontent")
	if err != nil {
		t.Fatalf("fresh disabled-content scan: %v", err)
	}
	if res.ContentPath != "" {
		t.Errorf("ContentPath = %q, want empty when no content collected", res.ContentPath)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "fresh-nocontent.content.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("disabled content must not create a content file, stat err = %v", err)
	}
	if !res.State.IsCompleted("127.0.0.1", "ollama") {
		t.Errorf("expected completed target even when content disabled")
	}

}

func setupMockA2A(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name":"PlannerAgent",
				"version":"1.2.0",
				"protocolVersion":"0.3.0",
				"url":"https://agent.internal/rpc",
				"provider":{"organization":"TestOrg"},
				"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}},
				"security":[{"bearer":[]}],
				"skills":[{"id":"plan","name":"Plan"}]
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func setupMockVLLM(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.6.4"}`))
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama3-8b","owned_by":"vllm","max_model_len":8192}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func setupMockQdrant(t *testing.T, extra string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"title":"qdrant - vector search engine","version":"1.12.5","commit":"deadbeef"}`))
		case "/collections":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"kb"}]},"status":"ok"}`))
		case "/collections/kb":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"status":"green","points_count":1,"config":{"params":{"vectors":{"size":1536,"distance":"Cosine"}}}}}`))
		case "/snapshots":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":[]}`))
		case "/collections/kb/points/scroll":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"result":{"points":[{"id":1,"vector":[0.1,0.2],"payload":{"note":"SCANNER_QDRANT_SECRET %s"}}],"next_page_offset":null}}`, extra)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestScanner_M2bCohortEndToEnd(t *testing.T) {
	a2aSrv := setupMockA2A(t)
	defer a2aSrv.Close()
	vllmSrv := setupMockVLLM(t)
	defer vllmSrv.Close()
	qdrantSrv := setupMockQdrant(t, "safe-note")
	defer qdrantSrv.Close()
	genericOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","owned_by":"openai"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer genericOpenAI.Close()

	defs := []discovery.Definition{
		{
			Surface:     discovery.SurfaceA2A,
			DefaultPort: parsePort(a2aSrv.URL),
			ProbePaths:  discovery.A2ADefinition().ProbePaths,
			Match:       discovery.A2ADefinition().Match,
		},
		{
			Surface:     discovery.SurfaceVLLM,
			DefaultPort: parsePort(vllmSrv.URL),
			ProbePaths:  discovery.VLLMDefinition().ProbePaths,
			Match:       discovery.VLLMDefinition().Match,
		},
		{
			Surface:     discovery.SurfaceQdrant,
			DefaultPort: parsePort(qdrantSrv.URL),
			ProbePaths:  discovery.QdrantDefinition().ProbePaths,
			Match:       discovery.QdrantDefinition().Match,
		},
	}

	tmpDir := t.TempDir()
	cfg := config.Defaults()
	cfg.Scope = "m2b-scope"
	cfg.VantageKey = "vantage-m2b"
	cfg.Targets = []string{"127.0.0.1"}

	s, err := scanner.New(cfg, scanner.WithDefinitions(defs))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Scan(context.Background(), []string{"127.0.0.1"}, tmpDir, "m2b")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	payloadData, err := os.ReadFile(res.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var payload emitter.Payload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatal(err)
	}
	foundKinds := map[string]bool{}
	for _, n := range payload.Graph.Nodes {
		for _, k := range n.Kinds {
			foundKinds[k] = true
		}
	}
	for _, want := range []string{
		"LLMHound_A2AAgent", "LLMHound_A2ASkill",
		"LLMHound_VLLMInstance", "LLMHound_AIModel",
		"LLMHound_QdrantInstance", "LLMHound_VectorCollection",
	} {
		if !foundKinds[want] {
			t.Errorf("missing node kind %s in %+v", want, foundKinds)
		}
	}

	contentRaw, err := os.ReadFile(res.ContentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contentRaw), `"surface":"a2a"`) || !strings.Contains(string(contentRaw), `"surface":"qdrant"`) {
		t.Errorf("content file missing a2a or qdrant surfaces: %s", contentRaw)
	}
	if strings.Contains(string(payloadData), "SCANNER_QDRANT_SECRET") {
		t.Errorf("qdrant content leaked into graph payload")
	}

	// Generic OpenAI-compatible server probed as vllm must not match or emit VLLMInstance.
	sGen, err := scanner.New(cfg, scanner.WithDefinitions([]discovery.Definition{{
		Surface:     discovery.SurfaceVLLM,
		DefaultPort: parsePort(genericOpenAI.URL),
		ProbePaths:  discovery.VLLMDefinition().ProbePaths,
		Match:       discovery.VLLMDefinition().Match,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	resGen, err := sGen.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "generic-openai")
	if err != nil {
		t.Fatal(err)
	}
	if resGen.State.IsCompleted("127.0.0.1", "vllm") || len(resGen.State.Nodes()) != 0 {
		t.Errorf("generic OpenAI server must fail vllm discovery without nodes: nodes=%d", len(resGen.State.Nodes()))
	}
}

func TestScanner_PathQualificationRules(t *testing.T) {
	jupSrv := setupMockJupyter(t)
	defer jupSrv.Close()

	defs := []discovery.Definition{
		{
			Surface:     discovery.SurfaceJupyter,
			DefaultPort: parsePort(jupSrv.URL),
			ProbePaths:  discovery.JupyterDefinition().ProbePaths,
			Match:       discovery.JupyterDefinition().Match,
		},
	}

	resolver, err := correlate.New([]correlate.Mapping{{
		Target:   "127.0.0.1",
		ObjectID: "S-1-5-21-1-2-3-1103",
		Kind:     "Computer",
	}})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Rules disabled by default -> zero CanExecuteOn edges in linking payload.
	cfgOff := config.Defaults()
	cfgOff.Scope = "corp-scope"
	cfgOff.VantageKey = "scanner-01"
	cfgOff.Targets = []string{"127.0.0.1"}

	sOff, err := scanner.New(cfgOff, scanner.WithDefinitions(defs), scanner.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	resOff, err := sOff.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "rules-off")
	if err != nil {
		t.Fatal(err)
	}
	linkOff, err := os.ReadFile(resOff.Artifacts.LinkingPayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(linkOff), "LLMHound_CanExecuteOn") {
		t.Fatalf("disabled rules must emit zero CanExecuteOn edges: %s", linkOff)
	}

	// 2. Enabled rule on mapped Jupyter -> emits sourceless CanExecuteOn in linking payload.
	cfgOn := cfgOff
	cfgOn.PathQualification = config.PathQualification{
		EnabledRules: []string{"jupyter-auth-disabled"},
		AssumedReachPrincipals: []config.ReachPrincipal{
			{ObjectID: "S-1-5-21-1-2-3-513", Kind: "Group"},
		},
	}
	sOn, err := scanner.New(cfgOn, scanner.WithDefinitions(defs), scanner.WithResolver(resolver))
	if err != nil {
		t.Fatal(err)
	}
	resOn, err := sOn.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "rules-on")
	if err != nil {
		t.Fatal(err)
	}
	baseOn, err := os.ReadFile(resOn.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(baseOn), "LLMHound_CanExecuteOn") {
		t.Fatalf("CanExecuteOn must never appear in base payload (M0 Q5): %s", baseOn)
	}
	linkOn, err := os.ReadFile(resOn.Artifacts.LinkingPayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var linkPayload emitter.Payload
	if err := json.Unmarshal(linkOn, &linkPayload); err != nil {
		t.Fatal(err)
	}
	if linkPayload.Metadata != nil {
		t.Fatalf("linking payload must have nil metadata, got %+v", linkPayload.Metadata)
	}
	var foundCanExec bool
	for _, e := range linkPayload.Graph.Edges {
		if e.Kind == "LLMHound_CanExecuteOn" {
			foundCanExec = true
			if e.Start.Value != "S-1-5-21-1-2-3-513" || e.End.Value != "S-1-5-21-1-2-3-1103" {
				t.Errorf("unexpected CanExecuteOn endpoints: %+v -> %+v", e.Start, e.End)
			}
			if e.Properties["rule_id"] != "jupyter-auth-disabled" || e.Properties["reach_basis"] != "scanner_vantage" {
				t.Errorf("missing rule provenance properties: %+v", e.Properties)
			}
		}
	}
	if !foundCanExec {
		t.Fatalf("expected LLMHound_CanExecuteOn edge in linking payload: %s", linkOn)
	}

	// 3. Enabled rule on unmapped target (NetworkEndpoint) -> fails closed (no CanExecuteOn).
	sUnmapped, err := scanner.New(cfgOn, scanner.WithDefinitions(defs))
	if err != nil {
		t.Fatal(err)
	}
	resUnmapped, err := sUnmapped.Scan(context.Background(), []string{"127.0.0.1"}, t.TempDir(), "rules-unmapped")
	if err != nil {
		t.Fatal(err)
	}
	if resUnmapped.Artifacts.LinkingPayloadPath != "" {
		t.Fatalf("unmapped target must not emit linking payload or CanExecuteOn")
	}
}

func TestScanner_ResumeSkipsCompletedAndRepairsTornTail(t *testing.T) {
	var hitsA atomic.Int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.6.0"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvA.Close()

	var hitsB atomic.Int32
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsB.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"0.6.3"}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"meta-llama/Llama-3-8B","object":"model","owned_by":"vllm"}]}`))
		case "/metrics":
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvB.Close()

	defA := discovery.OllamaDefinition()
	defA.DefaultPort = parsePort(srvA.URL)
	defB := discovery.VLLMDefinition()
	defB.DefaultPort = parsePort(srvB.URL)

	t1 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC)

	cfg := config.Defaults()
	cfg.Scope = "corp"
	cfg.VantageKey = "v1"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Bounds.MaxTargets = 10
	cfg.Content.Enabled = false

	outDir := t.TempDir()
	prefix := "resume-test"

	s1, err := scanner.New(cfg,
		scanner.WithNow(func() time.Time { return t1 }),
		scanner.WithDefinitions([]discovery.Definition{defA}),
	)
	if err != nil {
		t.Fatal(err)
	}
	res1, err := s1.Scan(context.Background(), []string{"127.0.0.1"}, outDir, prefix)
	if err != nil {
		t.Fatalf("initial scan: %v", err)
	}
	if hitsA.Load() == 0 {
		t.Fatal("expected initial scan to hit server A")
	}
	hitsA.Store(0)

	// Simulate crash leaving an unterminated torn line at EOF.
	jf, err := os.OpenFile(res1.JournalPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jf.WriteString(`{"entry_type":"result","result":{"target":"127.0.0.1"`); err != nil {
		_ = jf.Close()
		t.Fatal(err)
	}
	if err := jf.Close(); err != nil {
		t.Fatal(err)
	}

	// Scope mismatch must fail closed without touching completed state.
	badCfg := cfg
	badCfg.Scope = "other-scope"
	sBad, err := scanner.New(badCfg,
		scanner.WithNow(func() time.Time { return t2 }),
		scanner.WithDefinitions([]discovery.Definition{defA, defB}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sBad.Resume(context.Background(), res1.JournalPath, []string{"127.0.0.1"}, outDir, prefix); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("expected scope mismatch error on Resume, got %v", err)
	}

	s2, err := scanner.New(cfg,
		scanner.WithNow(func() time.Time { return t2 }),
		scanner.WithDefinitions([]discovery.Definition{defA, defB}),
	)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := s2.Resume(context.Background(), res1.JournalPath, []string{"127.0.0.1"}, outDir, prefix)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if got := hitsA.Load(); got != 0 {
		t.Fatalf("expected 0 hits on already-completed server A during resume, got %d", got)
	}
	if hitsB.Load() == 0 {
		t.Fatal("expected server B to be probed and collected during resume")
	}

	baseBytes, err := os.ReadFile(res2.Artifacts.BasePayloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var base emitter.Payload
	if err := json.Unmarshal(baseBytes, &base); err != nil {
		t.Fatal(err)
	}
	var seenA, seenB bool
	for _, n := range base.Graph.Nodes {
		obsAt, _ := n.Properties["observed_at"].(string)
		for _, k := range n.Kinds {
			switch k {
			case "LLMHound_OllamaInstance":
				seenA = true
				if obsAt != t1.Format(time.RFC3339) {
					t.Errorf("ollama observed_at = %q, want preserved %q", obsAt, t1.Format(time.RFC3339))
				}
			case "LLMHound_VLLMInstance":
				seenB = true
				if obsAt != t2.Format(time.RFC3339) {
					t.Errorf("vllm observed_at = %q, want %q", obsAt, t2.Format(time.RFC3339))
				}
			}
		}
	}
	if !seenA || !seenB {
		t.Fatalf("expected both ollama (%v) and vllm (%v) in resumed base payload", seenA, seenB)
	}

	evBytes, err := os.ReadFile(res2.Artifacts.EvidenceSidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(evBytes)), "\n")
	if len(lines) == 0 {
		t.Fatal("expected evidence records after resume")
	}
	for i, line := range lines {
		var rec evidence.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("evidence line %d invalid JSON: %v", i+1, err)
		}
	}
}
