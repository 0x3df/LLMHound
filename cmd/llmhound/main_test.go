package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func execute(args ...string) (string, error) {
	var out bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func inEmptyDirectory(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

func TestHelpAndVersion(t *testing.T) {
	inEmptyDirectory(t)
	for _, args := range [][]string{{}, {"--help"}, {"targets", "--help"}, {"scan", "--help"}, {"plan", "--help"}, {"upload", "--help"}} {
		out, err := execute(args...)
		if err != nil || !strings.Contains(out, "Usage:") {
			t.Fatalf("%v: %q %v", args, out, err)
		}
	}
	out, err := execute("--version")
	if err != nil || !strings.Contains(out, "dev") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestCLIErrors(t *testing.T) {
	inEmptyDirectory(t)
	for _, tc := range []struct {
		args    []string
		message string
	}{
		{[]string{"unknown"}, "unknown command"},
		{[]string{"targets", "--unknown"}, "unknown flag"},
		{[]string{"targets", "extra"}, "unknown command"},
		{[]string{"targets", "--targets", "ai.example.test"}, "required"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner"}, "at least one"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--cidr", "10.0.0.0/8"}, "expansion exceeds"},
		{[]string{"targets", "--config", "missing.yaml"}, "config"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "https://bad.example.test"}, "invalid CIDR"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--exclude", "ai.example.test"}, "no targets remain"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--concurrency=0"}, "concurrency"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--connect-timeout=oops"}, "invalid argument"},
	} {
		out, err := execute(tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.message) || out != "" {
			t.Fatalf("%v: output %q error %v; want %q", tc.args, out, err, tc.message)
		}
	}
}

func TestOfflineTargetCommand(t *testing.T) {
	inEmptyDirectory(t)
	out, err := execute("targets", "--scope", "tenant", "--vantage", "scanner", "--cidr", "192.0.2.0/30", "--targets", "AI.Example.Test.,192.0.2.3", "--exclude", "192.0.2.0/31")
	if err != nil || out != "192.0.2.2\n192.0.2.3\nai.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestDefaultConfigAndExplicitFlagReplacements(t *testing.T) {
	inEmptyDirectory(t)
	data := "scope: file\nvantage_key: scanner\ntargets: [from-file.example.test]\ncidrs: [192.0.2.0/30]\nbounds:\n  concurrency: 17\n  max_redirects: 4\ninsecure: true\ncontent:\n  enabled: false\n"
	if err := os.WriteFile("llmhound.yaml", []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute("targets", "--targets", "flag.example.test", "--exclude", "192.0.2.0/31", "--insecure=false", "--content=true", "--content-disable=ollama", "--content-max-item-bytes=2048", "--max-redirects=0")
	if err != nil || out != "192.0.2.2\n192.0.2.3\nflag.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
	// Legacy --prompts flag and opt_ins YAML keys must fail instead of silently ignoring content policy.
	if _, err := execute("plan", "--scope", "file", "--vantage", "scanner", "--targets", "ai.example.test", "--prompts=true"); err == nil {
		t.Fatal("expected legacy --prompts flag to be rejected")
	}
	if err := os.WriteFile("legacy.yaml", []byte("scope: file\nvantage_key: scanner\nopt_ins:\n  prompts: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("targets", "--config", "legacy.yaml"); err == nil {
		t.Fatal("expected legacy opt_ins YAML key to be rejected")
	}
	// Explicit empty scope is not silently replaced by the file value.
	if _, err := execute("targets", "--scope="); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatal(err)
	}
	// Invalid untouched file bounds are not silently replaced by flag defaults.
	data = strings.Replace(data, "concurrency: 17", "concurrency: 0", 1)
	if err := os.WriteFile("llmhound.yaml", []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("targets"); err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatal(err)
	}
	if _, err := execute("targets", "--concurrency=1"); err != nil {
		t.Fatal(err)
	}
}

func TestFilePathsAndListOverrides(t *testing.T) {
	inEmptyDirectory(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.txt"), []byte("file.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("flag.txt", []byte("flag.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "llmhound.yaml")
	if err := os.WriteFile(configPath, []byte("scope: tenant\nvantage_key: scanner\ntargets_files: [hosts.txt]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute("targets", "--config", configPath)
	if err != nil || out != "file.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
	out, err = execute("targets", "--config", configPath, "--targets-file", "flag.txt")
	if err != nil || out != "flag.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestUploadValidationAndPlanWritesNoArtifacts(t *testing.T) {
	t.Setenv("BLOODHOUND_URL", "")
	inEmptyDirectory(t)
	out, err := execute("upload")
	if err == nil || !strings.Contains(err.Error(), "bloodhound url is required") || out != "" {
		t.Fatalf("upload without url: %q %v", out, err)
	}

	out, err = execute("plan", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test")
	if err != nil {
		t.Fatalf("plan: %q %v", out, err)
	}
	if !strings.Contains(out, "TARGET: ai.example.test") {
		t.Fatalf("plan missing target: %q", out)
	}
	for _, surface := range []string{
		"jupyter", "mcp", "ollama", "a2a", "vllm", "qdrant",
		"litellm", "mlflow", "open_webui", "langserve",
		"ray", "langflow", "flowise", "chromadb", "openai_compatible",
	} {
		if !strings.Contains(out, "SURFACE: "+surface) {
			t.Fatalf("plan missing surface %s: %q", surface, out)
		}
	}
	for _, chk := range []string{"ollama_show", "jupyter_file_content", "mcp_resources_read", "qdrant_points_sample"} {
		if !strings.Contains(out, chk) {
			t.Fatalf("plan missing content check %s: %q", chk, out)
		}
	}
	if strings.Contains(out, "policy:") {
		t.Fatalf("default plan should enable content checks, got skip policy: %q", out)
	}

	outOff, err := execute("plan", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--content=false")
	if err != nil {
		t.Fatalf("plan --content=false: %q %v", outOff, err)
	}
	if !strings.Contains(outOff, "ollama_show") || !strings.Contains(outOff, "qdrant_points_sample") || !strings.Contains(outOff, "policy:") {
		t.Fatalf("plan --content=false should show inactive content checks with policy skip: %q", outOff)
	}

	files, err := os.ReadDir(".")
	if err != nil || len(files) != 0 {
		t.Fatalf("plan created artifacts: %v %v", files, err)
	}
}

func TestPlanMakesNoDNSQueriesOrTargetConnections(t *testing.T) {
	inEmptyDirectory(t)
	var dnsCalls atomic.Int32
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("unexpected DNS request")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	out, err := execute("plan", "--scope", "tenant", "--vantage", "scanner", "--targets", host+",never-resolve.example.test")
	if err != nil || !strings.Contains(out, "TARGET: "+host) {
		t.Fatalf("%q %v", out, err)
	}
	_ = port
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unexpected target connection during plan")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal(err)
	}
	if dnsCalls.Load() != 0 {
		t.Fatal("DNS called during plan")
	}
}

func cliMockOllama(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "0.3.12"}`))
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest","size":100,"digest":"sha256:abc","details":{"format":"gguf","family":"llama","parameter_size":"8B","quantization_level":"Q4_0"}}]}`))
		case "/api/ps":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/show":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"license":"MIT","modelfile":"FROM llama3\nSYSTEM CLI_OLLAMA_SECRET","template":"{{ .Prompt }}","system":"CLI_OLLAMA_SECRET"}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`Ollama is running`))
		}
	}))
}

func cliMockJupyter(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"2.14.0","jupyter_server_version":"2.14.0"}`))
		case "/api/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"started":"2026-10-01T12:00:00Z","kernels":0,"connections":0}`))
		case "/api/sessions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"","path":"","type":"directory","content":[{"name":"analysis.ipynb","path":"analysis.ipynb","type":"notebook","size":2048,"last_modified":"2026-10-01T12:00:00Z"}]}`))
		case "/api/contents/analysis.ipynb":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"analysis.ipynb","path":"analysis.ipynb","type":"notebook","format":"json","mimetype":"application/x-ipynb+json","content":{"cells":[{"source":["CLI_JUPYTER_SECRET"]}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func cliMockMCP(t *testing.T, extra string) *httptest.Server {
	t.Helper()
	impl := &mcpsdk.Implementation{Name: "cli-mcp", Version: "1.0.0", Title: "CLI MCP"}
	srv := mcpsdk.NewServer(impl, nil)
	srv.AddTool(&mcpsdk.Tool{
		Name:        "echo",
		Description: "Echoes input",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}},
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		t.Fatal("CallTool must never be called during read-only enumeration")
		return nil, nil
	})
	srv.AddResource(&mcpsdk.Resource{
		URI:      "file:///app/config.json",
		Name:     "config.json",
		MIMEType: "application/json",
	}, func(ctx context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		return &mcpsdk.ReadResourceResult{
			Contents: []*mcpsdk.ResourceContents{
				{URI: "file:///app/config.json", MIMEType: "application/json", Text: fmt.Sprintf(`{"token":"CLI_MCP_SECRET","gh":"%s"}`, extra)},
			},
		}, nil
	})
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server { return srv }, nil)
	return httptest.NewServer(handler)
}

func portOf(urlStr string) int {
	u, _ := http.NewRequest("GET", urlStr, nil)
	var port int
	fmt.Sscanf(u.URL.Port(), "%d", &port)
	return port
}

// propsOfKind returns the properties of the first node carrying kind.
func propsOfKind(t *testing.T, payload emitter.Payload, kind string) map[string]any {
	t.Helper()
	for _, n := range payload.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == kind {
				return n.Properties
			}
		}
	}
	t.Fatalf("no node with kind %s in payload", kind)
	return nil
}

func TestScanCLIEndToEndLoopbackFixtures(t *testing.T) {
	inEmptyDirectory(t)

	ollamaSrv := cliMockOllama(t)
	defer ollamaSrv.Close()
	jupyterSrv := cliMockJupyter(t)
	defer jupyterSrv.Close()
	// A checksum-valid classic GitHub token generated at test time: the MCP
	// resource body must surface it on the graph, redact the content file,
	// and leave the value nowhere on disk.
	tok := secretstest.GitHubToken("ghp", "Zq3Lm9Tx2Vb7Nc4Hd8Kf1Pw6Rj5Ys0")
	mcpSrv := cliMockMCP(t, tok)
	defer mcpSrv.Close()
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ollama"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"ollama: unauthorized"}`))
	}))
	defer deniedSrv.Close()

	defs := fmt.Sprintf(`[
  {"surface":"ollama","default_port":%d,"probe_paths":["/api/version","/api/tags","/"]},
  {"surface":"jupyter","default_port":%d,"probe_paths":["/api","/api/status","/tree","/login"]},
  {"surface":"mcp","default_port":%d,"probe_paths":["/mcp","/sse","/"]}
]`, portOf(ollamaSrv.URL), portOf(jupyterSrv.URL), portOf(mcpSrv.URL))
	if err := os.WriteFile("discovery.json", []byte(defs), 0600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	out, err := execute(
		"scan",
		"--scope", "cli-scope",
		"--vantage", "cli-vantage",
		"--targets", "127.0.0.1",
		"--discovery-file", "discovery.json",
		"--output-dir", outDir,
		"--prefix", "cli-live",
	)
	if err != nil {
		t.Fatalf("scan: %q %v", out, err)
	}
	if !strings.Contains(out, "Scan completed for 1 target(s)") {
		t.Fatalf("unexpected scan output: %q", out)
	}
	for _, name := range []string{"cli-live.json", "cli-live.evidence.jsonl", "cli-live.journal.jsonl", "cli-live.content.jsonl"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
		}
	}
	if !strings.Contains(out, "Content file:") {
		t.Errorf("scan output missing Content file line: %q", out)
	}
	contentInfo, err := os.Stat(filepath.Join(outDir, "cli-live.content.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if contentInfo.Mode().Perm() != 0600 {
		t.Errorf("content file mode = %o, want 0600", contentInfo.Mode().Perm())
	}
	contentRaw, err := os.ReadFile(filepath.Join(outDir, "cli-live.content.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	contentSurfaces := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(contentRaw)), "\n") {
		var crec content.Record
		if err := json.Unmarshal([]byte(line), &crec); err != nil {
			t.Fatalf("unmarshal content line: %v", err)
		}
		contentSurfaces[crec.Surface] = true
	}
	for _, wantSurf := range []string{"ollama", "jupyter", "mcp"} {
		if !contentSurfaces[wantSurf] {
			t.Errorf("missing surface %s in cli-live.content.jsonl: %+v", wantSurf, contentSurfaces)
		}
	}

	payloadData, err := os.ReadFile(filepath.Join(outDir, "cli-live.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload emitter.Payload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Metadata == nil || payload.Metadata.SourceKind != "LLMHound" {
		t.Fatalf("payload metadata = %+v", payload.Metadata)
	}
	kinds := map[string]bool{}
	for _, n := range payload.Graph.Nodes {
		for _, k := range n.Kinds {
			kinds[k] = true
		}
	}
	for _, want := range []string{
		"LLMHound_OllamaInstance", "LLMHound_AIModel",
		"LLMHound_JupyterServer", "LLMHound_WorkspaceFile",
		"LLMHound_MCPServer", "LLMHound_MCPTool",
		"LLMHound_NetworkEndpoint",
	} {
		if !kinds[want] {
			t.Errorf("missing kind %s in %+v", want, kinds)
		}
	}

	sidecar, err := os.ReadFile(filepath.Join(outDir, "cli-live.evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(sidecar)), "\n") {
		var rec evidence.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		types[string(rec.RecordType)] = true
	}
	for _, want := range []string{string(evidence.RecordCheckResult), string(evidence.RecordFingerprint), string(evidence.RecordCorrelation)} {
		if !types[want] {
			t.Errorf("missing evidence type %s in %+v", want, types)
		}
	}

	for _, secret := range []string{"CLI_OLLAMA_SECRET", "CLI_JUPYTER_SECRET", "CLI_MCP_SECRET"} {
		if strings.Contains(string(payloadData), secret) || strings.Contains(string(sidecar), secret) {
			t.Errorf("content secret %q leaked into base payload or sidecar", secret)
		}
	}

	// D4: the checksum-valid GitHub token in the MCP resource must be
	// detected, flagged on the graph, redacted in the content file, recorded
	// in the sidecar by type and location only, and stored nowhere.
	mcpProps := propsOfKind(t, payload, "LLMHound_MCPServer")
	if mcpProps["has_exposed_secret"] != true {
		t.Errorf("MCPServer has_exposed_secret = %v, want true", mcpProps["has_exposed_secret"])
	}
	if got, ok := mcpProps["secret_types"].([]any); !ok || len(got) != 1 || got[0] != "github_token" {
		t.Errorf("MCPServer secret_types = %v, want [github_token]", mcpProps["secret_types"])
	}
	if last, _ := mcpProps["secret_last_confirmed"].(string); last == "" {
		t.Errorf("MCPServer secret_last_confirmed missing: %v", mcpProps["secret_last_confirmed"])
	}
	for _, kind := range []string{"LLMHound_OllamaInstance", "LLMHound_JupyterServer"} {
		if props := propsOfKind(t, payload, kind); props["has_exposed_secret"] != nil {
			t.Errorf("%s has_exposed_secret = %v, want key absent", kind, props["has_exposed_secret"])
		}
	}
	if !strings.Contains(string(contentRaw), "[secret:github_token]") || strings.Contains(string(contentRaw), tok) {
		t.Errorf("content file must carry [secret:github_token] and not the token value")
	}
	outDirEntries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range outDirEntries {
		raw, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), tok) {
			t.Errorf("token value leaked into %s", e.Name())
		}
	}
	if strings.Contains(out, tok) {
		t.Errorf("token value leaked into scan output")
	}
	if !strings.Contains(string(sidecar), `"detected_exposures"`) ||
		!strings.Contains(string(sidecar), `"type":"github_token"`) ||
		!strings.Contains(string(sidecar), `"location":"file:///app/config.json"`) {
		t.Errorf("sidecar missing detected_exposures details: %s", sidecar)
	}

	// Honest denied coverage via a second scan remapped to a 401 Ollama fixture.
	deniedDefs := fmt.Sprintf(`[{"surface":"ollama","default_port":%d,"probe_paths":["/api/version","/"]}]`, portOf(deniedSrv.URL))
	if err := os.WriteFile("denied-discovery.json", []byte(deniedDefs), 0600); err != nil {
		t.Fatal(err)
	}
	deniedOut := t.TempDir()
	out, err = execute(
		"scan",
		"--scope", "cli-scope",
		"--vantage", "cli-vantage",
		"--targets", "127.0.0.1",
		"--discovery-file", "denied-discovery.json",
		"--output-dir", deniedOut,
		"--prefix", "cli-denied",
	)
	if err != nil {
		t.Fatalf("denied scan: %q %v", out, err)
	}
	sidecar, err = os.ReadFile(filepath.Join(deniedOut, "cli-denied.evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecar), "denied") && !strings.Contains(string(sidecar), "authentication") {
		t.Errorf("expected denied sidecar evidence, got: %s", sidecar)
	}
}

func TestPreparationMakesNoDNSQueriesOrTargetConnections(t *testing.T) {
	inEmptyDirectory(t)
	var dnsCalls atomic.Int32
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("unexpected DNS request")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	out, err := execute("targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "127.0.0.1,never-resolve.example.test")
	if err != nil || out != "127.0.0.1\nnever-resolve.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unexpected target connection")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal(err)
	}
	if dnsCalls.Load() != 0 {
		t.Fatal("DNS called during preparation")
	}
}

func TestTargetOutputWriteError(t *testing.T) {
	inEmptyDirectory(t)
	cmd := newRootCommand()
	cmd.SetOut(failingWriter{})
	cmd.SetArgs([]string{"targets", "--scope", "t", "--vantage", "v", "--targets", "ai.example.test"})
	if err := cmd.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRemovedCorrelationFlagsAreRejected(t *testing.T) {
	// Attribution belongs to the normalizer; these flags no longer exist.
	for _, flag := range [][]string{{"--ad-domain-suffix", "corp.example"}, {"--reverse-dns"}, {"--ce-lookup"}} {
		args := append([]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "127.0.0.1"}, flag...)
		if _, err := execute(args...); err == nil {
			t.Fatalf("removed flag %v accepted", flag)
		}
	}
}

func TestScanCLIM2bCohortLoopbackFixtures(t *testing.T) {
	inEmptyDirectory(t)
	tok := secretstest.GitHubToken("ghp", "Mn1Op5Qr9St3Uv7Wx2Yz6Ab0Cd4Ef8")

	a2aSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_, _ = w.Write([]byte(`{"name":"CLIAgent","version":"1.0.0","skills":[{"id":"sk1","name":"Sk1"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer a2aSrv.Close()

	vllmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"0.6.4"}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen2.5","owned_by":"vllm"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer vllmSrv.Close()

	qdrantSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"title":"qdrant","version":"1.12.5","commit":"cafebabe"}`))
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"secrets_kb"}]},"status":"ok"}`))
		case "/collections/secrets_kb":
			_, _ = w.Write([]byte(`{"result":{"status":"green","points_count":1,"config":{"params":{"vectors":{"size":128,"distance":"Cosine"}}}}}`))
		case "/snapshots":
			_, _ = w.Write([]byte(`{"result":[]}`))
		case "/collections/secrets_kb/points/scroll":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"result":{"points":[{"id":42,"payload":{"token":"%s"}}],"next_page_offset":null}}`, tok)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer qdrantSrv.Close()

	defs := fmt.Sprintf(`[
  {"surface":"a2a","default_port":%d,"probe_paths":["/.well-known/agent-card.json"]},
  {"surface":"vllm","default_port":%d,"probe_paths":["/v1/models","/version"]},
  {"surface":"qdrant","default_port":%d,"probe_paths":["/","/collections"]}
]`, portOf(a2aSrv.URL), portOf(vllmSrv.URL), portOf(qdrantSrv.URL))
	if err := os.WriteFile("m2b-discovery.json", []byte(defs), 0600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	out, err := execute(
		"scan",
		"--scope", "cli-m2b",
		"--vantage", "cli-vantage",
		"--targets", "127.0.0.1",
		"--discovery-file", "m2b-discovery.json",
		"--output-dir", outDir,
		"--prefix", "m2b-live",
	)
	if err != nil {
		t.Fatalf("scan: %q %v", out, err)
	}

	contentPath := filepath.Join(outDir, "m2b-live.content.jsonl")
	cInfo, err := os.Stat(contentPath)
	if err != nil {
		t.Fatal(err)
	}
	if cInfo.Mode().Perm() != 0600 {
		t.Errorf("content file mode = %o, want 0600", cInfo.Mode().Perm())
	}
	contentRaw, err := os.ReadFile(contentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contentRaw), "[secret:github_token]") || strings.Contains(string(contentRaw), tok) {
		t.Errorf("content file must redact token and not retain value")
	}

	payloadData, err := os.ReadFile(filepath.Join(outDir, "m2b-live.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload emitter.Payload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatal(err)
	}
	qProps := propsOfKind(t, payload, "LLMHound_QdrantInstance")
	if qProps["has_exposed_secret"] != true {
		t.Errorf("QdrantInstance has_exposed_secret = %v, want true", qProps["has_exposed_secret"])
	}
	sidecar, err := os.ReadFile(filepath.Join(outDir, "m2b-live.evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sidecar), `"detected_exposures"`) {
		t.Errorf("sidecar missing detected_exposures: %s", sidecar)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), tok) {
			t.Errorf("secret value leaked into %s", e.Name())
		}
	}
	if strings.Contains(out, tok) {
		t.Errorf("secret value leaked into CLI stdout")
	}
}

func TestScanCLID5D6CohortLoopbackFixtures(t *testing.T) {
	inEmptyDirectory(t)
	tok := secretstest.GitHubToken("ghp", "Qr1St5Uv9Wx3Yz7Ab1Cd5Ef9Gh3Ij7")

	litellmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(`{"info":{"title":"LiteLLM API","version":"0.1.0"},"paths":{"/v1/models":{},"/model/info":{}}}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o"}]}`))
		case "/model/info":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":[{"model_name":"gpt-4o","litellm_params":{"model":"openai/gpt-4o","api_key":"%s"}}]}`, tok)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer litellmSrv.Close()

	mlflowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte("2.16.2"))
		case "/api/2.0/mlflow/experiments/search":
			_, _ = w.Write([]byte(`{"experiments":[{"experiment_id":"0","name":"Default","artifact_location":"s3://mlflow-bucket/exp"}]}`))
		case "/api/2.0/mlflow/registered-models/search":
			_, _ = w.Write([]byte(`{"registered_models":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mlflowSrv.Close()

	openwebuiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.4.8"}`))
		case "/api/config":
			_, _ = w.Write([]byte(`{"status":true,"name":"Open WebUI","features":{"auth":false,"enable_signup":true}}`))
		case "/api/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"llama3"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer openwebuiSrv.Close()

	langserveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(`{"info":{"title":"LangChain Server","version":"1.0"},"paths":{"/chain/invoke":{},"/chain/input_schema":{}}}`))
		case "/chain/input_schema":
			_, _ = w.Write([]byte(`{"type":"object"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer langserveSrv.Close()

	raySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.8.0","ray_version":"2.37.0","ray_commit":"abc123"}`))
		case "/api/cluster_status":
			_, _ = w.Write([]byte(`{"result":true,"data":{"clusterStatus":{"active_nodes":{"head":1}}}}`))
		case "/api/jobs/":
			_, _ = w.Write([]byte(`[{"submission_id":"raysubmit_1","status":"SUCCEEDED","entrypoint":"echo hi"}]`))
		case "/api/v0/actors":
			_, _ = w.Write([]byte(`{"result":true,"data":{"result":{"total":0}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer raySrv.Close()

	langflowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`))
		case "/api/v1/auto_login":
			_, _ = w.Write([]byte(`{"access_token":"LF_RAW_JWT_SECRET","token_type":"bearer"}`))
		case "/api/v1/flows/":
			_, _ = w.Write([]byte(`[{"id":"f1","name":"Flow1","data":{"nodes":[]}}]`))
		case "/api/v1/all":
			_, _ = w.Write([]byte(`{"tools":{"ToolA":{}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer langflowSrv.Close()

	flowiseSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version":"2.1.4"}`))
		case "/api/v1/chatflows":
			_, _ = w.Write([]byte(`[{"id":"cf1","name":"Bot","isPublic":true,"flowData":"{}"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer flowiseSrv.Close()

	chromaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/heartbeat":
			_, _ = w.Write([]byte(`{"nanosecond heartbeat":1}`))
		case "/api/v2/version":
			_, _ = w.Write([]byte(`"0.5.20"`))
		case "/api/v2/auth/identity":
			_, _ = w.Write([]byte(`{"tenant":"default_tenant","databases":["default_database"]}`))
		case "/api/v2/tenants/default_tenant/databases/default_database/collections":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer chromaSrv.Close()

	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"local-llm","owned_by":"org"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer oaiSrv.Close()

	defs := fmt.Sprintf(`[
  {"surface":"litellm","default_port":%d,"probe_paths":["/openapi.json","/model/info"]},
  {"surface":"mlflow","default_port":%d,"probe_paths":["/api/2.0/mlflow/experiments/search?max_results=1"]},
  {"surface":"open_webui","default_port":%d,"probe_paths":["/api/config"]},
  {"surface":"langserve","default_port":%d,"probe_paths":["/openapi.json"]},
  {"surface":"ray","default_port":%d,"probe_paths":["/api/version"]},
  {"surface":"langflow","default_port":%d,"probe_paths":["/api/v1/version"]},
  {"surface":"flowise","default_port":%d,"probe_paths":["/api/v1/chatflows","/api/v1/version"]},
  {"surface":"chromadb","default_port":%d,"probe_paths":["/api/v2/heartbeat"]},
  {"surface":"openai_compatible","default_port":%d,"probe_paths":["/v1/models"]}
]`,
		portOf(litellmSrv.URL), portOf(mlflowSrv.URL), portOf(openwebuiSrv.URL), portOf(langserveSrv.URL),
		portOf(raySrv.URL), portOf(langflowSrv.URL), portOf(flowiseSrv.URL), portOf(chromaSrv.URL), portOf(oaiSrv.URL))
	if err := os.WriteFile("d5d6-discovery.json", []byte(defs), 0600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	out, err := execute(
		"scan",
		"--scope", "cli-d5d6",
		"--vantage", "cli-vantage",
		"--targets", "127.0.0.1",
		"--discovery-file", "d5d6-discovery.json",
		"--output-dir", outDir,
		"--prefix", "d5d6-live",
	)
	if err != nil {
		t.Fatalf("scan: %q %v", out, err)
	}

	payloadData, err := os.ReadFile(filepath.Join(outDir, "d5d6-live.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload emitter.Payload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, n := range payload.Graph.Nodes {
		for _, k := range n.Kinds {
			kinds[k] = true
		}
	}
	for _, want := range []string{
		"LLMHound_LiteLLMGateway", "LLMHound_MLflowServer", "LLMHound_OpenWebUIInstance", "LLMHound_LangServeApp",
		"LLMHound_RayDashboard", "LLMHound_LangflowInstance", "LLMHound_FlowiseInstance", "LLMHound_ChromaInstance",
		"LLMHound_OpenAICompatibleEndpoint",
	} {
		if !kinds[want] {
			t.Errorf("missing kind %s in %+v", want, kinds)
		}
	}

	contentPath := filepath.Join(outDir, "d5d6-live.content.jsonl")
	cInfo, err := os.Stat(contentPath)
	if err != nil {
		t.Fatal(err)
	}
	if cInfo.Mode().Perm() != 0600 {
		t.Errorf("content file mode = %o, want 0600", cInfo.Mode().Perm())
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(outDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), tok) || strings.Contains(string(raw), "LF_RAW_JWT_SECRET") {
			t.Errorf("secret leaked into %s", e.Name())
		}
	}
}

func TestResumeCLI(t *testing.T) {
	inEmptyDirectory(t)

	var hitsA atomic.Int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
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
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"0.6.3"}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"meta-llama/Llama-3-8B","object":"model","owned_by":"vllm"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvB.Close()

	defs1 := fmt.Sprintf(`[{"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]}]`, portOf(srvA.URL))
	if err := os.WriteFile("disc1.json", []byte(defs1), 0600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	out, err := execute("scan", "--scope", "cli-resume", "--vantage", "cli-v", "--targets", "127.0.0.1", "--content=false", "--discovery-file", "disc1.json", "--output-dir", outDir, "--prefix", "job1")
	if err != nil {
		t.Fatalf("initial scan: %q %v", out, err)
	}
	if hitsA.Load() == 0 {
		t.Fatal("expected hits on server A during initial scan")
	}
	hitsA.Store(0)

	journalPath := filepath.Join(outDir, "job1.journal.jsonl")
	jf, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jf.WriteString(`{"entry_type":"result","result":{"target":"127.0.0.1"`); err != nil {
		_ = jf.Close()
		t.Fatal(err)
	}
	_ = jf.Close()

	defs2 := fmt.Sprintf(`[
  {"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]},
  {"surface":"vllm","default_port":%d,"probe_paths":["/version"]}
]`, portOf(srvA.URL), portOf(srvB.URL))
	if err := os.WriteFile("disc2.json", []byte(defs2), 0600); err != nil {
		t.Fatal(err)
	}

	out, err = execute("resume", "--journal", journalPath, "--scope", "cli-resume", "--vantage", "cli-v", "--targets", "127.0.0.1", "--content=false", "--discovery-file", "disc2.json", "--output-dir", outDir, "--prefix", "job1")
	if err != nil {
		t.Fatalf("resume failed: %q %v", out, err)
	}
	if !strings.Contains(out, "Resume completed for 1 target(s)") {
		t.Fatalf("unexpected resume output: %q", out)
	}
	if hitsA.Load() != 0 {
		t.Fatalf("expected 0 hits on already-completed ollama during resume, got %d", hitsA.Load())
	}
	if hitsB.Load() == 0 {
		t.Fatal("expected vllm to be collected during resume")
	}

	rawBase, err := os.ReadFile(filepath.Join(outDir, "job1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawBase), "LLMHound_OllamaInstance") || !strings.Contains(string(rawBase), "LLMHound_VLLMInstance") {
		t.Fatalf("resumed base payload missing expected surfaces: %s", rawBase)
	}
}

func TestUploadCLIWithMockCE(t *testing.T) {
	inEmptyDirectory(t)

	var serverVersion atomic.Value
	serverVersion.Store("v9.7.1")

	var registeredSchema atomic.Value
	var uploadedFiles [][]byte
	var uploadedFileNames []string
	var importedZip []byte
	var deletedIDs []int64

	ce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/version":
			_, _ = fmt.Fprintf(w, `{"data":{"API":{"current_version":"v2"},"server_version":"%s","product_edition":"community"}}`, serverVersion.Load().(string))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/graphs/source-kinds":
			_, _ = w.Write([]byte(`{"data":{"kinds":[{"id":1,"name":"LLMHound"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions-edges":
			_, _ = w.Write([]byte(`{"data":[{"id":1,"name":"MemberOf","is_traversable":true},{"id":2,"name":"AdminTo","is_traversable":true},{"id":3,"name":"LLMHound_CanExecuteOn","is_traversable":true}]}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v2/extensions":
			b, _ := io.ReadAll(r.Body)
			registeredSchema.Store(string(b))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/graphs/cypher":
			var req struct {
				Query string `json:"query"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &req)
			if strings.Contains(req.Query, "LIMIT 1") {
				_, _ = w.Write([]byte(`{"data":{"nodes":{"1":{"objectId":"PROBE","kinds":["Computer"]}}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"nodes":{
				"1":{"objectId":"S-1-5-21-EXISTS","kinds":["Computer"]},
				"2":{"objectId":"S-1-5-21-STUB","kinds":[]}
			}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"id":%d}}`, len(uploadedFiles)+1)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/1":
			b, _ := io.ReadAll(r.Body)
			uploadedFiles = append(uploadedFiles, b)
			uploadedFileNames = append(uploadedFileNames, r.Header.Get("X-File-Upload-Name"))
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/2":
			b, _ := io.ReadAll(r.Body)
			uploadedFiles = append(uploadedFiles, b)
			uploadedFileNames = append(uploadedFileNames, r.Header.Get("X-File-Upload-Name"))
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/end"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/file-upload":
			_, _ = w.Write([]byte(`{"data":[{"id":1,"status":2},{"id":2,"status":2}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/completed-tasks"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			_, _ = w.Write([]byte(`{"data":[{"id":42,"name":"LLMHound_Old","description":"old","query":"MATCH (n) RETURN n"}]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/saved-queries/42":
			deletedIDs = append(deletedIDs, 42)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries/import":
			importedZip, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ce.Close()

	// 1. --validate-only passes on v9.7.1
	out, err := execute("upload", "--url", ce.URL, "--bearer-token", "tok", "--validate-only")
	if err != nil {
		t.Fatalf("--validate-only failed: %q %v", out, err)
	}
	if !strings.Contains(out, "adapter gate passed") {
		t.Fatalf("unexpected validate-only output: %q", out)
	}

	// 2. Write base and linking payloads and upload with --register-schema --enable-rules-schema --import-queries
	basePayload := emitter.Payload{
		Metadata: &emitter.Metadata{SourceKind: "LLMHound"},
		Graph: emitter.GraphPayload{
			Nodes: []emitter.NodePayload{{
				ID:         "svc-1",
				Kinds:      []string{"LLMHound_JupyterServer", "LLMHound_AIService"},
				Properties: map[string]any{"name": "jup", "deployment_scope": "s"},
			}},
		},
	}
	linkPayload := emitter.Payload{
		Graph: emitter.GraphPayload{
			Edges: []emitter.EdgePayload{
				{
					Kind:  "LLMHound_HostedOn",
					Start: emitter.EndpointPayload{MatchBy: "id", Value: "svc-1"},
					End:   emitter.EndpointPayload{MatchBy: "id", Value: "S-1-5-21-EXISTS"},
				},
				{
					Kind:  "LLMHound_HostedOn",
					Start: emitter.EndpointPayload{MatchBy: "id", Value: "svc-1"},
					End:   emitter.EndpointPayload{MatchBy: "id", Value: "S-1-5-21-STUB"},
				},
				{
					Kind:  "LLMHound_HostedOn",
					Start: emitter.EndpointPayload{MatchBy: "id", Value: "svc-1"},
					End:   emitter.EndpointPayload{MatchBy: "id", Value: "S-1-5-21-MISSING"},
				},
			},
		},
	}
	baseBytes, _ := json.Marshal(basePayload)
	linkBytes, _ := json.Marshal(linkPayload)
	if err := os.WriteFile("base.json", baseBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("link.json", linkBytes, 0600); err != nil {
		t.Fatal(err)
	}

	out, err = execute(
		"upload",
		"--url", ce.URL,
		"--bearer-token", "tok",
		"--register-schema",
		"--enable-rules-schema",
		"--base-file", "base.json",
		"--linking-file", "link.json",
		"--import-queries",
		"--include-can-execute-on",
		"--poll-interval", "1ms",
	)
	if err != nil {
		t.Fatalf("full upload failed: %q %v", out, err)
	}

	schemaRaw, _ := registeredSchema.Load().(string)
	if !strings.Contains(schemaRaw, `"LLMHound_CanExecuteOn"`) || !strings.Contains(schemaRaw, `"is_traversable": true`) {
		t.Fatalf("expected rules schema with traversable CanExecuteOn, got: %s", schemaRaw)
	}
	if len(uploadedFiles) != 2 {
		t.Fatalf("expected 2 uploaded files (base + filtered linking), got %d", len(uploadedFiles))
	}
	if !strings.Contains(string(uploadedFiles[0]), `"source_kind":"LLMHound"`) {
		t.Fatalf("first upload must contain source_kind")
	}
	if strings.Contains(string(uploadedFiles[1]), `"source_kind"`) {
		t.Fatalf("linking upload must NOT contain source_kind: %s", uploadedFiles[1])
	}
	if !strings.Contains(string(uploadedFiles[1]), "S-1-5-21-EXISTS") ||
		strings.Contains(string(uploadedFiles[1]), "S-1-5-21-STUB") ||
		strings.Contains(string(uploadedFiles[1]), "S-1-5-21-MISSING") {
		t.Fatalf("pre-flight filtering mismatch in linking payload: %s", uploadedFiles[1])
	}
	if len(deletedIDs) != 1 || deletedIDs[0] != 42 {
		t.Fatalf("expected existing LLMHound query to be deleted before import, got %v", deletedIDs)
	}
	if len(importedZip) == 0 {
		t.Fatal("expected non-empty saved queries zip import")
	}
	if !strings.Contains(out, "Imported 15 saved queries") {
		t.Fatalf("expected 15 imported saved queries, got: %q", out)
	}

	// 3. Unpinned CE version fails closed unless --allow-unvalidated-ce is set.
	serverVersion.Store("v9.8.0")
	_, err = execute("upload", "--url", ce.URL, "--bearer-token", "tok", "--validate-only")
	if err == nil || !strings.Contains(err.Error(), "v9.7.1") {
		t.Fatalf("expected version gate rejection on v9.8.0, got %v", err)
	}
	out, err = execute("upload", "--url", ce.URL, "--bearer-token", "tok", "--validate-only", "--allow-unvalidated-ce")
	if err != nil || !strings.Contains(out, "WARNING [version]") {
		t.Fatalf("expected warning with --allow-unvalidated-ce, got out=%q err=%v", out, err)
	}
}
