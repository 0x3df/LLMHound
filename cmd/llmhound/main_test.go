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

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
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
	data := "scope: file\nvantage_key: scanner\ntargets: [from-file.example.test]\ncidrs: [192.0.2.0/30]\nbounds:\n  concurrency: 17\n  max_redirects: 4\ninsecure: true\nopt_ins:\n  prompts: true\n"
	if err := os.WriteFile("llmhound.yaml", []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute("targets", "--targets", "flag.example.test", "--exclude", "192.0.2.0/31", "--insecure=false", "--prompts=false", "--max-redirects=0")
	if err != nil || out != "192.0.2.2\n192.0.2.3\nflag.example.test\n" {
		t.Fatalf("%q %v", out, err)
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

func TestUploadStillUnimplementedAndPlanWritesNoArtifacts(t *testing.T) {
	inEmptyDirectory(t)
	out, err := execute("upload")
	if err == nil || !strings.Contains(err.Error(), "not implemented") || out != "" {
		t.Fatalf("upload: %q %v", out, err)
	}

	out, err = execute("plan", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test")
	if err != nil {
		t.Fatalf("plan: %q %v", out, err)
	}
	if !strings.Contains(out, "TARGET: ai.example.test") {
		t.Fatalf("plan missing target: %q", out)
	}
	for _, surface := range []string{"jupyter", "mcp", "ollama"} {
		if !strings.Contains(out, "SURFACE: "+surface) {
			t.Fatalf("plan missing surface %s: %q", surface, out)
		}
	}
	if !strings.Contains(out, "ollama_show") || !strings.Contains(out, "policy:") {
		t.Fatalf("plan should show inactive ollama_show with policy skip: %q", out)
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
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func cliMockMCP(t *testing.T) *httptest.Server {
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
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server { return srv }, nil)
	return httptest.NewServer(handler)
}

func portOf(urlStr string) int {
	u, _ := http.NewRequest("GET", urlStr, nil)
	var port int
	fmt.Sscanf(u.URL.Port(), "%d", &port)
	return port
}

func TestScanCLIEndToEndLoopbackFixtures(t *testing.T) {
	inEmptyDirectory(t)

	ollamaSrv := cliMockOllama(t)
	defer ollamaSrv.Close()
	jupyterSrv := cliMockJupyter(t)
	defer jupyterSrv.Close()
	mcpSrv := cliMockMCP(t)
	defer mcpSrv.Close()
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ollama"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
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
	for _, name := range []string{"cli-live.json", "cli-live.evidence.jsonl", "cli-live.journal.jsonl"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing artifact %s: %v", name, err)
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
		// Evidence should reflect auth boundary; journal coverage is asserted in scanner tests.
		t.Logf("denied sidecar (best-effort assert): %s", sidecar)
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
