package discovery_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/discovery"
)

func TestJupyterDefinitionMatch(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		path      string
		wantMatch bool
	}{
		{
			name: "api version json response",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"version": "2.14.0", "jupyter_server_version": "2.14.0"}`))
			},
			wantMatch: true,
		},
		{
			name: "api status json response",
			path: "/api/status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"started": "2026-10-01T12:00:00Z", "kernels": 2, "connections": 1}`))
			},
			wantMatch: true,
		},
		{
			name: "generic tornado server is not jupyter",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "TornadoServer/6.3.3")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`ok`))
			},
			wantMatch: false,
		},
		{
			name: "unauthorized with jupyter keyword",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message": "Jupyter authentication required"}`))
			},
			wantMatch: true,
		},
		{
			name: "login redirect",
			path: "/tree",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/login?next=%2Ftree")
				w.WriteHeader(http.StatusFound)
			},
			wantMatch: true,
		},
		{
			name: "generic version json is not jupyter",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version": "1.2"}`))
			},
			wantMatch: false,
		},
		{
			name: "generic auth error is not jupyter",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error": "authentication required: missing token"}`))
			},
			wantMatch: false,
		},
		{
			name: "x-jupyter-version header",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Jupyter-Version", "2.14.0")
				w.WriteHeader(http.StatusForbidden)
			},
			wantMatch: true,
		},
		{
			name: "generic login redirect is not jupyter",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/login")
				w.WriteHeader(http.StatusFound)
			},
			wantMatch: false,
		},
		{
			name: "non-jupyter generic 404",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`404 page not found`))
			},
			wantMatch: false,
		},
		{
			name: "other service response",
			path: "/api",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`hello world`))
			},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			def := discovery.JupyterDefinition()
			// Override probe paths to single path for targeted unit testing
			def.ProbePaths = []string{tc.path}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := discovery.Probe(ctx, server.Client(), server.URL, def)
			if err != nil {
				t.Fatalf("Probe failed: %v", err)
			}
			if res.Matched != tc.wantMatch {
				t.Errorf("got matched=%v, want=%v", res.Matched, tc.wantMatch)
			}
			if res.Matched && res.Surface != discovery.SurfaceJupyter {
				t.Errorf("got surface=%v, want=%v", res.Surface, discovery.SurfaceJupyter)
			}
		})
	}
}

func TestOllamaDefinitionMatch(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		path      string
		wantMatch bool
	}{
		{
			name: "api version json",
			path: "/api/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"version": "0.3.12"}`))
			},
			wantMatch: true,
		},
		{
			name: "api tags json",
			path: "/api/tags",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"models": [{"name": "llama3:latest"}]}`))
			},
			wantMatch: true,
		},
		{
			name: "root banner",
			path: "/",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`Ollama is running`))
			},
			wantMatch: true,
		},
		{
			name: "server header",
			path: "/api/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "ollama/0.3.12")
				w.WriteHeader(http.StatusOK)
			},
			wantMatch: true,
		},
		{
			name: "denied with ollama body",
			path: "/api/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error": "ollama authentication required"}`))
			},
			wantMatch: true,
		},
		{
			name: "non-ollama 404",
			path: "/api/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`not found`))
			},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			def := discovery.OllamaDefinition()
			def.ProbePaths = []string{tc.path}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := discovery.Probe(ctx, server.Client(), server.URL, def)
			if err != nil {
				t.Fatalf("Probe failed: %v", err)
			}
			if res.Matched != tc.wantMatch {
				t.Errorf("got matched=%v, want=%v", res.Matched, tc.wantMatch)
			}
			if res.Matched && res.Surface != discovery.SurfaceOllama {
				t.Errorf("got surface=%v, want=%v", res.Surface, discovery.SurfaceOllama)
			}
		})
	}
}

func TestMCPDefinitionMatch(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		path      string
		wantMatch bool
	}{
		{
			name: "sse text/event-stream header",
			path: "/sse",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
			},
			wantMatch: true,
		},
		{
			name: "mcp session id header",
			path: "/mcp",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Mcp-Session-Id", "sess-12345")
				w.WriteHeader(http.StatusOK)
			},
			wantMatch: true,
		},
		{
			name: "oauth protected resource metadata",
			path: "/.well-known/oauth-protected-resource",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"resource": "https://mcp.corp", "authorization_servers": ["https://auth.corp"]}`))
			},
			wantMatch: true,
		},
		{
			name: "jsonrpc body",
			path: "/mcp",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jsonrpc": "2.0", "result": {}}`))
			},
			wantMatch: true,
		},
		{
			name: "generic html is not mcp",
			path: "/mcp",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<html><body>Hello</body></html>`))
			},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			def := discovery.MCPDefinition()
			def.ProbePaths = []string{tc.path}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := discovery.Probe(ctx, server.Client(), server.URL, def)
			if err != nil {
				t.Fatalf("Probe failed: %v", err)
			}
			if res.Matched != tc.wantMatch {
				t.Errorf("got matched=%v, want=%v", res.Matched, tc.wantMatch)
			}
			if res.Matched && res.Surface != discovery.SurfaceMCP {
				t.Errorf("got surface=%v, want=%v", res.Surface, discovery.SurfaceMCP)
			}
		})
	}
}

func TestBuiltinDefinitions(t *testing.T) {
	defs := discovery.BuiltinDefinitions()
	if len(defs) != 15 {
		t.Fatalf("expected 15 builtin definitions, got %d", len(defs))
	}
	if defs[len(defs)-1].Surface != discovery.SurfaceOpenAICompatible {
		t.Fatalf("last builtin definition must be %s, got %s", discovery.SurfaceOpenAICompatible, defs[len(defs)-1].Surface)
	}

	seen := make(map[discovery.Surface]bool)
	for _, d := range defs {
		seen[d.Surface] = true
		if d.DefaultPort <= 0 {
			t.Errorf("surface %s has invalid default port %d", d.Surface, d.DefaultPort)
		}
		if len(d.ProbePaths) == 0 {
			t.Errorf("surface %s has no probe paths", d.Surface)
		}
		if d.Match == nil {
			t.Errorf("surface %s has nil Match", d.Surface)
		}
	}

	for _, s := range []discovery.Surface{
		discovery.SurfaceJupyter, discovery.SurfaceOllama, discovery.SurfaceMCP,
		discovery.SurfaceA2A, discovery.SurfaceVLLM, discovery.SurfaceQdrant,
		discovery.SurfaceLiteLLM, discovery.SurfaceMLflow, discovery.SurfaceOpenWebUI, discovery.SurfaceLangServe,
		discovery.SurfaceRay, discovery.SurfaceLangflow, discovery.SurfaceFlowise,
		discovery.SurfaceChromaDB, discovery.SurfaceOpenAICompatible,
	} {
		if !seen[s] {
			t.Errorf("expected surface %s in builtin definitions", s)
		}
		def, ok := discovery.DefinitionForSurface(s)
		if !ok || def.Surface != s {
			t.Errorf("DefinitionForSurface(%s) failed", s)
		}
	}
}

func TestProbeHostAndLoadDefinitions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "0.3.12"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Parse server port
	u, _ := http.NewRequest("GET", server.URL, nil)
	host := u.URL.Hostname()
	port := 11434
	if p := u.URL.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	def := discovery.OllamaDefinition()
	def.DefaultPort = port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := discovery.ProbeHost(ctx, server.Client(), host, def, false)
	if err != nil {
		t.Fatalf("ProbeHost failed: %v", err)
	}
	if !res.Matched || res.Surface != discovery.SurfaceOllama {
		t.Errorf("ProbeHost got %+v, want match for ollama", res)
	}

	// Test LoadDefinitions
	jsonData := []byte(fmt.Sprintf(`[
		{"surface": "ollama", "default_port": %d, "probe_paths": ["/api/version"]},
		{"surface": "jupyter", "default_port": 8888, "probe_paths": ["/api"]}
	]`, port))

	customDefs, err := discovery.LoadDefinitions(jsonData)
	if err != nil {
		t.Fatalf("LoadDefinitions failed: %v", err)
	}
	if len(customDefs) != 2 {
		t.Fatalf("expected 2 custom definitions, got %d", len(customDefs))
	}
	if customDefs[0].DefaultPort != port {
		t.Errorf("custom def port %d, want %d", customDefs[0].DefaultPort, port)
	}

	// Invalid JSON
	if _, err := discovery.LoadDefinitions([]byte(`invalid`)); err == nil {
		t.Error("expected error for invalid json")
	}
	// Empty array
	if _, err := discovery.LoadDefinitions([]byte(`[]`)); err == nil {
		t.Error("expected error for empty definitions array")
	}
	// Missing surface
	if _, err := discovery.LoadDefinitions([]byte(`[{"default_port": 1234}]`)); err == nil {
		t.Error("expected error for missing surface")
	}
}

func TestProbeReturnsContextErrorOnCancellation(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := discovery.Probe(ctx, nil, srv.URL, discovery.OllamaDefinition())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled (result %+v)", err, res)
	}
}

func TestA2AVLLMQdrantDefinitionsMatch(t *testing.T) {
	tests := []struct {
		name      string
		def       discovery.Definition
		path      string
		handler   http.HandlerFunc
		wantMatch bool
	}{
		{
			name: "a2a agent card json",
			def:  discovery.A2ADefinition(),
			path: "/.well-known/agent-card.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"name":"Agent","skills":[{"id":"s1"}]}`))
			},
			wantMatch: true,
		},
		{
			name: "a2a generic json not matched",
			def:  discovery.A2ADefinition(),
			path: "/.well-known/agent-card.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"name":"GenericApp"}`))
			},
			wantMatch: false,
		},
		{
			name: "vllm models owned_by vllm",
			def:  discovery.VLLMDefinition(),
			path: "/v1/models",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama3","owned_by":"vllm"}]}`))
			},
			wantMatch: true,
		},
		{
			name: "vllm version json",
			def:  discovery.VLLMDefinition(),
			path: "/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"0.6.4"}`))
			},
			wantMatch: true,
		},
		{
			name: "vllm rejects generic openai models",
			def:  discovery.VLLMDefinition(),
			path: "/v1/models",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","owned_by":"openai"}]}`))
			},
			wantMatch: false,
		},
		{
			name: "qdrant root banner",
			def:  discovery.QdrantDefinition(),
			path: "/",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"title":"qdrant - vector search engine","version":"1.12.5"}`))
			},
			wantMatch: true,
		},
		{
			name: "qdrant collections json",
			def:  discovery.QdrantDefinition(),
			path: "/collections",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"result":{"collections":[]},"status":"ok"}`))
			},
			wantMatch: true,
		},
		{
			name: "qdrant rejects generic html",
			def:  discovery.QdrantDefinition(),
			path: "/",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`<html>welcome</html>`))
			},
			wantMatch: false,
		},
		{
			name: "litellm openapi",
			def:  discovery.LiteLLMDefinition(),
			path: "/openapi.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"info":{"title":"LiteLLM API","version":"0.1.0"},"paths":{"/v1/models":{}}}`))
			},
			wantMatch: true,
		},
		{
			name: "litellm rejects generic openai models",
			def:  discovery.LiteLLMDefinition(),
			path: "/v1/models",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","owned_by":"openai"}]}`))
			},
			wantMatch: false,
		},
		{
			name: "mlflow experiments",
			def:  discovery.MLflowDefinition(),
			path: "/api/2.0/mlflow/experiments/search?max_results=1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"experiments":[]}`))
			},
			wantMatch: true,
		},
		{
			name: "open_webui config",
			def:  discovery.OpenWebUIDefinition(),
			path: "/api/config",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"status":true,"name":"Open WebUI","features":{"auth":true}}`))
			},
			wantMatch: true,
		},
		{
			name: "langserve openapi runnable routes",
			def:  discovery.LangServeDefinition(),
			path: "/openapi.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"info":{"title":"App","version":"1.0"},"paths":{"/chain/invoke":{},"/chain/input_schema":{}}}`))
			},
			wantMatch: true,
		},
		{
			name: "langserve rejects generic fastapi",
			def:  discovery.LangServeDefinition(),
			path: "/openapi.json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/health":{}}}`))
			},
			wantMatch: false,
		},
		{
			name: "ray version",
			def:  discovery.RayDefinition(),
			path: "/api/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"0.8.0","ray_version":"2.37.0","ray_commit":"abc"}`))
			},
			wantMatch: true,
		},
		{
			name: "ray rejects ollama version",
			def:  discovery.RayDefinition(),
			path: "/api/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
			},
			wantMatch: false,
		},
		{
			name: "langflow version",
			def:  discovery.LangflowDefinition(),
			path: "/api/v1/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`))
			},
			wantMatch: true,
		},
		{
			name: "flowise rejects langflow version",
			def:  discovery.FlowiseDefinition(),
			path: "/api/v1/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`))
			},
			wantMatch: false,
		},
		{
			name: "flowise version",
			def:  discovery.FlowiseDefinition(),
			path: "/api/v1/version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"version":"2.1.4"}`))
			},
			wantMatch: true,
		},
		{
			name: "chromadb heartbeat",
			def:  discovery.ChromaDBDefinition(),
			path: "/api/v2/heartbeat",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"nanosecond heartbeat":1700000000}`))
			},
			wantMatch: true,
		},
		{
			name: "openai_compatible matches generic models",
			def:  discovery.OpenAICompatibleDefinition(),
			path: "/v1/models",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"local-llm","owned_by":"custom"}]}`))
			},
			wantMatch: true,
		},
		{
			name: "openai_compatible rejects vllm models",
			def:  discovery.OpenAICompatibleDefinition(),
			path: "/v1/models",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama3","owned_by":"vllm"}]}`))
			},
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			def := tc.def
			def.ProbePaths = []string{tc.path}
			res, err := discovery.Probe(context.Background(), srv.Client(), srv.URL, def)
			if err != nil {
				t.Fatalf("Probe failed: %v", err)
			}
			if res.Matched != tc.wantMatch {
				t.Fatalf("got matched=%v, want=%v", res.Matched, tc.wantMatch)
			}
		})
	}
}
