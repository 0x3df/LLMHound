package discovery_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/discovery"
)

func TestJupyterDefinitionMatch(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		path       string
		wantMatch  bool
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
