package langflow_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/langflow"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
)

type memSink struct {
	records []content.Record
}

func (m *memSink) Write(r content.Record) error {
	m.records = append(m.records, r)
	return nil
}

func testConfig(target string) config.Config {
	cfg := config.Defaults()
	cfg.Scope = "lab-scope"
	cfg.VantageKey = "scanner-a"
	cfg.Targets = []string{target}
	return cfg
}

func TestLangflowCollect_CompleteAndNeverRetainsAutoLoginTokens(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Kl8Mn2Op6Qr0St4Uv8Wx2Yz6Ab0Cd4")
	const syntheticJWT = "SYNTHETIC_ACCESS_TOKEN_MUST_NOT_APPEAR"
	var mutated bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			strings.HasPrefix(r.URL.Path, "/api/v1/validate/code") ||
			strings.HasPrefix(r.URL.Path, "/api/v1/run") {
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`))
		case "/api/v1/auto_login":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"access_token":"%s","refresh_token":"REFRESH_MUST_NOT_APPEAR","token_type":"bearer"}`, syntheticJWT)))
		case "/api/v1/flows/":
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":"flow-1","name":"Agent Flow","data":{"nodes":[{"id":"n1","token":"%s"}]}}]`, tok)))
		case "/api/v1/all":
			_, _ = w.Write([]byte(`{"agents":{"AgentExecutor":{}},"tools":{"PythonREPLTool":{}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := langflow.New(testConfig(srv.URL), langflow.WithContentSink(sink))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("mutating endpoint called")
	}
	if res.Observation.Coverage != graph.CoverageComplete || res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("coverage=%s (%s) status=%s", res.Observation.Coverage, res.Observation.CoverageReason, res.Status)
	}

	var svcItem *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.LangflowInstance {
			svcItem = &res.Nodes[i]
		}
	}
	if svcItem == nil {
		t.Fatal("missing LangflowInstance node")
	}
	props := svcItem.Properties
	if props["software_version"] != "1.0.19" {
		t.Errorf("software_version = %v", props["software_version"])
	}
	if props["auto_login_enabled"] != true || props["auth_advertised"] != "none" {
		t.Errorf("auto_login/auth_advertised mismatch: %+v", props)
	}
	if props["flow_count"] != 1 || props["component_count"] != 2 {
		t.Errorf("counts mismatch: %+v", props)
	}
	if !reflect.DeepEqual(props["exec_surface"], []string{graph.ExecCodeEval, graph.ExecWorkflowExec}) {
		t.Errorf("exec_surface = %v", props["exec_surface"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}

	// Ensure auto_login token and flow secret never appear anywhere in result or content sink.
	rawRes, _ := json.Marshal(res)
	if strings.Contains(string(rawRes), syntheticJWT) || strings.Contains(string(rawRes), "REFRESH_MUST_NOT_APPEAR") || strings.Contains(string(rawRes), tok) {
		t.Fatalf("token leaked into checkpoint result")
	}
	for _, r := range sink.records {
		if strings.Contains(r.Body, syntheticJWT) || strings.Contains(r.Body, tok) {
			t.Fatalf("token leaked into content record")
		}
	}
}

func TestLangflowCollect_AutoLoginDisabledAndTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`))
		case "/api/v1/auto_login":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"auto login is disabled"}`))
		case "/api/v1/flows/":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/v1/all":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	col := langflow.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoveragePartial || len(res.Nodes) == 0 {
		t.Fatalf("expected partial coverage with LangflowInstance node")
	}
	if res.Nodes[0].Properties["auto_login_enabled"] != false || res.Nodes[0].Properties["auth_observed"] != "denied" {
		t.Errorf("unexpected props: %+v", res.Nodes[0].Properties)
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.0.19","package":"Langflow"}`))
	}))
	defer tlsSrv.Close()
	colTLS := langflow.New(testConfig(tlsSrv.URL))
	resTLS, err := colTLS.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS Collect error: %v", err)
	}
	if resTLS.Observation.Coverage != graph.CoverageFailed || len(resTLS.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection")
	}
}
