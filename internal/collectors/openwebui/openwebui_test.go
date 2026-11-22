package openwebui_test

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
	"github.com/0x3df/LLMHound/internal/collectors/openwebui"
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

func TestOpenWebUICollect_CompleteAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Ef5Gh9Ij3Kl7Mn1Op5Qr9St3Uv7Wx1")
	var mutated bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.4.8"}`))
		case "/api/config":
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"status":true,
				"name":"Open WebUI",
				"version":"0.4.8",
				"features":{"auth":false,"enable_signup":true},
				"ollama_base_urls":["http://user:pass@ollama.internal:11434?token=1"],
				"openai_api_base_urls":["https://api.corp.internal/v1"],
				"extra_secret":"%s"
			}`, tok)))
		case "/api/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"llama3:latest","name":"Llama 3","owned_by":"ollama"},{"id":"gpt-4o","name":"GPT-4o","owned_by":"openai"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := openwebui.New(testConfig(srv.URL), openwebui.WithContentSink(sink))
	obsTime := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", obsTime, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("mutating request made")
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s), want complete", res.Observation.Coverage, res.Observation.CoverageReason)
	}
	if res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}

	var svcItem *emitter.NodeItem
	var modelCount int
	for i := range res.Nodes {
		n := &res.Nodes[i]
		if n.Node.Identity().Kind() == graph.OpenWebUIInstance {
			svcItem = n
		}
		if n.Node.Identity().Kind() == graph.AIModel {
			modelCount++
		}
	}
	if svcItem == nil {
		t.Fatal("missing OpenWebUIInstance node")
	}
	if modelCount != 2 {
		t.Fatalf("model count = %d, want 2", modelCount)
	}
	props := svcItem.Properties
	if props["software_version"] != "0.4.8" {
		t.Errorf("software_version = %v, want 0.4.8", props["software_version"])
	}
	if props["auth_advertised"] != "none" || props["signup_enabled"] != true {
		t.Errorf("auth/signup mismatch: %+v", props)
	}
	if props["auth_observed"] != "anonymous" {
		t.Errorf("auth_observed = %v, want anonymous", props["auth_observed"])
	}
	if !reflect.DeepEqual(props["anon_operations"], []string{"open_webui_models"}) {
		t.Errorf("anon_operations = %v", props["anon_operations"])
	}
	if !reflect.DeepEqual(props["exec_surface"], []string{graph.ExecCodeEval}) || props["exec_surface_basis"] != graph.BasisInferred {
		t.Errorf("exec_surface = %v (%v), want [code_eval] (inferred)", props["exec_surface"], props["exec_surface_basis"])
	}
	if !reflect.DeepEqual(props["backend_refs"], []string{"http://ollama.internal:11434", "https://api.corp.internal/v1"}) {
		t.Errorf("backend_refs = %v", props["backend_refs"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}
	if len(sink.records) != 1 || strings.Contains(sink.records[0].Body, tok) || !strings.Contains(sink.records[0].Body, "[secret:github_token]") {
		t.Fatalf("content record did not redact token: %+v", sink.records)
	}
	rawProps, _ := json.Marshal(props)
	if strings.Contains(string(rawProps), tok) || strings.Contains(string(rawProps), "user:pass") {
		t.Fatalf("secret leaked into properties: %s", string(rawProps))
	}
}

func TestOpenWebUICollect_FailClosedOnOllamaVersionOnly(t *testing.T) {
	// Ollama also serves {"version": "0.3.12"} at /api/version. Without Open WebUI
	// config/headers, Open WebUI must fail closed!
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	col := openwebui.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("expected failed coverage and 0 nodes on Ollama-like /api/version alone")
	}
}

func TestOpenWebUICollect_DeniedAndOptOutAndTLS(t *testing.T) {
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "open-webui")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"open-webui auth required"}`))
	}))
	defer deniedSrv.Close()

	col := openwebui.New(testConfig(deniedSrv.URL))
	res, err := col.Collect(context.Background(), deniedSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoveragePartial || len(res.Nodes) == 0 || res.Nodes[0].Properties["auth_observed"] != "denied" {
		t.Fatalf("expected partial denied OpenWebUIInstance")
	}

	// TLS failure stops collection.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"Open WebUI","features":{"auth":true}}`))
	}))
	defer tlsSrv.Close()
	colTLS := openwebui.New(testConfig(tlsSrv.URL))
	resTLS, err := colTLS.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS Collect error: %v", err)
	}
	if resTLS.Observation.Coverage != graph.CoverageFailed || len(resTLS.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection with 0 nodes")
	}
}

func TestOpenWebUICollect_EntraOIDCAndAuthRequiredNoExecSurface(t *testing.T) {
	tenant := "11111111-2222-3333-4444-555555555555"
	client := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.4.8"}`))
		case "/api/config":
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"status":true,
				"name":"Open WebUI",
				"version":"0.4.8",
				"features":{"auth":true},
				"oauth":{"providers":{"microsoft":"Microsoft"},"microsoft_tenant_id":"%s","microsoft_client_id":"%s"}
			}`, tenant, client)))
		case "/api/models":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	col := openwebui.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	var svcItem *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.OpenWebUIInstance {
			svcItem = &res.Nodes[i]
		}
	}
	if svcItem == nil {
		t.Fatal("missing OpenWebUIInstance node")
	}
	props := svcItem.Properties
	if _, hasExec := props["exec_surface"]; hasExec {
		t.Errorf("auth=true instance must not claim exec_surface: %+v", props["exec_surface"])
	}
	if props["entra_tenant_id"] != tenant || props["entra_client_id"] != strings.ToUpper(client) {
		t.Errorf("entra props = (%v, %v), want (%s, %s)", props["entra_tenant_id"], props["entra_client_id"], tenant, strings.ToUpper(client))
	}
}
