package langserve_test

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
	"github.com/0x3df/LLMHound/internal/collectors/langserve"
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

func TestLangServeCollect_CompleteNeverInvokesAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Gh6Ij0Kl4Mn8Op2Qr6St0Uv4Wx8Yz2")
	var invoked bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			strings.HasSuffix(r.URL.Path, "/invoke") ||
			strings.HasSuffix(r.URL.Path, "/batch") ||
			strings.HasSuffix(r.URL.Path, "/stream") ||
			strings.HasSuffix(r.URL.Path, "/stream_log") {
			invoked = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(`{
				"info":{"title":"LangChain Server","version":"1.0"},
				"paths":{
					"/chain/invoke":{},
					"/chain/batch":{},
					"/chain/stream":{},
					"/chain/input_schema":{},
					"/chain/output_schema":{},
					"/chain/config_schema":{},
					"/chain/playground":{}
				}
			}`))
		case "/chain/input_schema":
			_, _ = w.Write([]byte(`{"type":"object","properties":{"topic":{"type":"string"}}}`))
		case "/chain/output_schema":
			_, _ = w.Write([]byte(`{"type":"string"}`))
		case "/chain/config_schema":
			_, _ = w.Write([]byte(fmt.Sprintf(`{"type":"object","default":{"token":"%s"}}`, tok)))
		case "/chain/playground/":
			_, _ = w.Write([]byte(`<html><title>LangServe Playground</title></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := langserve.New(testConfig(srv.URL), langserve.WithContentSink(sink))
	obsTime := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", obsTime, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if invoked {
		t.Fatal("invoke/batch/stream endpoint or non-GET method was called")
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s), want complete", res.Observation.Coverage, res.Observation.CoverageReason)
	}
	if res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("status = %s, want completed", res.Status)
	}

	var svcItem *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.LangServeApp {
			svcItem = &res.Nodes[i]
		}
	}
	if svcItem == nil {
		t.Fatal("missing LangServeApp node")
	}
	props := svcItem.Properties
	if props["api_version"] != "1.0" {
		t.Errorf("api_version = %v, want 1.0", props["api_version"])
	}
	// OpenAPI info.version must NOT be assumed to be software_version.
	if props["software_version"] != nil {
		t.Errorf("software_version must stay unset without package header/field, got %v", props["software_version"])
	}
	if props["runnable_count"] != 1 {
		t.Errorf("runnable_count = %v, want 1", props["runnable_count"])
	}
	if !reflect.DeepEqual(props["runnable_routes"], []string{"/chain"}) {
		t.Errorf("runnable_routes = %v", props["runnable_routes"])
	}
	if props["playground_exposed"] != true {
		t.Errorf("playground_exposed = %v, want true", props["playground_exposed"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}
	if len(sink.records) != 3 {
		t.Fatalf("expected 3 schema content records, got %d", len(sink.records))
	}
	for _, r := range sink.records {
		if strings.Contains(r.Body, tok) {
			t.Fatalf("secret leaked into content record")
		}
	}
	rawProps, _ := json.Marshal(props)
	if strings.Contains(string(rawProps), tok) {
		t.Fatalf("secret leaked into node properties")
	}
}

func TestLangServeCollect_FailClosedOnGenericFastAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(`{"info":{"title":"FastAPI","version":"0.1.0"},"paths":{"/health":{}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	col := langserve.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("generic FastAPI must fail closed with 0 nodes")
	}
}

func TestLangServeCollect_TLSFailure(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"title":"LangServe","version":"1.0"},"paths":{}}`))
	}))
	defer tlsSrv.Close()

	col := langserve.New(testConfig(tlsSrv.URL))
	res, err := col.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection with 0 nodes")
	}
}
