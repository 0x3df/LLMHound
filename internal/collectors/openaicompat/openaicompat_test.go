package openaicompat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/openaicompat"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

func testConfig(target string) config.Config {
	cfg := config.Defaults()
	cfg.Scope = "lab-scope"
	cfg.VantageKey = "scanner-a"
	cfg.Targets = []string{target}
	return cfg
}

func TestOpenAICompatCollect_SuccessAndHonestUnknownVersion(t *testing.T) {
	var mutated bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Server", "uvicorn")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"local-llama","owned_by":"organization-owner","created":1700000001}]}`))
	}))
	defer srv.Close()

	col := openaicompat.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("unexpected request")
	}
	if res.Observation.Coverage != graph.CoverageComplete || res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("coverage=%s status=%s", res.Observation.Coverage, res.Status)
	}

	var svcItem *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.OpenAICompatibleEndpoint {
			svcItem = &res.Nodes[i]
		}
	}
	if svcItem == nil {
		t.Fatal("missing OpenAICompatibleEndpoint node")
	}
	props := svcItem.Properties
	if props["software_version"] != nil {
		t.Errorf("software_version must stay unset, got %v", props["software_version"])
	}
	if props["server_header"] != "uvicorn" {
		t.Errorf("server_header = %v, want uvicorn", props["server_header"])
	}
	if !reflect.DeepEqual(props["anon_operations"], []string{"openai_compatible_models"}) {
		t.Errorf("anon_operations = %v", props["anon_operations"])
	}
	if props["exec_surface"] != nil {
		t.Errorf("exec_surface must be omitted, got %v", props["exec_surface"])
	}
}

func TestOpenAICompatCollect_RejectsVLLMAndMalformedAndTLS(t *testing.T) {
	vllmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"llama3","owned_by":"vllm"}]}`))
	}))
	defer vllmSrv.Close()

	col := openaicompat.New(testConfig(vllmSrv.URL))
	res, err := col.Collect(context.Background(), vllmSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("vLLM response should fail closed in generic collector")
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer tlsSrv.Close()
	colTLS := openaicompat.New(testConfig(tlsSrv.URL))
	resTLS, err := colTLS.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS Collect error: %v", err)
	}
	if resTLS.Observation.Coverage != graph.CoverageFailed || len(resTLS.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection")
	}
}
