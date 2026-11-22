package litellm_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/litellm"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
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

func TestLiteLLMCollect_CompleteAndSecretsAndContent(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Ab3Cd7Ef1Gh5Ij9Kl2Mn6Op0Qr4St8")
	var mutated bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method != http.MethodGet:
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
		case r.URL.Path == "/openapi.json":
			w.Header().Set("X-LiteLLM-Version", "1.52.10")
			_, _ = w.Write([]byte(`{
				"info":{"title":"LiteLLM API","version":"0.1.0"},
				"paths":{
					"/v1/models":{},
					"/model/info":{},
					"/key/generate":{},
					"/key/list":{}
				}
			}`))
		case r.URL.Path == "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","owned_by":"openai","created":1700000000},{"id":"gpt-4o","owned_by":"openai"}]}`))
		case r.URL.Path == "/model/info":
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"data":[{
					"model_name":"gpt-4o",
					"litellm_params":{
						"model":"azure/gpt-4o",
						"api_base":"https://user:pass@backend.corp.internal:8443/v1?api-key=secret#frag",
						"api_key":"%s",
						"custom_llm_provider":"azure"
					},
					"model_info":{"id":"id-1","litellm_provider":"azure"}
				}]
			}`, tok)))
		case r.URL.Path == "/settings":
			w.WriteHeader(http.StatusNotFound)
		default:
			mutated = true
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := litellm.New(testConfig(srv.URL), litellm.WithContentSink(sink))
	obsTime := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", obsTime, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("mutating or forbidden endpoint was called")
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
		if n.Node.Identity().Kind() == graph.LiteLLMGateway {
			svcItem = n
		}
		if n.Node.Identity().Kind() == graph.AIModel {
			modelCount++
		}
	}
	if svcItem == nil {
		t.Fatal("missing LiteLLMGateway node")
	}
	if modelCount != 1 {
		t.Fatalf("model count = %d, want 1", modelCount)
	}
	props := svcItem.Properties
	if props["software_version"] != "1.52.10" || props["api_version"] != "0.1.0" {
		t.Errorf("versions mismatch: %+v", props)
	}
	if props["key_management_routes_advertised"] != true {
		t.Errorf("expected key_management_routes_advertised=true, got %v", props["key_management_routes_advertised"])
	}
	if props["auth_observed"] != "anonymous" {
		t.Errorf("auth_observed = %v, want anonymous", props["auth_observed"])
	}
	if !reflect.DeepEqual(props["anon_operations"], []string{"litellm_model_info", "litellm_models"}) {
		t.Errorf("anon_operations = %v", props["anon_operations"])
	}
	if !reflect.DeepEqual(props["backend_refs"], []string{"https://backend.corp.internal:8443/v1"}) {
		t.Errorf("backend_refs = %v (credentials/query/fragment must be stripped)", props["backend_refs"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true, got %v", props["has_exposed_secret"])
	}
	if !reflect.DeepEqual(props["secret_types"], []string{"github_token"}) {
		t.Errorf("secret_types = %v", props["secret_types"])
	}

	if len(sink.records) != 1 {
		t.Fatalf("expected 1 content record, got %d", len(sink.records))
	}
	if strings.Contains(sink.records[0].Body, tok) || !strings.Contains(sink.records[0].Body, "[secret:github_token]") {
		t.Fatalf("content record did not redact token: %s", sink.records[0].Body)
	}
	for _, ev := range res.Evidence {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), tok) {
			t.Fatalf("token leaked into evidence: %s", string(raw))
		}
	}
	rawNode, _ := json.Marshal(svcItem.Properties)
	if strings.Contains(string(rawNode), tok) {
		t.Fatalf("token leaked into node properties: %s", string(rawNode))
	}
}

func TestLiteLLMCollect_FailClosedOnGenericOpenAI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","owned_by":"openai"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	col := litellm.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("generic OpenAI endpoint must fail closed with 0 nodes; got coverage=%s nodes=%d", res.Observation.Coverage, len(res.Nodes))
	}
}

func TestLiteLLMCollect_DeniedAndPolicyAndTruncation(t *testing.T) {
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-LiteLLM-Version", "1.50.0")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"litellm proxy auth required"}`))
	}))
	defer deniedSrv.Close()

	col := litellm.New(testConfig(deniedSrv.URL))
	res, err := col.Collect(context.Background(), deniedSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoveragePartial {
		t.Fatalf("expected partial coverage on denied LiteLLM, got %s", res.Observation.Coverage)
	}
	if len(res.Nodes) == 0 || res.Nodes[0].Properties["auth_observed"] != "denied" {
		t.Fatalf("expected denied auth_observed on LiteLLMGateway")
	}

	// Content disabled + MaxItems truncation.
	truncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(`{"info":{"title":"LiteLLM Proxy","version":"1.0"},"paths":{"/v1/models":{}}}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m1"},{"id":"m2"},{"id":"m3"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer truncSrv.Close()

	cfg := testConfig(truncSrv.URL)
	cfg.Content.Surfaces = map[string]bool{"litellm": false}
	cfg.Bounds.MaxItems = 2
	sink := &memSink{}
	col2 := litellm.New(cfg, litellm.WithContentSink(sink))
	res2, err := col2.Collect(context.Background(), truncSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect trunc error: %v", err)
	}
	if res2.Observation.Coverage != graph.CoverageTruncated {
		t.Fatalf("expected truncated coverage, got %s", res2.Observation.Coverage)
	}
	if len(sink.records) != 0 {
		t.Fatalf("expected 0 content records when litellm content disabled")
	}
	var skippedContent bool
	for _, ev := range res2.Evidence {
		if ev.CheckID == litellm.CheckConfig && ev.Outcome == string(graph.OutcomeSkipped) {
			skippedContent = true
		}
	}
	if !skippedContent {
		t.Errorf("expected skipped litellm_config check record")
	}
}

func TestLiteLLMCollect_TLSFailureAndMappedTarget(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			_, _ = w.Write([]byte(`{"info":{"title":"LiteLLM API","version":"0.1.0"},"paths":{"/v1/models":{}}}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m1"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer tlsSrv.Close()

	colFail := litellm.New(testConfig(tlsSrv.URL))
	resFail, err := colFail.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS fail Collect error: %v", err)
	}
	if resFail.Observation.Coverage != graph.CoverageFailed || len(resFail.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection with 0 nodes")
	}

	cfg := testConfig(tlsSrv.URL)
	cfg.Insecure = true
	resolver, err := correlate.New([]correlate.Mapping{{Target: "127.0.0.1", ObjectID: "S-1-5-21-1-2-3-1103", Kind: graph.Computer}})
	if err != nil {
		t.Fatal(err)
	}
	colOk := litellm.New(cfg)
	resOk, err := colOk.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), resolver)
	if err != nil {
		t.Fatalf("insecure Collect error: %v", err)
	}
	var hasNativeObs bool
	for _, e := range resOk.Edges {
		if e.Kind() == graph.ObservedAt && e.TouchesNative() {
			hasNativeObs = true
		}
	}
	if !hasNativeObs {
		t.Errorf("expected native ObservedAt edge")
	}
	var hasTLS bool
	for _, ev := range resOk.Evidence {
		if ev.RecordType == evidence.RecordTLS {
			hasTLS = true
		}
	}
	if !hasTLS {
		t.Errorf("expected TLS evidence record")
	}
	_ = tls.VersionTLS13
}
