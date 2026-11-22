package flowise_test

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
	"github.com/0x3df/LLMHound/internal/collectors/flowise"
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

func TestFlowiseCollect_CompleteAndNeverPredictsAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Mn9Op3Qr7St1Uv5Wx9Yz3Ab7Cd1Ef5")
	var mutated bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || strings.HasPrefix(r.URL.Path, "/api/v1/prediction") {
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version":"2.1.4"}`))
		case "/api/v1/chatflows":
			_, _ = w.Write([]byte(fmt.Sprintf(`[
				{"id":"cf-1","name":"Support Bot","deployed":true,"isPublic":true,"type":"CHATFLOW","flowData":"{\"nodes\":[{\"token\":\"%s\"}]}"},
				{"id":"cf-2","name":"Internal Flow","deployed":false,"isPublic":false,"type":"CHATFLOW","flowData":"{}"}
			]`, tok)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := flowise.New(testConfig(srv.URL), flowise.WithContentSink(sink))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("prediction endpoint or non-GET called")
	}
	if res.Observation.Coverage != graph.CoverageComplete || res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("coverage=%s status=%s", res.Observation.Coverage, res.Status)
	}

	var svcItem *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.FlowiseInstance {
			svcItem = &res.Nodes[i]
		}
	}
	if svcItem == nil {
		t.Fatal("missing FlowiseInstance node")
	}
	props := svcItem.Properties
	if props["software_version"] != "2.1.4" || props["chatflow_count"] != 2 || props["public_chatflow_count"] != 1 {
		t.Errorf("unexpected props: %+v", props)
	}
	if !reflect.DeepEqual(props["exec_surface"], []string{graph.ExecWorkflowExec}) {
		t.Errorf("exec_surface = %v", props["exec_surface"])
	}
	if !reflect.DeepEqual(props["anon_operations"], []string{"flowise_chatflows"}) {
		t.Errorf("anon_operations = %v", props["anon_operations"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}
	if len(sink.records) != 2 {
		t.Fatalf("expected 2 content records, got %d", len(sink.records))
	}
	for _, r := range sink.records {
		if strings.Contains(r.Body, tok) {
			t.Fatalf("token leaked into content record")
		}
	}
	rawProps, _ := json.Marshal(props)
	if strings.Contains(string(rawProps), tok) {
		t.Fatalf("token leaked into properties")
	}
}

func TestFlowiseCollect_RejectsLangflowAndTLSFailure(t *testing.T) {
	langflowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte(`{"version":"1.0.19","main_version":"1.0.19","package":"Langflow"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer langflowSrv.Close()

	col := flowise.New(testConfig(langflowSrv.URL))
	res, err := col.Collect(context.Background(), langflowSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("Langflow version must fail closed in Flowise collector")
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"2.1.4"}`))
	}))
	defer tlsSrv.Close()
	colTLS := flowise.New(testConfig(tlsSrv.URL))
	resTLS, err := colTLS.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS Collect error: %v", err)
	}
	if resTLS.Observation.Coverage != graph.CoverageFailed || len(resTLS.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection")
	}
}
