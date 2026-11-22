package ray_test

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
	"github.com/0x3df/LLMHound/internal/collectors/ray"
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

func TestRayCollect_CompleteAndNeverSubmitsAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Ij7Kl1Mn5Op9Qr3St7Uv1Wx5Yz9Ab3")
	var mutated bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.8.0","ray_version":"2.37.0","ray_commit":"deadbeefcafebabe"}`))
		case "/api/cluster_status":
			_, _ = w.Write([]byte(`{"result":true,"data":{"clusterStatus":{"active_nodes":{"ray-head":1,"ray-worker":2}}}}`))
		case "/api/jobs/":
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"submission_id":"raysubmit_1","job_id":"0100","status":"RUNNING","type":"SUBMISSION","entrypoint":"python train.py","runtime_env":{"env_vars":{"GH_TOKEN":"%s"}}}]`, tok)))
		case "/api/v0/actors":
			_, _ = w.Write([]byte(`{"result":true,"data":{"result":{"total":4}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := ray.New(testConfig(srv.URL), ray.WithContentSink(sink))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("mutating request made")
	}
	if res.Observation.Coverage != graph.CoverageComplete || res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("coverage=%s (%s) status=%s", res.Observation.Coverage, res.Observation.CoverageReason, res.Status)
	}

	var svcItem *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.RayDashboard {
			svcItem = &res.Nodes[i]
		}
	}
	if svcItem == nil {
		t.Fatal("missing RayDashboard node")
	}
	props := svcItem.Properties
	if props["software_version"] != "2.37.0" || props["commit"] != "deadbeefcafebabe" {
		t.Errorf("version/commit mismatch: %+v", props)
	}
	if props["node_count"] != 3 || props["job_count"] != 1 || props["actor_count"] != 4 {
		t.Errorf("counts mismatch: %+v", props)
	}
	if !reflect.DeepEqual(props["exec_surface"], []string{graph.ExecJobSubmit}) {
		t.Errorf("exec_surface = %v", props["exec_surface"])
	}
	if !reflect.DeepEqual(props["anon_operations"], []string{"ray_actors", "ray_cluster_status", "ray_jobs"}) {
		t.Errorf("anon_operations = %v", props["anon_operations"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}
	if len(sink.records) != 1 || strings.Contains(sink.records[0].Body, tok) || !strings.Contains(sink.records[0].Body, "[secret:github_token]") {
		t.Fatalf("content record did not redact token: %+v", sink.records)
	}
	rawProps, _ := json.Marshal(props)
	if strings.Contains(string(rawProps), tok) {
		t.Fatalf("secret leaked into properties")
	}
}

func TestRayCollect_RejectsOllamaVersionOnlyAndTLSFailure(t *testing.T) {
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ollamaSrv.Close()

	col := ray.New(testConfig(ollamaSrv.URL))
	res, err := col.Collect(context.Background(), ollamaSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("Ollama /api/version must fail closed in Ray collector")
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ray_version":"2.37.0"}`))
	}))
	defer tlsSrv.Close()
	colTLS := ray.New(testConfig(tlsSrv.URL))
	resTLS, err := colTLS.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS Collect error: %v", err)
	}
	if resTLS.Observation.Coverage != graph.CoverageFailed || len(resTLS.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection")
	}
}

func TestRayCollect_NodesWorkerSummary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.RequestURI {
		case "/api/version":
			_, _ = w.Write([]byte(`{"ray_version":"2.37.0"}`))
		case "/api/cluster_status":
			_, _ = w.Write([]byte(`{"result":true,"data":{"clusterStatus":{"active_nodes":{"ray-head":1,"ray-worker":2}}}}`))
		case "/api/jobs/":
			_, _ = w.Write([]byte(`[]`))
		case "/api/v0/actors":
			_, _ = w.Write([]byte(`{"result":true,"data":{"actors":{}}}`))
		case "/nodes?view=summary":
			_, _ = w.Write([]byte(`{"result":true,"data":{"summary":[
				{"ip":"10.0.1.10","isHeadNode":true,"state":"ALIVE"},
				{"ip":"10.0.1.12","isHeadNode":false,"state":"ALIVE"},
				{"ip":"10.0.1.11","isHeadNode":false,"state":"ALIVE"},
				{"ip":"10.0.1.13","isHeadNode":false,"state":"DEAD"},
				{"ip":"not-an-ip","isHeadNode":false,"state":"ALIVE"}
			]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	col := ray.New(testConfig(srv.URL))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(res.Nodes) == 0 {
		t.Fatal("missing RayDashboard node")
	}
	got, _ := res.Nodes[0].Properties["worker_hosts"].([]string)
	want := []string{"10.0.1.11", "10.0.1.12"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("worker_hosts = %v, want %v", got, want)
	}
}
