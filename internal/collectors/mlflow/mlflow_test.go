package mlflow_test

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

	"github.com/0x3df/LLMHound/internal/collectors/mlflow"
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

func TestMLflowCollect_CompletePaginationWeightsSkippedAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Cd4Ef8Gh2Ij6Kl0Mn3Op7Qr1St5Uv9")
	var weightRequested bool
	var mutated bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutated = true
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte("2.16.2"))
		case "/api/2.0/mlflow/experiments/search":
			if r.URL.Query().Get("page_token") == "p2" {
				_, _ = w.Write([]byte(`{"experiments":[{"experiment_id":"2","name":"eval","artifact_location":"gs://mlflow-eval-bucket/artifacts"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"experiments":[{"experiment_id":"1","name":"Default","artifact_location":"s3://AKIA:secret@mlflow-prod-bucket/runs?token=abc#frag"}],"next_page_token":"p2"}`))
		case "/api/2.0/mlflow/registered-models/search":
			_, _ = w.Write([]byte(`{
				"registered_models":[{
					"name":"fraud-detector",
					"aliases":[{"alias":"champion","version":"3"}],
					"latest_versions":[{
						"name":"fraud-detector",
						"version":"3",
						"current_stage":"Production",
						"source":"s3://mlflow-prod-bucket/models/fraud/3",
						"run_id":"run-abc"
					}]
				}]
			}`))
		case "/api/2.0/mlflow/artifacts/list":
			_, _ = w.Write([]byte(`{
				"root_uri":"s3://mlflow-prod-bucket/runs/run-abc/artifacts",
				"files":[
					{"path":"model.pkl","is_dir":false,"file_size":104857600},
					{"path":"weights.safetensors","is_dir":false,"file_size":500000000},
					{"path":"MLmodel","is_dir":false,"file_size":120},
					{"path":"requirements.txt","is_dir":false,"file_size":80}
				]
			}`))
		case "/get-artifact":
			p := r.URL.Query().Get("path")
			if strings.HasSuffix(p, ".pkl") || strings.HasSuffix(p, ".safetensors") {
				weightRequested = true
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if p == "MLmodel" {
				_, _ = w.Write([]byte("flavors:\n  python_function:\n    loader_module: mlflow.sklearn\n"))
				return
			}
			if p == "requirements.txt" {
				_, _ = w.Write([]byte(fmt.Sprintf("scikit-learn==1.5.0\n# %s\n", tok)))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := mlflow.New(testConfig(srv.URL), mlflow.WithContentSink(sink))
	obsTime := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", obsTime, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if mutated {
		t.Fatal("non-GET method was called")
	}
	if weightRequested {
		t.Fatal("model weight file was requested")
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s), want complete", res.Observation.Coverage, res.Observation.CoverageReason)
	}

	var srvItem *emitter.NodeItem
	var modelArtifacts, artifactStores int
	for i := range res.Nodes {
		n := &res.Nodes[i]
		switch n.Node.Identity().Kind() {
		case graph.MLflowServer:
			srvItem = n
		case graph.ModelArtifact:
			modelArtifacts++
			if n.Properties["model_version"] != "3" {
				t.Errorf("model_version = %v, want 3", n.Properties["model_version"])
			}
			if n.Properties["stage"] != "Production" {
				t.Errorf("stage = %v, want Production", n.Properties["stage"])
			}
		case graph.ArtifactStore:
			artifactStores++
		}
	}
	if srvItem == nil {
		t.Fatal("missing MLflowServer node")
	}
	if modelArtifacts != 1 {
		t.Fatalf("expected 1 ModelArtifact, got %d", modelArtifacts)
	}
	if artifactStores != 3 {
		t.Fatalf("expected 3 ArtifactStore nodes, got %d", artifactStores)
	}
	props := srvItem.Properties
	if props["software_version"] != "2.16.2" {
		t.Errorf("software_version = %v, want 2.16.2", props["software_version"])
	}
	if props["experiment_count"] != 2 {
		t.Errorf("experiment_count = %v, want 2", props["experiment_count"])
	}
	if props["model_count"] != 1 {
		t.Errorf("model_count = %v, want 1", props["model_count"])
	}
	if !reflect.DeepEqual(props["exec_surface"], []string{graph.ExecModelMutation}) {
		t.Errorf("exec_surface = %v", props["exec_surface"])
	}
	if !reflect.DeepEqual(props["store_refs"], []string{
		"gs://mlflow-eval-bucket/artifacts",
		"s3://mlflow-prod-bucket/models/fraud/3",
		"s3://mlflow-prod-bucket/runs",
	}) {
		t.Errorf("store_refs = %v (credentials/query/fragment must be stripped)", props["store_refs"])
	}
	if props["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}
	if len(sink.records) != 2 {
		t.Fatalf("expected 2 content records, got %d", len(sink.records))
	}
	for _, r := range sink.records {
		if strings.Contains(r.Body, tok) {
			t.Fatalf("secret value leaked into content record")
		}
	}
	rawProps, _ := json.Marshal(props)
	if strings.Contains(string(rawProps), tok) || strings.Contains(string(rawProps), "AKIA:secret") {
		t.Fatalf("secret or URL userinfo leaked into node properties: %s", string(rawProps))
	}
}

func TestMLflowCollect_FailClosedAndHTMLAndTruncation(t *testing.T) {
	// Generic server returning HTML login page on /version and 404 elsewhere fails closed.
	htmlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>Sign in</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer htmlSrv.Close()

	col := mlflow.New(testConfig(htmlSrv.URL))
	res, err := col.Collect(context.Background(), htmlSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("expected failed coverage and 0 nodes for non-MLflow HTML")
	}

	// Pagination bound truncation + content opt-out.
	pagSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte("2.15.0"))
		case "/api/2.0/mlflow/experiments/search":
			_, _ = w.Write([]byte(`{"experiments":[{"experiment_id":"0","name":"Default"}],"next_page_token":"next"}`))
		case "/api/2.0/mlflow/registered-models/search":
			_, _ = w.Write([]byte(`{"registered_models":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer pagSrv.Close()

	cfg := testConfig(pagSrv.URL)
	cfg.Bounds.MaxPages = 1
	cfg.Content.Enabled = false
	col2 := mlflow.New(cfg)
	res2, err := col2.Collect(context.Background(), pagSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res2.Observation.Coverage != graph.CoverageTruncated {
		t.Fatalf("expected truncated coverage on max_pages=1, got %s", res2.Observation.Coverage)
	}
}

func TestMLflowCollect_TLSFailure(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("2.16.2"))
	}))
	defer tlsSrv.Close()

	col := mlflow.New(testConfig(tlsSrv.URL))
	res, err := col.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageFailed || len(res.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection with 0 nodes")
	}
}
