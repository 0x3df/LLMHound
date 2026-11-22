package chromadb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/chromadb"
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

func TestChromaDBCollect_V2NoEmbeddingsAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Op0Qr4St8Uv2Wx6Yz0Ab4Cd8Ef2Gh6")
	var requestedEmbeddings bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/heartbeat":
			_, _ = w.Write([]byte(`{"nanosecond heartbeat":1700000000000000000}`))
		case "/api/v2/version":
			_, _ = w.Write([]byte(`"0.5.20"`))
		case "/api/v2/auth/identity":
			_, _ = w.Write([]byte(`{"user_id":"","tenant":"default_tenant","databases":["default_database"]}`))
		case "/api/v2/tenants/default_tenant/databases/default_database/collections":
			_, _ = w.Write([]byte(`[{"id":"col-uuid-1","name":"runbooks","tenant":"default_tenant","database":"default_database"}]`))
		case "/api/v2/tenants/default_tenant/databases/default_database/collections/col-uuid-1/count":
			_, _ = w.Write([]byte(`12`))
		case "/api/v2/tenants/default_tenant/databases/default_database/collections/col-uuid-1/get":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "embeddings") {
				requestedEmbeddings = true
			}
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ids":["d1"],"documents":["deploy key %s"],"metadatas":[{"source":"wiki"}],"embeddings":[[0.1,0.2,0.3]]}`, tok)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	sink := &memSink{}
	col := chromadb.New(testConfig(srv.URL), chromadb.WithContentSink(sink))
	res, err := col.Collect(context.Background(), srv.URL, "lab-scope", "scanner-a", "scan-1", time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if requestedEmbeddings {
		t.Fatal("collector must never request embeddings")
	}
	if res.Observation.Coverage != graph.CoverageComplete || res.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("coverage=%s (%s) status=%s", res.Observation.Coverage, res.Observation.CoverageReason, res.Status)
	}

	var svcItem, colItem *emitter.NodeItem
	for i := range res.Nodes {
		n := &res.Nodes[i]
		if n.Node.Identity().Kind() == graph.ChromaInstance {
			svcItem = n
		}
		if n.Node.Identity().Kind() == graph.VectorCollection {
			colItem = n
		}
	}
	if svcItem == nil || colItem == nil {
		t.Fatalf("missing ChromaInstance or VectorCollection node")
	}
	if svcItem.Properties["software_version"] != "0.5.20" || svcItem.Properties["api_version"] != "v2" {
		t.Errorf("version mismatch: %+v", svcItem.Properties)
	}
	if svcItem.Properties["collection_count"] != 1 || colItem.Properties["points_count"] != int64(12) {
		t.Errorf("counts mismatch: svc=%+v col=%+v", svcItem.Properties, colItem.Properties)
	}
	if !reflect.DeepEqual(svcItem.Properties["anon_operations"], []string{"chromadb_collection_count", "chromadb_collections"}) {
		t.Errorf("anon_operations = %v", svcItem.Properties["anon_operations"])
	}
	if svcItem.Properties["has_exposed_secret"] != true {
		t.Errorf("expected has_exposed_secret=true")
	}
	if len(sink.records) != 1 || strings.Contains(sink.records[0].Body, "embeddings") || strings.Contains(sink.records[0].Body, tok) {
		t.Fatalf("content record leaked embeddings or raw token: %+v", sink.records)
	}
	rawProps, _ := json.Marshal(svcItem.Properties)
	if strings.Contains(string(rawProps), tok) {
		t.Fatalf("token leaked into properties")
	}
}

func TestChromaDBCollect_V1FallbackAndTLSFailure(t *testing.T) {
	v1Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/heartbeat":
			_, _ = w.Write([]byte(`{"nanosecond heartbeat":123}`))
		case "/api/v1/version":
			_, _ = w.Write([]byte(`"0.4.24"`))
		case "/api/v1/collections":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer v1Srv.Close()

	col := chromadb.New(testConfig(v1Srv.URL))
	res, err := col.Collect(context.Background(), v1Srv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("expected complete coverage on v1 ChromaDB, got %s (%s)", res.Observation.Coverage, res.Observation.CoverageReason)
	}

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"nanosecond heartbeat":1}`))
	}))
	defer tlsSrv.Close()
	colTLS := chromadb.New(testConfig(tlsSrv.URL))
	resTLS, err := colTLS.Collect(context.Background(), tlsSrv.URL, "lab-scope", "scanner-a", "scan-1", time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("TLS Collect error: %v", err)
	}
	if resTLS.Observation.Coverage != graph.CoverageFailed || len(resTLS.Nodes) != 0 {
		t.Fatalf("TLS failure must stop collection")
	}
}
