package qdrant_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/collectors/qdrant"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
	"github.com/0x3df/LLMHound/internal/transport"
)

type memoryContentSink struct {
	mu      sync.Mutex
	records []content.Record
}

func (m *memoryContentSink) Write(rec content.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	return nil
}

func baseCfg() config.Config {
	cfg := config.Defaults()
	cfg.Scope = "qdrant-scope"
	cfg.VantageKey = "vantage-qdrant"
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Content.Mode = config.ContentModeFull
	return cfg
}

func TestQdrantCollect_CompleteAndBoundedSampling(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Cd4Ef8Gh1Ij5Kl9Mn2Op6Qr0St3Uv7")
	var mu sync.Mutex
	var requests []string
	var scrollBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"title":"qdrant - vector search engine","version":"1.12.5","commit":"abc1234"}`))
		case "/collections":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"},{"name":"media"}]},"status":"ok"}`))
		case "/collections/docs":
			_, _ = w.Write([]byte(`{"result":{"status":"green","points_count":10,"indexed_vectors_count":10,"segments_count":2,"config":{"params":{"vectors":{"size":1536,"distance":"Cosine"}}}}}`))
		case "/collections/media":
			_, _ = w.Write([]byte(`{"result":{"status":"green","points_count":4,"indexed_vectors_count":8,"segments_count":1,"config":{"params":{"vectors":{"text":{"size":768,"distance":"Dot"},"image":{"size":512,"distance":"Cosine"}}}}}}`))
		case "/snapshots":
			if r.Method != http.MethodGet {
				t.Fatalf("snapshots must only be called via GET, got %s", r.Method)
			}
			_, _ = w.Write([]byte(`{"result":[{"name":"snap-1.snapshot"}]}`))
		case "/collections/docs/points/scroll":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			scrollBody = string(b)
			mu.Unlock()
			// Deliberately include a vector array in server response to confirm collector discards it.
			_, _ = w.Write([]byte(`{"result":{"points":[{"id":1,"vector":[0.9911,0.8822],"payload":{"text":"doc secret ` + tok + `"}}],"next_page_offset":null}}`))
		case "/collections/media/points/scroll":
			_, _ = w.Write([]byte(`{"result":{"points":[{"id":"uuid-1","payload":{"caption":"safe image"}}],"next_page_offset":null}}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	sink := &memoryContentSink{}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	res, err := qdrant.New(baseCfg(), qdrant.WithContentSink(sink)).
		Collect(context.Background(), srv.URL, "qdrant-scope", "vantage-qdrant", "scan-q", now, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s)", res.Observation.Coverage, res.Observation.CoverageReason)
	}
	if !strings.Contains(scrollBody, `"with_vector":false`) || !strings.Contains(scrollBody, `"limit":5`) {
		t.Fatalf("scroll request must specify with_vector:false and limit:5, got %s", scrollBody)
	}

	var srvProps map[string]any
	colls := map[string]map[string]any{}
	for _, n := range res.Nodes {
		switch n.Node.Identity().Kind() {
		case graph.QdrantInstance:
			srvProps = n.Properties
		case graph.VectorCollection:
			colls[n.Properties["collection_name"].(string)] = n.Properties
		}
	}
	if srvProps == nil || len(colls) != 2 {
		t.Fatalf("srv=%v colls=%d", srvProps != nil, len(colls))
	}
	if srvProps["software_version"] != "1.12.5" || srvProps["commit"] != "abc1234" {
		t.Fatalf("version/commit = %+v", srvProps)
	}
	if srvProps["collection_count"] != 2 || srvProps["snapshots_exposed"] != true || srvProps["snapshot_count"] != 1 {
		t.Fatalf("inventory/snapshots = %+v", srvProps)
	}
	if srvProps["auth_observed"] != "anonymous" {
		t.Fatalf("auth_observed = %v", srvProps["auth_observed"])
	}
	anonOps := srvProps["anon_operations"].([]string)
	for _, op := range anonOps {
		if op == qdrant.CheckVersion || op == qdrant.CheckPointsSample {
			t.Fatalf("%s must not appear in anon_operations: %v", op, anonOps)
		}
	}
	if srvProps["has_exposed_secret"] != true || !reflect.DeepEqual(srvProps["secret_types"], []string{"github_token"}) {
		t.Fatalf("secret props = (%v, %v)", srvProps["has_exposed_secret"], srvProps["secret_types"])
	}

	if colls["docs"]["dimensions"] != int64(1536) || colls["docs"]["distance"] != "Cosine" {
		t.Fatalf("single-vector collection props = %+v", colls["docs"])
	}
	if !reflect.DeepEqual(colls["media"]["vector_names"], []string{"image", "text"}) {
		t.Fatalf("named-vector collection vector_names = %v", colls["media"]["vector_names"])
	}

	// Verify content records redact the secret and drop vector arrays.
	if len(sink.records) != 2 {
		t.Fatalf("expected 2 content records, got %d", len(sink.records))
	}
	rawNodes, _ := json.Marshal(res.Nodes)
	rawEv, _ := json.Marshal(res.Evidence)
	for _, rec := range sink.records {
		if strings.Contains(rec.Body, "0.9911") || strings.Contains(rec.Body, tok) {
			t.Fatalf("vector or raw secret leaked into content record: %s", rec.Body)
		}
	}
	if strings.Contains(string(rawNodes), tok) || strings.Contains(string(rawEv), tok) {
		t.Fatalf("raw secret leaked into graph or evidence")
	}
	if !strings.Contains(string(rawEv), `"detected_exposures"`) {
		t.Fatalf("evidence missing detected_exposures: %s", rawEv)
	}
}

func TestQdrantCollect_SampleTruncationAndContentOptOut(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"title":"qdrant - vector search engine","version":"1.12.5"}`))
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"c1"}]},"status":"ok"}`))
		case "/collections/c1":
			_, _ = w.Write([]byte(`{"result":{"status":"green","points_count":10,"config":{"params":{"vectors":{"size":4,"distance":"Cosine"}}}}}`))
		case "/snapshots":
			_, _ = w.Write([]byte(`{"result":[]}`))
		case "/collections/c1/points/scroll":
			_, _ = w.Write([]byte(`{"result":{"points":[{"id":1,"payload":{"a":"b"}}],"next_page_offset":2}}`))
		}
	}))
	defer srv.Close()

	// 1. next_page_offset non-null -> CoverageTruncated + content_truncated=true
	resTrunc, err := qdrant.New(baseCfg()).Collect(context.Background(), srv.URL, "qdrant-scope", "vantage-qdrant", "s1", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resTrunc.Observation.Coverage != graph.CoverageTruncated || resTrunc.Nodes[0].Properties["content_truncated"] != true {
		t.Fatalf("expected truncated coverage and content_truncated=true: cov=%s props=%+v", resTrunc.Observation.Coverage, resTrunc.Nodes[0].Properties)
	}

	// 2. Content opt-out keeps CoverageComplete and skips scroll.
	cfgOff := baseCfg()
	cfgOff.Content.Surfaces = map[string]bool{"qdrant": false}
	resOff, err := qdrant.New(cfgOff).Collect(context.Background(), srv.URL, "qdrant-scope", "vantage-qdrant", "s2", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resOff.Observation.Coverage != graph.CoverageComplete || resOff.Nodes[0].Properties["content_bytes"] != nil {
		t.Fatalf("content opt-out got cov=%s props=%+v", resOff.Observation.Coverage, resOff.Nodes[0].Properties)
	}
}

func TestQdrantCollect_DeniedFailuresAndTLS(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// 1. Root public 200 + collections/snapshots 401 -> CoveragePartial, auth_observed=denied, anon_operations absent.
	rootOnlySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`{"title":"qdrant - vector search engine","version":"1.12.5"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer rootOnlySrv.Close()
	resDenied, err := qdrant.New(baseCfg()).Collect(context.Background(), rootOnlySrv.URL, "qdrant-scope", "vantage-qdrant", "s-den", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resDenied.Observation.Coverage != graph.CoveragePartial || resDenied.Nodes[0].Properties["auth_observed"] != "denied" || resDenied.Nodes[0].Properties["anon_operations"] != nil {
		t.Fatalf("root-only denied got cov=%s props=%+v", resDenied.Observation.Coverage, resDenied.Nodes[0].Properties)
	}

	// 2. Non-Qdrant 404/429 -> failed, no nodes
	nonQdrant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`{"title":"something else"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer nonQdrant.Close()
	res404, err := qdrant.New(baseCfg()).Collect(context.Background(), nonQdrant.URL, "qdrant-scope", "vantage-qdrant", "s-404", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res404.Observation.Coverage != graph.CoverageFailed || len(res404.Nodes) != 0 {
		t.Fatalf("non-qdrant 404 must fail with no nodes")
	}

	// 3. MaxItems truncation on collections
	manyColsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"title":"qdrant","version":"1.12.5"}`))
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"a"},{"name":"b"},{"name":"c"}]},"status":"ok"}`))
		case "/snapshots":
			_, _ = w.Write([]byte(`{"result":[]}`))
		default:
			if strings.HasSuffix(r.URL.Path, "/scroll") {
				_, _ = w.Write([]byte(`{"result":{"points":[]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"result":{"status":"green","points_count":0}}`))
		}
	}))
	defer manyColsSrv.Close()
	cfgItems := baseCfg()
	cfgItems.Bounds.MaxItems = 2
	resItems, err := qdrant.New(cfgItems).Collect(context.Background(), manyColsSrv.URL, "qdrant-scope", "vantage-qdrant", "s-items", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resItems.Observation.Coverage != graph.CoverageTruncated || resItems.Nodes[0].Properties["collection_count"] != 2 {
		t.Fatalf("max_items truncation got cov=%s props=%+v", resItems.Observation.Coverage, resItems.Nodes[0].Properties)
	}

	// 4. TLS strict fail vs insecure + mapping + redirect rejection
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`{"title":"qdrant","version":"1.12.5"}`))
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[]},"status":"ok"}`))
		case "/snapshots":
			_, _ = w.Write([]byte(`{"result":[]}`))
		}
	}))
	defer tlsSrv.Close()

	resTLSFail, err := qdrant.New(baseCfg()).Collect(context.Background(), tlsSrv.URL, "qdrant-scope", "vantage-qdrant", "s-tls1", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resTLSFail.Observation.Coverage != graph.CoverageFailed || len(resTLSFail.Nodes) != 0 {
		t.Fatalf("strict TLS must fail without nodes")
	}
	hasTLS := false
	for _, ev := range resTLSFail.Evidence {
		if ev.RecordType == evidence.RecordTLS && ev.VerificationResult == "failed" {
			hasTLS = true
		}
	}
	if !hasTLS {
		t.Fatalf("expected failed TLS evidence")
	}

	cfgIns := baseCfg()
	cfgIns.Insecure = true
	resolver, err := correlate.New([]correlate.Mapping{{Target: "127.0.0.1", ObjectID: "S-1-5-21-1-1002", Kind: "Computer"}})
	if err != nil {
		t.Fatal(err)
	}
	resTLSOK, err := qdrant.New(cfgIns).Collect(context.Background(), tlsSrv.URL, "qdrant-scope", "vantage-qdrant", "s-tls2", now, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if resTLSOK.Observation.Coverage != graph.CoverageComplete || resTLSOK.Nodes[0].Properties["tls_verification"] != "insecure_override" {
		t.Fatalf("insecure override got cov=%s props=%+v", resTLSOK.Observation.Coverage, resTLSOK.Nodes[0].Properties)
	}
	if len(resTLSOK.Edges) == 0 || !resTLSOK.Edges[len(resTLSOK.Edges)-1].TouchesNative() {
		t.Fatalf("expected native ObservedAt edge")
	}

	extSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer extSrv.Close()
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, extSrv.URL+"/", http.StatusFound)
	}))
	defer redirSrv.Close()
	cfgRedir := baseCfg()
	cfgRedir.Bounds.MaxRedirects = 2
	resRedir, err := qdrant.New(cfgRedir, qdrant.WithTransport(transport.NewClient(transport.Config{Bounds: cfgRedir.Bounds}))).
		Collect(context.Background(), redirSrv.URL, "qdrant-scope", "vantage-qdrant", "s-redir", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resRedir.Observation.Coverage != graph.CoverageFailed || len(resRedir.Nodes) != 0 {
		t.Fatalf("cross-host redirect must fail without nodes")
	}
}
