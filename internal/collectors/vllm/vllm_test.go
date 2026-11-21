package vllm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/collectors/vllm"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/transport"
)

func baseCfg() config.Config {
	cfg := config.Defaults()
	cfg.Scope = "vllm-scope"
	cfg.VantageKey = "vantage-vllm"
	cfg.Targets = []string{"127.0.0.1"}
	return cfg
}

func TestVLLMCollect_CompleteSuccess(t *testing.T) {
	var mu sync.Mutex
	var requested []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.Method+" "+r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "0.6.4.post1"}`))
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"object": "list",
				"data": [
					{"id": "Meta-Llama-3-8B", "object": "model", "created": 1700000000, "owned_by": "vllm", "root": "/models/llama3", "max_model_len": 8192},
					{"id": "alias-chat", "object": "model", "owned_by": "vllm", "parent": "Meta-Llama-3-8B"}
				]
			}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	res, err := vllm.New(baseCfg()).Collect(context.Background(), srv.URL, "vllm-scope", "vantage-vllm", "scan-vllm", now, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s)", res.Observation.Coverage, res.Observation.CoverageReason)
	}
	for _, req := range requested {
		if !strings.HasPrefix(req, "GET /version") && !strings.HasPrefix(req, "GET /v1/models") {
			t.Fatalf("forbidden request recorded: %s", req)
		}
	}

	var srvProps map[string]any
	modelProps := map[string]map[string]any{}
	for _, n := range res.Nodes {
		switch n.Node.Identity().Kind() {
		case graph.VLLMInstance:
			srvProps = n.Properties
		case graph.AIModel:
			modelProps[n.Properties["model_id"].(string)] = n.Properties
		}
	}
	if srvProps == nil || len(modelProps) != 2 {
		t.Fatalf("srv=%v models=%d", srvProps != nil, len(modelProps))
	}
	if srvProps["auth_observed"] != "anonymous" || !reflect.DeepEqual(srvProps["anon_operations"], []string{vllm.CheckModels}) {
		t.Fatalf("access = (%v, %v)", srvProps["auth_observed"], srvProps["anon_operations"])
	}
	if srvProps["software_version_raw"] != "0.6.4.post1" || srvProps["model_count"] != 2 {
		t.Fatalf("props = %+v", srvProps)
	}
	if _, ok := srvProps["exec_surface"]; ok {
		t.Fatalf("vllm must not emit exec_surface, got %v", srvProps["exec_surface"])
	}
	if m := modelProps["Meta-Llama-3-8B"]; m["root"] != "/models/llama3" || m["max_model_len"] != int64(8192) {
		t.Fatalf("model props unexpected: %+v", m)
	}
}

func TestVLLMCollect_PrecisionGenericOpenAIAndUnknownVersion(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// 1. Generic OpenAI-compatible server must NOT produce a VLLMInstance node.
	genericSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/models":
			w.Header().Set("Server", "envoy")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o","owned_by":"openai"}]}`))
		}
	}))
	defer genericSrv.Close()

	resGen, err := vllm.New(baseCfg()).Collect(context.Background(), genericSrv.URL, "vllm-scope", "vantage-vllm", "s-gen", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resGen.Observation.Coverage != graph.CoverageFailed || len(resGen.Nodes) != 0 {
		t.Fatalf("generic OpenAI server must not emit VLLMInstance: cov=%s nodes=%d", resGen.Observation.Coverage, len(resGen.Nodes))
	}

	// 2. Proxy banner + /version 404 + vllm-owned model -> partial coverage, version omitted.
	noVerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "envoy-proxy/1.29")
		switch r.URL.Path {
		case "/version":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen2.5","owned_by":"vllm"}]}`))
		}
	}))
	defer noVerSrv.Close()

	resPartial, err := vllm.New(baseCfg()).Collect(context.Background(), noVerSrv.URL, "vllm-scope", "vantage-vllm", "s-nover", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resPartial.Observation.Coverage != graph.CoveragePartial || len(resPartial.Nodes) == 0 {
		t.Fatalf("expected partial coverage with node, got %s nodes=%d", resPartial.Observation.Coverage, len(resPartial.Nodes))
	}
	if resPartial.Nodes[0].Properties["software_version"] != nil || resPartial.Nodes[0].Properties["software_version_raw"] != nil {
		t.Fatalf("proxy banner must never populate software_version: %+v", resPartial.Nodes[0].Properties)
	}
}

func TestVLLMCollect_DeniedRateLimitMalformedAndTruncation(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// 1. Version public 200 + models 401 -> auth_observed=denied, anon_operations absent.
	mixedDeniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"0.6.4"}`))
		case "/v1/models":
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer mixedDeniedSrv.Close()
	resMix, err := vllm.New(baseCfg()).Collect(context.Background(), mixedDeniedSrv.URL, "vllm-scope", "vantage-vllm", "s1", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resMix.Observation.Coverage != graph.CoveragePartial {
		t.Fatalf("expected CoveragePartial, got %s", resMix.Observation.Coverage)
	}
	if resMix.Nodes[0].Properties["auth_observed"] != "denied" || resMix.Nodes[0].Properties["anon_operations"] != nil {
		t.Fatalf("version must not count as anon_operations: %+v", resMix.Nodes[0].Properties)
	}
	if resMix.Nodes[0].Properties["model_count"] != nil {
		t.Fatalf("denied models must omit model_count: %v", resMix.Nodes[0].Properties["model_count"])
	}

	// 2. Both 401 -> CoveragePartial, auth_observed=denied
	bothDeniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer bothDeniedSrv.Close()
	resBoth, err := vllm.New(baseCfg()).Collect(context.Background(), bothDeniedSrv.URL, "vllm-scope", "vantage-vllm", "s2", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resBoth.Observation.Coverage != graph.CoveragePartial || resBoth.Nodes[0].Properties["auth_observed"] != "denied" {
		t.Fatalf("both denied got cov=%s props=%+v", resBoth.Observation.Coverage, resBoth.Nodes[0].Properties)
	}

	// 3. 429 + malformed
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer badSrv.Close()
	resBad, err := vllm.New(baseCfg()).Collect(context.Background(), badSrv.URL, "vllm-scope", "vantage-vllm", "s3", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resBad.Observation.Coverage != graph.CoverageFailed || len(resBad.Nodes) != 0 {
		t.Fatalf("429+malformed must fail with no nodes")
	}

	// 4. MaxItems truncation + MaxResponseBytes truncation
	truncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			_, _ = w.Write([]byte(`{"version":"0.6.4"}`))
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m1","owned_by":"vllm"},{"id":"m2","owned_by":"vllm"},{"id":"m3","owned_by":"vllm"}]}`))
	}))
	defer truncSrv.Close()
	cfgTrunc := baseCfg()
	cfgTrunc.Bounds.MaxItems = 2
	resTrunc, err := vllm.New(cfgTrunc).Collect(context.Background(), truncSrv.URL, "vllm-scope", "vantage-vllm", "s4", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resTrunc.Observation.Coverage != graph.CoverageTruncated || resTrunc.Nodes[0].Properties["model_count"] != 2 {
		t.Fatalf("truncation got cov=%s props=%+v", resTrunc.Observation.Coverage, resTrunc.Nodes[0].Properties)
	}

	cfgRespTrunc := baseCfg()
	cfgRespTrunc.Bounds.MaxResponseBytes = 25
	resRespTrunc, err := vllm.New(cfgRespTrunc).Collect(context.Background(), truncSrv.URL, "vllm-scope", "vantage-vllm", "s5", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resRespTrunc.Observation.Coverage != graph.CoverageTruncated {
		t.Fatalf("expected CoverageTruncated on MaxResponseBytes, got %s", resRespTrunc.Observation.Coverage)
	}
}

func TestVLLMCollect_TLSRedirectsAndMapping(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"0.6.4"}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m1","owned_by":"vllm"}]}`))
		}
	}))
	defer tlsSrv.Close()

	// Strict TLS fails without nodes.
	resFail, err := vllm.New(baseCfg()).Collect(context.Background(), tlsSrv.URL, "vllm-scope", "vantage-vllm", "s-tls1", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resFail.Observation.Coverage != graph.CoverageFailed || len(resFail.Nodes) != 0 {
		t.Fatalf("strict TLS failure must fail without nodes")
	}
	hasTLS := false
	for _, ev := range resFail.Evidence {
		if ev.RecordType == evidence.RecordTLS && ev.VerificationResult == "failed" {
			hasTLS = true
		}
	}
	if !hasTLS {
		t.Fatalf("expected failed TLS evidence")
	}

	// Insecure override + native AZVM mapping.
	cfgIns := baseCfg()
	cfgIns.Insecure = true
	resolver, err := correlate.New([]correlate.Mapping{{Target: "127.0.0.1", ObjectID: "/SUBSCRIPTIONS/1/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM1", Kind: "AZVM"}})
	if err != nil {
		t.Fatal(err)
	}
	resOK, err := vllm.New(cfgIns).Collect(context.Background(), tlsSrv.URL, "vllm-scope", "vantage-vllm", "s-tls2", now, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if resOK.Observation.Coverage != graph.CoverageComplete || resOK.Nodes[0].Properties["tls_verification"] != "insecure_override" {
		t.Fatalf("insecure override props = %+v", resOK.Nodes[0].Properties)
	}
	if len(resOK.Edges) == 0 || !resOK.Edges[len(resOK.Edges)-1].TouchesNative() {
		t.Fatalf("expected native ObservedAt edge")
	}

	// Redirect refused cleanly.
	extSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer extSrv.Close()
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, extSrv.URL+"/version", http.StatusFound)
	}))
	defer redirSrv.Close()

	cfgRedir := baseCfg()
	cfgRedir.Bounds.MaxRedirects = 2
	resRedir, err := vllm.New(cfgRedir, vllm.WithTransport(transport.NewClient(transport.Config{Bounds: cfgRedir.Bounds}))).
		Collect(context.Background(), redirSrv.URL, "vllm-scope", "vantage-vllm", "s-redir", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resRedir.Observation.Coverage != graph.CoverageFailed || len(resRedir.Nodes) != 0 {
		t.Fatalf("cross-host redirect must fail without nodes")
	}
}
