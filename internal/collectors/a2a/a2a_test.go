package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/collectors/a2a"
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
	cfg.Scope = "a2a-scope"
	cfg.VantageKey = "vantage-a2a"
	cfg.Targets = []string{"127.0.0.1"}
	return cfg
}

func TestA2ACollect_PrimaryCardAndContentAndSecrets(t *testing.T) {
	tok := secretstest.GitHubToken("ghp", "Ab3Cd9Ef2Gh7Ij4Kl8Mn1Op6Qr5St0")
	var mu sync.Mutex
	var requested []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested = append(requested, r.Method+" "+r.URL.Path)
		mu.Unlock()

		if r.URL.Path == "/.well-known/agent-card.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name": "ResearchAgent",
				"description": "Coordinates tasks\nwith token ` + tok + `",
				"url": "https://user:pass@agent.internal:8443/a2a?token=secret#frag",
				"version": "v1.4.2",
				"protocolVersion": "0.3.0",
				"documentationUrl": "https://user:pw@docs.internal/a2a?api_key=123",
				"provider": {"organization": "Example AI", "url": "https://example.ai?ref=1"},
				"capabilities": {"streaming": true, "pushNotifications": false, "extendedAgentCard": true},
				"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
				"security": [{"bearerAuth": []}],
				"defaultInputModes": ["text/plain"],
				"defaultOutputModes": ["application/json"],
				"skills": [
					{"id": "skill-1", "name": "Summarize", "description": "Summarizes docs", "tags": ["nlp"]},
					{"id": "skill-2", "name": "Search", "inputModes": ["text/plain"]}
				],
				"additionalInterfaces": [{"url": "https://alt.internal/rpc?key=val", "transport": "JSONRPC"}]
			}`))
			return
		}
		t.Fatalf("unexpected path requested: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	sink := &memoryContentSink{}
	col := a2a.New(baseCfg(), a2a.WithContentSink(sink))
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	res, err := col.Collect(context.Background(), srv.URL, "a2a-scope", "vantage-a2a", "scan-a2a", now, nil)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s), want complete", res.Observation.Coverage, res.Observation.CoverageReason)
	}
	if len(requested) != 1 || requested[0] != "GET /.well-known/agent-card.json" {
		t.Fatalf("unexpected requests: %v", requested)
	}

	var agentProps map[string]any
	skillCount := 0
	for _, n := range res.Nodes {
		switch n.Node.Identity().Kind() {
		case graph.A2AAgent:
			agentProps = n.Properties
		case graph.A2ASkill:
			skillCount++
		}
	}
	if agentProps == nil || skillCount != 2 {
		t.Fatalf("agent=%v skills=%d", agentProps != nil, skillCount)
	}
	if agentProps["auth_observed"] != "anonymous" || !reflect.DeepEqual(agentProps["anon_operations"], []string{a2a.CheckAgentCard}) {
		t.Fatalf("access props = (%v, %v)", agentProps["auth_observed"], agentProps["anon_operations"])
	}
	if agentProps["auth_advertised"] != "required" || agentProps["auth_advertised_basis"] != "declared" {
		t.Fatalf("auth_advertised = (%v, %v)", agentProps["auth_advertised"], agentProps["auth_advertised_basis"])
	}
	if !reflect.DeepEqual(agentProps["exec_surface"], []string{graph.ExecToolInvocation}) || agentProps["exec_surface_basis"] != "declared" {
		t.Fatalf("exec_surface = (%v, %v)", agentProps["exec_surface"], agentProps["exec_surface_basis"])
	}
	if agentProps["software_version"] != "1.4.2" || agentProps["software_version_raw"] != "v1.4.2" || agentProps["protocol_version"] != "0.3.0" {
		t.Fatalf("versions = (%v, %v, %v)", agentProps["software_version"], agentProps["software_version_raw"], agentProps["protocol_version"])
	}
	if agentProps["skill_count"] != 2 || agentProps["card_path"] != "/.well-known/agent-card.json" {
		t.Fatalf("skill_count=%v card_path=%v", agentProps["skill_count"], agentProps["card_path"])
	}
	if !reflect.DeepEqual(agentProps["backend_refs"], []string{"https://agent.internal:8443/a2a", "https://alt.internal/rpc"}) {
		t.Fatalf("backend_refs not sanitized cleanly: %v", agentProps["backend_refs"])
	}
	if agentProps["provider_url"] != "https://example.ai" || agentProps["documentation_url"] != "https://docs.internal/a2a" {
		t.Fatalf("sanitized urls = (%v, %v)", agentProps["provider_url"], agentProps["documentation_url"])
	}
	if agentProps["has_exposed_secret"] != true || !reflect.DeepEqual(agentProps["secret_types"], []string{"github_token"}) {
		t.Fatalf("secret graph properties = (%v, %v)", agentProps["has_exposed_secret"], agentProps["secret_types"])
	}
	if desc, _ := agentProps["description"].(string); !strings.Contains(desc, "[secret:github_token]") || strings.Contains(desc, tok) {
		t.Fatalf("agent description did not redact token: %q", desc)
	}

	// Secret must be redacted in content sink and absent from nodes, edges, and evidence.
	if len(sink.records) != 1 || !strings.Contains(sink.records[0].Body, "[secret:github_token]") || strings.Contains(sink.records[0].Body, tok) {
		t.Fatalf("content record did not redact token: %+v", sink.records)
	}
	rawNodes, _ := json.Marshal(res.Nodes)
	rawEv, _ := json.Marshal(res.Evidence)
	if strings.Contains(string(rawNodes), tok) || strings.Contains(string(rawEv), tok) {
		t.Fatalf("token leaked into graph or evidence")
	}
	if !strings.Contains(string(rawEv), `"detected_exposures"`) {
		t.Fatalf("evidence missing detected_exposures: %s", rawEv)
	}
}

func TestA2ACollect_LegacyFallbackAndAuthModes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			w.WriteHeader(http.StatusNotFound)
		case "/.well-known/agent.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"name": "LegacyAgent",
				"url": "https://legacy.internal/a2a",
				"security": [{}]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := baseCfg()
	cfg.Content.Surfaces = map[string]bool{"a2a": false}
	col := a2a.New(cfg)

	res, err := col.Collect(context.Background(), srv.URL, "a2a-scope", "vantage-a2a", "scan-legacy", time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Fatalf("coverage = %s (%s)", res.Observation.Coverage, res.Observation.CoverageReason)
	}
	var agentProps map[string]any
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.A2AAgent {
			agentProps = n.Properties
		}
	}
	if agentProps["card_path"] != "/.well-known/agent.json" || agentProps["auth_advertised"] != "none" || agentProps["skill_count"] != 0 {
		t.Fatalf("unexpected legacy props: %+v", agentProps)
	}
	if agentProps["content_bytes"] != nil {
		t.Fatalf("content opt-out must omit content_bytes, got %v", agentProps["content_bytes"])
	}
}

func TestA2ACollect_OutcomesFailuresAndTruncation(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	// 1. Denied (401)
	deniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer deniedSrv.Close()
	res, err := a2a.New(baseCfg()).Collect(context.Background(), deniedSrv.URL, "a2a-scope", "vantage-a2a", "s1", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Observation.Coverage != graph.CoveragePartial || len(res.Nodes) == 0 {
		t.Fatalf("401 should yield partial coverage and A2AAgent node, got %s nodes=%d", res.Observation.Coverage, len(res.Nodes))
	}
	if res.Nodes[0].Properties["auth_observed"] != "denied" || res.Nodes[0].Properties["skill_count"] != nil {
		t.Fatalf("401 node props = %+v", res.Nodes[0].Properties)
	}

	// 2. Ambiguous 404 on both paths -> failed (not unsupported), no node
	notFoundSrv := httptest.NewServer(http.NotFoundHandler())
	defer notFoundSrv.Close()
	res404, err := a2a.New(baseCfg()).Collect(context.Background(), notFoundSrv.URL, "a2a-scope", "vantage-a2a", "s2", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res404.Observation.Coverage != graph.CoverageFailed || len(res404.Nodes) != 0 {
		t.Fatalf("404 should fail with no nodes: %+v", res404)
	}
	if res404.Evidence[0].Outcome != string(graph.OutcomeFailed) {
		t.Fatalf("404 check outcome = %s, want failed", res404.Evidence[0].Outcome)
	}

	// 3. 429 rate limit
	rateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer rateSrv.Close()
	res429, err := a2a.New(baseCfg()).Collect(context.Background(), rateSrv.URL, "a2a-scope", "vantage-a2a", "s3", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res429.Observation.Coverage != graph.CoverageFailed || !strings.Contains(res429.Observation.CoverageReason, "429") {
		t.Fatalf("429 coverage = %s (%s)", res429.Observation.Coverage, res429.Observation.CoverageReason)
	}

	// 4. Malformed / non-A2A JSON
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"generic"}`))
	}))
	defer badSrv.Close()
	resBad, err := a2a.New(baseCfg()).Collect(context.Background(), badSrv.URL, "a2a-scope", "vantage-a2a", "s4", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resBad.Observation.Coverage != graph.CoverageFailed || len(resBad.Nodes) != 0 {
		t.Fatalf("non-A2A JSON must fail with no nodes")
	}

	// 5. Truncated skills (MaxItems) and content (MaxItemBytes)
	truncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"BigAgent","skills":[{"id":"a"},{"id":"b"},{"id":"c"}]}`))
	}))
	defer truncSrv.Close()
	cfgTrunc := baseCfg()
	cfgTrunc.Bounds.MaxItems = 2
	cfgTrunc.Content.MaxItemBytes = 20
	resTrunc, err := a2a.New(cfgTrunc).Collect(context.Background(), truncSrv.URL, "a2a-scope", "vantage-a2a", "s5", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resTrunc.Observation.Coverage != graph.CoverageTruncated {
		t.Fatalf("expected CoverageTruncated, got %s", resTrunc.Observation.Coverage)
	}
	if resTrunc.Nodes[0].Properties["skill_count"] != 2 || resTrunc.Nodes[0].Properties["content_truncated"] != true {
		t.Fatalf("truncated props = %+v", resTrunc.Nodes[0].Properties)
	}
}

func TestA2ACollect_TLSRedirectsAndMapping(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/agent-card.json" {
			_, _ = w.Write([]byte(`{"name":"TLSAgent","skills":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tlsSrv.Close()

	// Strict TLS fails cleanly.
	cfgStrict := baseCfg()
	resFail, err := a2a.New(cfgStrict).Collect(context.Background(), tlsSrv.URL, "a2a-scope", "vantage-a2a", "s-tls1", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resFail.Observation.Coverage != graph.CoverageFailed || len(resFail.Nodes) != 0 {
		t.Fatalf("TLS failure must fail without nodes")
	}
	hasTLSRec := false
	for _, ev := range resFail.Evidence {
		if ev.RecordType == evidence.RecordTLS && ev.VerificationResult == "failed" {
			hasTLSRec = true
		}
	}
	if !hasTLSRec {
		t.Fatalf("expected failed TLS evidence record")
	}

	// Insecure override succeeds and attaches via mapping file without NetworkEndpoint fallback.
	cfgInsecure := baseCfg()
	cfgInsecure.Insecure = true
	resolver, err := correlate.New([]correlate.Mapping{{Target: "127.0.0.1", ObjectID: "S-1-5-21-1-1001", Kind: "Computer"}})
	if err != nil {
		t.Fatal(err)
	}
	resOK, err := a2a.New(cfgInsecure).Collect(context.Background(), tlsSrv.URL, "a2a-scope", "vantage-a2a", "s-tls2", now, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if resOK.Observation.Coverage != graph.CoverageComplete || resOK.Nodes[0].Properties["tls_verification"] != "insecure_override" {
		t.Fatalf("insecure override props = %+v", resOK.Nodes[0].Properties)
	}
	for _, n := range resOK.Nodes {
		if n.Node.Identity().Kind() == graph.NetworkEndpoint {
			t.Fatalf("mapped target must not emit NetworkEndpoint fallback")
		}
	}
	if len(resOK.Edges) == 0 || !resOK.Edges[len(resOK.Edges)-1].TouchesNative() {
		t.Fatalf("expected native ObservedAt edge")
	}

	// Cross-host redirect refused cleanly.
	extSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer extSrv.Close()
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, extSrv.URL+"/.well-known/agent-card.json", http.StatusFound)
	}))
	defer redirSrv.Close()

	cfgRedir := baseCfg()
	cfgRedir.Bounds.MaxRedirects = 2
	resRedir, err := a2a.New(cfgRedir, a2a.WithTransport(transport.NewClient(transport.Config{Bounds: cfgRedir.Bounds}))).
		Collect(context.Background(), redirSrv.URL, "a2a-scope", "vantage-a2a", "s-redir", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resRedir.Observation.Coverage != graph.CoverageFailed || len(resRedir.Nodes) != 0 {
		t.Fatalf("unauthorized cross-host redirect must fail without nodes")
	}
}
