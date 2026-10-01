package ollama_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/ollama"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/transport"
)

func helperVantage(t *testing.T, scope, key string) graph.Identity {
	t.Helper()
	v, err := graph.NewVantageIdentity(scope, key)
	if err != nil {
		t.Fatalf("failed to create vantage identity: %v", err)
	}
	return v
}

func TestOllama_AnonymousHappyPath(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"models": [
					{
						"name": "llama3:latest",
						"model": "llama3:latest",
						"modified_at": "2024-05-01T12:00:00Z",
						"size": 4661224676,
						"digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
						"details": {
							"format": "gguf",
							"family": "llama",
							"families": ["llama"],
							"parameter_size": "8.0B",
							"quantization_level": "Q4_0"
						}
					},
					{
						"name": "mistral:7b",
						"size": 4109849200,
						"digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
						"details": {
							"format": "gguf",
							"family": "mistral",
							"parameter_size": "7.2B",
							"quantization_level": "Q4_K_M"
						}
					}
				]
			}`))
		case "/api/ps":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"models": [
					{
						"name": "llama3:latest",
						"size_vram": 4661224676,
						"expires_at": "2026-10-01T13:00:00Z"
					}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"

	collector := ollama.New(cfg)
	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	res, err := collector.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected collection error: %v", err)
	}

	// Verify target status and coverage
	if res.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("expected TargetStatusCompleted, got %s", res.Status)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("expected CoverageComplete, got %s", res.Observation.Coverage)
	}
	if res.Observation.CoverageReason != "" {
		t.Errorf("expected empty CoverageReason on complete coverage, got %q", res.Observation.CoverageReason)
	}

	// Verify nodes
	// Expect 1 OllamaInstance + 2 AIModel + 1 fallback NetworkEndpoint = 4 nodes
	var srvItem *emitter.NodeItem
	var llamaItem *emitter.NodeItem
	var mistralItem *emitter.NodeItem
	var netItem *emitter.NodeItem

	for i := range res.Nodes {
		n := &res.Nodes[i]
		switch n.Node.Identity().Kind() {
		case graph.OllamaInstance:
			srvItem = n
		case graph.AIModel:
			name := n.Properties["name"].(string)
			if strings.Contains(name, "LLAMA3") {
				llamaItem = n
			} else if strings.Contains(name, "MISTRAL") {
				mistralItem = n
			}
		case graph.NetworkEndpoint:
			netItem = n
		}
	}

	if srvItem == nil {
		t.Fatalf("expected OllamaInstance node")
	}
	if srvItem.Properties["product"] != "Ollama" {
		t.Errorf("expected product Ollama, got %v", srvItem.Properties["product"])
	}
	if srvItem.Properties["software_version"] != "0.3.12" {
		t.Errorf("expected software_version 0.3.12, got %v", srvItem.Properties["software_version"])
	}

	if llamaItem == nil {
		t.Fatalf("expected llama3 AIModel node")
	}
	if llamaItem.Properties["format"] != "gguf" || llamaItem.Properties["family"] != "llama" {
		t.Errorf("unexpected llama properties: %v", llamaItem.Properties)
	}
	if llamaItem.Properties["running"] != true {
		t.Errorf("expected llama3 to be marked running from /api/ps")
	}

	if mistralItem == nil {
		t.Fatalf("expected mistral AIModel node")
	}
	if netItem == nil {
		t.Fatalf("expected fallback NetworkEndpoint node")
	}

	// Verify edges
	var hasAccessEdge bool
	var providesModelCount int
	var hasObservedAtEdge bool

	for _, e := range res.Edges {
		switch e.Kind() {
		case graph.UnauthenticatedAccess:
			hasAccessEdge = true
			if e.Start().ID() != vantage.ID() || e.End().ID() != srvItem.Node.Identity().ID() {
				t.Errorf("access edge endpoints mismatch")
			}
		case graph.ProvidesModel:
			providesModelCount++
			if e.Start().ID() != srvItem.Node.Identity().ID() {
				t.Errorf("providesModel start is not service ID")
			}
		case graph.ObservedAt:
			hasObservedAtEdge = true
			if e.Start().ID() != srvItem.Node.Identity().ID() || e.End().ID() != netItem.Node.Identity().ID() {
				t.Errorf("observedAt edge endpoints mismatch")
			}
		}
	}

	if !hasAccessEdge {
		t.Errorf("expected UnauthenticatedAccess edge")
	}
	if providesModelCount != 2 {
		t.Errorf("expected 2 ProvidesModel edges, got %d", providesModelCount)
	}
	if !hasObservedAtEdge {
		t.Errorf("expected ObservedAt edge")
	}

	// Verify evidence records
	var hasFpRecord bool
	var hasTagsCheckRecord bool
	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordFingerprint {
			hasFpRecord = true
			if ev.SoftwareVersion != "0.3.12" {
				t.Errorf("expected fingerprint version 0.3.12, got %s", ev.SoftwareVersion)
			}
		}
		if ev.RecordType == evidence.RecordCheckResult && ev.CheckID == ollama.CheckTags {
			hasTagsCheckRecord = true
			if ev.Outcome != string(graph.OutcomeSuccess) {
				t.Errorf("expected tags outcome success, got %s", ev.Outcome)
			}
			if ev.Anonymous == nil || !*ev.Anonymous {
				t.Errorf("expected anonymous true on tags check")
			}
		}
	}
	if !hasFpRecord {
		t.Errorf("expected Fingerprint evidence record")
	}
	if !hasTagsCheckRecord {
		t.Errorf("expected Tags check evidence record")
	}
}

func TestOllama_VersionFailurePartialCoverage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			http.NotFound(w, r) // 404 on version
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"

	collector := ollama.New(cfg)
	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	res, err := collector.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Status != checkpoint.TargetStatusPartial {
		t.Errorf("expected TargetStatusPartial, got %s", res.Status)
	}
	if res.Observation.Coverage != graph.CoveragePartial {
		t.Errorf("expected CoveragePartial, got %s", res.Observation.Coverage)
	}
	if res.Observation.CoverageReason == "" {
		t.Errorf("expected non-empty CoverageReason on partial coverage")
	}

	// Service node should not have software_version
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.OllamaInstance {
			if _, ok := n.Properties["software_version"]; ok {
				t.Errorf("expected software_version not set on version failure")
			}
		}
	}

	// Access edge is still preserved because tags succeeded
	var hasAccessEdge bool
	for _, e := range res.Edges {
		if e.Kind() == graph.UnauthenticatedAccess {
			hasAccessEdge = true
		}
	}
	if !hasAccessEdge {
		t.Errorf("expected UnauthenticatedAccess edge when tags succeeds")
	}
}

func TestOllama_TagsDeniedAccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.WriteHeader(http.StatusUnauthorized) // 401 Unauthorized
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"

	collector := ollama.New(cfg)
	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	res, err := collector.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Status != checkpoint.TargetStatusPartial {
		t.Errorf("expected TargetStatusPartial, got %s", res.Status)
	}
	if res.Observation.Coverage != graph.CoveragePartial {
		t.Errorf("expected CoveragePartial, got %s", res.Observation.Coverage)
	}

	// NO UnauthenticatedAccess edge
	for _, e := range res.Edges {
		if e.Kind() == graph.UnauthenticatedAccess {
			t.Errorf("must NOT emit UnauthenticatedAccess edge when tags check is denied")
		}
		if e.Kind() == graph.ProvidesModel {
			t.Errorf("must NOT emit ProvidesModel edges when tags check is denied")
		}
	}

	// NO AIModel nodes
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.AIModel {
			t.Errorf("must NOT emit AIModel nodes when tags check is denied")
		}
	}
}

func TestOllama_Truncation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"models": [
					{"name":"m1"}, {"name":"m2"}, {"name":"m3"}, {"name":"m4"}, {"name":"m5"}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.Bounds.MaxItems = 2 // Cap at 2 models

	collector := ollama.New(cfg)
	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	res, err := collector.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Observation.Coverage != graph.CoverageTruncated {
		t.Errorf("expected CoverageTruncated, got %s", res.Observation.Coverage)
	}
	if res.Status != checkpoint.TargetStatusPartial {
		t.Errorf("expected TargetStatusPartial on truncation, got %s", res.Status)
	}
	if !strings.Contains(res.Observation.CoverageReason, "max_items") {
		t.Errorf("expected coverage reason to mention max_items, got %q", res.Observation.CoverageReason)
	}

	modelCount := 0
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.AIModel {
			modelCount++
		}
	}
	if modelCount != 2 {
		t.Errorf("expected exactly 2 models emitted, got %d", modelCount)
	}
}

func TestOllama_OptInSensitiveMetadata(t *testing.T) {
	showCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		case "/api/show":
			showCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"modelfile": "FROM llama3\nSYSTEM You are helpful",
				"template": "{{ .Prompt }}",
				"system": "You are helpful"
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ctx := context.Background()
	vantage := helperVantage(t, "corp-scope", "vantage-01")
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	// 1. Default policy (opt-in = false): /api/show must NOT be called
	cfgDefault := config.Defaults()
	cfgDefault.Scope = "corp-scope"
	cfgDefault.VantageKey = "vantage-01"

	collectorDefault := ollama.New(cfgDefault)
	res, err := collectorDefault.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if showCalled {
		t.Errorf("show endpoint must NOT be called when opt-in is false")
	}

	// Check that check_id ollama_show was marked skipped
	var hasSkippedShow bool
	for _, cr := range res.Evidence {
		if cr.CheckID == ollama.CheckShow && cr.Outcome == string(graph.OutcomeSkipped) {
			hasSkippedShow = true
		}
	}
	if !hasSkippedShow {
		t.Errorf("expected ollama_show check to be recorded as skipped")
	}

	// 2. Opt-in enabled: /api/show IS called
	cfgOptIn := config.Defaults()
	cfgOptIn.Scope = "corp-scope"
	cfgOptIn.VantageKey = "vantage-01"
	cfgOptIn.OptIns.Prompts = true

	collectorOptIn := ollama.New(cfgOptIn)
	res, err = collectorOptIn.Collect(ctx, ts.URL, vantage, "scan-002", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !showCalled {
		t.Errorf("show endpoint must be called when OptIns.Prompts is true")
	}

	var hasSuccessShow bool
	for _, cr := range res.Evidence {
		if cr.CheckID == ollama.CheckShow && cr.Outcome == string(graph.OutcomeSuccess) {
			hasSuccessShow = true
		}
	}
	if !hasSuccessShow {
		t.Errorf("expected ollama_show check to be recorded as success with opt-in")
	}
}

func TestOllama_TargetUnreachable(t *testing.T) {
	// Point to an unused local port
	badURL := "http://127.0.0.1:49999"

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.Bounds.ConnectTimeout = 100 * time.Millisecond
	cfg.Bounds.ResponseTimeout = 200 * time.Millisecond

	collector := ollama.New(cfg)
	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	res, err := collector.Collect(ctx, badURL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error from Collect: %v", err)
	}

	if res.Status != checkpoint.TargetStatusFailed {
		t.Errorf("expected TargetStatusFailed, got %s", res.Status)
	}
	if res.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("expected CoverageFailed, got %s", res.Observation.Coverage)
	}
	if !strings.Contains(res.Observation.CoverageReason, "unreachable") && !strings.Contains(res.Observation.CoverageReason, "connection") {
		t.Errorf("expected unreachable/connection reason, got %q", res.Observation.CoverageReason)
	}
}

func TestOllama_ComputerCorrelation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.Targets = []string{"ollama.corp.local"}
	cfg.Correlation.ADDomainSuffixes = []string{"corp.local"}

	// Set up correlation resolver
	resolver, err := correlate.NewFromConfig(cfg, nil, true)
	if err != nil {
		t.Fatalf("failed to create correlation resolver: %v", err)
	}

	verifiedComputers := []correlate.Computer{
		{
			ObjectID: "S-1-5-21-123456789-1001",
			Name:     "OLLAMA.CORP.LOCAL",
		},
	}

	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	// 1. Test verified correlation match with custom dialer routing to ts.Listener
	customTransport := transport.NewClient(transport.Config{
		Bounds: cfg.Bounds,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, ts.Listener.Addr().String())
		},
	})
	collectorVerified := ollama.New(cfg, ollama.WithTransport(customTransport))

	resVerified, err := collectorVerified.Collect(ctx, "http://ollama.corp.local:11434", vantage, "scan-001", now, resolver, verifiedComputers)
	if err != nil {
		t.Fatalf("unexpected error on verified target: %v", err)
	}

	var hasLinkingEdge bool
	for _, e := range resVerified.Edges {
		if e.Kind() == graph.ObservedAt && e.TouchesNative() {
			hasLinkingEdge = true
		}
	}
	if !hasLinkingEdge {
		t.Errorf("expected native Computer linking edge for verified correlation")
	}

	// 2. Test fallback on uncorrelated target (127.0.0.1)
	resFallback, err := collectorVerified.Collect(ctx, ts.URL, vantage, "scan-002", now, resolver, verifiedComputers)
	if err != nil {
		t.Fatalf("unexpected error on fallback target: %v", err)
	}

	var hasNetworkFallback bool
	for _, n := range resFallback.Nodes {
		if n.Node.Identity().Kind() == graph.NetworkEndpoint {
			hasNetworkFallback = true
		}
	}
	if !hasNetworkFallback {
		t.Errorf("expected fallback NetworkEndpoint for uncorrelated 127.0.0.1 target")
	}
}

func TestOllama_CheckpointJournalAndEmissionRoundtrip(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"models": [
					{
						"name": "llama3:latest",
						"digest": "sha256:0123456789abcdef",
						"size": 4661224676
					}
				]
			}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	journalPath := filepath.Join(tempDir, "scan.journal.jsonl")

	journalFile, err := os.OpenFile(journalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("failed to open journal file: %v", err)
	}

	header := checkpoint.Header{
		SchemaVersion:    "1",
		DeploymentScope:  "corp-scope",
		ScanID:           "scan-journal-test",
		CollectorVersion: "0.1.0",
		VantageKey:       "vantage-dc01",
		CreatedAt:        "2026-10-01T12:00:00Z",
	}

	j, err := checkpoint.NewWriter(journalFile, header)
	if err != nil {
		t.Fatalf("failed to create journal writer: %v", err)
	}

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-dc01"

	collector := ollama.New(cfg)
	ctx := context.Background()

	// 1. Collect to journal
	res, err := collector.CollectToJournal(ctx, ts.URL, j, nil, nil)
	if err != nil {
		t.Fatalf("CollectToJournal failed: %v", err)
	}
	if res.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("expected TargetStatusCompleted, got %s", res.Status)
	}

	if err := j.Close(); err != nil {
		t.Fatalf("failed to close journal: %v", err)
	}
	_ = journalFile.Close()

	// 2. Replay journal
	readJournal, err := os.Open(journalPath)
	if err != nil {
		t.Fatalf("failed to open journal for reading: %v", err)
	}
	defer readJournal.Close()

	state, err := checkpoint.Replay(readJournal)
	if err != nil {
		t.Fatalf("journal replay failed: %v", err)
	}

	if !state.IsCompleted(ts.URL, ollama.Surface) {
		t.Errorf("expected state.IsCompleted to be true for target %s surface %s", ts.URL, ollama.Surface)
	}
	if len(state.Nodes()) < 2 {
		t.Errorf("expected at least 2 nodes in replay state, got %d", len(state.Nodes()))
	}

	// 3. Emit OpenGraph payload and evidence sidecar
	artifacts, err := emitter.EmitScan(tempDir, "llmhound-test", state.Nodes(), state.Edges(), state.Evidence())
	if err != nil {
		t.Fatalf("EmitScan failed: %v", err)
	}

	if _, err := os.Stat(artifacts.BasePayloadPath); err != nil {
		t.Fatalf("base payload file missing: %v", err)
	}
	if _, err := os.Stat(artifacts.EvidenceSidecarPath); err != nil {
		t.Fatalf("evidence sidecar file missing: %v", err)
	}

	// Verify base payload content
	payloadData, err := os.ReadFile(artifacts.BasePayloadPath)
	if err != nil {
		t.Fatalf("failed to read payload: %v", err)
	}

	var payload emitter.Payload
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}

	if payload.Metadata == nil || payload.Metadata.SourceKind != "LLMHound" {
		t.Errorf("payload metadata source_kind missing or incorrect")
	}
	if len(payload.Graph.Nodes) < 2 {
		t.Errorf("expected at least 2 nodes in payload graph, got %d", len(payload.Graph.Nodes))
	}
	if len(payload.Graph.Edges) < 2 {
		t.Errorf("expected at least 2 edges in payload graph, got %d", len(payload.Graph.Edges))
	}
}

func TestOllama_HTMLResponseFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>Welcome to nginx</body></html>`))
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"

	collector := ollama.New(cfg)
	ctx := context.Background()
	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	res, err := collector.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Status != checkpoint.TargetStatusFailed {
		t.Errorf("expected TargetStatusFailed on HTML response, got %s", res.Status)
	}
	if res.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("expected CoverageFailed on HTML response, got %s", res.Observation.Coverage)
	}
	if !strings.Contains(res.Observation.CoverageReason, "failed") {
		t.Errorf("expected coverage reason to mention failure, got %q", res.Observation.CoverageReason)
	}
}

func TestOllama_TLSVerification(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ctx := context.Background()
	vantage := helperVantage(t, "corp-scope", "vantage-01")
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	// 1. Strict TLS (insecure = false): self-signed cert should fail verification
	cfgStrict := config.Defaults()
	cfgStrict.Scope = "corp-scope"
	cfgStrict.VantageKey = "vantage-01"
	cfgStrict.Insecure = false

	collectorStrict := ollama.New(cfgStrict)
	res, err := collectorStrict.Collect(ctx, ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != checkpoint.TargetStatusFailed {
		t.Errorf("expected TargetStatusFailed for unverified TLS cert, got %s", res.Status)
	}

	// Verify TLS failure record was created
	var hasTLSRecord bool
	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordTLS {
			hasTLSRecord = true
			if ev.VerificationResult != "failed" {
				t.Errorf("expected verification_result failed, got %q", ev.VerificationResult)
			}
			if ev.CertFingerprint == "" {
				t.Errorf("expected captured cert fingerprint")
			}
		}
	}
	if !hasTLSRecord {
		t.Errorf("expected TLS record on verification failure")
	}

	// 2. Explicit insecure override (insecure = true)
	cfgInsecure := config.Defaults()
	cfgInsecure.Scope = "corp-scope"
	cfgInsecure.VantageKey = "vantage-01"
	cfgInsecure.Insecure = true

	collectorInsecure := ollama.New(cfgInsecure)
	resInsecure, err := collectorInsecure.Collect(ctx, ts.URL, vantage, "scan-002", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error with Insecure=true: %v", err)
	}
	if resInsecure.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("expected TargetStatusCompleted with Insecure=true, got %s", resInsecure.Status)
	}

	// Verify service properties reflect unverified_override
	for _, n := range resInsecure.Nodes {
		if n.Node.Identity().Kind() == graph.OllamaInstance {
			if n.Properties["tls_verification"] != "unverified_override" {
				t.Errorf("expected tls_verification unverified_override, got %v", n.Properties["tls_verification"])
			}
		}
	}
}

func TestOllama_SafetyRejectsGeneration(t *testing.T) {
	// Directly test that any mutating/generation paths are forbidden
	forbidden := []string{
		"/api/generate",
		"/api/chat",
		"/api/embeddings",
		"/api/pull",
		"/api/push",
		"/api/create",
		"/api/delete",
		"/api/copy",
		"/api/blobs",
	}

	for _, p := range forbidden {
		if err := transport.CheckSafety(http.MethodGet, p); err == nil {
			t.Errorf("expected CheckSafety error for GET %s", p)
		}
		if err := transport.CheckSafety(http.MethodPost, p); err == nil {
			t.Errorf("expected CheckSafety error for POST %s", p)
		}
	}
}


func TestOllama_ShowRecordsOnlyRedactedProvenance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"tuned:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/show":
			_, _ = w.Write([]byte(`{
				"modelfile": "FROM llama3\nSYSTEM SECRET-MODELFILE-TOKEN",
				"template": "SECRET-TEMPLATE-TOKEN {{ .Prompt }}",
				"system": "SECRET-SYSTEM-TOKEN",
				"parameters": "SECRET-PARAMETERS-TOKEN",
				"license": "Apache License 2.0",
				"details": {"parent_model": "llama3:8b", "family": "llama"}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.OptIns.Prompts = true

	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res, err := ollama.New(cfg).Collect(context.Background(), ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("expected complete coverage, got %s (%s)", res.Observation.Coverage, res.Observation.CoverageReason)
	}

	var props map[string]any
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.AIModel {
			props = n.Properties
		}
	}
	if props == nil {
		t.Fatalf("expected an AIModel node")
	}
	if props["parent_model"] != "llama3:8b" || props["family"] != "llama" || props["license"] != "Apache License 2.0" {
		t.Errorf("expected provenance on model node, got %v", props)
	}

	persisted, err := json.Marshal(struct {
		Nodes    any
		Evidence any
	}{Nodes: nodeProps(res), Evidence: res.Evidence})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"SECRET-MODELFILE-TOKEN", "SECRET-TEMPLATE-TOKEN", "SECRET-SYSTEM-TOKEN", "SECRET-PARAMETERS-TOKEN"} {
		if strings.Contains(string(persisted), secret) {
			t.Errorf("sensitive show content %q must not be persisted", secret)
		}
	}
}

func nodeProps(res checkpoint.Result) []map[string]any {
	var out []map[string]any
	for _, n := range res.Nodes {
		out = append(out, n.Properties)
	}
	return out
}

func TestOllama_PSAndShowFailuresDowngradeCoverage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"a"},{"name":"b"}]}`))
		case "/api/ps":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/show":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.OptIns.Prompts = true

	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res, err := ollama.New(cfg).Collect(context.Background(), ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Observation.Coverage != graph.CoveragePartial || res.Status != checkpoint.TargetStatusPartial {
		t.Errorf("expected partial coverage/status, got %s/%s", res.Observation.Coverage, res.Status)
	}
	if !strings.Contains(res.Observation.CoverageReason, "running models") || !strings.Contains(res.Observation.CoverageReason, "provenance") {
		t.Errorf("expected reason to name ps and show degradation, got %q", res.Observation.CoverageReason)
	}
}

func TestOllama_TruncatedTagsBodyReportedAsTruncation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"` + strings.Repeat("x", 4096) + `"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.Bounds.MaxResponseBytes = 256

	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res, err := ollama.New(cfg).Collect(context.Background(), ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var reason string
	for _, r := range res.Evidence {
		if r.CheckID == ollama.CheckTags {
			reason = r.Reason
		}
	}
	if !strings.Contains(reason, "truncated") {
		t.Errorf("expected tags outcome to report truncation, got %q", reason)
	}
}

func TestOllama_PSBoundedByMaxItems(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"a"},{"name":"b"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"a"},{"name":"b"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.Bounds.MaxItems = 1

	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res, err := ollama.New(cfg).Collect(context.Background(), ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	running := 0
	for _, n := range res.Nodes {
		if n.Properties["running"] == true {
			running++
		}
	}
	if running > 1 {
		t.Errorf("running models must be bounded by max_items, got %d", running)
	}
}

func TestOllama_ShowTruncatedBodyReportedAsTruncation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.3.12"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"a"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/show":
			_, _ = w.Write([]byte(`{"license":"MIT","model_info":"` + strings.Repeat("x", 4096) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-01"
	cfg.OptIns.Prompts = true
	cfg.Bounds.MaxResponseBytes = 256

	vantage := helperVantage(t, cfg.Scope, cfg.VantageKey)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res, err := ollama.New(cfg).Collect(context.Background(), ts.URL, vantage, "scan-001", now, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var reason string
	for _, r := range res.Evidence {
		if r.CheckID == ollama.CheckShow {
			reason = r.Reason
		}
	}
	if !strings.Contains(reason, "truncated") {
		t.Errorf("expected show outcome to report truncation, got %q", reason)
	}
}
