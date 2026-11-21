package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	collectormcp "github.com/0x3df/LLMHound/internal/collectors/mcp"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func testConfig() config.Config {
	cfg := config.Defaults()
	cfg.Scope = "test-deployment"
	cfg.VantageKey = "test-vantage"
	cfg.Targets = []string{"127.0.0.1"}
	return cfg
}

func setupTestMCPServer(t *testing.T) *mcpsdk.Server {
	t.Helper()
	impl := &mcpsdk.Implementation{
		Name:    "demo-mcp-server",
		Version: "1.2.3",
		Title:   "Demo MCP Server",
	}

	srv := mcpsdk.NewServer(impl, nil)

	srv.AddTool(&mcpsdk.Tool{
		Name:        "calculator",
		Description: "Performs mathematical calculations",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"expression": map[string]any{"type": "string"},
			},
		},
		Annotations: &mcpsdk.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		t.Fatal("CallTool must never be called during read-only enumeration!")
		return nil, nil
	})

	srv.AddResource(&mcpsdk.Resource{
		URI:         "file:///etc/hosts",
		Name:        "hosts",
		Description: "Hosts file descriptor",
		MIMEType:    "text/plain",
		Size:        1024,
	}, func(ctx context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		t.Fatal("ReadResource must never be called: resource descriptors authorize metadata only!")
		return nil, nil
	})

	srv.AddPrompt(&mcpsdk.Prompt{
		Name:        "code_review",
		Description: "Reviews code changes for security issues",
		Arguments: []*mcpsdk.PromptArgument{
			{Name: "diff", Description: "Git diff content"},
		},
	}, func(ctx context.Context, req *mcpsdk.GetPromptRequest) (*mcpsdk.GetPromptResult, error) {
		t.Fatal("GetPrompt must never be called during metadata enumeration!")
		return nil, nil
	})

	return srv
}

func TestMCPCollector_StreamableHTTP_Success(t *testing.T) {
	srv := setupTestMCPServer(t)
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	fixedTime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	collector, err := collectormcp.New(
		cfg,
		collectormcp.WithClock(func() time.Time { return fixedTime }),
		collectormcp.WithScanID("scan-test-001"),
		collectormcp.WithEvidenceID("ev-test-001"),
	)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	target := collectormcp.Target{
		URL:            ts.URL + "/mcp",
		OriginalTarget: ts.Listener.Addr().String(),
		Transport:      "streamable",
	}

	result, err := collector.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Verify surface coverage and status
	if result.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("expected CoverageComplete, got %q (reason: %s)", result.Observation.Coverage, result.Observation.CoverageReason)
	}
	if result.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("expected TargetStatusCompleted, got %q", result.Status)
	}

	// Verify nodes
	var srvNode *emitter.NodeItem
	var toolNodes []emitter.NodeItem
	var resNodes []emitter.NodeItem
	var promptNodes []emitter.NodeItem
	var fallbackNodes []emitter.NodeItem

	for _, n := range result.Nodes {
		switch n.Node.Identity().Kind() {
		case graph.MCPServer:
			nodeCopy := n
			srvNode = &nodeCopy
		case graph.MCPTool:
			toolNodes = append(toolNodes, n)
		case graph.MCPResource:
			resNodes = append(resNodes, n)
		case graph.MCPPrompt:
			promptNodes = append(promptNodes, n)
		case graph.NetworkEndpoint:
			fallbackNodes = append(fallbackNodes, n)
		default:
			t.Errorf("unexpected node kind: %s", n.Node.Identity().Kind())
		}
	}

	if srvNode == nil {
		t.Fatal("expected MCPServer node, got nil")
	}

	// Verify MCPServer node properties
	props := srvNode.Properties
	if props["product"] != "demo-mcp-server" {
		t.Errorf("expected product 'demo-mcp-server', got %v", props["product"])
	}
	if props["software_version_raw"] != "1.2.3" {
		t.Errorf("expected software_version_raw '1.2.3', got %v", props["software_version_raw"])
	}
	if props["protocol_version"] == nil || props["protocol_version"] == "" {
		t.Errorf("expected non-empty protocol_version, got %v", props["protocol_version"])
	}
	if props["software_version_raw"] == props["protocol_version"] {
		t.Errorf("version and protocol_version should be distinct")
	}

	// Verify MCPServer has AIService kind
	kinds := srvNode.Node.Kinds()
	if len(kinds) != 2 || kinds[0] != graph.MCPServer || kinds[1] != graph.AIService {
		t.Errorf("expected kinds [MCPServer, AIService], got %v", kinds)
	}

	// Verify tools, resources, prompts
	if len(toolNodes) != 1 {
		t.Fatalf("expected 1 tool node, got %d", len(toolNodes))
	}
	if toolNodes[0].Properties["tool_name"] != "calculator" {
		t.Errorf("expected tool_name 'calculator', got %v", toolNodes[0].Properties["tool_name"])
	}

	if len(resNodes) != 1 {
		t.Fatalf("expected 1 resource node, got %d", len(resNodes))
	}
	if resNodes[0].Properties["uri"] != "file:///etc/hosts" {
		t.Errorf("expected resource uri 'file:///etc/hosts', got %v", resNodes[0].Properties["uri"])
	}

	if len(promptNodes) != 1 {
		t.Fatalf("expected 1 prompt node, got %d", len(promptNodes))
	}
	if promptNodes[0].Properties["prompt_name"] != "code_review" {
		t.Errorf("expected prompt_name 'code_review', got %v", promptNodes[0].Properties["prompt_name"])
	}

	// Verify fallback NetworkEndpoint
	if len(fallbackNodes) != 1 {
		t.Fatalf("expected 1 fallback NetworkEndpoint node, got %d", len(fallbackNodes))
	}

	// Verify edges
	var hasObservedAt, hasProvidesTool, hasProvidesResource, hasProvidesPrompt, hasUnauthenticatedAccess bool
	for _, e := range result.Edges {
		if e.IsTraversable() {
			t.Errorf("all v1 edges must be non-traversable, edge %s is traversable", e.Kind())
		}
		switch e.Kind() {
		case graph.ObservedAt:
			hasObservedAt = true
			if e.Start().ID() != srvNode.Node.Identity().ID() {
				t.Errorf("ObservedAt start must be MCPServer")
			}
		case graph.ProvidesTool:
			hasProvidesTool = true
		case graph.ProvidesResource:
			hasProvidesResource = true
		case graph.ProvidesPrompt:
			hasProvidesPrompt = true
		case graph.UnauthenticatedAccess:
			hasUnauthenticatedAccess = true
			if e.End().ID() != srvNode.Node.Identity().ID() {
				t.Errorf("UnauthenticatedAccess end must be MCPServer")
			}
			acc, ok := e.AccessEvidence()
			if !ok || !acc.Anonymous || acc.Outcome != graph.OutcomeSuccess || acc.OperationKind != graph.EnumerationOperation {
				t.Errorf("invalid access evidence on UnauthenticatedAccess edge: %+v", acc)
			}
		}
	}

	if !hasObservedAt {
		t.Error("missing ObservedAt edge")
	}
	if !hasProvidesTool {
		t.Error("missing ProvidesTool edge")
	}
	if !hasProvidesResource {
		t.Error("missing ProvidesResource edge")
	}
	if !hasProvidesPrompt {
		t.Error("missing ProvidesPrompt edge")
	}
	if !hasUnauthenticatedAccess {
		t.Error("missing UnauthenticatedAccess edge")
	}

	// Verify evidence records
	var hasInitCheck, hasToolsCheck, hasResourcesCheck, hasPromptsCheck, hasRFC9728Check, hasFingerprint bool
	for _, ev := range result.Evidence {
		if err := ev.Validate(); err != nil {
			t.Errorf("evidence record failed validation: %v", err)
		}
		switch ev.RecordType {
		case evidence.RecordCheckResult:
			switch ev.CheckID {
			case collectormcp.CheckIDInitialize:
				hasInitCheck = true
				if ev.Outcome != string(graph.OutcomeSuccess) {
					t.Errorf("initialize check outcome = %s, want success", ev.Outcome)
				}
				if ev.Anonymous == nil || !*ev.Anonymous {
					t.Errorf("initialize check must record anonymous = true")
				}
			case collectormcp.CheckIDToolsList:
				hasToolsCheck = true
				if ev.Outcome != string(graph.OutcomeSuccess) {
					t.Errorf("tools check outcome = %s, want success", ev.Outcome)
				}
			case collectormcp.CheckIDResourcesList:
				hasResourcesCheck = true
				if ev.Outcome != string(graph.OutcomeSuccess) {
					t.Errorf("resources check outcome = %s, want success", ev.Outcome)
				}
			case collectormcp.CheckIDPromptsList:
				hasPromptsCheck = true
				if ev.Outcome != string(graph.OutcomeSuccess) {
					t.Errorf("prompts check outcome = %s, want success", ev.Outcome)
				}
			case collectormcp.CheckIDRFC9728:
				hasRFC9728Check = true
				if ev.Outcome != string(graph.OutcomeSkipped) {
					t.Errorf("RFC9728 check outcome = %s, want skipped", ev.Outcome)
				}
			}
		case evidence.RecordFingerprint:
			hasFingerprint = true
			if ev.Product != "demo-mcp-server" || ev.SoftwareVersionRaw != "1.2.3" {
				t.Errorf("fingerprint mismatch: product=%s, version=%s", ev.Product, ev.SoftwareVersionRaw)
			}
		}
	}

	if !hasInitCheck || !hasToolsCheck || !hasResourcesCheck || !hasPromptsCheck || !hasRFC9728Check {
		t.Errorf("missing check results: init=%v, tools=%v, resources=%v, prompts=%v, rfc9728=%v",
			hasInitCheck, hasToolsCheck, hasResourcesCheck, hasPromptsCheck, hasRFC9728Check)
	}
	if !hasFingerprint {
		t.Error("missing fingerprint evidence record")
	}
}

func TestMCPCollector_SSE_Success(t *testing.T) {
	srv := setupTestMCPServer(t)
	handler := mcpsdk.NewSSEHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	target := collectormcp.Target{
		URL:            ts.URL + "/sse",
		OriginalTarget: ts.Listener.Addr().String(),
		Transport:      "sse",
	}

	result, err := collector.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("Collect over SSE failed: %v", err)
	}

	if result.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("expected CoverageComplete over SSE, got %q (reason: %s)", result.Observation.Coverage, result.Observation.CoverageReason)
	}
	if len(result.Nodes) < 4 {
		t.Errorf("expected at least 4 nodes (server, tool, resource, prompt), got %d", len(result.Nodes))
	}
}

func TestMCPCollector_MissingCapabilities_SkippedHonesty(t *testing.T) {
	// Server advertises ONLY tools, no resources or prompts
	impl := &mcpsdk.Implementation{Name: "tools-only-server", Version: "0.1.0"}
	srv := mcpsdk.NewServer(impl, nil)
	srv.AddTool(&mcpsdk.Tool{
		Name:        "ping",
		Description: "Ping tool",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		return nil, nil
	})

	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	target := collectormcp.Target{
		URL: ts.URL + "/mcp",
	}

	result, err := collector.Collect(context.Background(), target)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if result.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("expected CoverageComplete when unadvertised capabilities skipped cleanly, got %q", result.Observation.Coverage)
	}

	checkMap := make(map[string]evidence.Record)
	for _, ev := range result.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			checkMap[ev.CheckID] = ev
		}
	}

	if checkMap[collectormcp.CheckIDToolsList].Outcome != string(graph.OutcomeSuccess) {
		t.Errorf("tools check expected success, got %s", checkMap[collectormcp.CheckIDToolsList].Outcome)
	}
	if checkMap[collectormcp.CheckIDResourcesList].Outcome != string(graph.OutcomeSkipped) {
		t.Errorf("resources check expected skipped, got %s", checkMap[collectormcp.CheckIDResourcesList].Outcome)
	}
	if checkMap[collectormcp.CheckIDPromptsList].Outcome != string(graph.OutcomeSkipped) {
		t.Errorf("prompts check expected skipped, got %s", checkMap[collectormcp.CheckIDPromptsList].Outcome)
	}
}

func TestMCPCollector_BoundedPagination_MaxItems(t *testing.T) {
	impl := &mcpsdk.Implementation{Name: "lots-of-tools-server", Version: "1.0.0"}
	srv := mcpsdk.NewServer(impl, nil)

	// Add 5 tools
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("tool_%d", i)
		srv.AddTool(&mcpsdk.Tool{
			Name:        name,
			Description: fmt.Sprintf("Tool number %d", i),
			InputSchema: map[string]any{"type": "object"},
		}, func(ctx context.Context, req *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			return nil, nil
		})
	}

	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	cfg.Bounds.MaxItems = 2 // Cap items to 2

	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if result.Observation.Coverage != graph.CoverageTruncated {
		t.Errorf("expected CoverageTruncated, got %q", result.Observation.Coverage)
	}
	if result.Status != checkpoint.TargetStatusPartial {
		t.Errorf("expected TargetStatusPartial when truncated, got %q", result.Status)
	}
	if !strings.Contains(result.Observation.CoverageReason, "item limit") {
		t.Errorf("expected coverage reason to mention item limit, got: %s", result.Observation.CoverageReason)
	}

	// Verify only 2 tool nodes collected
	toolCount := 0
	for _, n := range result.Nodes {
		if n.Node.Identity().Kind() == graph.MCPTool {
			toolCount++
		}
	}
	if toolCount != 2 {
		t.Errorf("expected exactly 2 tool nodes, got %d", toolCount)
	}
}

func TestMCPCollector_Auth401_TriggersRFC9728(t *testing.T) {
	mux := http.NewServeMux()

	// MCP endpoint requires authentication
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})

	// RFC 9728 OAuth Protected Resource Metadata endpoint
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://example.com/mcp",
			"authorization_servers": []string{"https://auth.corp.local/oauth2"},
			"scopes_supported":      []string{"mcp:tools", "mcp:resources"},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if result.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("expected CoverageFailed on 401, got %q", result.Observation.Coverage)
	}
	if result.Status != checkpoint.TargetStatusFailed {
		t.Errorf("expected TargetStatusFailed, got %q", result.Status)
	}

	// No MCPServer node must be emitted on discovery/handshake failure
	for _, n := range result.Nodes {
		if n.Node.Identity().Kind() == graph.MCPServer {
			t.Errorf("MCPServer node must NOT be emitted when initialization is denied")
		}
	}

	// Check results
	checkMap := make(map[string]evidence.Record)
	for _, ev := range result.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			checkMap[ev.CheckID] = ev
		}
	}

	initCheck, ok := checkMap[collectormcp.CheckIDInitialize]
	if !ok || initCheck.Outcome != string(graph.OutcomeDenied) {
		t.Errorf("expected initialize check OutcomeDenied, got %+v", initCheck)
	}

	rfcCheck, ok := checkMap[collectormcp.CheckIDRFC9728]
	if !ok || rfcCheck.Outcome != string(graph.OutcomeSuccess) {
		t.Errorf("expected RFC9728 check OutcomeSuccess, got %+v", rfcCheck)
	}
	if rfcCheck.Details == nil {
		t.Fatal("expected RFC9728 details to contain authorization servers")
	}
	authServers, ok := rfcCheck.Details["oauth_servers"].([]any)
	if !ok || len(authServers) == 0 || authServers[0] != "https://auth.corp.local/oauth2" {
		t.Errorf("expected oauth_servers in details, got %v", rfcCheck.Details["oauth_servers"])
	}
}

func TestMCPCollector_Auth403_Denied(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if result.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("expected CoverageFailed on 403, got %q", result.Observation.Coverage)
	}
	if result.Status != checkpoint.TargetStatusFailed {
		t.Errorf("expected TargetStatusFailed, got %q", result.Status)
	}

	for _, ev := range result.Evidence {
		if ev.CheckID == collectormcp.CheckIDInitialize {
			if ev.Outcome != string(graph.OutcomeDenied) {
				t.Errorf("expected initialize check outcome denied, got %s", ev.Outcome)
			}
		}
	}
}

func TestMCPCollector_UnknownVersion_DistinctAndNotGuessed(t *testing.T) {
	impl := &mcpsdk.Implementation{
		Name:    "unversioned-server",
		Version: "", // Empty / unknown version
	}
	srv := mcpsdk.NewServer(impl, nil)
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	for _, n := range result.Nodes {
		if n.Node.Identity().Kind() == graph.MCPServer {
			if _, ok := n.Properties["software_version_raw"]; ok {
				t.Errorf("software_version_raw must NOT be present when version is empty, got %v", n.Properties["software_version_raw"])
			}
			if n.Properties["protocol_version"] == nil {
				t.Errorf("protocol_version should still be captured even when software version is unknown")
			}
		}
	}

	for _, ev := range result.Evidence {
		if ev.RecordType == evidence.RecordFingerprint {
			if ev.SoftwareVersionRaw != "" {
				t.Errorf("expected empty SoftwareVersionRaw, got %q", ev.SoftwareVersionRaw)
			}
			if ev.ProtocolVersion == "" {
				t.Errorf("expected ProtocolVersion to be preserved")
			}
		}
	}
}

func TestMCPCollector_TLSVerification_EnforcedAndBypassed(t *testing.T) {
	srv := setupTestMCPServer(t)
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)

	ts := httptest.NewTLSServer(handler)
	defer ts.Close()

	// Case A: Insecure: false (default). Handshake verification fails, stops collection.
	cfgDefault := testConfig()
	cfgDefault.Insecure = false

	collectorDefault, err := collectormcp.New(cfgDefault)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	resA, err := collectorDefault.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if resA.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("expected CoverageFailed on TLS verification failure, got %q", resA.Observation.Coverage)
	}

	var tlsRecordA *evidence.Record
	for _, ev := range resA.Evidence {
		if ev.RecordType == evidence.RecordTLS {
			evCopy := ev
			tlsRecordA = &evCopy
		}
	}
	if tlsRecordA == nil {
		t.Fatal("expected TLS evidence record on verification failure")
	}
	if tlsRecordA.VerificationResult != "failed" {
		t.Errorf("expected VerificationResult 'failed', got %s", tlsRecordA.VerificationResult)
	}
	if tlsRecordA.InsecureOverride == nil || *tlsRecordA.InsecureOverride != false {
		t.Errorf("expected InsecureOverride = false")
	}

	// Case B: Insecure: true. Verification bypassed, collection proceeds, override recorded in evidence.
	cfgInsecure := testConfig()
	cfgInsecure.Insecure = true

	collectorInsecure, err := collectormcp.New(cfgInsecure)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	resB, err := collectorInsecure.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if resB.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("expected CoverageComplete when insecure override enabled, got %q", resB.Observation.Coverage)
	}

	var tlsRecordB *evidence.Record
	for _, ev := range resB.Evidence {
		if ev.RecordType == evidence.RecordTLS {
			evCopy := ev
			tlsRecordB = &evCopy
		}
	}
	if tlsRecordB == nil {
		t.Fatal("expected TLS evidence record")
	}
	if tlsRecordB.InsecureOverride == nil || *tlsRecordB.InsecureOverride != true {
		t.Errorf("expected InsecureOverride = true")
	}
	if tlsRecordB.CertFingerprint == "" {
		t.Error("expected leaf certificate fingerprint to be captured")
	}

	// Server node must indicate tls_verification = failed
	for _, n := range resB.Nodes {
		if n.Node.Identity().Kind() == graph.MCPServer {
			if n.Properties["tls_verification"] != "failed" {
				t.Errorf("expected tls_verification = 'failed' on server node, got %v", n.Properties["tls_verification"])
			}
		}
	}
}

func TestMCPCollector_Correlation_NativeComputer(t *testing.T) {
	srv := setupTestMCPServer(t)
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resolver, err := correlate.New(correlate.Config{
		Mappings: []correlate.Mapping{
			{Target: "127.0.0.1", ComputerID: "S-1-5-21-9999-1001"},
		},
	})
	if err != nil {
		t.Fatalf("New correlator: %v", err)
	}

	computers := []correlate.Computer{
		{ObjectID: "S-1-5-21-9999-1001", Name: "AI-HOST-01.LAB.LOCAL"},
	}

	cfg := testConfig()
	collector, err := collectormcp.New(cfg, collectormcp.WithCorrelator(resolver, computers))
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{
		URL:            ts.URL + "/mcp",
		OriginalTarget: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Verify no fallback NetworkEndpoint was emitted
	for _, n := range result.Nodes {
		if n.Node.Identity().Kind() == graph.NetworkEndpoint {
			t.Errorf("fallback NetworkEndpoint must NOT be emitted when target correlates to native Computer")
		}
	}

	// Verify ObservedAt edge touches native Computer without source_kind
	var nativeObservedAt *graph.Edge
	for _, e := range result.Edges {
		if e.Kind() == graph.ObservedAt {
			edgeCopy := e
			nativeObservedAt = &edgeCopy
		}
	}
	if nativeObservedAt == nil {
		t.Fatal("missing ObservedAt edge")
	}
	if !nativeObservedAt.TouchesNative() {
		t.Error("ObservedAt must touch native Computer")
	}
	if nativeObservedAt.SourceKind() != "" {
		t.Errorf("native-touching edge must have empty SourceKind, got %q", nativeObservedAt.SourceKind())
	}
	if nativeObservedAt.End().ID() != "S-1-5-21-9999-1001" {
		t.Errorf("ObservedAt end ID = %s, want S-1-5-21-9999-1001", nativeObservedAt.End().ID())
	}
}

func TestMCPCollector_EndToEnd_JournalReplayAndEmission(t *testing.T) {
	srv := setupTestMCPServer(t)
	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg, collectormcp.WithScanID("scan-e2e-001"), collectormcp.WithEvidenceID("ev-e2e-001"))
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	// Write to checkpoint Journal
	var journalBuf bytes.Buffer
	header := checkpoint.Header{
		SchemaVersion:    "1",
		DeploymentScope:  cfg.Scope,
		ScanID:           "scan-e2e-001",
		CollectorVersion: "0.1.0",
		VantageKey:       cfg.VantageKey,
		CreatedAt:        time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}

	j, err := checkpoint.NewWriter(&journalBuf, header)
	if err != nil {
		t.Fatalf("NewWriter journal: %v", err)
	}

	_, err = collector.CollectTarget(context.Background(), collectormcp.Target{
		URL:            ts.URL + "/mcp",
		OriginalTarget: ts.Listener.Addr().String(),
	}, j)
	if err != nil {
		t.Fatalf("CollectTarget failed: %v", err)
	}

	if err := j.Close(); err != nil {
		t.Fatalf("Close journal: %v", err)
	}

	// Replay journal
	state, err := checkpoint.Replay(bytes.NewReader(journalBuf.Bytes()))
	if err != nil {
		t.Fatalf("Replay journal: %v", err)
	}

	if len(state.Nodes()) < 4 {
		t.Errorf("expected at least 4 nodes from journal replay, got %d", len(state.Nodes()))
	}
	if len(state.Edges()) < 5 {
		t.Errorf("expected at least 5 edges from journal replay, got %d", len(state.Edges()))
	}
	if len(state.Evidence()) < 6 {
		t.Errorf("expected at least 6 evidence records from journal replay, got %d", len(state.Evidence()))
	}

	// Emit OpenGraph base payload
	var basePayloadBuf bytes.Buffer
	if err := emitter.EmitBasePayload(&basePayloadBuf, state.Nodes(), state.Edges()); err != nil {
		t.Fatalf("EmitBasePayload: %v", err)
	}

	var parsedPayload map[string]any
	if err := json.Unmarshal(basePayloadBuf.Bytes(), &parsedPayload); err != nil {
		t.Fatalf("unmarshal emitted base payload: %v", err)
	}
	if parsedPayload["metadata"].(map[string]any)["source_kind"] != "LLMHound" {
		t.Errorf("base payload must carry source_kind: LLMHound")
	}

	// Emit Evidence Sidecar
	var sidecarBuf bytes.Buffer
	evWriter := evidence.NewWriter(&sidecarBuf)
	for _, rec := range state.Evidence() {
		if err := evWriter.Write(rec); err != nil {
			t.Fatalf("write evidence sidecar: %v", err)
		}
	}
	if err := evWriter.Flush(); err != nil {
		t.Fatalf("flush evidence writer: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(sidecarBuf.String()), "\n")
	if len(lines) != len(state.Evidence()) {
		t.Errorf("expected %d sidecar lines, got %d", len(state.Evidence()), len(lines))
	}
}

func TestMCPCollector_ResourceContentNotFetched(t *testing.T) {
	impl := &mcpsdk.Implementation{Name: "content-guard-server", Version: "1.0.0"}
	srv := mcpsdk.NewServer(impl, nil)

	contentReadAttempted := false
	srv.AddResource(&mcpsdk.Resource{
		URI:         "file:///secret.key",
		Name:        "secret.key",
		Description: "Sensitive file",
		MIMEType:    "application/octet-stream",
	}, func(ctx context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		contentReadAttempted = true
		t.Fatal("ReadResource was called, but resource descriptors must never authorize reading content!")
		return nil, nil
	})

	handler := mcpsdk.NewStreamableHTTPHandler(func(req *http.Request) *mcpsdk.Server {
		return srv
	}, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if contentReadAttempted {
		t.Fatal("Resource content was read during collection!")
	}

	// Verify the resource descriptor was collected
	foundResource := false
	for _, n := range result.Nodes {
		if n.Node.Identity().Kind() == graph.MCPResource && n.Properties["uri"] == "file:///secret.key" {
			foundResource = true
		}
	}
	if !foundResource {
		t.Error("expected resource descriptor to be collected without reading content")
	}

	// Verify NO PublicAccess edge was emitted
	for _, e := range result.Edges {
		if e.Kind() == graph.PublicAccess {
			t.Errorf("PublicAccess edge must not be emitted without content read")
		}
	}
}

func TestMCPCollector_UnreachableTarget_Failed(t *testing.T) {
	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	// Non-listening local port
	result, err := collector.Collect(context.Background(), collectormcp.Target{
		URL:            "http://127.0.0.1:59999/mcp",
		OriginalTarget: "127.0.0.1:59999",
	})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if result.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("expected CoverageFailed for unreachable target, got %q", result.Observation.Coverage)
	}
	if result.Status != checkpoint.TargetStatusFailed {
		t.Errorf("expected TargetStatusFailed, got %q", result.Status)
	}
	if len(result.Nodes) > 0 {
		t.Errorf("expected 0 nodes on unreachable target, got %d", len(result.Nodes))
	}
}

func TestMCPCollector_Redirect_CrossHostUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil-external-host.corp.local/mcp", http.StatusFound)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := testConfig()
	collector, err := collectormcp.New(cfg)
	if err != nil {
		t.Fatalf("New collector: %v", err)
	}

	result, err := collector.Collect(context.Background(), collectormcp.Target{URL: ts.URL + "/mcp"})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Check that unauthorized cross-host redirect was recorded in evidence
	foundUnauthorizedRedirect := false
	for _, ev := range result.Evidence {
		if ev.RecordType == evidence.RecordRedirect {
			if ev.Authorized != nil && !*ev.Authorized {
				foundUnauthorizedRedirect = true
			}
		}
	}
	if !foundUnauthorizedRedirect {
		t.Error("expected unauthorized cross-host redirect to be recorded in evidence")
	}
}
