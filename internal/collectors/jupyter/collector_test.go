package jupyter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/collectors/jupyter"
	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/discovery"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

func mockJupyterHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"version": "2.14.0",
				"jupyter_server_version": "2.14.0",
				"server_version": "2.14.0"
			}`))
		case "/api/sessions":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[
				{
					"id": "sess-1",
					"path": "notebooks/EDA.ipynb",
					"name": "EDA.ipynb",
					"type": "notebook",
					"kernel": {
						"id": "k-1",
						"name": "python3",
						"execution_state": "idle",
						"connections": 1
					}
				},
				{
					"id": "sess-2",
					"path": "train.py",
					"name": "train.py",
					"type": "file",
					"kernel": {
						"id": "k-2",
						"name": "python3",
						"execution_state": "idle",
						"connections": 0
					}
				}
			]`))
		case "/api/contents":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"name": "",
				"path": "",
				"type": "directory",
				"content": [
					{
						"name": "EDA.ipynb",
						"path": "notebooks/EDA.ipynb",
						"type": "notebook",
						"size": 15420,
						"last_modified": "2026-10-01T12:00:00Z"
					},
					{
						"name": "train.py",
						"path": "train.py",
						"type": "file",
						"size": 3200,
						"last_modified": "2026-10-01T12:05:00Z"
					}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}
}

func testFixedTime() time.Time {
	return time.Date(2026, 10, 1, 14, 0, 0, 0, time.UTC)
}

func TestAnonymousJupyterServer(t *testing.T) {
	server := httptest.NewServer(mockJupyterHandler(t))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	ctx := context.Background()
	res, err := col.Collect(ctx, server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if res.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("got status %q, want %q", res.Status, checkpoint.TargetStatusCompleted)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("got coverage %q, want %q", res.Observation.Coverage, graph.CoverageComplete)
	}

	// Verify nodes
	var srvNode *emitter.NodeItem
	fileNodes := make(map[string]emitter.NodeItem)
	var vantageNode *emitter.NodeItem
	var endpointNode *emitter.NodeItem

	for i := range res.Nodes {
		n := &res.Nodes[i]
		switch n.Node.Identity().Kind() {
		case graph.JupyterServer:
			srvNode = n
		case graph.WorkspaceFile:
			fileNodes[n.Properties["path"].(string)] = *n
		case graph.CollectionVantage:
			vantageNode = n
		case graph.NetworkEndpoint:
			endpointNode = n
		}
	}

	if vantageNode == nil {
		t.Fatal("expected CollectionVantage node")
	}
	if srvNode == nil {
		t.Fatal("expected JupyterServer node")
	}
	if endpointNode == nil {
		t.Fatal("expected NetworkEndpoint node (fallback)")
	}

	// Verify JupyterServer properties
	props := srvNode.Properties
	if props["product"] != "Jupyter Server" {
		t.Errorf("got product %v, want 'Jupyter Server'", props["product"])
	}
	if props["api_version"] != "2.14.0" {
		t.Errorf("got api_version %v, want '2.14.0'", props["api_version"])
	}
	if props["software_version"] != "2.14.0" {
		t.Errorf("got software_version %v, want '2.14.0'", props["software_version"])
	}
	if props["auth_required"] != false {
		t.Errorf("got auth_required %v, want false", props["auth_required"])
	}
	if props["active_sessions"] != 2 {
		t.Errorf("got active_sessions %v, want 2", props["active_sessions"])
	}

	// Verify WorkspaceFiles: exactly 2 files (directory skipped)
	if len(fileNodes) != 2 {
		t.Fatalf("got %d workspace files, want 2", len(fileNodes))
	}
	eda, ok := fileNodes["notebooks/EDA.ipynb"]
	if !ok {
		t.Fatal("missing notebooks/EDA.ipynb")
	}
	if eda.Properties["file_type"] != "notebook" {
		t.Errorf("got file_type %v, want notebook", eda.Properties["file_type"])
	}
	if eda.Properties["size"] != int64(15420) {
		t.Errorf("got size %v, want 15420", eda.Properties["size"])
	}

	// Verify Edges
	var unauthAccessCount, containsCount, observedAtCount int
	for _, e := range res.Edges {
		switch e.Kind() {
		case graph.UnauthenticatedAccess:
			unauthAccessCount++
			if e.Start().ID() != vantageNode.Node.Identity().ID() {
				t.Errorf("UnauthenticatedAccess start mismatch")
			}
			if e.End().ID() != srvNode.Node.Identity().ID() {
				t.Errorf("UnauthenticatedAccess end mismatch")
			}
		case graph.Contains:
			containsCount++
			if e.Start().ID() != srvNode.Node.Identity().ID() {
				t.Errorf("Contains start must be server")
			}
		case graph.ObservedAt:
			observedAtCount++
			if e.Start().ID() != srvNode.Node.Identity().ID() {
				t.Errorf("ObservedAt start must be server")
			}
			if e.End().ID() != endpointNode.Node.Identity().ID() {
				t.Errorf("ObservedAt end must be endpoint fallback")
			}
		}
	}

	if unauthAccessCount != 1 {
		t.Errorf("got %d UnauthenticatedAccess edges, want 1", unauthAccessCount)
	}
	if containsCount != 2 {
		t.Errorf("got %d Contains edges, want 2", containsCount)
	}
	if observedAtCount != 1 {
		t.Errorf("got %d ObservedAt edges, want 1", observedAtCount)
	}

	// Verify Evidence records
	var fpRecCount, checkRecCount, corrRecCount int
	for _, ev := range res.Evidence {
		switch ev.RecordType {
		case evidence.RecordFingerprint:
			fpRecCount++
			if ev.APIVersion != "2.14.0" {
				t.Errorf("fingerprint APIVersion got %s, want 2.14.0", ev.APIVersion)
			}
		case evidence.RecordCheckResult:
			checkRecCount++
			if ev.Outcome != "success" {
				t.Errorf("check %s got outcome %s, want success", ev.CheckID, ev.Outcome)
			}
		case evidence.RecordCorrelation:
			corrRecCount++
		}
	}

	if fpRecCount != 1 {
		t.Errorf("got %d fingerprint records, want 1", fpRecCount)
	}
	if checkRecCount != 3 {
		t.Errorf("got %d check result records, want 3", checkRecCount)
	}
	if corrRecCount != 1 {
		t.Errorf("got %d correlation records, want 1", corrRecCount)
	}
}

func TestAuthenticatedJupyterServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message": "Jupyter token or credentials required"}`))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-auth-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if res.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("got status %q, want completed", res.Status)
	}
	if res.Observation.Coverage != graph.CoverageComplete {
		t.Errorf("got coverage %q, want complete", res.Observation.Coverage)
	}

	// Verify server node has auth_required = true
	var srvNode *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.JupyterServer {
			srvNode = &res.Nodes[i]
		}
		if res.Nodes[i].Node.Identity().Kind() == graph.WorkspaceFile {
			t.Errorf("expected no WorkspaceFile nodes on authenticated server")
		}
	}
	if srvNode == nil {
		t.Fatal("expected JupyterServer node")
	}
	if srvNode.Properties["auth_required"] != true {
		t.Errorf("got auth_required %v, want true", srvNode.Properties["auth_required"])
	}

	// Verify NO UnauthenticatedAccess edge
	for _, e := range res.Edges {
		if e.Kind() == graph.UnauthenticatedAccess {
			t.Errorf("should not emit UnauthenticatedAccess edge on authenticated server")
		}
		if e.Kind() == graph.Contains {
			t.Errorf("should not emit Contains edges on authenticated server")
		}
	}

	// Verify all 3 checks have denied outcome
	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			if ev.Outcome != "denied" {
				t.Errorf("check %s got outcome %s, want denied", ev.CheckID, ev.Outcome)
			}
		}
	}
}

func TestPartialAuthenticatedServer(t *testing.T) {
	// /api returns 200 with version, but /api/sessions and /api/contents return 403 Forbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version": "1.2.0", "jupyter_server_version": "1.2.0"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "Forbidden"}`))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-part-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Server version was discovered
	var srvNode *emitter.NodeItem
	for i := range res.Nodes {
		if res.Nodes[i].Node.Identity().Kind() == graph.JupyterServer {
			srvNode = &res.Nodes[i]
		}
	}
	if srvNode == nil {
		t.Fatal("expected JupyterServer node")
	}
	if srvNode.Properties["api_version"] != "1.2.0" {
		t.Errorf("got api_version %v, want '1.2.0'", srvNode.Properties["api_version"])
	}
	if srvNode.Properties["auth_required"] != true {
		t.Errorf("got auth_required %v, want true", srvNode.Properties["auth_required"])
	}

	// Contents and sessions were denied, so no workspace files and no unauthenticated access
	for _, e := range res.Edges {
		if e.Kind() == graph.UnauthenticatedAccess {
			t.Errorf("should not emit UnauthenticatedAccess edge when workspace/sessions are denied")
		}
	}
}

func TestHtmlLoginPageDetection(t *testing.T) {
	// Server returns HTTP 200 OK with HTML login page instead of JSON API response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
		<html>
		<head><title>Jupyter Server Login</title></head>
		<body>
			<form action="/login" method="post">
				<input type="password" name="password" placeholder="Password or token"/>
				<button type="submit">Log in</button>
			</form>
		</body>
		</html>`))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-html-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// HTML login page is recognized as auth boundary -> denied outcome
	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			if ev.Outcome != "denied" {
				t.Errorf("check %s got outcome %s, want denied", ev.CheckID, ev.Outcome)
			}
			if !strings.Contains(ev.Reason, "login page") {
				t.Errorf("check %s reason %q should mention login page", ev.CheckID, ev.Reason)
			}
		}
	}

	// Verify no WorkspaceFile nodes created from HTML
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.WorkspaceFile {
			t.Errorf("unexpected WorkspaceFile node from HTML response")
		}
	}
}

func TestRedirectToLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login?next=%2Ftree")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-redir-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			if ev.Outcome != "denied" {
				t.Errorf("check %s got outcome %s, want denied on login redirect", ev.CheckID, ev.Outcome)
			}
		}
	}
}

func TestUnreachableTarget(t *testing.T) {
	// Point to unreachable loopback address
	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-fail-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		Bounds: config.Bounds{
			ConnectTimeout:  100 * time.Millisecond,
			ResponseTimeout: 200 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), "http://127.0.0.1:59999")
	if err != nil {
		t.Fatalf("Collect should return honest failed result, got error: %v", err)
	}

	if res.Status != checkpoint.TargetStatusFailed {
		t.Errorf("got status %q, want failed", res.Status)
	}
	if res.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("got coverage %q, want failed", res.Observation.Coverage)
	}
	if !strings.Contains(res.Observation.CoverageReason, "unreachable") {
		t.Errorf("coverage reason %q should mention unreachable", res.Observation.CoverageReason)
	}

	// No fingerprinted nodes emitted
	if len(res.Nodes) != 0 {
		t.Errorf("got %d nodes on failed collection, want 0", len(res.Nodes))
	}
	if len(res.Edges) != 0 {
		t.Errorf("got %d edges on failed collection, want 0", len(res.Edges))
	}
}

func TestWorkspaceTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version": "2.0.0", "jupyter_server_version": "2.0.0"}`))
			return
		}
		if r.URL.Path == "/api/sessions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.URL.Path == "/api/contents" {
			w.Header().Set("Content-Type", "application/json")
			var items []string
			for i := 0; i < 25; i++ {
				items = append(items, fmt.Sprintf(`{"name": "file_%d.ipynb", "path": "file_%d.ipynb", "type": "notebook", "size": 100}`, i, i))
			}
			_, _ = w.Write([]byte(fmt.Sprintf(`{"name": "", "path": "", "type": "directory", "content": [%s]}`, strings.Join(items, ","))))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-trunc-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		Bounds: config.Bounds{
			MaxItems: 10, // bound items to 10
		},
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if res.Status != checkpoint.TargetStatusPartial {
		t.Errorf("got status %q, want partial", res.Status)
	}
	if res.Observation.Coverage != graph.CoverageTruncated {
		t.Errorf("got coverage %q, want truncated", res.Observation.Coverage)
	}

	var fileCount int
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.WorkspaceFile {
			fileCount++
		}
	}
	if fileCount != 10 {
		t.Errorf("got %d workspace files, want 10 due to bound", fileCount)
	}
}

func TestADComputerCorrelation(t *testing.T) {
	server := httptest.NewServer(mockJupyterHandler(t))
	defer server.Close()

	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-dc01"
	cfg.Correlation.ADDomainSuffixes = []string{"corp.local"}

	resolver, err := correlate.NewFromConfig(cfg, nil, true)
	if err != nil {
		t.Fatalf("correlate.NewFromConfig: %v", err)
	}

	verifiedComputers := []correlate.Computer{
		{
			ObjectID: "S-1-5-21-9999-8888-7777-2002",
			Name:     "JUPYTER-SRV01.CORP.LOCAL",
		},
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	customClient := &http.Client{Transport: transport}

	col, err := jupyter.New(jupyter.Config{
		Scope:             "corp-scope",
		VantageKey:        "vantage-dc01",
		ScanID:            "scan-ad-001",
		CollectorVersion:  "0.1.0",
		Now:               testFixedTime,
		Resolver:          resolver,
		VerifiedComputers: verifiedComputers,
		HTTPClient:        customClient,
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	// Target matches AD domain suffix
	res, err := col.Collect(context.Background(), "http://jupyter-srv01.corp.local:8888")
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Verify ObservedAt edge points to native Computer
	var observedAtEdge *graph.Edge
	for i := range res.Edges {
		if res.Edges[i].Kind() == graph.ObservedAt {
			observedAtEdge = &res.Edges[i]
			break
		}
	}
	if observedAtEdge == nil {
		t.Fatal("missing ObservedAt edge")
	}

	if !observedAtEdge.TouchesNative() {
		t.Error("expected ObservedAt edge to touch native Computer")
	}
	if observedAtEdge.SourceKind() != "" {
		t.Errorf("got SourceKind %q, want empty for native-touching edge", observedAtEdge.SourceKind())
	}
	if observedAtEdge.End().Kind() != graph.Computer {
		t.Errorf("got end kind %v, want Computer", observedAtEdge.End().Kind())
	}
	if observedAtEdge.End().ID() != "S-1-5-21-9999-8888-7777-2002" {
		t.Errorf("got end native ID %s, want S-1-5-21-9999-8888-7777-2002", observedAtEdge.End().ID())
	}

	// Verify no fallback NetworkEndpoint node was created
	for _, n := range res.Nodes {
		if n.Node.Identity().Kind() == graph.NetworkEndpoint {
			t.Errorf("unexpected NetworkEndpoint node when target correlates to AD Computer")
		}
	}
}

func TestJournalReplayAndEmission(t *testing.T) {
	server := httptest.NewServer(mockJupyterHandler(t))
	defer server.Close()

	header := checkpoint.Header{
		SchemaVersion:    "1",
		DeploymentScope:  "test-scope",
		ScanID:           "journal-scan-001",
		CollectorVersion: "0.1.0",
		VantageKey:       "vantage-dc01",
		CreatedAt:        testFixedTime().Format(time.RFC3339),
	}

	var buf bytes.Buffer
	journalWriter, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatalf("checkpoint.NewWriter: %v", err)
	}

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "journal-scan-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.CollectToJournal(context.Background(), journalWriter, server.URL)
	if err != nil {
		t.Fatalf("CollectToJournal failed: %v", err)
	}
	if res.Status != checkpoint.TargetStatusCompleted {
		t.Errorf("got status %q, want completed", res.Status)
	}
	if err := journalWriter.Close(); err != nil {
		t.Fatalf("journalWriter.Close: %v", err)
	}

	// Replay journal from buffer
	state, err := checkpoint.Replay(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("checkpoint.Replay failed: %v", err)
	}

	if len(state.Targets()) != 1 {
		t.Errorf("got %d targets in replayed state, want 1", len(state.Targets()))
	}
	if !state.IsCompleted(server.URL, "jupyter") {
		t.Errorf("expected surface jupyter to be completed in replayed state")
	}

	// Emit payloads via EmitSplit
	var baseBuf, linkBuf bytes.Buffer
	err = emitter.EmitSplit(&baseBuf, &linkBuf, state.Nodes(), state.Edges())
	if err != nil {
		t.Fatalf("emitter.EmitSplit: %v", err)
	}

	if baseBuf.Len() == 0 {
		t.Fatal("base payload is empty")
	}

	var basePayload emitter.Payload
	if err := json.Unmarshal(baseBuf.Bytes(), &basePayload); err != nil {
		t.Fatalf("unmarshal base payload: %v", err)
	}

	if basePayload.Metadata == nil || basePayload.Metadata.SourceKind != "LLMHound" {
		t.Errorf("invalid base payload metadata: %v", basePayload.Metadata)
	}

	// Validate nodes in emitted payload
	if len(basePayload.Graph.Nodes) < 3 { // Vantage, JupyterServer, at least 1 WorkspaceFile
		t.Errorf("got %d nodes in emitted payload, want at least 3", len(basePayload.Graph.Nodes))
	}
}

func TestTLSInspection(t *testing.T) {
	server := httptest.NewTLSServer(mockJupyterHandler(t))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-tls-001",
		CollectorVersion: "0.1.0",
		Insecure:         true,
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	var tlsRec *evidence.Record
	for i := range res.Evidence {
		if res.Evidence[i].RecordType == evidence.RecordTLS {
			tlsRec = &res.Evidence[i]
			break
		}
	}
	if tlsRec == nil {
		t.Fatal("expected RecordTLS in evidence")
	}
	if tlsRec.CertFingerprint == "" {
		t.Error("expected non-empty CertFingerprint")
	}
	if tlsRec.VerificationResult != "insecure_override" {
		t.Errorf("got VerificationResult %q, want insecure_override", tlsRec.VerificationResult)
	}
}

func TestMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"version": "x", "jupyter_server_version": `)) // Malformed JSON
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-mal-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if res.Observation.Coverage != graph.CoveragePartial {
		t.Errorf("got coverage %q, want partial on malformed json", res.Observation.Coverage)
	}
	if res.Status != checkpoint.TargetStatusPartial {
		t.Errorf("got status %q, want partial on malformed json", res.Status)
	}
}

func TestRateLimiting429(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`Too many requests`))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-429-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			if ev.Outcome != "failed" {
				t.Errorf("check %s got outcome %s, want failed on 429", ev.CheckID, ev.Outcome)
			}
		}
	}
}

func Test404Endpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`404 Not Found`))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-404-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordCheckResult {
			if ev.Outcome != "failed" {
				t.Errorf("check %s got outcome %s, want failed on 404", ev.CheckID, ev.Outcome)
			}
		}
	}
}

func TestResponseTooLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Send 10KB of padding
		_, _ = w.Write([]byte(fmt.Sprintf(`{"jupyter_server_version": "1", "version": "%s"}`, strings.Repeat("a", 10000))))
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope:            "test-scope",
		VantageKey:       "vantage-dc01",
		ScanID:           "scan-large-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		Bounds: config.Bounds{
			MaxResponseBytes: 500, // limit to 500 bytes
		},
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Large response triggers failed outcome for that check
	for _, ev := range res.Evidence {
		if ev.RecordType == evidence.RecordCheckResult && ev.CheckID == jupyter.CheckIDVersion {
			if ev.Outcome != "failed" {
				t.Errorf("got outcome %s, want failed on response too large", ev.Outcome)
			}
		}
	}
}

func TestEndToEndTargetDiscoveryAndEmission(t *testing.T) {
	server := httptest.NewServer(mockJupyterHandler(t))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Discovery probe
	def := discovery.JupyterDefinition()
	probeRes, err := discovery.Probe(ctx, server.Client(), server.URL, def)
	if err != nil {
		t.Fatalf("discovery.Probe failed: %v", err)
	}
	if !probeRes.Matched || probeRes.Surface != discovery.SurfaceJupyter {
		t.Fatalf("expected discovery match for jupyter, got %+v", probeRes)
	}

	// 2. Collection to journal
	header := checkpoint.Header{
		SchemaVersion:    "1",
		DeploymentScope:  "lab-scope",
		ScanID:           "e2e-scan-001",
		CollectorVersion: "0.1.0",
		VantageKey:       "vantage-lab",
		CreatedAt:        testFixedTime().Format(time.RFC3339),
	}

	var journalBuf bytes.Buffer
	writer, err := checkpoint.NewWriter(&journalBuf, header)
	if err != nil {
		t.Fatalf("checkpoint.NewWriter: %v", err)
	}

	col, err := jupyter.New(jupyter.Config{
		Scope:            "lab-scope",
		VantageKey:       "vantage-lab",
		ScanID:           "e2e-scan-001",
		CollectorVersion: "0.1.0",
		Now:              testFixedTime,
		HTTPClient:       server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}

	result, err := col.CollectToJournal(ctx, writer, server.URL)
	if err != nil {
		t.Fatalf("CollectToJournal failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	if result.Status != checkpoint.TargetStatusCompleted {
		t.Fatalf("expected completed status, got %s", result.Status)
	}

	// 3. Replay from journal
	replayed, err := checkpoint.Replay(bytes.NewReader(journalBuf.Bytes()))
	if err != nil {
		t.Fatalf("checkpoint.Replay: %v", err)
	}

	if !replayed.IsCompleted(server.URL, "jupyter") {
		t.Error("expected surface jupyter to be completed in replayed state")
	}

	// 4. Emit OpenGraph payload and evidence sidecar
	var basePayloadBuf, linkPayloadBuf bytes.Buffer
	if err := emitter.EmitSplit(&basePayloadBuf, &linkPayloadBuf, replayed.Nodes(), replayed.Edges()); err != nil {
		t.Fatalf("emitter.EmitSplit: %v", err)
	}

	var payload emitter.Payload
	if err := json.Unmarshal(basePayloadBuf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal base payload: %v", err)
	}

	if payload.Metadata == nil || payload.Metadata.SourceKind != "LLMHound" {
		t.Errorf("expected source_kind LLMHound, got %v", payload.Metadata)
	}

	// Verify all node kinds in base payload
	kindsFound := make(map[string]bool)
	for _, n := range payload.Graph.Nodes {
		for _, k := range n.Kinds {
			kindsFound[k] = true
		}
	}

	expectedKinds := []string{
		"LLMHound_CollectionVantage",
		"LLMHound_JupyterServer",
		"LLMHound_AIService",
		"LLMHound_WorkspaceFile",
	}
	for _, ek := range expectedKinds {
		if !kindsFound[ek] {
			t.Errorf("expected kind %s in emitted graph, found: %v", ek, kindsFound)
		}
	}

	// Verify edges in base payload
	edgeKindsFound := make(map[string]bool)
	for _, e := range payload.Graph.Edges {
		edgeKindsFound[e.Kind] = true
	}
	expectedEdges := []string{
		"LLMHound_UnauthenticatedAccess",
		"LLMHound_Contains",
		"LLMHound_ObservedAt",
	}
	for _, ee := range expectedEdges {
		if !edgeKindsFound[ee] {
			t.Errorf("expected edge %s in emitted graph, found: %v", ee, edgeKindsFound)
		}
	}
}


func TestNonJupyterServerYieldsNoGraph(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TornadoServer/6.3.3")
		http.NotFound(w, r)
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope: "test-scope", VantageKey: "vantage-dc01", ScanID: "scan-nonj-001",
		Now: testFixedTime, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}
	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if res.Status != checkpoint.TargetStatusFailed || res.Observation.Coverage != graph.CoverageFailed {
		t.Errorf("got status %q coverage %q, want failed", res.Status, res.Observation.Coverage)
	}
	if !strings.Contains(res.Observation.CoverageReason, "not identified as jupyter") {
		t.Errorf("unexpected reason %q", res.Observation.CoverageReason)
	}
	if len(res.Nodes) != 0 || len(res.Edges) != 0 {
		t.Errorf("got %d nodes %d edges, want none", len(res.Nodes), len(res.Edges))
	}
}

func TestRootOnlyListingIsPartial(t *testing.T) {
	base := mockJupyterHandler(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/contents" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"type":"directory","content":[{"name":"d","path":"d","type":"directory"}]}`))
			return
		}
		base(w, r)
	}))
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope: "test-scope", VantageKey: "vantage-dc01", ScanID: "scan-root-001",
		Now: testFixedTime, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}
	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if res.Observation.Coverage != graph.CoveragePartial || !strings.Contains(res.Observation.CoverageReason, "root listing only") {
		t.Errorf("got coverage %q reason %q, want partial root listing", res.Observation.Coverage, res.Observation.CoverageReason)
	}
}

func TestSessionListTruncation(t *testing.T) {
	base := mockJupyterHandler(t)
	server := httptest.NewServer(base)
	defer server.Close()

	col, err := jupyter.New(jupyter.Config{
		Scope: "test-scope", VantageKey: "vantage-dc01", ScanID: "scan-sess-001",
		Now: testFixedTime, HTTPClient: server.Client(),
		Bounds: config.Bounds{MaxItems: 1},
	})
	if err != nil {
		t.Fatalf("jupyter.New: %v", err)
	}
	res, err := col.Collect(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}
	if res.Observation.Coverage != graph.CoverageTruncated {
		t.Errorf("got coverage %q, want truncated", res.Observation.Coverage)
	}
}
