package bloodhound_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/bloodhound"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/savedsearch"
)

type mockCEServer struct {
	mu              sync.Mutex
	serverVersion   string
	cypherQueries   []string
	existingNodes   map[string]bloodhound.CypherNode
	uploadedJobs    []mockJob
	nextJobID       int64
	registered      bool
	importedZipLen  int
	deletedQueryIDs []int64
	savedQueries    []bloodhound.SavedQueryRecord
	failSourceKinds bool
	cancelFirstJob  bool
	canceledOnce    bool
	authHeaderSeen  string
}

type mockJob struct {
	ID       int64
	FileName string
	Payload  emitter.Payload
	Status   int
}

func newMockCE(t *testing.T) (*mockCEServer, *httptest.Server) {
	t.Helper()
	m := &mockCEServer{
		serverVersion: "v9.7.1",
		existingNodes: map[string]bloodhound.CypherNode{
			"S-1-5-21-1103": {ObjectID: "S-1-5-21-1103", Kinds: []string{"Base", "Computer"}},
			"S-1-5-21-513":  {ObjectID: "S-1-5-21-513", Kinds: []string{"Base", "Group"}},
			"STUB-MISSING":  {ObjectID: "STUB-MISSING", Kinds: []string{}}, // kindless stub must be rejected!
		},
		nextJobID: 1,
		savedQueries: []bloodhound.SavedQueryRecord{
			{ID: 10, Name: "LLMHound P1: stale"},
			{ID: 11, Name: "Custom AD Query"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.authHeaderSeen = r.Header.Get("Authorization")
		m.mu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/login":
			_, _ = w.Write([]byte(`{"data":{"session_token":"jwt-session-tok"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/version":
			_, _ = fmt.Fprintf(w, `{"data":{"server_version":%q,"product_edition":"community","API":{"current_version":"v2"}}}`, m.serverVersion)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions":
			_, _ = w.Write([]byte(`{"data":{"extensions":[{"id":1,"name":"LLMHound","namespace":"LLMHound","version":"v0.1.0"}]}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v2/extensions":
			m.mu.Lock()
			m.registered = true
			m.mu.Unlock()
			_, _ = w.Write([]byte(`{"data":{"name":"LLMHound"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/graphs/source-kinds":
			if m.failSourceKinds {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"kinds":[{"id":1,"name":"Base"},{"id":2,"name":"LLMHound"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions-edges":
			_, _ = w.Write([]byte(`{"data":{"edges":[{"name":"MemberOf","is_traversable":true,"is_builtin":true},{"name":"LLMHound_ObservedAt","is_traversable":false,"schema_name":"LLMHound"}]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/graphs/cypher":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(body, &req)
			m.mu.Lock()
			m.cypherQueries = append(m.cypherQueries, req.Query)
			m.mu.Unlock()

			nodes := map[string]bloodhound.CypherNode{}
			idx := 0
			for id, n := range m.existingNodes {
				if strings.Contains(req.Query, id) {
					nodes[fmt.Sprintf("n%d", idx)] = n
					idx++
				}
			}
			if strings.Contains(req.Query, "LIMIT 1") {
				nodes["n0"] = bloodhound.CypherNode{ObjectID: "S-1-5-21-1103", Kinds: []string{"Computer"}}
			}
			if len(nodes) == 0 {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[{"message":"resource not found"}]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"nodes": nodes, "edges": []any{}}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			m.mu.Lock()
			jid := m.nextJobID
			m.nextJobID++
			m.uploadedJobs = append(m.uploadedJobs, mockJob{ID: jid, Status: 0})
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"id":%d}}`, jid)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/file-upload/") && strings.HasSuffix(r.URL.Path, "/end"):
			var jid int64
			_, _ = fmt.Sscanf(r.URL.Path, "/api/v2/file-upload/%d/end", &jid)
			m.mu.Lock()
			for i := range m.uploadedJobs {
				if m.uploadedJobs[i].ID == jid {
					if m.cancelFirstJob && !m.canceledOnce {
						m.canceledOnce = true
						m.uploadedJobs[i].Status = 3 // canceled -> triggers retry
					} else {
						m.uploadedJobs[i].Status = 2
					}
				}
			}
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/file-upload/"):
			var jid int64
			_, _ = fmt.Sscanf(r.URL.Path, "/api/v2/file-upload/%d", &jid)
			body, _ := io.ReadAll(r.Body)
			var p emitter.Payload
			_ = json.Unmarshal(body, &p)
			m.mu.Lock()
			for i := range m.uploadedJobs {
				if m.uploadedJobs[i].ID == jid {
					m.uploadedJobs[i].FileName = r.Header.Get("X-File-Upload-Name")
					m.uploadedJobs[i].Payload = p
				}
			}
			m.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/file-upload":
			m.mu.Lock()
			var list []map[string]any
			for _, j := range m.uploadedJobs {
				list = append(list, map[string]any{"id": j.ID, "status": j.Status})
			}
			m.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"data": list})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/completed-tasks"):
			_, _ = w.Write([]byte(`{"data":[{"file_name":"ok.json","errors":[]}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": m.savedQueries})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/saved-queries/"):
			var qid int64
			_, _ = fmt.Sscanf(r.URL.Path, "/api/v2/saved-queries/%d", &qid)
			m.mu.Lock()
			m.deletedQueryIDs = append(m.deletedQueryIDs, qid)
			m.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries/import":
			rawZip, _ := io.ReadAll(r.Body)
			zr, err := zip.NewReader(bytes.NewReader(rawZip), int64(len(rawZip)))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m.mu.Lock()
			m.importedZipLen = len(zr.File)
			m.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":"imported"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return m, srv
}

func TestHMACSigningAndGate(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v2/graphs/cypher", nil)
	fixed := time.Date(2026, 11, 21, 12, 34, 56, 0, time.UTC)
	bloodhound.SignRequest(req, "tok-id", "tok-key", []byte(`{"query":"MATCH (n) RETURN n"}`), fixed)
	if !strings.HasPrefix(req.Header.Get("Authorization"), "bhesignature tok-id") {
		t.Fatalf("unexpected auth header: %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("RequestDate") != "2026-11-21T12:34:56Z" || req.Header.Get("Signature") == "" {
		t.Fatalf("missing signature headers")
	}

	m, srv := newMockCE(t)
	defer srv.Close()

	client, err := bloodhound.NewClient(bloodhound.ClientConfig{
		BaseURL: srv.URL,
		Auth:    bloodhound.AuthConfig{TokenID: "tok-id", TokenKey: "tok-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := client.ValidateAdapter(context.Background(), false)
	if err != nil || !report.Supported {
		t.Fatalf("ValidateAdapter failed: %v %+v", err, report)
	}
	if !strings.HasPrefix(m.authHeaderSeen, "bhesignature ") {
		t.Fatalf("expected bhesignature header, got %q", m.authHeaderSeen)
	}

	// Unsupported CE version fails closed unless allowUnvalidated=true.
	m.serverVersion = "v9.9.0"
	if _, err := client.ValidateAdapter(context.Background(), false); err == nil {
		t.Fatalf("expected unsupported CE version error")
	}
	rep2, err := client.ValidateAdapter(context.Background(), true)
	if err != nil || !rep2.Supported {
		t.Fatalf("expected allowUnvalidated=true to pass with warning: %v", err)
	}

	// Missing source-kinds capability fails with actionable error.
	m.serverVersion = "v9.7.1"
	m.failSourceKinds = true
	if _, err := client.ValidateAdapter(context.Background(), false); err == nil || !strings.Contains(err.Error(), "source-kinds") {
		t.Fatalf("expected source-kinds gate error, got: %v", err)
	}
}

func TestTwoStepUploadAndPreflightChunkingAndStubRejection(t *testing.T) {
	m, srv := newMockCE(t)
	m.cancelFirstJob = true
	defer srv.Close()

	client, err := bloodhound.NewClient(bloodhound.ClientConfig{
		BaseURL: srv.URL,
		Auth:    bloodhound.AuthConfig{Username: "admin", Password: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}

	basePayload := emitter.Payload{
		Metadata: &emitter.Metadata{SourceKind: "LLMHound"},
		Graph: emitter.GraphPayload{
			Nodes: []emitter.NodePayload{{ID: "SVC-1", Kinds: []string{"LLMHound_OllamaInstance", "LLMHound_AIService"}, Properties: map[string]any{"name": "SVC-1"}}},
			Edges: []emitter.EdgePayload{},
		},
	}
	baseBytes, _ := json.Marshal(basePayload)

	linkPayload := emitter.Payload{
		Metadata: nil,
		Graph: emitter.GraphPayload{
			Nodes: []emitter.NodePayload{},
			Edges: []emitter.EdgePayload{
				{Kind: "LLMHound_ObservedAt", Start: emitter.EndpointPayload{MatchBy: "id", Value: "SVC-1"}, End: emitter.EndpointPayload{MatchBy: "id", Value: "S-1-5-21-1103"}},
				{Kind: "LLMHound_ObservedAt", Start: emitter.EndpointPayload{MatchBy: "id", Value: "SVC-1"}, End: emitter.EndpointPayload{MatchBy: "id", Value: "STUB-MISSING"}},
				{Kind: "LLMHound_ObservedAt", Start: emitter.EndpointPayload{MatchBy: "id", Value: "SVC-1"}, End: emitter.EndpointPayload{MatchBy: "id", Value: "DOES-NOT-EXIST"}},
				{Kind: "LLMHound_CanExecuteOn", Start: emitter.EndpointPayload{MatchBy: "id", Value: "S-1-5-21-513"}, End: emitter.EndpointPayload{MatchBy: "id", Value: "S-1-5-21-1103"}},
			},
		},
	}
	linkBytes, _ := json.Marshal(linkPayload)

	rep, err := client.UploadScan(context.Background(), bloodhound.UploadOptions{
		BasePayloadBytes:    baseBytes,
		BaseFileName:        "base.json",
		LinkingPayloadBytes: linkBytes,
		LinkingFileName:     "linking.json",
		PollInterval:        10 * time.Millisecond,
		PollTimeout:         5 * time.Second,
		MaxRetries:          2,
	})
	if err != nil {
		t.Fatalf("UploadScan failed: %v", err)
	}
	if rep.BaseJob == nil || rep.BaseJob.Attempts != 2 {
		t.Fatalf("expected base job retry (2 attempts), got %+v", rep.BaseJob)
	}
	if rep.KeptEdges != 2 || len(rep.SkippedEdges) != 2 {
		t.Fatalf("expected 2 kept and 2 skipped (stub + missing), got kept=%d skipped=%+v", rep.KeptEdges, rep.SkippedEdges)
	}

	// Verify base payload kept source_kind and linking payload stayed sourceless.
	lastLink := m.uploadedJobs[len(m.uploadedJobs)-1].Payload
	if lastLink.Metadata != nil {
		t.Fatalf("uploaded linking payload must stay sourceless, got %+v", lastLink.Metadata)
	}

	// Reject linking payload that mistakenly declares source_kind (M0 Q5).
	badLinkBytes, _ := json.Marshal(emitter.Payload{Metadata: &emitter.Metadata{SourceKind: "LLMHound"}})
	if _, err := client.UploadScan(context.Background(), bloodhound.UploadOptions{LinkingPayloadBytes: badLinkBytes}); err == nil {
		t.Fatal("expected linking payload with source_kind to be rejected")
	}

	// Verify CheckExistingNodes chunks at 500.
	var manyIDs []string
	for i := 0; i < 620; i++ {
		manyIDs = append(manyIDs, fmt.Sprintf("ID-%04d", i))
	}
	beforeQueries := len(m.cypherQueries)
	if _, err := client.CheckExistingNodes(context.Background(), manyIDs); err != nil {
		t.Fatal(err)
	}
	if len(m.cypherQueries)-beforeQueries != 2 {
		t.Fatalf("expected 2 preflight chunks for 620 IDs, got %d", len(m.cypherQueries)-beforeQueries)
	}
}

func TestImportSavedQueries(t *testing.T) {
	m, srv := newMockCE(t)
	defer srv.Close()

	client, err := bloodhound.NewClient(bloodhound.ClientConfig{
		BaseURL: srv.URL,
		Auth:    bloodhound.AuthConfig{BearerToken: "jwt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	queries := savedsearch.Generate([]string{"MemberOf"})
	n, err := client.ImportSavedQueries(context.Background(), queries)
	if err != nil {
		t.Fatalf("ImportSavedQueries: %v", err)
	}
	if n != len(queries) || m.importedZipLen != len(queries) {
		t.Fatalf("imported=%d zip=%d want=%d", n, m.importedZipLen, len(queries))
	}
	if len(m.deletedQueryIDs) != 1 || m.deletedQueryIDs[0] != 10 {
		t.Fatalf("expected only stale LLMHound query (id 10) deleted, got %v", m.deletedQueryIDs)
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	var targetHit atomicBool
	offOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.set(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer offOrigin.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offOrigin.URL+"/leaked", http.StatusFound)
	}))
	defer redirector.Close()

	client, err := bloodhound.NewClient(bloodhound.ClientConfig{
		BaseURL: redirector.URL,
		Auth:    bloodhound.AuthConfig{TokenID: "  tok-id  ", TokenKey: "  tok-key  "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("expected unfollowed HTTP 302 error, got %v", err)
	}
	if targetHit.get() {
		t.Fatal("client followed redirect and could leak credentials/HMAC headers")
	}
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) set(b bool) {
	a.mu.Lock()
	a.v = b
	a.mu.Unlock()
}

func (a *atomicBool) get() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}
