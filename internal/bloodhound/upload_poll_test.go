package bloodhound_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/bloodhound"
)

// paginatedCE mimics a long-lived CE instance: the upload-job listing holds
// many historical jobs and returns at most `defaultLimit` rows per request
// unless skip/limit are given. The new job is never on the first default page.
type paginatedCE struct {
	mu            sync.Mutex
	rejectFilter  bool // answer ?id=eq: with HTTP 400
	ignoreFilter  bool // ignore ?id=eq: and return the default page
	hideJob       bool // never list the new job
	runningPolls  int  // polls that report the new job as running before completion
	listCalls     int
	filteredCalls int
	nextID        int64
	jobs          []map[string]any
}

const defaultLimit = 10

func newPaginatedCE(t *testing.T, ce *paginatedCE) *httptest.Server {
	t.Helper()
	for i := 1; i <= 25; i++ {
		ce.jobs = append(ce.jobs, map[string]any{"id": int64(i), "status": 2})
	}
	ce.nextID = 26
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ce.mu.Lock()
		defer ce.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			id := ce.nextID
			ce.nextID++
			if !ce.hideJob {
				ce.jobs = append(ce.jobs, map[string]any{"id": id, "status": 0})
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": id}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/end"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v2/file-upload/"):
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/file-upload":
			ce.listCalls++
			q := r.URL.Query()
			if f := q.Get("id"); f != "" {
				ce.filteredCalls++
				if ce.rejectFilter {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !ce.ignoreFilter {
					want, _ := strconv.ParseInt(strings.TrimPrefix(f, "eq:"), 10, 64)
					var rows []map[string]any
					for _, j := range ce.jobs {
						if j["id"].(int64) == want {
							rows = append(rows, ce.advance(j))
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": rows})
					return
				}
			}
			skip, _ := strconv.Atoi(q.Get("skip"))
			limit, err := strconv.Atoi(q.Get("limit"))
			if err != nil || limit <= 0 {
				limit = defaultLimit
			}
			var rows []map[string]any
			for i := skip; i < len(ce.jobs) && i < skip+limit; i++ {
				rows = append(rows, ce.advance(ce.jobs[i]))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": rows})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/completed-tasks"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// advance moves the newest job from running to complete after runningPolls.
func (ce *paginatedCE) advance(j map[string]any) map[string]any {
	if j["id"].(int64) >= 26 && j["status"].(int) != 2 {
		if ce.runningPolls > 0 {
			ce.runningPolls--
			j["status"] = 1
		} else {
			j["status"] = 2
		}
	}
	return map[string]any{"id": j["id"], "status": j["status"]}
}

func pollClient(t *testing.T, url string) *bloodhound.Client {
	t.Helper()
	c, err := bloodhound.NewClient(bloodhound.ClientConfig{BaseURL: url, Auth: bloodhound.AuthConfig{BearerToken: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUploadFileJob_WaitsForJobBeyondFirstPage(t *testing.T) {
	for _, tc := range []struct {
		name string
		ce   *paginatedCE
	}{
		{"id filter honored", &paginatedCE{runningPolls: 2}},
		{"id filter rejected", &paginatedCE{rejectFilter: true, runningPolls: 2}},
		{"id filter ignored", &paginatedCE{ignoreFilter: true, runningPolls: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newPaginatedCE(t, tc.ce)
			job, err := pollClient(t, srv.URL).UploadFileJob(context.Background(), []byte(`{"graph":{"nodes":[],"edges":[]}}`),
				"application/json", "x.json", time.Millisecond, 5*time.Second, 0)
			if err != nil {
				t.Fatalf("upload: %v", err)
			}
			if job.Status != 2 {
				t.Fatalf("status = %d, want complete (2)", job.Status)
			}
			tc.ce.mu.Lock()
			defer tc.ce.mu.Unlock()
			if tc.ce.runningPolls != 0 {
				t.Fatalf("returned before the job finished running (%d running polls left)", tc.ce.runningPolls)
			}
		})
	}
}

func TestUploadFileJob_InvisibleJobIsNotSuccess(t *testing.T) {
	srv := newPaginatedCE(t, &paginatedCE{hideJob: true})
	_, err := pollClient(t, srv.URL).UploadFileJob(context.Background(), []byte(`{"graph":{"nodes":[],"edges":[]}}`),
		"application/json", "x.json", time.Millisecond, 50*time.Millisecond, 0)
	if err == nil || !strings.Contains(err.Error(), "not visible") {
		t.Fatalf("a job that never appears must fail, got %v", err)
	}
}

func TestUploadScanRejectsBaseEdgeToMissingNode(t *testing.T) {
	srv := newPaginatedCE(t, &paginatedCE{})
	base := []byte(`{"metadata":{"source_kind":"LLMHound"},"graph":{"nodes":[{"id":"A","kinds":["LLMHound_OllamaInstance"],"properties":{}}],` +
		`"edges":[{"kind":"LLMHound_HostsModel","start":{"match_by":"id","value":"A"},"end":{"match_by":"id","value":"S-1-5-21-NATIVE"}}]}}`)
	_, err := pollClient(t, srv.URL).UploadScan(context.Background(), bloodhound.UploadOptions{BasePayloadBytes: base, DisableZIP: true})
	if err == nil || !strings.Contains(err.Error(), "not a node in the base payload") {
		t.Fatalf("base edge to a non-base node must be refused before upload, got %v", err)
	}
}

func TestTier0SeedReportsCECap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/graphs/cypher":
			var req struct {
				Query string `json:"query"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			nodes := map[string]any{}
			if strings.Contains(req.Query, "Tag_Tier_Zero) RETURN t") {
				for i := 0; i < bloodhound.CEResultCap; i++ {
					id := "S-1-5-21-" + strconv.Itoa(i)
					nodes[id] = map[string]any{"kinds": []string{"User"}, "objectId": id}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"nodes": nodes, "edges": []any{}}})
		case "/api/v2/extensions-edges":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ids, capped, err := pollClient(t, srv.URL).Tier0AdjacentObjectIDsWithCap(context.Background(), 2, bloodhound.CEResultCap)
	if err != nil {
		t.Fatal(err)
	}
	if !capped || len(ids) != bloodhound.CEResultCap {
		t.Fatalf("capped=%v ids=%d, want truncation reported", capped, len(ids))
	}
}
