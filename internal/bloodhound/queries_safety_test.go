package bloodhound_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/0x3df/LLMHound/internal/bloodhound"
	"github.com/0x3df/LLMHound/internal/savedsearch"
)

type queryCE struct {
	mu         sync.Mutex
	queries    []bloodhound.SavedQueryRecord
	deleted    []int64
	recreated  []string
	failImport bool
}

func newQueryCE(t *testing.T, ce *queryCE) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ce.mu.Lock()
		defer ce.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
			limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil || limit <= 0 {
				limit = 10 // CE-style small default page
			}
			var page []bloodhound.SavedQueryRecord
			for i := skip; i < len(ce.queries) && i < skip+limit; i++ {
				page = append(page, ce.queries[i])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": page})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/saved-queries/"):
			id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/v2/saved-queries/"), 10, 64)
			ce.deleted = append(ce.deleted, id)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries/import":
			if ce.failImport {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			ce.recreated = append(ce.recreated, body["name"])
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func manyQueries() []bloodhound.SavedQueryRecord {
	var qs []bloodhound.SavedQueryRecord
	for i := 1; i <= 150; i++ {
		qs = append(qs, bloodhound.SavedQueryRecord{ID: int64(i), Name: fmt.Sprintf("Analyst query %d", i), Query: "MATCH (n) RETURN n"})
	}
	qs[119] = bloodhound.SavedQueryRecord{ID: 120, Name: "LLMHound P1: older title", Query: "MATCH (o) RETURN o"}
	qs[130] = bloodhound.SavedQueryRecord{ID: 131, Name: "LLMHound triage (analyst)", Query: "MATCH (a) RETURN a"}
	return qs
}

func queryClient(t *testing.T, url string) *bloodhound.Client {
	t.Helper()
	c, err := bloodhound.NewClient(bloodhound.ClientConfig{BaseURL: url, Auth: bloodhound.AuthConfig{BearerToken: "jwt"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestListSavedQueriesReadsAllPages(t *testing.T) {
	ce := &queryCE{queries: manyQueries()}
	got, err := queryClient(t, newQueryCE(t, ce).URL).ListSavedQueries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 150 {
		t.Fatalf("listed %d queries, want 150", len(got))
	}
}

func TestImportSavedQueriesReplacesOnlyShippedQueries(t *testing.T) {
	ce := &queryCE{queries: manyQueries()}
	if _, err := queryClient(t, newQueryCE(t, ce).URL).ImportSavedQueries(context.Background(), savedsearch.Generate([]string{"MemberOf"})); err != nil {
		t.Fatal(err)
	}
	if len(ce.deleted) != 1 || ce.deleted[0] != 120 {
		t.Fatalf("deleted %v, want only the shipped query on page 2 (id 120)", ce.deleted)
	}
}

func TestImportSavedQueriesRestoresOnFailedImport(t *testing.T) {
	ce := &queryCE{queries: manyQueries(), failImport: true}
	_, err := queryClient(t, newQueryCE(t, ce).URL).ImportSavedQueries(context.Background(), savedsearch.Generate([]string{"MemberOf"}))
	if err == nil {
		t.Fatal("expected the failed import to surface an error")
	}
	if len(ce.recreated) != 1 || ce.recreated[0] != "LLMHound P1: older title" {
		t.Fatalf("replaced query must be restored after a failed import, recreated %v", ce.recreated)
	}
}
