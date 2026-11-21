package savedsearch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dir = "../../extension/saved_searches"

func loadKinds(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "path_kinds.txt"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePathKinds(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The shipped files must equal the generator output (run `go run ./tools/gensearches`).
func TestShippedFilesAreCurrent(t *testing.T) {
	for _, q := range Generate(loadKinds(t)) {
		want, err := Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, FileName(q)))
		if err != nil {
			t.Fatalf("%s: %v (run go run ./tools/gensearches)", FileName(q), err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is stale; run go run ./tools/gensearches", FileName(q))
		}
	}
}

func TestQueriesUseEmittedKindsAndTypedPaths(t *testing.T) {
	for _, q := range Generate(loadKinds(t)) {
		for _, bad := range []string{"[*", ":AIService", ":ObservedAt", ":NetworkEndpoint", "IN n.system_tags"} {
			if strings.Contains(q.Query, bad) {
				t.Errorf("%s contains %q", q.Name, bad)
			}
		}
		if strings.Contains(q.Query, "shortestPath") && strings.Contains(q.Query, "LLMHound_CanExecuteOn") {
			t.Errorf("%s must not follow rule edges by default", q.Name)
		}
	}
}

func TestParsePathKindsRejectsInjection(t *testing.T) {
	for _, in := range []string{"A|B", "MemberOf]->()", "LLMHound_ObservedAt", ""} {
		if _, err := ParsePathKinds(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}
}
