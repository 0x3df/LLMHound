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
	all := Generate(loadKinds(t))
	if len(all) != 19 {
		t.Fatalf("expected 19 saved queries (P1-P12, I1-I7), got %d", len(all))
	}
	for _, q := range all {
		for _, bad := range []string{"[*", ":AIService", ":ObservedAt", ":NetworkEndpoint", "IN n.system_tags"} {
			if strings.Contains(q.Query, bad) {
				t.Errorf("%s contains %q", q.Name, bad)
			}
		}
		if strings.Contains(q.Query, "shortestPath") && (strings.Contains(q.Query, "LLMHound_CanExecuteOn") || strings.Contains(q.Query, "LLMHound_CanAssumePrincipal")) {
			t.Errorf("%s must not follow rule edges by default", q.Name)
		}
	}
	withRules := GenerateWithOptions(loadKinds(t), GenerateOptions{IncludeCanExecuteOn: true})
	if !strings.Contains(withRules[0].Query, "LLMHound_CanExecuteOn") || !strings.Contains(withRules[0].Query, "LLMHound_CanAssumePrincipal") {
		t.Errorf("IncludeCanExecuteOn should add rule edge kinds to path kinds")
	}
}

func TestParsePathKindsRejectsInjection(t *testing.T) {
	for _, in := range []string{"A|B", "MemberOf]->()", "123BadKind", "_LeadingUnderscore", "MemberOf\nMemberOf", "LLMHound_ObservedAt", ""} {
		if _, err := ParsePathKinds(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}
}

func TestP4ExcludesNetworkEndpoint(t *testing.T) {
	for _, q := range Generate([]string{"MemberOf"}) {
		if strings.HasPrefix(q.Name, "LLMHound P4:") {
			if !strings.Contains(q.Query, "NOT h:LLMHound_NetworkEndpoint") {
				t.Errorf("P4 must exclude NetworkEndpoint nodes: %s", q.Query)
			}
			return
		}
	}
	t.Fatal("P4 query missing")
}
