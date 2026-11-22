package correlate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/graph"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "map")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMappingFileFormats(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		want    []correlate.Mapping
	}{
		"json array with kinds": {
			`[{"target":"Ai1.Corp.Example","object_id":"S-1-5-21-1","kind":"Computer"},{"target":"10.0.0.5","object_id":"vm-1","kind":"AZVM"}]`,
			[]correlate.Mapping{{Target: "ai1.corp.example", ObjectID: "S-1-5-21-1", Kind: graph.Computer}, {Target: "10.0.0.5", ObjectID: "vm-1", Kind: "AZVM"}},
		},
		"json array kind defaults to Computer": {
			`[{"target":"ai1.corp.example","object_id":"id-1"}]`,
			[]correlate.Mapping{{Target: "ai1.corp.example", ObjectID: "id-1", Kind: graph.Computer}},
		},
		"json dictionary": {
			`{"ai1.corp.example":"id-1"}`,
			[]correlate.Mapping{{Target: "ai1.corp.example", ObjectID: "id-1", Kind: graph.Computer}},
		},
		"lines with comments and optional kind": {
			"# normalizer export\nai1.corp.example, id-1\nai2.corp.example id-2 AZVM # inline\n\n",
			[]correlate.Mapping{{Target: "ai1.corp.example", ObjectID: "id-1", Kind: graph.Computer}, {Target: "ai2.corp.example", ObjectID: "id-2", Kind: "AZVM"}},
		},
		"identical duplicates collapse": {
			"ai1.corp.example,id-1\nAI1.corp.example,id-1\n",
			[]correlate.Mapping{{Target: "ai1.corp.example", ObjectID: "id-1", Kind: graph.Computer}},
		},
	} {
		got, err := correlate.LoadMappingFile(write(t, tc.content))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v", name, got)
		}
		have := map[correlate.Mapping]bool{}
		for _, m := range got {
			have[m] = true
		}
		for _, w := range tc.want {
			if !have[w] {
				t.Fatalf("%s: missing %+v in %v", name, w, got)
			}
		}
	}
}

func TestLoadMappingFileRejections(t *testing.T) {
	for name, content := range map[string]string{
		"empty":            "   \n",
		"conflicting id":   "ai1.corp.example,id-1\nai1.corp.example,id-2\n",
		"conflicting kind": "ai1.corp.example,id-1,Computer\nai1.corp.example,id-1,AZVM\n",
		"owned kind":       "ai1.corp.example,id-1,OllamaInstance\n",
		"too many fields":  "a.example,id,Computer,extra\n",
		"one field":        "a.example\n",
		"bad target":       "http://a.example,id\n",
		"bad json shape":   `{"a":1}`,
		"only comments":    "# nothing\n",
		"bad object id":    `[{"target":"a.example","object_id":" ","kind":"Computer"}]`,
	} {
		if _, err := correlate.LoadMappingFile(write(t, content)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := correlate.LoadMappingFile(""); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := correlate.LoadMappingFile(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := correlate.LoadMappingFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	big := strings.Repeat("a.example,id\n", (correlate.MaxMappingFileBytes/13)+10)
	if _, err := correlate.LoadMappingFile(write(t, big)); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestNewFromConfig(t *testing.T) {
	// No mapping file: everything falls back to NetworkEndpoint for the normalizer.
	r, err := correlate.NewFromConfig(config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Resolve("scope", "ai1.corp.example")
	if err != nil || res.Target().IsNative() {
		t.Fatal("unmapped target attached")
	}
	cfg := config.Config{Correlation: config.Correlation{MappingFile: write(t, "ai1.corp.example,id-1,AZVM\n")}}
	r, err = correlate.NewFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, _ = r.Resolve("scope", "ai1.corp.example")
	if !res.Target().IsNative() || res.Target().Kind() != "AZVM" {
		t.Fatal("configured mapping not applied")
	}
	if _, err := correlate.NewFromConfig(config.Config{Correlation: config.Correlation{MappingFile: filepath.Join(t.TempDir(), "nope")}}); err == nil {
		t.Fatal("missing configured mapping file accepted")
	}

	// Envelope with mapping_source provenance.
	envFile := write(t, `{"source":"norm-rev-20261121","mappings":[{"target":"ai2.corp.example","object_id":"S-1-5-21-1","kind":"Computer"}]}`)
	rEnv, err := correlate.NewFromConfig(config.Config{Correlation: config.Correlation{MappingFile: envFile}})
	if err != nil {
		t.Fatal(err)
	}
	resEnv, err := rEnv.Resolve("scope", "ai2.corp.example")
	if err != nil {
		t.Fatal(err)
	}
	if resEnv.Evidence().Correlation.MappingSource != "norm-rev-20261121" {
		t.Fatalf("expected mapping_source norm-rev-20261121, got %q", resEnv.Evidence().Correlation.MappingSource)
	}
}
