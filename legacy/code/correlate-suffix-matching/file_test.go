//go:build ignore

// ARCHIVED. Not compiled. See legacy/README.md.
// Retired: AD-suffix property matching against a caller-supplied verified
// inventory (superseded by mapping-file-only attachment of any native kind).

package correlate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
)

func TestLoadMappingFile_JSON(t *testing.T) {
	dir := t.TempDir()
	arrayPath := filepath.Join(dir, "mappings_array.json")
	dictPath := filepath.Join(dir, "mappings_dict.json")

	if err := os.WriteFile(arrayPath, []byte(`[
		{"target": "192.0.2.1", "computer_id": "S-1-5-21-1111-2222-3333-1001"},
		{"target": "ai.lab.local", "computer_id": "S-1-5-21-1111-2222-3333-1002"}
	]`), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(dictPath, []byte(`{
		"192.0.2.2": "S-1-5-21-1111-2222-3333-1003"
	}`), 0600); err != nil {
		t.Fatal(err)
	}

	mappings, err := correlate.LoadMappingFile(arrayPath)
	if err != nil {
		t.Fatalf("LoadMappingFile array: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
	if mappings[0].Target != "192.0.2.1" || mappings[0].ComputerID != "S-1-5-21-1111-2222-3333-1001" {
		t.Errorf("unexpected mapping 0: %+v", mappings[0])
	}

	mappings, err = correlate.LoadMappingFile(dictPath)
	if err != nil {
		t.Fatalf("LoadMappingFile dict: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	if mappings[0].Target != "192.0.2.2" {
		t.Errorf("unexpected mapping: %+v", mappings[0])
	}
}

func TestLoadMappingFile_LineDelimited(t *testing.T) {
	dir := t.TempDir()
	linesPath := filepath.Join(dir, "mappings.txt")
	content := `# Line delimited mappings with comments
192.0.2.10 S-1-5-21-1111-2222-3333-2001
192.0.2.11, S-1-5-21-1111-2222-3333-2002 # comma separated

ai-01.lab.local S-1-5-21-1111-2222-3333-2003
`
	if err := os.WriteFile(linesPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	mappings, err := correlate.LoadMappingFile(linesPath)
	if err != nil {
		t.Fatalf("LoadMappingFile line-delimited: %v", err)
	}
	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(mappings))
	}
	if mappings[1].Target != "192.0.2.11" || mappings[1].ComputerID != "S-1-5-21-1111-2222-3333-2002" {
		t.Errorf("unexpected mapping 1: %+v", mappings[1])
	}
}

func TestLoadMappingFile_Errors(t *testing.T) {
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(emptyPath, []byte("  \n# only comments\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := correlate.LoadMappingFile(""); err == nil {
		t.Error("expected error on empty path")
	}
	if _, err := correlate.LoadMappingFile(emptyPath); err == nil {
		t.Error("expected error on empty file")
	}
	if _, err := correlate.LoadMappingFile(filepath.Join(dir, "nonexistent")); err == nil {
		t.Error("expected error on nonexistent file")
	}

	badPath := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(badPath, []byte("just_one_field\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := correlate.LoadMappingFile(badPath); err == nil {
		t.Error("expected error on invalid line")
	}
}

func TestNewFromConfig(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "map.json")
	if err := os.WriteFile(mapPath, []byte(`[{"target": "10.0.0.1", "computer_id": "S-1-5-21-100"}]`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Scope = "corp"
	cfg.VantageKey = "scanner-1"
	cfg.Correlation.MappingFile = mapPath
	cfg.Correlation.ADDomainSuffixes = []string{"corp.local"}

	resolver, err := correlate.NewFromConfig(cfg, nil, true)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}

	verified := []correlate.Computer{
		{ObjectID: "S-1-5-21-100", Name: "HOST-100.CORP.LOCAL"},
	}

	res, err := resolver.Resolve("corp", "10.0.0.1", verified)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !res.Evidence().Verified || res.Target().ID() != "S-1-5-21-100" {
		t.Errorf("failed to correlate via loaded mapping file: %+v", res)
	}
}

func TestLoadMappingFile_RejectsConflictingTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.txt")
	body := "192.0.2.1 S-1-5-21-1111-2222-3333-1001\n192.0.2.1 S-1-5-21-1111-2222-3333-1002\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := correlate.LoadMappingFile(path); err == nil {
		t.Fatal("expected conflict error")
	}
}
