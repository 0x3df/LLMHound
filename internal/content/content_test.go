package content_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/content"
)

func baseInput(body string) content.RecordInput {
	return content.RecordInput{
		DeploymentScope: "scope-1",
		ScanID:          "scan-1",
		VantageKey:      "vantage-1",
		ServiceID:       strings.Repeat("A", 64),
		Surface:         "ollama",
		CheckID:         "ollama_show",
		Source:          "http://user:pass@127.0.0.1:11434/api/show?secret=1",
		Kind:            content.KindSystemPrompt,
		Location:        "llama3:latest#system",
		ObservedAt:      time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC),
		Body:            body,
	}
}

func TestBudget_ItemAndServiceLimitsAndUTF8(t *testing.T) {
	cfg := config.DefaultContent()
	cfg.MaxItemBytes = 10
	cfg.MaxServiceBytes = 15
	cfg.MaxItemsPerResource = 2

	b := content.NewBudget(cfg, nil)

	// Multi-byte UTF-8 boundary: 8 ASCII bytes + 3-byte '€' = 11 bytes (> 10).
	rec, added, err := b.Add(baseInput("12345678€"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !added || !rec.Truncated || rec.Body != "12345678" || !utf8.ValidString(rec.Body) {
		t.Fatalf("unexpected UTF-8 truncated record: added=%v rec=%+v", added, rec)
	}
	if strings.Contains(rec.Source, "pass") || strings.Contains(rec.Source, "secret=1") {
		t.Fatalf("source URL not sanitized: %s", rec.Source)
	}

	// Second item capped by remaining service bytes (15 - 8 = 7 bytes).
	rec2, added2, err := b.Add(baseInput("abcdefghij"))
	if err != nil {
		t.Fatalf("Add 2: %v", err)
	}
	if !added2 || !rec2.Truncated || rec2.Body != "abcdefg" {
		t.Fatalf("expected service-byte cap to 7 bytes, got added=%v rec=%+v", added2, rec2)
	}
	if b.Bytes() != 15 || !b.Truncated() {
		t.Fatalf("bytes=%d truncated=%v, want 15/true", b.Bytes(), b.Truncated())
	}

	// Third item rejected cleanly when service budget exhausted.
	_, added3, err := b.Add(baseInput("more"))
	if err != nil || added3 {
		t.Fatalf("expected exhausted service budget to skip item, added=%v err=%v", added3, err)
	}
}

func TestBudget_ClaimResourceItemAndRedactor(t *testing.T) {
	cfg := config.DefaultContent()
	cfg.MaxItemsPerResource = 1
	b := content.NewBudget(cfg, func(body string) (string, []content.Finding) {
		return strings.ReplaceAll(body, "TOPSECRET", "[secret:test]"), []content.Finding{{Type: "test", Line: 1}}
	})

	if ok, _ := b.ClaimResourceItem("res"); !ok {
		t.Fatal("first claim should succeed")
	}
	if ok, reason := b.ClaimResourceItem("res"); ok || !strings.Contains(reason, "max_items_per_resource") {
		t.Fatalf("second claim should fail with max_items_per_resource, ok=%v reason=%q", ok, reason)
	}
	rec, added, err := b.Add(baseInput("prefix TOPSECRET suffix"))
	if err != nil || !added {
		t.Fatalf("Add redacted: added=%v err=%v", added, err)
	}
	if strings.Contains(rec.Body, "TOPSECRET") || !strings.Contains(rec.Body, "[secret:test]") {
		t.Fatalf("redactor not applied: %q", rec.Body)
	}

	findings := b.Findings()
	if len(findings) != 1 || findings[0].Type != "test" || findings[0].Location != "llama3:latest#system" || findings[0].Line != 1 {
		t.Fatalf("findings = %+v, want one test finding at llama3:latest#system line 1", findings)
	}
	if types := b.SecretTypes(); len(types) != 1 || types[0] != "test" {
		t.Fatalf("SecretTypes = %v, want [test]", types)
	}
}

func TestBudget_SecretTypesSortedUnique(t *testing.T) {
	b := content.NewBudget(config.DefaultContent(), func(body string) (string, []content.Finding) {
		if body == "a" {
			return body, []content.Finding{{Type: "private_key"}, {Type: "github_token"}, {Type: "github_token"}}
		}
		return body, nil
	})
	for _, body := range []string{"a", "b", "c"} {
		if _, added, err := b.Add(baseInput(body)); err != nil || !added {
			t.Fatalf("Add %q: added=%v err=%v", body, added, err)
		}
	}
	if types := b.SecretTypes(); len(types) != 2 || types[0] != "github_token" || types[1] != "private_key" {
		t.Fatalf("SecretTypes = %v, want sorted unique [github_token private_key]", types)
	}
	if got := len(b.Findings()); got != 3 {
		t.Fatalf("Findings = %d entries, want 3", got)
	}
}

func TestBinaryDetection(t *testing.T) {
	for _, tc := range []struct {
		name, mime string
		want       bool
	}{
		{"model.gguf", "", true},
		{"weights.safetensors", "", true},
		{"blob.bin", "application/octet-stream", true},
		{"avatar.png", "image/png", true},
		{"notebook.ipynb", "application/json", false},
		{"config.yaml", "text/plain; charset=utf-8", false},
	} {
		if got := content.IsBinaryContent(tc.name, tc.mime); got != tc.want {
			t.Errorf("IsBinaryContent(%q, %q) = %v, want %v", tc.name, tc.mime, got, tc.want)
		}
	}
	if !content.LooksBinary([]byte("abc\x00def")) || !content.LooksBinary([]byte{0xff, 0xfe, 0xfd}) {
		t.Error("LooksBinary should reject NUL bytes and invalid UTF-8")
	}
	lateNUL := append([]byte(strings.Repeat("a", 5000)), 0)
	if !content.LooksBinary(lateNUL) {
		t.Error("LooksBinary must inspect the full bounded body for NUL bytes")
	}
	if content.LooksBinary([]byte("hello world\n")) {
		t.Error("LooksBinary rejected plain UTF-8 text")
	}
	// A valid multi-byte rune crossing the old 4096-byte probe boundary remains text.
	edge := append(make([]byte, 4094), []byte("€")...)
	for i := range 4094 {
		edge[i] = 'a'
	}
	if content.LooksBinary(edge) {
		t.Error("LooksBinary split a valid multi-byte rune")
	}

	b := content.NewBudget(config.DefaultContent(), nil)
	recForBinary, added, err := b.Add(baseInput("ok"))
	if err != nil || !added {
		t.Fatalf("build valid record: added=%v err=%v", added, err)
	}
	recForBinary.Body += "\x00"
	recForBinary.BodyBytes = int64(len(recForBinary.Body))
	if err := recForBinary.Validate(); err == nil {
		t.Fatal("Record.Validate must reject NUL bytes")
	}
}

func TestLazyFileWriter_PermissionsAndConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "scan.content.jsonl")
	w := content.NewLazyFileWriter(path)
	if err := w.Close(); err != nil {
		t.Fatalf("close unused writer: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unused LazyFileWriter must not create file: %v", err)
	}

	w = content.NewLazyFileWriter(path)
	b := content.NewBudget(config.DefaultContent(), nil)
	rec, _, err := b.Add(baseInput("system prompt body"))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Write(rec); err != nil {
				t.Errorf("Write: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("content file mode = %o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 8 {
		t.Fatalf("got %d JSONL lines, want 8", len(lines))
	}
	var parsed content.Record
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil || parsed.Body != "system prompt body" {
		t.Fatalf("invalid JSONL record: %v %+v", err, parsed)
	}
}
func TestLazyFileWriterRejectsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.content.jsonl")
	want := []byte("keep-me\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	b := content.NewBudget(config.DefaultContent(), nil)
	rec, _, err := b.Add(baseInput("new body"))
	if err != nil {
		t.Fatal(err)
	}
	if err := content.NewLazyFileWriter(path).Write(rec); err == nil {
		t.Fatal("writer must fail rather than truncate an existing content artifact")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("existing content artifact changed: got %q want %q", got, want)
	}
}
