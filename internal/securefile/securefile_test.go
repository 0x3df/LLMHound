package securefile_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/0x3df/LLMHound/internal/securefile"
)

func TestOpenFileExclusiveAndRestricted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.jsonl")
	f, err := securefile.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("x\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := securefile.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY); !errors.Is(err, os.ErrExist) {
		t.Fatalf("O_EXCL on an existing file must fail with ErrExist, got %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("mode = %o, want 0600", perm)
		}
	}
}

func TestOpenFileRestrictsExistingLooseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "loose.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := securefile.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 0600 after re-restriction", perm)
	}
}

func TestOpenFileAppendCreatesThenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "append.jsonl")
	for i := 0; i < 2; i++ {
		f, err := securefile.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("line\n"); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "line\nline\n" {
		t.Fatalf("content = %q", b)
	}
}
