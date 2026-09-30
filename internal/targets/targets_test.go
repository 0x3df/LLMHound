package targets

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareNormalizesDeduplicatesAndExcludes(t *testing.T) {
	got, err := Prepare(Input{Entries: []string{"192.0.2.0/30", "API.Example.Test.", "api.example.test", "2001:0db8::1", "::ffff:192.0.2.2"}, Exclude: []string{"192.0.2.0/31", "API.EXAMPLE.TEST."}, MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.2", "192.0.2.3", "2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPrepareIPv6AndExactNames(t *testing.T) {
	got, err := Prepare(Input{Entries: []string{"2001:db8::/126", "a.example.test", "b.a.example.test"}, Exclude: []string{"2001:db8::1/128", "a.example.test"}, MaxTargets: 6})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::", "2001:db8::2", "2001:db8::3", "b.a.example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPrepareFiles(t *testing.T) {
	dir := t.TempDir()
	file, excluded := filepath.Join(dir, "targets.txt"), filepath.Join(dir, "exclude.txt")
	if err := os.WriteFile(file, []byte("# comment\n\n192.0.2.1\nAI.Example.Test. # owner\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excluded, []byte("192.0.2.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Prepare(Input{Files: []string{file}, ExcludeFiles: []string{excluded}, MaxTargets: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"ai.example.test"}) {
		t.Fatal(got)
	}
	if err := os.WriteFile(file, []byte("192.0.2.1\nhttps://bad.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Input{Files: []string{file}, MaxTargets: 10}); err == nil || !strings.Contains(err.Error(), ":2") {
		t.Fatalf("want line error, got %v", err)
	}
}

func TestPrepareRejectsInvalidTargets(t *testing.T) {
	for _, value := range []string{"", "localhost", "https://ai.example.test", "ai.example.test:80", "user@ai.example.test", "*.example.test", "bad_name.example.test", "-bad.example.test", "bad..example.test", "K.example.test", strings.Repeat("a", 64) + ".example.test", strings.Repeat("a.", 127) + "test", "999.1.1.1", "192.168.001.1", "fe80::1%eth0", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "192.0.2.1/24", "192.0.2.0/33", "::ffff:192.0.2.0/120"} {
		t.Run(value, func(t *testing.T) {
			if got, err := Prepare(Input{Entries: []string{value}, MaxTargets: 10}); err == nil || got != nil {
				t.Fatalf("accepted %q: %v, %v", value, got, err)
			}
		})
	}
}

func TestPrepareLimitsBeforeExclusion(t *testing.T) {
	for _, in := range []Input{
		{Entries: []string{"10.0.0.0/8"}, Exclude: []string{"0.0.0.0/0"}, MaxTargets: 10},
		{Entries: []string{"2001:db8::/32"}, MaxTargets: 10},
		{Entries: []string{"192.0.2.0/30", "192.0.2.0/30"}, MaxTargets: 4},
		{Entries: []string{"a.example.test", "b.example.test"}, MaxTargets: 1},
		{Entries: []string{"a.example.test"}, MaxTargets: 0},
		{Entries: []string{"a.example.test"}, MaxTargets: HardMaxTargets + 1},
	} {
		if _, err := Prepare(in); err == nil {
			t.Fatalf("accepted limit violation: %+v", in)
		}
	}
	got, err := Prepare(Input{Entries: []string{"192.0.2.1"}, Exclude: []string{"0.0.0.0/0"}, MaxTargets: 1})
	if err != nil || len(got) != 0 {
		t.Fatalf("nonexpanding exclusion: %v %v", got, err)
	}
}

func TestPrepareFileAndEntryBounds(t *testing.T) {
	file := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(file, []byte(strings.Repeat("#", MaxInputBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, in := range []Input{
		{Files: []string{file}, MaxTargets: 1},
		{Files: []string{file + "missing"}, MaxTargets: 1},
		{Entries: make([]string, MaxInputEntries+1), MaxTargets: 1},
		{Entries: []string{"192.0.2.1"}, Exclude: []string{"https://bad.example.test"}, MaxTargets: 1},
	} {
		if _, err := Prepare(in); err == nil {
			t.Fatalf("accepted invalid input: %+v", in.Files)
		}
	}
}

func TestPrepareFileBoundaries(t *testing.T) {
	dir := t.TempDir()
	large := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(large, []byte(strings.Repeat("# comment\n", 60000)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Input{Files: []string{large, large}, MaxTargets: 1}); err == nil {
		t.Fatal("accepted aggregate oversized files")
	}
	longLine := filepath.Join(dir, "line.txt")
	if err := os.WriteFile(longLine, []byte(strings.Repeat("a", 5000)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Input{Files: []string{longLine}, MaxTargets: 1}); err == nil {
		t.Fatal("accepted oversized line")
	}
	if _, err := Prepare(Input{Files: []string{dir}, MaxTargets: 1}); err == nil {
		t.Fatal("accepted directory")
	}
	if _, err := Prepare(Input{Files: make([]string, 129), MaxTargets: 1}); err == nil || !strings.Contains(err.Error(), "too many input files") {
		t.Fatalf("want file count limit, got %v", err)
	}
}

func TestPrepareExpansionBoundary(t *testing.T) {
	got, err := Prepare(Input{Entries: []string{"192.0.2.0/24"}, Exclude: []string{"192.0.2.0/25", "192.0.2.128/26"}, MaxTargets: 256})
	if err != nil || len(got) != 64 {
		t.Fatalf("boundary: %d %v", len(got), err)
	}
	got, err = Prepare(Input{Entries: []string{"2001:db8::1/128", "192.0.2.1/32"}, MaxTargets: 2})
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("single address prefixes: %v %v", got, err)
	}
}

func TestPrepareRejectsAlternateNumericIPv4Spellings(t *testing.T) {
	for _, value := range []string{"0x7f.0.0.1", "0x7f000001.0", "127.0.0.0x1", "0X7F.0.0.1", "127.0.0.0X1", "10.0.0.1."} {
		t.Run(value, func(t *testing.T) {
			if got, err := Prepare(Input{Entries: []string{value}, MaxTargets: 10}); err == nil || got != nil {
				t.Fatalf("accepted %q as %v", value, got)
			}
			if got, err := Prepare(Input{Entries: []string{"ai.example.test"}, Exclude: []string{value}, MaxTargets: 10}); err == nil || got != nil {
				t.Fatalf("accepted exclusion %q: %v", value, got)
			}
			if got, err := NormalizeHost(value); err == nil {
				t.Fatalf("normalized %q to %q", value, got)
			}
		})
	}
	got, err := Prepare(Input{Entries: []string{"0x7f.example.test", "host.0x7f.test", "123.example.test"}, MaxTargets: 10})
	if err != nil || !reflect.DeepEqual(got, []string{"0x7f.example.test", "123.example.test", "host.0x7f.test"}) {
		t.Fatalf("hex-like non-final labels: %v %v", got, err)
	}
}

func TestNormalizeHostReportsEmptyLabels(t *testing.T) {
	for _, value := range []string{"ai.example.test..", "..", "10.0.0.1.."} {
		if got, err := NormalizeHost(value); err == nil || err.Error() != "invalid FQDN label" {
			t.Fatalf("%q: got %q, %v; want invalid FQDN label", value, got, err)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{"API.Example.Test.": "api.example.test", "::ffff:192.0.2.1": "192.0.2.1", "2001:0DB8::1": "2001:db8::1"} {
		got, err := NormalizeHost(in)
		if err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
}
