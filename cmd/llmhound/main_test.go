package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func execute(args ...string) (string, error) {
	var out bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func inEmptyDirectory(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

func TestHelpAndVersion(t *testing.T) {
	inEmptyDirectory(t)
	for _, args := range [][]string{{}, {"--help"}, {"targets", "--help"}, {"scan", "--help"}, {"plan", "--help"}, {"upload", "--help"}} {
		out, err := execute(args...)
		if err != nil || !strings.Contains(out, "Usage:") {
			t.Fatalf("%v: %q %v", args, out, err)
		}
	}
	out, err := execute("--version")
	if err != nil || !strings.Contains(out, "dev") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestCLIErrors(t *testing.T) {
	inEmptyDirectory(t)
	for _, tc := range []struct {
		args    []string
		message string
	}{
		{[]string{"unknown"}, "unknown command"},
		{[]string{"targets", "--unknown"}, "unknown flag"},
		{[]string{"targets", "extra"}, "unknown command"},
		{[]string{"targets", "--targets", "ai.example.test"}, "required"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner"}, "at least one"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--cidr", "10.0.0.0/8"}, "expansion exceeds"},
		{[]string{"targets", "--config", "missing.yaml"}, "config"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "https://bad.example.test"}, "invalid CIDR"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--exclude", "ai.example.test"}, "no targets remain"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--concurrency=0"}, "concurrency"},
		{[]string{"targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test", "--connect-timeout=oops"}, "invalid argument"},
	} {
		out, err := execute(tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.message) || out != "" {
			t.Fatalf("%v: output %q error %v; want %q", tc.args, out, err, tc.message)
		}
	}
}

func TestOfflineTargetCommand(t *testing.T) {
	inEmptyDirectory(t)
	out, err := execute("targets", "--scope", "tenant", "--vantage", "scanner", "--cidr", "192.0.2.0/30", "--targets", "AI.Example.Test.,192.0.2.3", "--exclude", "192.0.2.0/31")
	if err != nil || out != "192.0.2.2\n192.0.2.3\nai.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestDefaultConfigAndExplicitFlagReplacements(t *testing.T) {
	inEmptyDirectory(t)
	data := "scope: file\nvantage_key: scanner\ntargets: [from-file.example.test]\ncidrs: [192.0.2.0/30]\nbounds:\n  concurrency: 17\n  max_redirects: 4\ninsecure: true\nopt_ins:\n  prompts: true\n"
	if err := os.WriteFile("llmhound.yaml", []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute("targets", "--targets", "flag.example.test", "--exclude", "192.0.2.0/31", "--insecure=false", "--prompts=false", "--max-redirects=0")
	if err != nil || out != "192.0.2.2\n192.0.2.3\nflag.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
	// Explicit empty scope is not silently replaced by the file value.
	if _, err := execute("targets", "--scope="); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatal(err)
	}
	// Invalid untouched file bounds are not silently replaced by flag defaults.
	data = strings.Replace(data, "concurrency: 17", "concurrency: 0", 1)
	if err := os.WriteFile("llmhound.yaml", []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("targets"); err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatal(err)
	}
	if _, err := execute("targets", "--concurrency=1"); err != nil {
		t.Fatal(err)
	}
}

func TestFilePathsAndListOverrides(t *testing.T) {
	inEmptyDirectory(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.txt"), []byte("file.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("flag.txt", []byte("flag.example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "llmhound.yaml")
	if err := os.WriteFile(configPath, []byte("scope: tenant\nvantage_key: scanner\ntargets_files: [hosts.txt]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := execute("targets", "--config", configPath)
	if err != nil || out != "file.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
	out, err = execute("targets", "--config", configPath, "--targets-file", "flag.txt")
	if err != nil || out != "flag.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestUnimplementedCommandsNeverCreateArtifacts(t *testing.T) {
	inEmptyDirectory(t)
	for _, command := range []string{"scan", "plan", "upload"} {
		args := []string{command}
		if command != "upload" {
			args = append(args, "--scope", "tenant", "--vantage", "scanner", "--targets", "ai.example.test")
		}
		out, err := execute(args...)
		if err == nil || !strings.Contains(err.Error(), "not implemented") || out != "" {
			t.Fatalf("%s: %q %v", command, out, err)
		}
	}
	files, err := os.ReadDir(".")
	if err != nil || len(files) != 0 {
		t.Fatalf("created artifacts: %v %v", files, err)
	}
}

func TestPreparationMakesNoDNSQueriesOrTargetConnections(t *testing.T) {
	inEmptyDirectory(t)
	var dnsCalls atomic.Int32
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("unexpected DNS request")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	out, err := execute("targets", "--scope", "tenant", "--vantage", "scanner", "--targets", "127.0.0.1,never-resolve.example.test", "--reverse-dns", "--ce-lookup")
	if err != nil || out != "127.0.0.1\nnever-resolve.example.test\n" {
		t.Fatalf("%q %v", out, err)
	}
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unexpected target connection")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal(err)
	}
	if dnsCalls.Load() != 0 {
		t.Fatal("DNS called during preparation")
	}
}

func TestTargetOutputWriteError(t *testing.T) {
	inEmptyDirectory(t)
	cmd := newRootCommand()
	cmd.SetOut(failingWriter{})
	cmd.SetArgs([]string{"targets", "--scope", "t", "--vantage", "v", "--targets", "ai.example.test"})
	if err := cmd.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
