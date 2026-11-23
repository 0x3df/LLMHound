package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/0x3df/LLMHound/internal/runresult"
	"github.com/0x3df/LLMHound/internal/secrets/secretstest"
)

func executeWithContext(ctx context.Context, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := newRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

func readResultFile(t *testing.T, path string) (runresult.Result, string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result file %s: %v", path, err)
	}
	var res runresult.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("decode result file %s: %v\n%s", path, err, raw)
	}
	return res, string(raw)
}

func TestScanResultFileLifecycleComplete(t *testing.T) {
	inEmptyDirectory(t)
	tok := secretstest.GitHubToken("ghp", "Ab3Cd7Ef1Gh5Ij9Kl3Mn7Op1Qr5St9")

	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.6.0"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/show":
			_, _ = fmt.Fprintf(w, `{"modelfile":"FROM llama3\nSYSTEM \"token=%s\""}`, tok)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ollamaSrv.Close()

	defs := fmt.Sprintf(`[{"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]}]`, portOf(ollamaSrv.URL))
	if err := os.WriteFile("disc.json", []byte(defs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("map.json", []byte(`{"127.0.0.1":"S-1-5-21-100-200-1001"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	resultPath := filepath.Join(t.TempDir(), "scan-result.json")
	out, err := execute(
		"scan",
		"--scope", "prod",
		"--vantage", "scanner-a",
		"--targets", "127.0.0.1",
		"--discovery-file", "disc.json",
		"--mapping-file", "map.json",
		"--profile", "full",
		"--graph-mode", "full",
		"--content-mode", "full",
		"--output-dir", outDir,
		"--prefix", "job-ok",
		"--result-file", resultPath,
	)
	if err != nil {
		t.Fatalf("scan failed: %q %v", out, err)
	}

	res, raw := readResultFile(t, resultPath)
	if res.SchemaVersion != runresult.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", res.SchemaVersion, runresult.SchemaVersion)
	}
	if res.Command != runresult.CommandScan || res.Status != runresult.StatusComplete {
		t.Errorf("command=%s status=%s", res.Command, res.Status)
	}
	if res.ExitCode == nil || *res.ExitCode != 0 {
		t.Errorf("exit_code = %v, want 0", res.ExitCode)
	}
	if res.DurationMS == nil || *res.DurationMS < 0 || res.StartedAt == "" || res.UpdatedAt == "" || res.FinishedAt == "" {
		t.Errorf("unexpected timing fields: %+v", res)
	}
	if res.Error != "" {
		t.Errorf("unexpected error: %q", res.Error)
	}
	if res.Scan == nil {
		t.Fatal("missing scan section")
	}
	if res.Scan.Scope != "prod" || res.Scan.VantageKey != "scanner-a" || res.Scan.Prefix != "job-ok" || res.Scan.OutputDir != outDir {
		t.Errorf("unexpected scan metadata: %+v", res.Scan)
	}
	if res.Scan.TargetsCount == nil || *res.Scan.TargetsCount != 1 {
		t.Errorf("targets_count = %v, want 1", res.Scan.TargetsCount)
	}
	if res.Scan.Resumable {
		t.Error("resumable should be false on complete scan")
	}
	if res.Scan.TargetErrorCount != 0 || len(res.Scan.TargetErrors) != 0 {
		t.Errorf("unexpected target errors: %+v", res.Scan)
	}
	for _, p := range []string{
		res.Scan.Artifacts.BasePayloadPath,
		res.Scan.Artifacts.LinkingPayloadPath,
		res.Scan.Artifacts.EvidenceSidecarPath,
		res.Scan.Artifacts.JournalPath,
		res.Scan.Artifacts.ContentPath,
	} {
		if p == "" {
			t.Errorf("expected non-empty artifact path in %+v", res.Scan.Artifacts)
			continue
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("artifact %q missing: %v", p, err)
		}
	}
	if res.Scan.Counts == nil {
		t.Fatal("expected scan.counts on complete scan")
	}
	if res.Scan.Counts.Services != 1 || res.Scan.Counts.BaseNodes != 2 || res.Scan.Counts.BaseEdges != 1 || res.Scan.Counts.LinkingEdges != 1 || res.Scan.Counts.ExposedSecretServices != 1 || res.Scan.Counts.EvidenceRecords == 0 {
		t.Errorf("unexpected scan.counts: %+v", *res.Scan.Counts)
	}
	if strings.Contains(raw, tok) {
		t.Fatal("secret token value leaked into result file")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(resultPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("result file mode = %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestScanResultFileLifecycleFailedConfigAndStaleOverwrite(t *testing.T) {
	inEmptyDirectory(t)
	resultPath := filepath.Join(t.TempDir(), "stale.json")
	stale := `{"schema_version":"1","command":"scan","status":"complete","exit_code":0}`
	if err := os.WriteFile(resultPath, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	// Missing --targets triggers prepare() failure after pending has already replaced the stale complete file.
	_, err := execute("scan", "--scope", "prod", "--vantage", "v1", "--result-file", resultPath)
	if err == nil {
		t.Fatal("expected invalid scan config error")
	}

	res, _ := readResultFile(t, resultPath)
	if res.Status != runresult.StatusFailed || res.Command != runresult.CommandScan {
		t.Fatalf("status=%s command=%s, want failed/scan", res.Status, res.Command)
	}
	if res.ExitCode == nil || *res.ExitCode != 1 || res.Error == "" || res.FinishedAt == "" {
		t.Fatalf("unexpected failed envelope: %+v", res)
	}
	if res.Scan == nil || res.Scan.Counts != nil || res.Scan.Resumable {
		t.Fatalf("unexpected scan section on config failure: %+v", res.Scan)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(resultPath)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("mode after overwrite = %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestScanResultFileLifecyclePendingThenInterrupted(t *testing.T) {
	inEmptyDirectory(t)

	hitCh := make(chan struct{})
	var hitOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitOnce.Do(func() { close(hitCh) })
		<-r.Context().Done()
	}))
	defer srv.Close()

	defs := fmt.Sprintf(`[{"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]}]`, portOf(srv.URL))
	if err := os.WriteFile("disc.json", []byte(defs), 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	resultPath := filepath.Join(t.TempDir(), "scan-interrupt.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type cmdOutcome struct {
		out string
		err error
	}
	doneCh := make(chan cmdOutcome, 1)
	go func() {
		out, err := executeWithContext(
			ctx,
			"scan",
			"--scope", "prod",
			"--vantage", "v1",
			"--targets", "127.0.0.1",
			"--discovery-file", "disc.json",
			"--profile", "full",
			"--output-dir", outDir,
			"--prefix", "job-int",
			"--result-file", resultPath,
		)
		doneCh <- cmdOutcome{out: out, err: err}
	}()

	<-hitCh
	pendingRes, pendingRaw := readResultFile(t, resultPath)
	if pendingRes.Status != runresult.StatusPending {
		t.Fatalf("mid-flight status = %s, want pending\n%s", pendingRes.Status, pendingRaw)
	}
	if pendingRes.ExitCode != nil || strings.Contains(pendingRaw, `"exit_code"`) {
		t.Fatalf("pending file must omit exit_code: %s", pendingRaw)
	}
	if pendingRes.Scan == nil || pendingRes.Scan.Artifacts.JournalPath == "" {
		t.Fatalf("pending file missing scan/journal_path: %+v", pendingRes.Scan)
	}

	cancel()
	outcome := <-doneCh
	if !errors.Is(outcome.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got out=%q err=%v", outcome.out, outcome.err)
	}

	finalRes, _ := readResultFile(t, resultPath)
	if finalRes.Status != runresult.StatusInterrupted {
		t.Fatalf("final status = %s, want interrupted", finalRes.Status)
	}
	if finalRes.ExitCode == nil || *finalRes.ExitCode != 1 || finalRes.Error == "" {
		t.Fatalf("unexpected final envelope: %+v", finalRes)
	}
	if finalRes.Scan == nil || !finalRes.Scan.Resumable || finalRes.Scan.Counts != nil {
		t.Fatalf("expected resumable=true and counts=nil on interrupted scan, got %+v", finalRes.Scan)
	}
	if _, err := os.Stat(finalRes.Scan.Artifacts.JournalPath); err != nil {
		t.Fatalf("journal file missing after interruption: %v", err)
	}
}

func TestScanResultFileTargetErrorMarksFailed(t *testing.T) {
	inEmptyDirectory(t)

	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.6.0"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ollamaSrv.Close()

	// Returning an invalid path-traversal tenant segment from ChromaDB triggers a real collector target error.
	badChromaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/heartbeat":
			_, _ = w.Write([]byte(`{"nanosecond heartbeat":1}`))
		case "/api/v2/version":
			_, _ = w.Write([]byte(`"0.5.20"`))
		case "/api/v2/auth/identity":
			_, _ = w.Write([]byte(`{"tenant":"../bad","databases":["default_database"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer badChromaSrv.Close()

	defs := fmt.Sprintf(`[
  {"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]},
  {"surface":"chromadb","default_port":%d,"probe_paths":["/api/v2/heartbeat"]}
]`, portOf(ollamaSrv.URL), portOf(badChromaSrv.URL))
	if err := os.WriteFile("disc.json", []byte(defs), 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	resultPath := filepath.Join(t.TempDir(), "target-err.json")
	_, err := execute(
		"scan",
		"--scope", "prod",
		"--vantage", "v1",
		"--targets", "127.0.0.1",
		"--discovery-file", "disc.json",
		"--profile", "full",
		"--content=false",
		"--output-dir", outDir,
		"--prefix", "job-terr",
		"--result-file", resultPath,
	)
	if err == nil {
		t.Fatal("expected non-nil error when target_error_count > 0")
	}

	res, _ := readResultFile(t, resultPath)
	if res.Status != runresult.StatusFailed || res.ExitCode == nil || *res.ExitCode != 1 {
		t.Fatalf("status=%s exit_code=%v, want failed/1", res.Status, res.ExitCode)
	}
	if res.Scan == nil || res.Scan.TargetErrorCount != 1 || len(res.Scan.TargetErrors) != 1 {
		t.Fatalf("expected 1 target error, got %+v", res.Scan)
	}
	if !res.Scan.Resumable {
		t.Fatal("expected resumable=true when target errors are journaled as failed")
	}
	if res.Scan.Counts == nil || res.Scan.Counts.Services != 1 {
		t.Fatalf("expected healthy ollama service to be counted in emitted artifacts, got %+v", res.Scan.Counts)
	}
	if _, statErr := os.Stat(res.Scan.Artifacts.BasePayloadPath); statErr != nil {
		t.Fatalf("expected base payload to still be emitted: %v", statErr)
	}
}

func TestResumeResultFileLifecycle(t *testing.T) {
	inEmptyDirectory(t)

	var hitsA, hitsB atomic.Int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.6.0"}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvA.Close()

	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsB.Add(1)
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"0.6.3"}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"qwen","owned_by":"vllm"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srvB.Close()

	defs1 := fmt.Sprintf(`[{"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]}]`, portOf(srvA.URL))
	if err := os.WriteFile("d1.json", []byte(defs1), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if out, err := execute("scan", "--scope", "res-scope", "--vantage", "v1", "--targets", "127.0.0.1", "--content=false", "--discovery-file", "d1.json", "--output-dir", outDir, "--prefix", "rjob"); err != nil {
		t.Fatalf("initial scan: %q %v", out, err)
	}
	hitsA.Store(0)

	defs2 := fmt.Sprintf(`[
  {"surface":"ollama","default_port":%d,"probe_paths":["/api/version"]},
  {"surface":"vllm","default_port":%d,"probe_paths":["/version"]}
]`, portOf(srvA.URL), portOf(srvB.URL))
	if err := os.WriteFile("d2.json", []byte(defs2), 0o600); err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(outDir, "rjob.journal.jsonl")
	resultPath := filepath.Join(t.TempDir(), "resume-result.json")
	out, err := execute(
		"resume",
		"--journal", journalPath,
		"--scope", "res-scope",
		"--vantage", "v1",
		"--targets", "127.0.0.1",
		"--content=false",
		"--discovery-file", "d2.json",
		"--output-dir", outDir,
		"--prefix", "rjob",
		"--result-file", resultPath,
	)
	if err != nil {
		t.Fatalf("resume failed: %q %v", out, err)
	}
	if hitsA.Load() != 0 || hitsB.Load() == 0 {
		t.Fatalf("expected hitsA=0 hitsB>0, got %d/%d", hitsA.Load(), hitsB.Load())
	}

	res, _ := readResultFile(t, resultPath)
	if res.Command != runresult.CommandResume || res.Status != runresult.StatusComplete || res.ExitCode == nil || *res.ExitCode != 0 {
		t.Fatalf("unexpected resume result: %+v", res)
	}
	if res.Scan == nil || res.Scan.Resumable || res.Scan.Counts == nil || res.Scan.Counts.Services != 2 {
		t.Fatalf("unexpected resume scan section: %+v", res.Scan)
	}

	// Missing --journal writes pending -> failed cleanly.
	missingResultPath := filepath.Join(t.TempDir(), "resume-missing.json")
	if _, err := execute("resume", "--scope", "res-scope", "--vantage", "v1", "--targets", "127.0.0.1", "--result-file", missingResultPath); err == nil {
		t.Fatal("expected error when --journal is missing")
	}
	missRes, _ := readResultFile(t, missingResultPath)
	if missRes.Command != runresult.CommandResume || missRes.Status != runresult.StatusFailed || missRes.ExitCode == nil || *missRes.ExitCode != 1 {
		t.Fatalf("unexpected failed resume result: %+v", missRes)
	}
	if missRes.Scan == nil || missRes.Scan.Resumable {
		t.Fatalf("expected resumable=false when --journal is missing, got %+v", missRes.Scan)
	}
}

func TestUploadResultFileLifecycleCompleteAndSanitization(t *testing.T) {
	inEmptyDirectory(t)

	ce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/version":
			_, _ = w.Write([]byte(`{"data":{"API":{"current_version":"v2"},"server_version":"v9.7.1","product_edition":"community"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/graphs/source-kinds":
			_, _ = w.Write([]byte(`{"data":{"kinds":[{"id":1,"name":"LLMHound"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions-edges":
			_, _ = w.Write([]byte(`{"data":[{"id":1,"name":"MemberOf","is_traversable":true}]}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v2/extensions":
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = w.Write([]byte(`{"data":{}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/graphs/cypher":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "LIMIT 1") {
				_, _ = w.Write([]byte(`{"data":{"nodes":{"1":{"objectId":"PROBE","kinds":["Computer"]}}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"nodes":{"1":{"objectId":"S-1-5-21-EXISTS","kinds":["Computer"]}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":7}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/7":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/end"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/file-upload":
			_, _ = w.Write([]byte(`{"data":[{"id":7,"status":2}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/completed-tasks"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries/import":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ce.Close()

	t.Setenv("BLOODHOUND_BEARER_TOKEN", "super-secret-bearer-token")
	dirtyURL := "http://admin:super-secret-pass@" + strings.TrimPrefix(ce.URL, "http://")

	// 1. --validate-only
	valPath := filepath.Join(t.TempDir(), "validate.json")
	if out, err := execute("upload", "--url", dirtyURL, "--validate-only", "--result-file", valPath); err != nil {
		t.Fatalf("validate-only failed: %q %v", out, err)
	}
	valRes, valRaw := readResultFile(t, valPath)
	if valRes.Command != runresult.CommandUpload || valRes.Status != runresult.StatusComplete || !valRes.Upload.ValidateOnly || valRes.Upload.Gate == nil || !valRes.Upload.Gate.Supported {
		t.Fatalf("unexpected validate-only result: %+v", valRes)
	}
	if valRes.Upload.URL != ce.URL {
		t.Fatalf("sanitized url = %q, want %q", valRes.Upload.URL, ce.URL)
	}
	for _, secret := range []string{"admin", "super-secret-pass", "super-secret-bearer-token"} {
		if strings.Contains(valRaw, secret) {
			t.Fatalf("secret/userinfo %q leaked into result file: %s", secret, valRaw)
		}
	}

	// 2. Full upload with base + linking (including skipped edge) + schema + queries
	if err := os.WriteFile("base.json", []byte(`{"metadata":{"source_kind":"LLMHound"},"graph":{"nodes":[{"id":"SVC-1","kinds":["LLMHound_OllamaInstance","LLMHound_AIService"],"properties":{"name":"o"}}],"edges":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("link.json", []byte(`{"graph":{"nodes":[],"edges":[{"kind":"LLMHound_ObservedAt","start":{"match_by":"id","value":"SVC-1"},"end":{"match_by":"id","value":"S-1-5-21-EXISTS"}},{"kind":"LLMHound_ObservedAt","start":{"match_by":"id","value":"SVC-1"},"end":{"match_by":"id","value":"S-1-5-21-MISSING"}}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	fullPath := filepath.Join(t.TempDir(), "upload-full.json")
	if out, err := execute(
		"upload",
		"--url", dirtyURL,
		"--register-schema",
		"--base-file", "base.json",
		"--linking-file", "link.json",
		"--import-queries",
		"--poll-interval", "1ms",
		"--result-file", fullPath,
	); err != nil {
		t.Fatalf("full upload failed: %q %v", out, err)
	}

	res, raw := readResultFile(t, fullPath)
	if res.Status != runresult.StatusComplete || res.ExitCode == nil || *res.ExitCode != 0 || res.Upload == nil {
		t.Fatalf("unexpected upload result: %+v", res)
	}
	u := res.Upload
	if !u.SchemaRegistered || !u.BaseUploaded || !u.LinkingUploaded || len(u.BaseJobs) != 1 || len(u.LinkingJobs) != 1 {
		t.Fatalf("unexpected upload flags/jobs: %+v", u)
	}
	if u.KeptEdges == nil || *u.KeptEdges != 1 || u.SkippedEdgesCount == nil || *u.SkippedEdgesCount != 1 || len(u.SkippedEdges) != 1 {
		t.Fatalf("unexpected linking pre-flight stats: %+v", u)
	}
	if u.QueriesImported == 0 {
		t.Fatalf("expected QueriesImported > 0")
	}
	for _, secret := range []string{"admin", "super-secret-pass", "super-secret-bearer-token"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("secret/userinfo %q leaked into full upload result file", secret)
		}
	}

	// 3. Query string and fragment are also stripped when recorded in upload.url.
	queryURLPath := filepath.Join(t.TempDir(), "upload-query-url.json")
	if _, err := execute("upload", "--url", dirtyURL+"/sub?token=leak#frag", "--validate-only", "--result-file", queryURLPath); err == nil {
		t.Fatal("expected 404 on /sub/api/version")
	}
	qRes, qRaw := readResultFile(t, queryURLPath)
	if qRes.Upload == nil || qRes.Upload.URL != ce.URL+"/sub" {
		t.Fatalf("sanitized query/frag url = %+v, want %q", qRes.Upload, ce.URL+"/sub")
	}
	for _, secret := range []string{"admin", "super-secret-pass", "leak", "frag", "super-secret-bearer-token"} {
		if strings.Contains(qRaw, secret) {
			t.Fatalf("secret/query/frag %q leaked into result file", secret)
		}
	}
}

func TestUploadResultFileLifecycleFailedPartialAndInterrupted(t *testing.T) {
	inEmptyDirectory(t)
	t.Setenv("BLOODHOUND_BEARER_TOKEN", "tok")

	var serverVer atomic.Value
	serverVer.Store("v9.8.0")
	var failLinking atomic.Bool
	var blockPoll atomic.Bool
	pollHitCh := make(chan struct{})
	var pollOnce sync.Once

	ce := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/version":
			_, _ = fmt.Fprintf(w, `{"data":{"API":{"current_version":"v2"},"server_version":"%s","product_edition":"community"}}`, serverVer.Load().(string))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/graphs/source-kinds":
			_, _ = w.Write([]byte(`{"data":{"kinds":[{"id":1,"name":"LLMHound"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/extensions-edges":
			_, _ = w.Write([]byte(`{"data":[{"id":1,"name":"MemberOf","is_traversable":true}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/graphs/cypher":
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "LIMIT 1") {
				_, _ = w.Write([]byte(`{"data":{"nodes":{"1":{"objectId":"PROBE","kinds":["Computer"]}}}}`))
				return
			}
			if failLinking.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"cypher boom"}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"nodes":{"1":{"objectId":"S-1-5-21-EXISTS","kinds":["Computer"]}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":9}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/9":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/end"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/file-upload":
			if blockPoll.Load() {
				pollOnce.Do(func() { close(pollHitCh) })
				<-r.Context().Done()
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":9,"status":2}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/completed-tasks"):
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ce.Close()

	// 1. Unpinned CE version -> failed with gate.supported=false.
	gateFailPath := filepath.Join(t.TempDir(), "gate-fail.json")
	if _, err := execute("upload", "--url", ce.URL, "--validate-only", "--result-file", gateFailPath); err == nil {
		t.Fatal("expected unpinned CE version error")
	}
	gateRes, _ := readResultFile(t, gateFailPath)
	if gateRes.Status != runresult.StatusFailed || gateRes.Upload == nil || gateRes.Upload.Gate == nil || gateRes.Upload.Gate.Supported {
		t.Fatalf("expected failed gate with supported=false, got %+v", gateRes)
	}

	// 2. Linking fails after base succeeds -> failed with base_uploaded=true, base_jobs populated, linking_uploaded=false.
	serverVer.Store("v9.7.1")
	failLinking.Store(true)
	if err := os.WriteFile("base.json", []byte(`{"metadata":{"source_kind":"LLMHound"},"graph":{"nodes":[{"id":"SVC-1","kinds":["LLMHound_OllamaInstance","LLMHound_AIService"],"properties":{"name":"o"}}],"edges":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("link.json", []byte(`{"graph":{"nodes":[],"edges":[{"kind":"LLMHound_ObservedAt","start":{"match_by":"id","value":"SVC-1"},"end":{"match_by":"id","value":"S-1-5-21-EXISTS"}}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	partialFailPath := filepath.Join(t.TempDir(), "partial-fail.json")
	if _, err := execute("upload", "--url", ce.URL, "--base-file", "base.json", "--linking-file", "link.json", "--poll-interval", "1ms", "--result-file", partialFailPath); err == nil {
		t.Fatal("expected linking pre-flight error")
	}
	partRes, _ := readResultFile(t, partialFailPath)
	if partRes.Status != runresult.StatusFailed || partRes.Upload == nil || !partRes.Upload.BaseUploaded || len(partRes.Upload.BaseJobs) != 1 || partRes.Upload.LinkingUploaded {
		t.Fatalf("expected partial upload state on linking failure, got %+v", partRes)
	}

	// 3. Blocked upload poll canceled mid-flight -> pending on disk, then interrupted.
	failLinking.Store(false)
	blockPoll.Store(true)
	intPath := filepath.Join(t.TempDir(), "upload-int.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh := make(chan error, 1)
	go func() {
		_, err := executeWithContext(ctx, "upload", "--url", ce.URL, "--base-file", "base.json", "--poll-interval", "1ms", "--result-file", intPath)
		doneCh <- err
	}()

	<-pollHitCh
	pendRes, pendRaw := readResultFile(t, intPath)
	if pendRes.Status != runresult.StatusPending || strings.Contains(pendRaw, `"exit_code"`) {
		t.Fatalf("expected pending upload result mid-flight, got %s", pendRaw)
	}
	cancel()
	if err := <-doneCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	intRes, _ := readResultFile(t, intPath)
	if intRes.Status != runresult.StatusInterrupted || intRes.ExitCode == nil || *intRes.ExitCode != 1 || intRes.Upload == nil || intRes.Upload.Gate == nil || intRes.Upload.BaseUploaded {
		t.Fatalf("unexpected interrupted upload result: %+v", intRes)
	}
}

func TestResultFileCollisionGuardsAndValidation(t *testing.T) {
	inEmptyDirectory(t)

	// 1. Explicit empty --result-file "" is rejected.
	if _, err := execute("upload", "--url", "http://127.0.0.1:1", "--validate-only", "--result-file", ""); err == nil {
		t.Fatal("expected error for explicit empty --result-file")
	}

	// 2. Collision with --base-file on upload preserves original file.
	baseBody := []byte(`{"metadata":{"source_kind":"LLMHound"},"graph":{"nodes":[],"edges":[]}}`)
	if err := os.WriteFile("base.json", baseBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("upload", "--url", "http://127.0.0.1:1", "--base-file", "base.json", "--result-file", "base.json"); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("expected collision error on upload --base-file, got %v", err)
	}
	gotBase, err := os.ReadFile("base.json")
	if err != nil || string(gotBase) != string(baseBody) {
		t.Fatalf("collision modified base.json: %q %v", gotBase, err)
	}

	// 3. Collision with --journal on resume preserves journal.
	journalBody := []byte("{\"entry_type\":\"header\"}\n")
	if err := os.WriteFile("keep.journal.jsonl", journalBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("resume", "--journal", "keep.journal.jsonl", "--scope", "s", "--vantage", "v", "--targets", "127.0.0.1", "--result-file", "keep.journal.jsonl"); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("expected collision error on resume --journal, got %v", err)
	}
	gotJournal, err := os.ReadFile("keep.journal.jsonl")
	if err != nil || string(gotJournal) != string(journalBody) {
		t.Fatalf("collision modified journal: %q %v", gotJournal, err)
	}

	// 4. Collision with scan <prefix>.json preserves existing file.
	outDir := t.TempDir()
	existingOut := filepath.Join(outDir, "run1.json")
	origOut := []byte(`{"preserved":true}`)
	if err := os.WriteFile(existingOut, origOut, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("scan", "--scope", "s", "--vantage", "v", "--targets", "127.0.0.1", "--output-dir", outDir, "--prefix", "run1", "--result-file", existingOut); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("expected collision error on scan <prefix>.json, got %v", err)
	}
	gotOut, err := os.ReadFile(existingOut)
	if err != nil || string(gotOut) != string(origOut) {
		t.Fatalf("collision modified %s: %q %v", existingOut, gotOut, err)
	}
}
