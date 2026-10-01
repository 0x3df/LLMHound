package checkpoint_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

var semanticsTime = time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)

func recordSurface(t *testing.T, j checkpoint.Journal, obs graph.Observation, target, surface string, cov graph.Coverage) {
	t.Helper()
	obs.Surface = surface
	obs.Coverage = cov
	if cov != graph.CoverageComplete {
		obs.CoverageReason = "limited by test"
	}
	if err := j.RecordResult(checkpoint.Result{Target: target, Surface: surface, Observation: obs}); err != nil {
		t.Fatalf("record %s/%s: %v", target, surface, err)
	}
}

func TestResumeCompletionRequiresFullCoverage(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatal(err)
	}
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)

	recordSurface(t, j, obs, "10.0.0.1", "ollama", graph.CoverageComplete)
	recordSurface(t, j, obs, "10.0.0.1", "jupyter", graph.CoveragePartial)
	recordSurface(t, j, obs, "10.0.0.2", "ollama", graph.CoverageComplete)
	recordSurface(t, j, obs, "10.0.0.2", "mcp", graph.CoverageComplete)
	recordSurface(t, j, obs, "10.0.0.3", "ollama", graph.CoverageTruncated)
	if err := j.RecordTarget(checkpoint.TargetRecord{Target: "10.0.0.4", Status: checkpoint.TargetStatusCompleted}); err == nil {
		t.Fatal("surface-less completed record must be rejected")
	}

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		target, surface string
		want            bool
	}{
		{"10.0.0.1", "ollama", true},
		{"10.0.0.1", "jupyter", false},
		{"10.0.0.2", "ollama", true},
		{"10.0.0.2", "mcp", true},
		{"10.0.0.3", "ollama", false},
		{"10.0.0.2", "qdrant", false},
		{"10.0.0.4", "ollama", false},
		{"10.0.0.4", "", false},
	} {
		if got := state.IsCompleted(tc.target, tc.surface); got != tc.want {
			t.Errorf("IsCompleted(%s,%q)=%v want %v", tc.target, tc.surface, got, tc.want)
		}
	}

	completed := state.CompletedTargets()
	if len(completed) != 1 || completed[0] != "10.0.0.2" {
		t.Fatalf("completed targets = %v, want [10.0.0.2]", completed)
	}
}

func TestLaterPartialResultSupersedesCompletion(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)
	recordSurface(t, j, obs, "10.0.0.1", "ollama", graph.CoverageComplete)
	recordSurface(t, j, obs, "10.0.0.1", "ollama", graph.CoverageTruncated)

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if state.IsCompleted("10.0.0.1", "ollama") {
		t.Fatal("surface re-recorded as truncated must not remain completed")
	}
}

func TestStatusValidation(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)

	if err := j.RecordTarget(checkpoint.TargetRecord{Target: "h", Surface: "s", Status: "bogus"}); err == nil {
		t.Fatal("expected undefined target status rejected")
	}
	if err := j.RecordResult(checkpoint.Result{Target: "h", Surface: "ollama", Observation: obs, Status: "bogus"}); err == nil {
		t.Fatal("expected undefined result status rejected")
	}
	partial := obs
	partial.Coverage = graph.CoveragePartial
	partial.CoverageReason = "cut short"
	if err := j.RecordResult(checkpoint.Result{Target: "h", Surface: "ollama", Observation: partial, Status: checkpoint.TargetStatusCompleted}); err == nil {
		t.Fatal("expected completed status with partial coverage rejected")
	}

	forged := `{"entry_type":"target","target":{"target":"h","surface":"s","status":"bogus"}}` + "\n"
	hdr := bytes.Split(buf.Bytes(), []byte("\n"))[0]
	if _, err := checkpoint.Replay(strings.NewReader(string(hdr) + "\n" + forged)); err == nil {
		t.Fatal("expected replay to reject undefined status")
	}
}

func TestProvenanceEnforcedAtWrite(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	scope := header.DeploymentScope
	vantage := sampleVantage(t, scope, header.VantageKey)
	other := sampleVantage(t, scope, "other-vantage")
	good := sampleObservation(t, vantage, "ev-1", semanticsTime)
	foreign := sampleObservation(t, other, "ev-2", semanticsTime)

	if err := j.RecordResult(checkpoint.Result{Target: "h", Surface: "ollama", Observation: foreign}); err == nil {
		t.Fatal("expected foreign-vantage result rejected")
	}

	foreignNode := sampleServiceNode(t, scope, other, "http://10.0.0.1:11434")
	if err := j.RecordNode(foreignNode); err == nil {
		t.Fatal("expected foreign-vantage node rejected")
	}
	if err := j.RecordResult(checkpoint.Result{Target: "h", Surface: "ollama", Observation: good, Nodes: []emitter.NodeItem{foreignNode}}); err == nil {
		t.Fatal("expected nested foreign-vantage node rejected")
	}

	if err := j.RecordNode(emitter.NodeItem{}); err == nil {
		t.Fatal("expected zero node rejected")
	}
	if err := j.RecordEdge(graph.Edge{}); err == nil {
		t.Fatal("expected zero edge rejected")
	}

	foreignScopeNode := sampleServiceNode(t, "other-scope", sampleVantage(t, "other-scope", "v"), "http://10.0.0.1:11434")
	if err := j.RecordResult(checkpoint.Result{Target: "h", Surface: "ollama", Observation: good, Nodes: []emitter.NodeItem{foreignScopeNode}}); err == nil {
		t.Fatal("expected nested foreign-scope node rejected")
	}

	if _, err := checkpoint.Replay(&buf); err != nil {
		t.Fatalf("journal must stay replayable after rejected writes: %v", err)
	}
}

func TestFreeTextRedactedAndBounded(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header, checkpoint.WithMaxStringSize(40))
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)
	obs.Coverage = graph.CoveragePartial
	obs.CoverageReason = "fetch http://u:hunter2@10.0.0.1/x?token=abc failed"

	err := j.RecordResult(checkpoint.Result{
		Target:      "http://u:hunter2@10.0.0.1:11434/?token=abc",
		Surface:     "ollama",
		Observation: obs,
		Error:       "Authorization: Bearer sk-secretvalue rejected by http://u:hunter2@10.0.0.1/?k=v",
		Details:     map[string]any{"max_tokens": 4096, "empty": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTarget(checkpoint.TargetRecord{
		Target: "u:hunter2@10.0.0.9:11434", Surface: "ollama", Status: checkpoint.TargetStatusFailed,
		Error: "password=hunter2 refused",
	}); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, leak := range []string{"hunter2", "sk-secretvalue", "token=abc"} {
		if strings.Contains(out, leak) {
			t.Fatalf("journal leaked %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, `"max_tokens":4096`) {
		t.Fatalf("benign max_tokens must not be redacted:\n%s", out)
	}
	if !strings.Contains(out, `"empty":{}`) {
		t.Fatalf("empty nested map must stay an object:\n%s", out)
	}
	if _, err := checkpoint.Replay(strings.NewReader(out)); err != nil {
		t.Fatalf("replay of sanitized journal: %v", err)
	}
}

func TestBoundStringKeepsValidUTF8(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header, checkpoint.WithMaxStringSize(5))
	if err := j.RecordTarget(checkpoint.TargetRecord{Target: "h", Surface: "s", Status: checkpoint.TargetStatusFailed, Error: "ééééé"}); err != nil {
		t.Fatal(err)
	}
	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if e := state.Targets()["h|s"].Error; !strings.HasPrefix(e, "éé") || strings.ContainsRune(e, '\uFFFD') {
		t.Fatalf("bad truncation: %q", e)
	}
}

func TestOpenFileRepairsTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	header := sampleHeader()
	fj, err := checkpoint.CreateFile(path, header)
	if err != nil {
		t.Fatal(err)
	}
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)
	recordSurface(t, fj, obs, "10.0.0.1", "ollama", graph.CoverageComplete)
	_ = fj.Close()

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.WriteString(`{"entry_type":"result","result":{"target":"10.0.0.2`)
	_ = f.Close()

	fj, err = checkpoint.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recordSurface(t, fj, obs, "10.0.0.3", "ollama", graph.CoverageComplete)
	_ = fj.Close()

	state, err := checkpoint.ReplayFile(path)
	if err != nil {
		t.Fatalf("replay after torn-tail append: %v", err)
	}
	if !state.IsCompleted("10.0.0.1", "ollama") || !state.IsCompleted("10.0.0.3", "ollama") {
		t.Fatal("expected records before and after the torn tail")
	}
	if state.IsCompleted("10.0.0.2", "ollama") {
		t.Fatal("torn record must not be treated as completed")
	}
}

func TestCreateFileDoesNotClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	fj, err := checkpoint.CreateFile(path, sampleHeader())
	if err != nil {
		t.Fatal(err)
	}
	_ = fj.Close()
	if _, err := checkpoint.CreateFile(path, sampleHeader()); err == nil {
		t.Fatal("expected CreateFile to refuse an existing journal")
	}
	if _, err := checkpoint.ReplayFile(path); err != nil {
		t.Fatalf("existing journal must survive: %v", err)
	}
}

type failingWriter struct{ fail bool }

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.fail {
		return len(p) / 2, errors.New("disk full")
	}
	return len(p), nil
}

func TestFailedWritePoisonsJournal(t *testing.T) {
	w := &failingWriter{}
	header := sampleHeader()
	j, err := checkpoint.NewWriter(w, header)
	if err != nil {
		t.Fatal(err)
	}
	w.fail = true
	rec := checkpoint.TargetRecord{Target: "h", Surface: "s", Status: checkpoint.TargetStatusStarted}
	if err := j.RecordTarget(rec); err == nil {
		t.Fatal("expected write failure")
	}
	w.fail = false
	if err := j.RecordTarget(rec); err == nil {
		t.Fatal("journal must refuse writes after a failed write")
	}
}

func TestCompletedWithoutObservationNeverCounts(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)
	recordSurface(t, j, obs, "h", "mcp", graph.CoveragePartial)

	if err := j.RecordTarget(checkpoint.TargetRecord{Target: "h", Surface: "mcp", Status: checkpoint.TargetStatusCompleted}); err == nil {
		t.Fatal("completed record without observation must be rejected at write")
	}

	hdr := bytes.Split(buf.Bytes(), []byte("\n"))
	forged := `{"entry_type":"target","target":{"target":"h","surface":"mcp","status":"completed"}}` + "\n"
	if _, err := checkpoint.Replay(strings.NewReader(string(hdr[0]) + "\n" + forged)); err == nil {
		t.Fatal("replay must reject completed record without observation")
	}

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if state.IsCompleted("h", "mcp") || len(state.CompletedTargets()) != 0 {
		t.Fatal("partial surface must not be completed")
	}
}

func TestReplayDerivesStatusFromCoverageNotClaim(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	obs := sampleObservation(t, sampleVantage(t, header.DeploymentScope, header.VantageKey), "ev-1", semanticsTime)
	recordSurface(t, j, obs, "h", "ollama", graph.CoveragePartial)

	forged := strings.Replace(buf.String(), `"surface":"ollama","observation"`, `"surface":"ollama","status":"completed","observation"`, 1)
	if forged == buf.String() {
		t.Fatal("failed to forge status into result entry")
	}
	state, err := checkpoint.Replay(strings.NewReader(forged))
	if err != nil {
		t.Fatal(err)
	}
	if state.IsCompleted("h", "ollama") {
		t.Fatal("result claiming completed with partial coverage must not be completed")
	}
	if got := state.Targets()["h|ollama"].Status; got != checkpoint.TargetStatusPartial {
		t.Fatalf("status = %q, want partial", got)
	}
}
