package runresult_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/bloodhound"
	"github.com/0x3df/LLMHound/internal/runresult"
)

func TestTrackerLifecycleTransitions(t *testing.T) {
	t.Run("pending update complete", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "scan.result.json")
		nowTime := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
		tr, err := runresult.NewTracker(path, runresult.CommandScan, "v1.0.0", func() time.Time { return nowTime })
		if err != nil {
			t.Fatalf("NewTracker: %v", err)
		}

		if err := tr.StartPending(func(r *runresult.Result) {
			r.Scan = &runresult.ScanSection{Scope: "prod", VantageKey: "scanner-a"}
		}); err != nil {
			t.Fatalf("StartPending: %v", err)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"exit_code"`) || strings.Contains(string(raw), `"duration_ms"`) || strings.Contains(string(raw), `"finished_at"`) {
			t.Fatalf("pending file must omit terminal fields: %s", raw)
		}
		var pending runresult.Result
		if err := json.Unmarshal(raw, &pending); err != nil {
			t.Fatal(err)
		}
		if pending.Status != runresult.StatusPending || pending.Command != runresult.CommandScan || pending.SchemaVersion != runresult.SchemaVersion {
			t.Fatalf("unexpected pending result: %+v", pending)
		}
		if pending.ExitCode != nil || pending.DurationMS != nil {
			t.Fatalf("pending ExitCode/DurationMS must be nil")
		}

		nowTime = nowTime.Add(1500 * time.Millisecond)
		if err := tr.UpdatePending(func(r *runresult.Result) {
			r.Scan.ScanID = "scan-123"
			r.Scan.Artifacts.JournalPath = "/tmp/scan.journal.jsonl"
		}); err != nil {
			t.Fatalf("UpdatePending: %v", err)
		}
		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &pending); err != nil {
			t.Fatal(err)
		}
		if pending.Status != runresult.StatusPending || pending.Scan.ScanID != "scan-123" || pending.ExitCode != nil {
			t.Fatalf("unexpected updated pending result: %+v", pending)
		}

		nowTime = nowTime.Add(2500 * time.Millisecond)
		if err := tr.Finish(runresult.StatusComplete, 0, "", func(r *runresult.Result) {
			r.Scan.Counts = &runresult.ScanCounts{Services: 3, BaseNodes: 4, BaseEdges: 2}
		}); err != nil {
			t.Fatalf("Finish: %v", err)
		}

		raw, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var done runresult.Result
		if err := json.Unmarshal(raw, &done); err != nil {
			t.Fatal(err)
		}
		if done.Status != runresult.StatusComplete || done.ExitCode == nil || *done.ExitCode != 0 {
			t.Fatalf("unexpected finished result: %+v", done)
		}
		if done.DurationMS == nil || *done.DurationMS != 4000 {
			t.Fatalf("duration_ms = %v, want 4000", done.DurationMS)
		}
		if done.FinishedAt == "" || done.Scan.Counts == nil || done.Scan.Counts.Services != 3 {
			t.Fatalf("unexpected scan counts/finished_at: %+v", done)
		}
	})

	t.Run("pending to failed and interrupted", func(t *testing.T) {
		for _, tc := range []struct {
			status runresult.Status
			errMsg string
		}{
			{runresult.StatusFailed, "bad config"},
			{runresult.StatusInterrupted, "context canceled"},
		} {
			path := filepath.Join(t.TempDir(), string(tc.status)+".json")
			now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
			tr, err := runresult.NewTracker(path, runresult.CommandUpload, "v1.0.0", func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if err := tr.StartPending(nil); err != nil {
				t.Fatal(err)
			}
			now = now.Add(250 * time.Millisecond)
			if err := tr.Finish(tc.status, 1, tc.errMsg, nil); err != nil {
				t.Fatalf("Finish(%s): %v", tc.status, err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got runresult.Result
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.Status != tc.status || got.ExitCode == nil || *got.ExitCode != 1 || got.Error != tc.errMsg {
				t.Fatalf("got %+v", got)
			}
		}
	})

	t.Run("illegal transitions rejected", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "illegal.json")
		tr, err := runresult.NewTracker(path, runresult.CommandResume, "v1.0.0", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.UpdatePending(nil); err == nil {
			t.Fatal("UpdatePending before StartPending must fail")
		}
		if err := tr.Finish(runresult.StatusComplete, 0, "", nil); err == nil {
			t.Fatal("Finish before StartPending must fail")
		}
		if err := tr.StartPending(nil); err != nil {
			t.Fatal(err)
		}
		if err := tr.StartPending(nil); err == nil {
			t.Fatal("duplicate StartPending must fail")
		}
		if err := tr.Finish(runresult.StatusPending, 0, "", nil); err == nil {
			t.Fatal("Finish with pending status must fail")
		}
		if err := tr.Finish(runresult.StatusComplete, 1, "", nil); err == nil {
			t.Fatal("Finish complete with non-zero exit_code must fail")
		}
		if err := tr.Finish(runresult.StatusComplete, 0, "err", nil); err == nil {
			t.Fatal("Finish complete with non-empty error must fail")
		}
		if err := tr.Finish(runresult.StatusFailed, 0, "err", nil); err == nil {
			t.Fatal("Finish failed with zero exit_code must fail")
		}
		if err := tr.Finish(runresult.StatusInterrupted, 0, "err", nil); err == nil {
			t.Fatal("Finish interrupted with zero exit_code must fail")
		}
		if err := tr.Finish(runresult.StatusComplete, 0, "", nil); err != nil {
			t.Fatalf("valid Finish failed: %v", err)
		}
		if err := tr.UpdatePending(nil); err == nil {
			t.Fatal("UpdatePending after Finish must fail")
		}
		if err := tr.Finish(runresult.StatusFailed, 1, "late", nil); err == nil {
			t.Fatal("second Finish must fail")
		}
	})
}

func TestStatusHelpersAndClassifyStatus(t *testing.T) {
	for _, s := range []runresult.Status{runresult.StatusPending, runresult.StatusComplete, runresult.StatusFailed, runresult.StatusInterrupted} {
		if !runresult.IsValidStatus(s) {
			t.Fatalf("IsValidStatus(%q) = false", s)
		}
	}
	if runresult.IsValidStatus("quarantined") || runresult.IsTerminal(runresult.StatusPending) {
		t.Fatal("unexpected status classification")
	}

	if got := runresult.ClassifyStatus(nil, nil); got != runresult.StatusComplete {
		t.Fatalf("nil/nil => %s, want complete", got)
	}
	if got := runresult.ClassifyStatus(context.Canceled, errors.New("aborted")); got != runresult.StatusInterrupted {
		t.Fatalf("canceled ctx => %s, want interrupted", got)
	}
	if got := runresult.ClassifyStatus(nil, context.Canceled); got != runresult.StatusInterrupted {
		t.Fatalf("wrapped canceled err => %s, want interrupted", got)
	}
	if got := runresult.ClassifyStatus(context.DeadlineExceeded, context.DeadlineExceeded); got != runresult.StatusFailed {
		t.Fatalf("deadline exceeded => %s, want failed", got)
	}
	if got := runresult.ClassifyStatus(nil, errors.New("boom")); got != runresult.StatusFailed {
		t.Fatalf("generic error => %s, want failed", got)
	}
}

func TestSanitizeURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"://invalid", ""},
		{"https://user:secret@bh.example.com:8443/v2?token=abc#frag", "https://bh.example.com:8443/v2"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080"},
	}
	for _, tc := range cases {
		if got := runresult.SanitizeURL(tc.in); got != tc.want {
			t.Errorf("SanitizeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestApplyUploadReportTruncation(t *testing.T) {
	skipped := make([]bloodhound.SkippedEdge, runresult.MaxRetainedSkippedEdges+25)
	for i := range skipped {
		skipped[i] = bloodhound.SkippedEdge{Kind: "LLMHound_ObservedAt", StartID: "A", EndID: "B", Reason: "missing"}
	}
	rep := &bloodhound.UploadReport{
		BaseUploaded:    true,
		BaseJobs:        []bloodhound.JobResult{{JobID: 1, Status: 2, Attempts: 1}},
		LinkingUploaded: true,
		LinkingJobs:     []bloodhound.JobResult{{JobID: 2, Status: 2, Attempts: 1}},
		PreflightRan:    true,
		KeptEdges:       7,
		SkippedEdges:    skipped,
	}
	var sec runresult.UploadSection
	runresult.ApplyUploadReport(&sec, rep)
	if !sec.BaseUploaded || !sec.LinkingUploaded || len(sec.BaseJobs) != 1 || len(sec.LinkingJobs) != 1 {
		t.Fatalf("unexpected upload flags/jobs: %+v", sec)
	}
	if sec.KeptEdges == nil || *sec.KeptEdges != 7 {
		t.Fatalf("KeptEdges = %v, want 7", sec.KeptEdges)
	}
	if sec.SkippedEdgesCount == nil || *sec.SkippedEdgesCount != runresult.MaxRetainedSkippedEdges+25 {
		t.Fatalf("SkippedEdgesCount = %v", sec.SkippedEdgesCount)
	}
	if len(sec.SkippedEdges) != runresult.MaxRetainedSkippedEdges || !sec.SkippedEdgesTruncated {
		t.Fatalf("len(SkippedEdges)=%d truncated=%v", len(sec.SkippedEdges), sec.SkippedEdgesTruncated)
	}
}

func TestValidatePathAndPathCollides(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", "   ", " out.json", "out.json ", "bad\n.json", dir, dir + "/"} {
		if err := runresult.ValidatePath(bad); err == nil {
			t.Errorf("ValidatePath(%q) succeeded, want error", bad)
		}
	}
	fileA := filepath.Join(dir, "a.json")
	if err := runresult.ValidatePath(fileA); err != nil {
		t.Fatalf("ValidatePath(%q): %v", fileA, err)
	}
	if !runresult.PathCollides(fileA, filepath.Join(dir, ".", "a.json")) {
		t.Fatal("expected relative clean path to collide")
	}
	if runresult.PathCollides(fileA, filepath.Join(dir, "b.json")) {
		t.Fatal("distinct paths should not collide")
	}
	if runtime.GOOS == "windows" {
		if !runresult.PathCollides(fileA, filepath.Join(dir, "A.JSON")) {
			t.Fatal("expected case-insensitive collision on Windows")
		}
	}
}
