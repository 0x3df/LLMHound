// Package runresult manages stable, machine-readable lifecycle result files
// for scan, resume, and upload invocations.
package runresult

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/0x3df/LLMHound/internal/bloodhound"
	"github.com/0x3df/LLMHound/internal/securefile"
)

const (
	// SchemaVersion identifies the machine-readable result JSON schema.
	SchemaVersion = "1"

	// MaxRetainedSkippedEdges bounds UploadSection.SkippedEdges in the result file.
	MaxRetainedSkippedEdges = 1000

	// MaxRetainedTargetErrors bounds ScanSection.TargetErrors in the result file.
	MaxRetainedTargetErrors = 1000
)

// Status represents the lifecycle state of an invocation.
type Status string

const (
	StatusPending     Status = "pending"
	StatusComplete    Status = "complete"
	StatusFailed      Status = "failed"
	StatusInterrupted Status = "interrupted"
)

// IsValidStatus reports whether s is a defined lifecycle status.
func IsValidStatus(s Status) bool {
	switch s {
	case StatusPending, StatusComplete, StatusFailed, StatusInterrupted:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether s is a completed terminal lifecycle status.
func IsTerminal(s Status) bool {
	switch s {
	case StatusComplete, StatusFailed, StatusInterrupted:
		return true
	default:
		return false
	}
}

// Command names the CLI subcommand that produced a result file.
type Command string

const (
	CommandScan   Command = "scan"
	CommandResume Command = "resume"
	CommandUpload Command = "upload"
)

// IsValidCommand reports whether c is a supported result-producing command.
func IsValidCommand(c Command) bool {
	switch c {
	case CommandScan, CommandResume, CommandUpload:
		return true
	default:
		return false
	}
}

// Result is the top-level machine-readable lifecycle envelope written to --result-file.
type Result struct {
	SchemaVersion    string         `json:"schema_version"`
	Command          Command        `json:"command"`
	Status           Status         `json:"status"`
	CollectorVersion string         `json:"collector_version"`
	StartedAt        string         `json:"started_at"`
	UpdatedAt        string         `json:"updated_at"`
	FinishedAt       string         `json:"finished_at,omitempty"`
	DurationMS       *int64         `json:"duration_ms,omitempty"`
	ExitCode         *int           `json:"exit_code,omitempty"`
	Error            string         `json:"error,omitempty"`
	Scan             *ScanSection   `json:"scan,omitempty"`
	Upload           *UploadSection `json:"upload,omitempty"`
}

// ScanSection captures scan or resume metadata, artifact paths, counts, and target errors.
type ScanSection struct {
	ScanID                string        `json:"scan_id,omitempty"`
	Scope                 string        `json:"scope,omitempty"`
	VantageKey            string        `json:"vantage_key,omitempty"`
	Prefix                string        `json:"prefix,omitempty"`
	OutputDir             string        `json:"output_dir,omitempty"`
	Profile               string        `json:"profile,omitempty"`
	GraphMode             string        `json:"graph_mode,omitempty"`
	ContentMode           string        `json:"content_mode,omitempty"`
	TargetsCount          *int          `json:"targets_count,omitempty"`
	Artifacts             ScanArtifacts `json:"artifacts"`
	Counts                *ScanCounts   `json:"counts,omitempty"`
	TargetErrorCount      int           `json:"target_error_count"`
	TargetErrors          []string      `json:"target_errors,omitempty"`
	TargetErrorsTruncated bool          `json:"target_errors_truncated,omitempty"`
	Resumable             bool          `json:"resumable"`
}

// ScanArtifacts records the file paths written or managed during scan/resume.
type ScanArtifacts struct {
	BasePayloadPath     string `json:"base_payload_path,omitempty"`
	LinkingPayloadPath  string `json:"linking_payload_path,omitempty"`
	EvidenceSidecarPath string `json:"evidence_sidecar_path,omitempty"`
	JournalPath         string `json:"journal_path,omitempty"`
	ContentPath         string `json:"content_path,omitempty"`
}

// ScanCounts holds exact graph and sidecar counts from emitted scan artifacts.
type ScanCounts struct {
	Services              int `json:"services"`
	BaseNodes             int `json:"base_nodes"`
	BaseEdges             int `json:"base_edges"`
	LinkingEdges          int `json:"linking_edges"`
	EvidenceRecords       int `json:"evidence_records"`
	ExposedSecretServices int `json:"exposed_secret_services"`
}

// UploadSection captures BloodHound CE adapter gate, schema, upload, and query import results.
type UploadSection struct {
	URL                   string                   `json:"url,omitempty"`
	ValidateOnly          bool                     `json:"validate_only"`
	RegisterSchema        bool                     `json:"register_schema"`
	EnableRulesSchema     bool                     `json:"enable_rules_schema,omitempty"`
	ImportQueries         bool                     `json:"import_queries"`
	IncludeCanExecuteOn   bool                     `json:"include_can_execute_on,omitempty"`
	AllowUnvalidatedCE    bool                     `json:"allow_unvalidated_ce,omitempty"`
	BaseFile              string                   `json:"base_file,omitempty"`
	LinkingFile           string                   `json:"linking_file,omitempty"`
	QueriesDir            string                   `json:"queries_dir,omitempty"`
	Gate                  *bloodhound.GateReport   `json:"gate,omitempty"`
	SchemaRegistered      bool                     `json:"schema_registered"`
	BaseUploaded          bool                     `json:"base_uploaded"`
	BaseJobs              []bloodhound.JobResult   `json:"base_jobs,omitempty"`
	LinkingUploaded       bool                     `json:"linking_uploaded"`
	LinkingJobs           []bloodhound.JobResult   `json:"linking_jobs,omitempty"`
	KeptEdges             *int                     `json:"kept_edges,omitempty"`
	SkippedEdgesCount     *int                     `json:"skipped_edges_count,omitempty"`
	SkippedEdges          []bloodhound.SkippedEdge `json:"skipped_edges,omitempty"`
	SkippedEdgesTruncated bool                     `json:"skipped_edges_truncated,omitempty"`
	QueriesImported       int                      `json:"queries_imported"`
}

// ValidatePath rejects empty, whitespace-padded, or control-character result paths.
func ValidatePath(path string) error {
	if strings.TrimSpace(path) == "" || path != strings.TrimSpace(path) || strings.ContainsFunc(path, unicode.IsControl) {
		return errors.New("result-file path must be nonblank without surrounding whitespace or control characters")
	}
	if strings.HasSuffix(path, "/") || (runtime.GOOS == "windows" && strings.HasSuffix(path, `\`)) {
		return fmt.Errorf("result-file path %q must name a file, not a directory", path)
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("result-file path %q is a directory", path)
	}
	return nil
}

// PathCollides reports whether paths a and b refer to the same file path.
func PathCollides(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	if ia, errA := os.Stat(a); errA == nil {
		if ib, errB := os.Stat(b); errB == nil && os.SameFile(ia, ib) {
			return true
		}
	}
	na := normalizePath(a)
	nb := normalizePath(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(na, nb)
	}
	return na == nb
}

func normalizePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

// SanitizeURL strips userinfo, query parameters, and fragments from a URL before
// recording it in a result file. Unparseable URLs return an empty string.
func SanitizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// ClassifyStatus maps run and context errors to a terminal lifecycle status.
// Only context cancellation produces StatusInterrupted; deadlines map to StatusFailed.
func ClassifyStatus(ctxErr, runErr error) Status {
	if runErr == nil {
		return StatusComplete
	}
	if errors.Is(ctxErr, context.Canceled) || errors.Is(runErr, context.Canceled) {
		return StatusInterrupted
	}
	return StatusFailed
}

// ApplyUploadReport populates u from a BloodHound UploadReport, preserving
// bounded skipped-edge records.
func ApplyUploadReport(u *UploadSection, rep *bloodhound.UploadReport) {
	if u == nil || rep == nil {
		return
	}
	u.BaseUploaded = rep.BaseUploaded
	if len(rep.BaseJobs) > 0 {
		u.BaseJobs = append([]bloodhound.JobResult(nil), rep.BaseJobs...)
	}
	u.LinkingUploaded = rep.LinkingUploaded
	if len(rep.LinkingJobs) > 0 {
		u.LinkingJobs = append([]bloodhound.JobResult(nil), rep.LinkingJobs...)
	}
	if rep.PreflightRan {
		kept := rep.KeptEdges
		skippedCount := len(rep.SkippedEdges)
		u.KeptEdges = &kept
		u.SkippedEdgesCount = &skippedCount
		if skippedCount > MaxRetainedSkippedEdges {
			u.SkippedEdges = append([]bloodhound.SkippedEdge(nil), rep.SkippedEdges[:MaxRetainedSkippedEdges]...)
			u.SkippedEdgesTruncated = true
		} else if skippedCount > 0 {
			u.SkippedEdges = append([]bloodhound.SkippedEdge(nil), rep.SkippedEdges...)
			u.SkippedEdgesTruncated = false
		}
	}
}

// Tracker manages atomic lifecycle updates to a result file.
type Tracker struct {
	mu               sync.Mutex
	path             string
	cmd              Command
	collectorVersion string
	now              func() time.Time

	started   bool
	finalized bool
	startedAt time.Time
	result    Result
}

// NewTracker validates inputs and constructs a Tracker ready for StartPending.
func NewTracker(path string, cmd Command, collectorVersion string, now func() time.Time) (*Tracker, error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	if !IsValidCommand(cmd) {
		return nil, fmt.Errorf("unsupported result command %q", cmd)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Tracker{
		path:             path,
		cmd:              cmd,
		collectorVersion: collectorVersion,
		now:              now,
	}, nil
}

// StartPending writes the initial "pending" state atomically to disk.
func (t *Tracker) StartPending(mutate func(*Result)) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return errors.New("result tracker already started")
	}

	ts := t.now().UTC()
	tsStr := ts.Format(time.RFC3339)
	res := Result{
		SchemaVersion:    SchemaVersion,
		Command:          t.cmd,
		Status:           StatusPending,
		CollectorVersion: t.collectorVersion,
		StartedAt:        tsStr,
		UpdatedAt:        tsStr,
	}
	if mutate != nil {
		mutate(&res)
	}
	stampPendingEnvelope(&res, t.cmd, t.collectorVersion, tsStr, tsStr)

	if err := writeResultFile(t.path, res); err != nil {
		return err
	}
	t.started = true
	t.startedAt = ts
	t.result = res
	return nil
}

// UpdatePending applies non-terminal progress updates while remaining "pending".
func (t *Tracker) UpdatePending(mutate func(*Result)) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.started {
		return errors.New("result tracker has not been started")
	}
	if t.finalized {
		return errors.New("result tracker already finalized")
	}

	tsStr := t.now().UTC().Format(time.RFC3339)
	res := cloneResult(t.result)
	if mutate != nil {
		mutate(&res)
	}
	stampPendingEnvelope(&res, t.cmd, t.collectorVersion, t.result.StartedAt, tsStr)

	if err := writeResultFile(t.path, res); err != nil {
		return err
	}
	t.result = res
	return nil
}

// Finish writes the terminal lifecycle status atomically to disk.
func (t *Tracker) Finish(status Status, exitCode int, errMsg string, mutate func(*Result)) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.started {
		return errors.New("result tracker has not been started")
	}
	if t.finalized {
		return errors.New("result tracker already finalized")
	}
	if !IsTerminal(status) {
		return fmt.Errorf("invalid terminal result status %q", status)
	}
	if status == StatusComplete && (exitCode != 0 || errMsg != "") {
		return fmt.Errorf("complete result status requires exit_code 0 and empty error (got exit_code=%d, error=%q)", exitCode, errMsg)
	}
	if (status == StatusFailed || status == StatusInterrupted) && exitCode == 0 {
		return fmt.Errorf("%s result status requires a non-zero exit_code", status)
	}

	finishedAt := t.now().UTC()
	finishedStr := finishedAt.Format(time.RFC3339)
	durMS := finishedAt.Sub(t.startedAt).Milliseconds()
	if durMS < 0 {
		durMS = 0
	}
	codeCopy := exitCode
	durCopy := durMS

	res := cloneResult(t.result)
	if mutate != nil {
		mutate(&res)
	}
	res.SchemaVersion = SchemaVersion
	res.Command = t.cmd
	res.Status = status
	res.CollectorVersion = t.collectorVersion
	res.StartedAt = t.result.StartedAt
	res.UpdatedAt = finishedStr
	res.FinishedAt = finishedStr
	res.DurationMS = &durCopy
	res.ExitCode = &codeCopy
	res.Error = errMsg

	if err := writeResultFile(t.path, res); err != nil {
		return err
	}
	t.finalized = true
	t.result = res
	return nil
}

func stampPendingEnvelope(res *Result, cmd Command, collectorVersion, startedAt, updatedAt string) {
	res.SchemaVersion = SchemaVersion
	res.Command = cmd
	res.Status = StatusPending
	res.CollectorVersion = collectorVersion
	res.StartedAt = startedAt
	res.UpdatedAt = updatedAt
	res.FinishedAt = ""
	res.DurationMS = nil
	res.ExitCode = nil
	res.Error = ""
}

func cloneResult(src Result) Result {
	cp := src
	if src.DurationMS != nil {
		v := *src.DurationMS
		cp.DurationMS = &v
	}
	if src.ExitCode != nil {
		v := *src.ExitCode
		cp.ExitCode = &v
	}
	if src.Scan != nil {
		s := *src.Scan
		if s.TargetsCount != nil {
			v := *s.TargetsCount
			s.TargetsCount = &v
		}
		if s.Counts != nil {
			c := *s.Counts
			s.Counts = &c
		}
		if s.TargetErrors != nil {
			s.TargetErrors = append([]string(nil), s.TargetErrors...)
		}
		cp.Scan = &s
	}
	if src.Upload != nil {
		u := *src.Upload
		if u.KeptEdges != nil {
			v := *u.KeptEdges
			u.KeptEdges = &v
		}
		if u.SkippedEdgesCount != nil {
			v := *u.SkippedEdgesCount
			u.SkippedEdgesCount = &v
		}
		if u.BaseJobs != nil {
			u.BaseJobs = append([]bloodhound.JobResult(nil), u.BaseJobs...)
		}
		if u.LinkingJobs != nil {
			u.LinkingJobs = append([]bloodhound.JobResult(nil), u.LinkingJobs...)
		}
		if u.SkippedEdges != nil {
			u.SkippedEdges = append([]bloodhound.SkippedEdge(nil), u.SkippedEdges...)
		}
		if u.Gate != nil {
			g := *u.Gate
			if g.Checks != nil {
				g.Checks = append([]bloodhound.GateCheck(nil), g.Checks...)
			}
			u.Gate = &g
		}
		cp.Upload = &u
	}
	return cp
}

func writeResultFile(path string, res Result) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(res); err != nil {
		return fmt.Errorf("encode result file: %w", err)
	}
	return securefile.WriteFileAtomic(path, buf.Bytes())
}
