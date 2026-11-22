package bloodhound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/graph"
)

const (
	jobStatusReady    = 0
	jobStatusRunning  = 1
	jobStatusComplete = 2
	jobStatusCanceled = 3
	jobStatusPartial  = 8
)

// JobResult summarizes one BloodHound CE file-upload job.
type JobResult struct {
	JobID      int64           `json:"job_id"`
	Status     int             `json:"status"`
	Attempts   int             `json:"attempts"`
	TaskErrors []TaskErrorInfo `json:"task_errors,omitempty"`
}

// TaskErrorInfo records per-file ingest errors from completed-tasks.
type TaskErrorInfo struct {
	FileName string   `json:"file_name"`
	Errors   []string `json:"errors"`
}

// UploadOptions configures two-step scan upload.
type UploadOptions struct {
	BasePayloadBytes    []byte
	BaseFileName        string
	LinkingPayloadBytes []byte
	LinkingFileName     string
	PollInterval        time.Duration
	PollTimeout         time.Duration
	MaxRetries          int
}

// UploadReport summarizes a two-step upload including existence pre-flight.
type UploadReport struct {
	BaseJob      *JobResult    `json:"base_job,omitempty"`
	LinkingJob   *JobResult    `json:"linking_job,omitempty"`
	SkippedEdges []SkippedEdge `json:"skipped_edges,omitempty"`
	KeptEdges    int           `json:"kept_edges"`
}

// UploadFileJob runs the CE 9.7.1 job upload lifecycle:
// POST /api/v2/file-upload/start -> POST /api/v2/file-upload/{id} ->
// POST /api/v2/file-upload/{id}/end -> poll GET /api/v2/file-upload ->
// inspect GET /api/v2/file-upload/{id}/completed-tasks.
func (c *Client) UploadFileJob(
	ctx context.Context,
	payloadBytes []byte,
	contentType, fileName string,
	pollInterval, pollTimeout time.Duration,
	maxRetries int,
) (JobResult, error) {
	if len(payloadBytes) == 0 {
		return JobResult{}, errors.New("upload payload cannot be empty")
	}
	if contentType == "" {
		contentType = "application/json"
	}
	if fileName == "" {
		fileName = "payload.json"
	}
	if pollInterval <= 0 {
		pollInterval = 1 * time.Second
	}
	if pollTimeout <= 0 {
		pollTimeout = 5 * time.Minute
	}
	if maxRetries < 0 {
		maxRetries = 0
	}

	var lastJob JobResult
	var lastErr error
	for attempt := 1; attempt <= maxRetries+1; attempt++ {
		jobID, err := c.startUploadJob(ctx)
		if err != nil {
			return JobResult{}, err
		}

		headers := map[string]string{"X-File-Upload-Name": fileName}
		status, body, err := c.doRaw(ctx, http.MethodPost, fmt.Sprintf("/api/v2/file-upload/%d", jobID), contentType, payloadBytes, headers)
		if err != nil {
			return JobResult{}, err
		}
		if status != http.StatusAccepted && status != http.StatusOK && status != http.StatusCreated {
			return JobResult{}, fmt.Errorf("file upload failed (HTTP %d): %s", status, truncateBody(body))
		}

		status, body, err = c.doRaw(ctx, http.MethodPost, fmt.Sprintf("/api/v2/file-upload/%d/end", jobID), "", nil, nil)
		if err != nil {
			return JobResult{}, err
		}
		if status != http.StatusOK && status != http.StatusAccepted {
			return JobResult{}, fmt.Errorf("file-upload/end failed (HTTP %d): %s", status, truncateBody(body))
		}

		jobStatus, gone, err := c.pollUploadJob(ctx, jobID, pollInterval, pollTimeout)
		if err != nil {
			return JobResult{}, err
		}
		taskErrors, err := c.completedTaskErrors(ctx, jobID)
		if err != nil {
			return JobResult{}, err
		}

		lastJob = JobResult{
			JobID:      jobID,
			Status:     jobStatus,
			Attempts:   attempt,
			TaskErrors: taskErrors,
		}

		if len(taskErrors) > 0 {
			return lastJob, fmt.Errorf("upload job %d failed ingest with %d file error(s): %s", jobID, len(taskErrors), strings.Join(taskErrors[0].Errors, "; "))
		}
		if jobStatus == jobStatusCanceled {
			lastErr = fmt.Errorf("upload job %d was canceled (status 3)", jobID)
			continue
		}
		if jobStatus == jobStatusPartial {
			return lastJob, fmt.Errorf("upload job %d finished with partial failure (status 8)", jobID)
		}
		if gone || jobStatus == jobStatusComplete {
			return lastJob, nil
		}
		lastErr = fmt.Errorf("upload job %d ended in unexpected status %d", jobID, jobStatus)
	}
	return lastJob, lastErr
}

func (c *Client) startUploadJob(ctx context.Context) (int64, error) {
	status, body, err := c.doRaw(ctx, http.MethodPost, "/api/v2/file-upload/start", "", nil, nil)
	if err != nil {
		return 0, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return 0, fmt.Errorf("file-upload/start failed (HTTP %d): %s", status, truncateBody(body))
	}
	var env struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Data.ID <= 0 {
		return 0, fmt.Errorf("decode file-upload/start response: %w", err)
	}
	return env.Data.ID, nil
}

func (c *Client) pollUploadJob(ctx context.Context, jobID int64, interval, timeout time.Duration) (int, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		status, body, err := c.doRaw(ctx, http.MethodGet, "/api/v2/file-upload", "", nil, nil)
		if err != nil {
			return 0, false, err
		}
		if status != http.StatusOK {
			return 0, false, fmt.Errorf("GET /api/v2/file-upload returned HTTP %d: %s", status, truncateBody(body))
		}
		var env struct {
			Data []struct {
				ID     int64 `json:"id"`
				Status int   `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return 0, false, fmt.Errorf("decode file-upload list: %w", err)
		}
		found := false
		jobStatus := 0
		for _, job := range env.Data {
			if job.ID == jobID {
				found = true
				jobStatus = job.Status
				break
			}
		}
		if !found {
			return jobStatusComplete, true, nil
		}
		switch jobStatus {
		case jobStatusComplete, jobStatusCanceled, jobStatusPartial:
			return jobStatus, false, nil
		}
		if time.Now().After(deadline) {
			return jobStatus, false, fmt.Errorf("timed out waiting for upload job %d (last status=%d)", jobID, jobStatus)
		}
		select {
		case <-ctx.Done():
			return jobStatus, false, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (c *Client) completedTaskErrors(ctx context.Context, jobID int64) ([]TaskErrorInfo, error) {
	status, body, err := c.doRaw(ctx, http.MethodGet, fmt.Sprintf("/api/v2/file-upload/%d/completed-tasks", jobID), "", nil, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET completed-tasks returned HTTP %d: %s", status, truncateBody(body))
	}
	var env struct {
		Data []struct {
			FileName string `json:"file_name"`
			Errors   []any  `json:"errors"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decode completed-tasks: %w", err)
	}
	var out []TaskErrorInfo
	for _, t := range env.Data {
		if len(t.Errors) == 0 {
			continue
		}
		var msgs []string
		for _, rawErr := range t.Errors {
			msgs = append(msgs, fmt.Sprint(rawErr))
		}
		out = append(out, TaskErrorInfo{FileName: t.FileName, Errors: msgs})
	}
	return out, nil
}

// UploadScan enforces the M0 Q5 two-step upload safety contract and runs the
// read-only existence pre-flight on any linking payload before uploading.
func (c *Client) UploadScan(ctx context.Context, opts UploadOptions) (*UploadReport, error) {
	if len(opts.BasePayloadBytes) == 0 && len(opts.LinkingPayloadBytes) == 0 {
		return nil, errors.New("upload requires at least a base payload or linking payload")
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 2
	}

	report := &UploadReport{}
	var baseNodeIDs map[string]bool

	if len(opts.BasePayloadBytes) > 0 {
		var base emitter.Payload
		if err := json.Unmarshal(opts.BasePayloadBytes, &base); err != nil {
			return nil, fmt.Errorf("parse base payload: %w", err)
		}
		if base.Metadata == nil || base.Metadata.SourceKind != graph.SourceKind {
			return nil, fmt.Errorf("base payload must declare metadata.source_kind %q (M0 Q5)", graph.SourceKind)
		}
		baseNodeIDs = make(map[string]bool, len(base.Graph.Nodes))
		for _, n := range base.Graph.Nodes {
			if id := strings.ToUpper(strings.TrimSpace(n.ID)); id != "" {
				baseNodeIDs[id] = true
			}
		}

		name := opts.BaseFileName
		if name == "" {
			name = "llmhound-base.json"
		}
		job, err := c.UploadFileJob(ctx, opts.BasePayloadBytes, "application/json", name, opts.PollInterval, opts.PollTimeout, opts.MaxRetries)
		report.BaseJob = &job
		if err != nil {
			return report, fmt.Errorf("upload base payload: %w", err)
		}
	}

	if len(opts.LinkingPayloadBytes) > 0 {
		var link emitter.Payload
		if err := json.Unmarshal(opts.LinkingPayloadBytes, &link); err != nil {
			return report, fmt.Errorf("parse linking payload: %w", err)
		}
		if link.Metadata != nil && link.Metadata.SourceKind != "" {
			return report, fmt.Errorf("linking payload must NOT declare metadata.source_kind (M0 Q5 would tag and delete native nodes)")
		}

		filtered, skipped, err := c.FilterLinkingPayload(ctx, link, baseNodeIDs)
		if err != nil {
			return report, fmt.Errorf("linking existence pre-flight: %w", err)
		}
		report.SkippedEdges = skipped
		report.KeptEdges = len(filtered.Graph.Edges)

		if len(filtered.Graph.Edges) > 0 {
			filteredBytes, err := json.Marshal(filtered)
			if err != nil {
				return report, fmt.Errorf("marshal filtered linking payload: %w", err)
			}
			name := opts.LinkingFileName
			if name == "" {
				name = "llmhound-linking.json"
			}
			job, err := c.UploadFileJob(ctx, filteredBytes, "application/json", name, opts.PollInterval, opts.PollTimeout, opts.MaxRetries)
			report.LinkingJob = &job
			if err != nil {
				return report, fmt.Errorf("upload linking payload: %w", err)
			}
		}
	}

	return report, nil
}
