// Package content manages bounded, anonymous, read-only collection of
// existing service content (system prompts, modelfiles, configuration,
// workspace files, MCP resource bodies, flow definitions, and bounded samples)
// into a restricted .content.jsonl file (mode 0600) outside the BloodHound
// ingest path.
package content

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const SchemaVersion = "1"

// Kind classifies a collected content item.
type Kind string

const (
	KindSystemPrompt  Kind = "system_prompt"
	KindModelfile     Kind = "modelfile"
	KindTemplate      Kind = "template"
	KindConfig        Kind = "config"
	KindNotebook      Kind = "notebook"
	KindWorkspaceFile Kind = "workspace_file"
	KindMCPResource   Kind = "mcp_resource"
	KindFlow          Kind = "flow"
	KindSample        Kind = "sample"
	KindArtifactText  Kind = "artifact_text"
)

// Finding describes a redacted secret location without retaining its value.
type Finding struct {
	Type     string `json:"type"`
	Location string `json:"location,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// Redactor replaces secret spans in a content body before persistence (D4).
type Redactor func(body string) (redacted string, findings []Finding)

// Record is one line of the restricted .content.jsonl output.
type Record struct {
	SchemaVersion   string `json:"schema_version"`
	DeploymentScope string `json:"deployment_scope"`
	ScanID          string `json:"scan_id"`
	VantageKey      string `json:"vantage_key"`
	ServiceID       string `json:"service_id"`
	ResourceID      string `json:"resource_id,omitempty"`
	Surface         string `json:"surface"`
	CheckID         string `json:"check_id"`
	Source          string `json:"source"`
	Kind            Kind   `json:"kind"`
	Location        string `json:"location"`
	MediaType       string `json:"media_type,omitempty"`
	ObservedAt      string `json:"observed_at"`
	Body            string `json:"body"`
	BodyBytes       int64  `json:"body_bytes"`
	OriginalBytes   int64  `json:"original_bytes"`
	BodySHA256      string `json:"body_sha256"`
	Truncated       bool   `json:"truncated"`
	TruncateReason  string `json:"truncate_reason,omitempty"`
}

// Validate checks required provenance, UTF-8 body integrity, and size accounting.
func (r Record) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported content schema_version %q", r.SchemaVersion)
	}
	for _, f := range []struct {
		name, val string
	}{
		{"deployment_scope", r.DeploymentScope},
		{"scan_id", r.ScanID},
		{"vantage_key", r.VantageKey},
		{"service_id", r.ServiceID},
		{"surface", r.Surface},
		{"check_id", r.CheckID},
		{"source", r.Source},
		{"kind", string(r.Kind)},
		{"location", r.Location},
	} {
		if strings.TrimSpace(f.val) == "" {
			return fmt.Errorf("content record requires %s", f.name)
		}
	}
	if r.ObservedAt == "" {
		return errors.New("content record requires observed_at")
	}
	t, err := time.Parse(time.RFC3339, r.ObservedAt)
	if err != nil {
		return fmt.Errorf("observed_at must be RFC3339: %w", err)
	}
	if _, offset := t.Zone(); offset != 0 {
		return errors.New("observed_at must be UTC")
	}
	if strings.IndexByte(r.Body, 0) >= 0 || !utf8.ValidString(r.Body) {
		return errors.New("content body must be valid UTF-8 without NUL bytes")
	}
	if r.BodyBytes != int64(len(r.Body)) {
		return fmt.Errorf("body_bytes %d does not match body length %d", r.BodyBytes, len(r.Body))
	}
	if r.OriginalBytes < 0 {
		return errors.New("original_bytes cannot be negative")
	}
	if len(r.BodySHA256) != 64 {
		return errors.New("body_sha256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(r.BodySHA256); err != nil {
		return fmt.Errorf("body_sha256 must be valid hex: %w", err)
	}
	if r.Truncated && strings.TrimSpace(r.TruncateReason) == "" {
		return errors.New("truncated content record requires truncate_reason")
	}
	return nil
}
