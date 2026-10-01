package evidence_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

func sampleObservation(t *testing.T) graph.Observation {
	t.Helper()
	v, err := graph.NewVantageIdentity("corp-scope", "vantage-east")
	if err != nil {
		t.Fatal(err)
	}
	return graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-1234",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-5678",
		Source:           "https://ollama.corp.local:11434/api/tags",
		Surface:          "ollama",
		ObservedAt:       time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Vantage:          v,
		Coverage:         graph.CoverageComplete,
	}
}

func TestCheckResultRecord(t *testing.T) {
	obs := sampleObservation(t)
	check := graph.CheckResult{
		Observation: obs,
		CheckID:     "check_ollama_list",
		Operation:   "ollama_tags",
		TargetID:    "TGT-001",
		Outcome:     graph.OutcomeSuccess,
		Reason:      "tags retrieved successfully",
	}

	details := map[string]any{
		"http_status":   200,
		"authorization": "Bearer supersecret",
		"model_count":   5,
	}

	rec, err := evidence.NewCheckResultRecord(check, details)
	if err != nil {
		t.Fatalf("NewCheckResultRecord: %v", err)
	}

	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if rec.RecordType != evidence.RecordCheckResult {
		t.Errorf("unexpected record_type: %s", rec.RecordType)
	}
	if rec.Details["authorization"] != "[REDACTED]" {
		t.Errorf("expected authorization to be redacted, got: %v", rec.Details["authorization"])
	}
	if rec.Details["http_status"] != 200 {
		t.Errorf("expected http_status 200, got: %v", rec.Details["http_status"])
	}
}

func TestCorrelationRecord(t *testing.T) {
	obs := sampleObservation(t)
	ev := correlate.Evidence{
		OriginalTarget:   "ai.corp.local",
		NormalizedTarget: "ai.corp.local",
		TargetType:       graph.DNSTarget,
		Verified:         true,
		Correlation: graph.Correlation{
			MatchMethod: "ad_suffix_name",
			MatchValue:  "AI.CORP.LOCAL",
			Confidence:  "unique_property_match",
		},
	}

	rec, err := evidence.NewCorrelationRecord(ev, obs)
	if err != nil {
		t.Fatalf("NewCorrelationRecord: %v", err)
	}

	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if rec.RecordType != evidence.RecordCorrelation {
		t.Errorf("unexpected record_type: %s", rec.RecordType)
	}
	if rec.MatchMethod != "ad_suffix_name" || rec.MatchValue != "AI.CORP.LOCAL" {
		t.Errorf("unexpected correlation fields: %+v", rec)
	}
}

func TestTLSRecord(t *testing.T) {
	obs := sampleObservation(t)
	rec, err := evidence.NewTLSRecord(evidence.TLSRecordInput{
		Observation:        obs,
		TargetID:           "TGT-001",
		CertFingerprint:    "SHA256:abcd1234",
		Issuer:             "CN=Corp CA",
		Subject:            "CN=ai.corp.local",
		SANs:               []string{"ai.corp.local", "ollama.corp.local"},
		ValidFrom:          "2026-01-01T00:00:00Z",
		ValidTo:            "2027-01-01T00:00:00Z",
		VerificationResult: "verified",
		VerificationReason: "valid leaf and root chain",
		NegotiatedVersion:  "TLS 1.3",
		InsecureOverride:   false,
	})
	if err != nil {
		t.Fatalf("NewTLSRecord: %v", err)
	}

	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if rec.RecordType != evidence.RecordTLS {
		t.Errorf("unexpected record_type: %s", rec.RecordType)
	}
}

func TestFingerprintRecord(t *testing.T) {
	obs := sampleObservation(t)
	rec, err := evidence.NewFingerprintRecord(evidence.FingerprintInput{
		Observation:        obs,
		TargetID:           "TGT-001",
		Product:            "Ollama",
		Vendor:             "Ollama",
		SoftwareVersion:    "0.3.12",
		SoftwareVersionRaw: "ollama version is 0.3.12",
		Method:             "version_api",
		Confidence:         "exact",
	})
	if err != nil {
		t.Fatalf("NewFingerprintRecord: %v", err)
	}

	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if rec.RecordType != evidence.RecordFingerprint {
		t.Errorf("unexpected record_type: %s", rec.RecordType)
	}
}

func TestRedirectRecord(t *testing.T) {
	obs := sampleObservation(t)
	rec, err := evidence.NewRedirectRecord(evidence.RedirectRecordInput{
		Observation: obs,
		FromURL:     "http://user:pass@example.com/api",
		ToURL:       "https://example.com/api",
		StatusCode:  301,
		Authorized:  true,
		Reason:      "https upgrade",
	})
	if err != nil {
		t.Fatalf("NewRedirectRecord: %v", err)
	}

	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if strings.Contains(rec.FromURL, "user") || strings.Contains(rec.FromURL, "pass") {
		t.Errorf("credentials not stripped from redirect FromURL: %s", rec.FromURL)
	}
}

func TestWriter(t *testing.T) {
	var buf bytes.Buffer
	w := evidence.NewWriter(&buf)

	obs := sampleObservation(t)
	check := graph.CheckResult{
		Observation: obs,
		CheckID:     "check_1",
		Operation:   "op_1",
		TargetID:    "tgt_1",
		Outcome:     graph.OutcomeSuccess,
		Reason:      "ok",
	}
	rec, err := evidence.NewCheckResultRecord(check, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("json parse error: %v", err)
	}
	if parsed["record_type"] != "check_result" {
		t.Errorf("unexpected record_type in written JSON: %v", parsed["record_type"])
	}
}

func TestCheckResultRecordRedactsNestedDetails(t *testing.T) {
	check := graph.CheckResult{
		Observation: sampleObservation(t),
		CheckID:     "check_ollama_list",
		Operation:   "ollama_tags",
		TargetID:    "TGT-001",
		Outcome:     graph.OutcomeSuccess,
		Reason:      "ok",
	}
	long := strings.Repeat("a", evidence.MaxDetailSize*2)
	rec, err := evidence.NewCheckResultRecord(check, map[string]any{
		"headers":      map[string]any{"X-API-Key": "k", "Accept": "json"},
		"access_token": "t",
		"max_tokens":   4096,
		"token_count":  7,
		"items":        []any{long},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(rec.Details)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"k"`) || strings.Contains(string(out), `"t"`) {
		t.Errorf("secret leaked: %s", out)
	}
	if rec.Details["max_tokens"] != 4096 || rec.Details["token_count"] != 7 {
		t.Errorf("telemetry keys redacted: %s", out)
	}
	if len(out) > evidence.MaxDetailSize*2 {
		t.Errorf("long nested string not bounded: %d bytes", len(out))
	}
}
