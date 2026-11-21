package common

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/transport"
)

func TestParseTargetEndpoint(t *testing.T) {
	ep, host, err := ParseTargetEndpoint("ai.example.test", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if ep.String() != "http://ai.example.test:8080/" || host != "ai.example.test" {
		t.Fatalf("got (%s, %s)", ep.String(), host)
	}

	ep6, host6, err := ParseTargetEndpoint("::1", 6333)
	if err != nil {
		t.Fatal(err)
	}
	if ep6.String() != "http://[::1]:6333/" || host6 != "::1" {
		t.Fatalf("ipv6 got (%s, %s)", ep6.String(), host6)
	}

	ep6b, host6b, err := ParseTargetEndpoint("[::1]", 6333)
	if err != nil {
		t.Fatal(err)
	}
	if ep6b.String() != "http://[::1]:6333/" || host6b != "::1" {
		t.Fatalf("bracketed ipv6 got (%s, %s)", ep6b.String(), host6b)
	}

	epPort, _, err := ParseTargetEndpoint("127.0.0.1:9000", 8000)
	if err != nil {
		t.Fatal(err)
	}
	if epPort.String() != "http://127.0.0.1:9000/" {
		t.Fatalf("host:port got %s", epPort.String())
	}

	if _, _, err := ParseTargetEndpoint(" ", 8000); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestSanitizeHelpersAndVersion(t *testing.T) {
	err := errors.New(`Get "https://user:secret@host.example:8000/v1/models?token=abc#frag": dial failed`)
	san := SanitizeError(err)
	if strings.Contains(san, "secret") || strings.Contains(san, "token=abc") || strings.Contains(san, "frag") {
		t.Fatalf("error leaked credentials/query: %q", san)
	}
	if !strings.Contains(san, "https://host.example:8000/v1/models") {
		t.Fatalf("sanitized error missing base url: %q", san)
	}

	if got := SanitizeHTTPReference("https://user:pass@agent.example/a2a?key=1#s"); got != "https://agent.example/a2a" {
		t.Fatalf("SanitizeHTTPReference = %q", got)
	}
	if got := SanitizeHTTPReference("ftp://agent.example/file"); got != "" {
		t.Fatalf("non-HTTP ref must be rejected, got %q", got)
	}
	if got := SanitizeHTTPReference("https://agent.example/\npath"); got != "" {
		t.Fatalf("control char ref must be rejected, got %q", got)
	}

	for in, want := range map[string]string{
		"0.6.4":       "0.6.4",
		"v1.12.5":     "1.12.5",
		" V2.0.1-rc1": "2.0.1-rc1",
		"unknown":     "",
		"nightly":     "",
		"0.6":         "0.6",
		"dev-abc":     "",
	} {
		if got := NormalizeVersion(in); got != want {
			t.Errorf("NormalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}

	multi := strings.Repeat("a", 9) + "é"
	bounded := BoundString("  hello\n\x00world "+multi, 18)
	if !utf8.ValidString(bounded) || strings.ContainsRune(bounded, '\n') || strings.ContainsRune(bounded, 0) {
		t.Fatalf("BoundString invalid UTF-8 or controls: %q", bounded)
	}
	if !strings.HasSuffix(bounded, "…[truncated]") {
		t.Fatalf("expected truncated suffix: %q", bounded)
	}
}

func TestSummarizeAccessAndAttachAndEvidence(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	ep, err := graph.ParseEndpoint("http://127.0.0.1:8000", "")
	if err != nil {
		t.Fatal(err)
	}
	srvID, err := graph.NewServiceIdentity("scope-a", graph.VLLMInstance, ep)
	if err != nil {
		t.Fatal(err)
	}
	evID := EvidenceID("scan-1", srvID.ID(), now)
	obs := graph.Observation{
		SchemaVersion: "1", ScanID: "scan-1", CollectorVersion: "0.1.0",
		EvidenceID: evID, Source: ep.String(), Surface: "vllm",
		ObservedAt: now, DeploymentScope: "scope-a", VantageKey: "v1",
		Coverage: graph.CoverageComplete,
	}

	checks := []CheckEntry{
		{CheckID: "vllm_version", Operation: "vllm_version", Outcome: graph.OutcomeSuccess, Reason: "ok", Anonymous: true, OperationKind: graph.EnumerationOperation, CountForAccess: false},
		{CheckID: "vllm_models", Operation: "vllm_models", Outcome: graph.OutcomeSuccess, Reason: "ok", Anonymous: true, OperationKind: graph.EnumerationOperation, CountForAccess: true},
		{CheckID: "qdrant_points_sample", Operation: "qdrant_points_sample", Outcome: graph.OutcomeDenied, Reason: "401", Anonymous: false, OperationKind: graph.ResourceReadOperation, CountForAccess: false},
	}
	acc := SummarizeAccess(srvID.ID(), obs, checks)
	if acc.AuthObserved != "mixed" || !reflect.DeepEqual(acc.Operations, []string{"vllm_models"}) {
		t.Fatalf("SummarizeAccess = %+v", acc)
	}

	// Nil resolver falls back to NetworkEndpoint.
	corrObs := obs
	corrObs.EvidenceID = evID + "-correlation"
	edge, fb, corrRec, err := AttachService("scope-a", "127.0.0.1", srvID, obs, corrObs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil || edge.TouchesNative() {
		t.Fatalf("nil resolver must produce NetworkEndpoint fallback: fb=%v touchesNative=%v", fb, edge.TouchesNative())
	}

	// Mapped resolver attaches to native node without fallback.
	res, err := correlate.New([]correlate.Mapping{{Target: "127.0.0.1", ObjectID: "S-1-5-21-1-1001", Kind: "Computer"}})
	if err != nil {
		t.Fatal(err)
	}
	edge2, fb2, corrRec2, err := AttachService("scope-a", "127.0.0.1", srvID, obs, corrObs, res)
	if err != nil {
		t.Fatal(err)
	}
	if fb2 != nil || !edge2.TouchesNative() {
		t.Fatalf("mapped resolver must emit native edge without fallback: fb=%v touchesNative=%v", fb2, edge2.TouchesNative())
	}
	_ = corrRec2

	recs, err := BuildEvidenceRecords(
		srvID.ID(), obs, evID, checks,
		&evidence.FingerprintInput{TargetID: srvID.ID(), Product: "vLLM", Method: "vllm_version", Confidence: "exact"},
		&transport.TLSInfo{VerificationResult: "verified"},
		[]transport.RedirectInfo{{FromURL: "http://a", ToURL: "http://b", StatusCode: 302, Authorized: true}},
		&corrRec,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 7 {
		t.Fatalf("expected 7 evidence records, got %d", len(recs))
	}
}
