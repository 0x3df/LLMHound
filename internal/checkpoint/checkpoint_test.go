package checkpoint_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/checkpoint"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

func sampleHeader() checkpoint.Header {
	return checkpoint.Header{
		SchemaVersion:    "1",
		DeploymentScope:  "corp-east",
		ScanID:           "scan-20261001-001",
		CollectorVersion: "1.0.0",
		VantageKey:       "scanner-vantage-1",
		CreatedAt:        "2026-10-01T12:00:00Z",
	}
}

func sampleVantage(t *testing.T, scope, key string) graph.Identity {
	t.Helper()
	v, err := graph.NewVantageIdentity(scope, key)
	if err != nil {
		t.Fatalf("create vantage: %v", err)
	}
	return v
}

func sampleObservation(t *testing.T, vantage graph.Identity, evidenceID string, ts time.Time) graph.Observation {
	t.Helper()
	return graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-20261001-001",
		CollectorVersion: "1.0.0",
		EvidenceID:       evidenceID,
		Source:           "https://target.corp:11434/api/version",
		Surface:          "ollama",
		ObservedAt:       ts.UTC(),
		Vantage:          vantage,
		Coverage:         graph.CoverageComplete,
	}
}

func sampleServiceNode(t *testing.T, scope string, vantage graph.Identity, rawURL string) emitter.NodeItem {
	t.Helper()
	ep, err := graph.ParseEndpoint(rawURL, "")
	if err != nil {
		t.Fatalf("parse endpoint %s: %v", rawURL, err)
	}
	ident, err := graph.NewServiceIdentity(scope, graph.OllamaInstance, ep)
	if err != nil {
		t.Fatalf("create service identity: %v", err)
	}
	obs := sampleObservation(t, vantage, "ev-node-001", time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC))
	node, err := graph.NewNode(ident, obs)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	item, err := emitter.NewNodeItem(node, map[string]any{
		"product": "Ollama",
		"version": "0.1.32",
	})
	if err != nil {
		t.Fatalf("create node item: %v", err)
	}
	return item
}

func sampleModelNode(t *testing.T, scope string, serviceIdent graph.Identity, vantage graph.Identity, modelName string) emitter.NodeItem {
	t.Helper()
	ident, err := graph.NewResourceIdentity(scope, graph.AIModel, serviceIdent, modelName)
	if err != nil {
		t.Fatalf("create model identity: %v", err)
	}
	obs := sampleObservation(t, vantage, "ev-model-001", time.Date(2026, 9, 20, 10, 5, 0, 0, time.UTC))
	node, err := graph.NewNode(ident, obs)
	if err != nil {
		t.Fatalf("create model node: %v", err)
	}
	item, err := emitter.NewNodeItem(node, map[string]any{
		"model_name": modelName,
		"format":     "gguf",
	})
	if err != nil {
		t.Fatalf("create model node item: %v", err)
	}
	return item
}

func TestHeaderValidation(t *testing.T) {
	h := sampleHeader()
	if err := h.Validate(); err != nil {
		t.Fatalf("valid header failed: %v", err)
	}

	for _, tc := range []struct {
		name string
		mod  func(h *checkpoint.Header)
	}{
		{"wrong schema", func(h *checkpoint.Header) { h.SchemaVersion = "2" }},
		{"empty scope", func(h *checkpoint.Header) { h.DeploymentScope = "" }},
		{"whitespace scope", func(h *checkpoint.Header) { h.DeploymentScope = "   " }},
		{"empty scan_id", func(h *checkpoint.Header) { h.ScanID = "" }},
		{"empty collector_version", func(h *checkpoint.Header) { h.CollectorVersion = "" }},
		{"empty vantage_key", func(h *checkpoint.Header) { h.VantageKey = "" }},
		{"empty created_at", func(h *checkpoint.Header) { h.CreatedAt = "" }},
		{"non-RFC3339 created_at", func(h *checkpoint.Header) { h.CreatedAt = "2026-10-01 12:00:00" }},
		{"non-UTC created_at", func(h *checkpoint.Header) { h.CreatedAt = "2026-10-01T12:00:00-04:00" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := sampleHeader()
			tc.mod(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestRedactionAndBounding(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, err := checkpoint.NewWriter(&buf, header, checkpoint.WithMaxStringSize(64))
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}

	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	ep, _ := graph.ParseEndpoint("http://target.corp:11434", "")
	serviceIdent, _ := graph.NewServiceIdentity(header.DeploymentScope, graph.OllamaInstance, ep)
	obs := sampleObservation(t, vantage, "ev-001", time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC))
	node, _ := graph.NewNode(serviceIdent, obs)

	longString := strings.Repeat("A", 100) // exceeds maxStringSize (64)
	nodeItem, err := emitter.NewNodeItem(node, map[string]any{
		"api_key":       "secret-token-12345",
		"password":      "SuperSecretP@ssword",
		"auth_token":    "bearer-jwt-token-xyz",
		"authorization": "Bearer secret",
		"cookie":        "sessionid=secret",
		"long_desc":     longString,
		"safe_info":     "normal_metadata",
	})
	if err != nil {
		t.Fatalf("create node item: %v", err)
	}

	// Result with userinfo in target URL
	res := checkpoint.Result{
		Target:      "http://admin:secretPass@target.corp:11434/api/tags?token=secret123#frag",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{nodeItem},
		Details: map[string]any{
			"api_key":   "detail-secret",
			"long_text": longString,
		},
	}

	if err := j.RecordResult(res); err != nil {
		t.Fatalf("record result: %v", err)
	}
	_ = j.Flush()

	journalText := buf.String()

	// Check URL sanitization
	if strings.Contains(journalText, "admin:secretPass") {
		t.Fatalf("userinfo was not redacted from journal: %s", journalText)
	}
	if strings.Contains(journalText, "token=secret123") {
		t.Fatalf("query string was not redacted from journal: %s", journalText)
	}

	// Check property redaction
	if strings.Contains(journalText, "secret-token-12345") {
		t.Fatalf("api_key secret leaked in journal: %s", journalText)
	}
	if strings.Contains(journalText, "SuperSecretP@ssword") {
		t.Fatalf("password leaked in journal: %s", journalText)
	}
	if strings.Contains(journalText, "bearer-jwt-token-xyz") {
		t.Fatalf("auth_token leaked in journal: %s", journalText)
	}

	// Check string truncation
	if strings.Contains(journalText, longString) {
		t.Fatalf("long string was not truncated in journal: %s", journalText)
	}
	if !strings.Contains(journalText, checkpoint.TruncatedSuffix) {
		t.Fatalf("expected truncated suffix in journal: %s", journalText)
	}

	// Replay and verify values
	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	nodes := state.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	props := nodes[0].Properties
	if props["api_key"] != checkpoint.RedactedPlaceholder {
		t.Fatalf("expected api_key redacted, got %v", props["api_key"])
	}
	if props["password"] != checkpoint.RedactedPlaceholder {
		t.Fatalf("expected password redacted, got %v", props["password"])
	}
	if props["safe_info"] != "normal_metadata" {
		t.Fatalf("expected safe_info intact, got %v", props["safe_info"])
	}
	if !strings.HasSuffix(props["long_desc"].(string), checkpoint.TruncatedSuffix) {
		t.Fatalf("expected truncated suffix on long_desc, got %v", props["long_desc"])
	}
}

func TestProvenancePreservation(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatalf("create journal: %v", err)
	}

	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	historicalTime := time.Date(2026, 8, 15, 14, 30, 0, 0, time.UTC)
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "scan-historical-123",
		CollectorVersion: "0.9.5",
		EvidenceID:       "ev-hist-001",
		Source:           "https://target.corp:11434/api/tags",
		Surface:          "ollama",
		ObservedAt:       historicalTime,
		Vantage:          vantage,
		Coverage:         graph.CoveragePartial,
		CoverageReason:   "timed out reading models",
	}

	ep, _ := graph.ParseEndpoint("http://target.corp:11434", "")
	ident, _ := graph.NewServiceIdentity(header.DeploymentScope, graph.OllamaInstance, ep)
	node, _ := graph.NewNode(ident, obs)
	nodeItem, _ := emitter.NewNodeItem(node, map[string]any{"name": "test-ollama"})

	res := checkpoint.Result{
		Target:      "http://target.corp:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{nodeItem},
	}

	if err := j.RecordResult(res); err != nil {
		t.Fatalf("record result: %v", err)
	}

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	replayedNodes := state.Nodes()
	if len(replayedNodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(replayedNodes))
	}

	replayedObs := replayedNodes[0].Node.Observation()
	if !replayedObs.ObservedAt.Equal(historicalTime) {
		t.Fatalf("ObservedAt changed: want %v, got %v", historicalTime, replayedObs.ObservedAt)
	}
	if replayedObs.ScanID != "scan-historical-123" {
		t.Fatalf("ScanID changed: want scan-historical-123, got %s", replayedObs.ScanID)
	}
	if replayedObs.CollectorVersion != "0.9.5" {
		t.Fatalf("CollectorVersion changed: want 0.9.5, got %s", replayedObs.CollectorVersion)
	}
	if replayedObs.EvidenceID != "ev-hist-001" {
		t.Fatalf("EvidenceID changed: want ev-hist-001, got %s", replayedObs.EvidenceID)
	}
	if replayedObs.Coverage != graph.CoveragePartial {
		t.Fatalf("Coverage changed: want partial, got %s", replayedObs.Coverage)
	}
	if replayedObs.CoverageReason != "timed out reading models" {
		t.Fatalf("CoverageReason changed: want 'timed out reading models', got %q", replayedObs.CoverageReason)
	}
}

func TestDeterministicReplayAndPayloadEquivalence(t *testing.T) {
	header := sampleHeader()
	scope := header.DeploymentScope
	vantage := sampleVantage(t, scope, header.VantageKey)
	tObs := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	// 1. Build test graph elements
	serviceNode := sampleServiceNode(t, scope, vantage, "http://ai-server-01.lab.local:11434")
	modelNode1 := sampleModelNode(t, scope, serviceNode.Node.Identity(), vantage, "llama3:latest")
	modelNode2 := sampleModelNode(t, scope, serviceNode.Node.Identity(), vantage, "mistral:7b")

	obs := sampleObservation(t, vantage, "ev-edge-001", tObs)

	// ProvidesModel edges
	edgeModel1, err := graph.NewTopologyEdge(graph.ProvidesModel, serviceNode.Node.Identity().Reference(), modelNode1.Node.Identity().Reference(), obs)
	if err != nil {
		t.Fatalf("create edgeModel1: %v", err)
	}
	edgeModel2, err := graph.NewTopologyEdge(graph.ProvidesModel, serviceNode.Node.Identity().Reference(), modelNode2.Node.Identity().Reference(), obs)
	if err != nil {
		t.Fatalf("create edgeModel2: %v", err)
	}

	// Correlated edge to native Computer by name (linking edge)
	compRef, err := graph.ExistingComputerByName("S-1-5-21-12345-1001", "AI-SERVER-01.LAB.LOCAL")
	if err != nil {
		t.Fatalf("create compRef: %v", err)
	}
	edgeObservedAt, err := graph.NewObservedAtEdge(serviceNode.Node.Identity().Reference(), compRef, obs, graph.Correlation{
		MatchMethod: "ad_suffix_fqdn",
		MatchValue:  "AI-SERVER-01.LAB.LOCAL",
		Confidence:  "high",
	})
	if err != nil {
		t.Fatalf("create edgeObservedAt: %v", err)
	}

	// Fallback edge to NetworkEndpoint
	tgt, _ := graph.ParseTarget("192.0.2.50")
	netID, _ := graph.NewNetworkEndpointIdentity(scope, tgt)
	edgeFallback, err := graph.NewObservedAtEdge(serviceNode.Node.Identity().Reference(), netID.Reference(), obs, graph.Correlation{
		FallbackReason: "uncorrelated_ip",
		CandidateIDs:   []string{"S-1-5-21-999-1", "S-1-5-21-999-2"},
	})
	if err != nil {
		t.Fatalf("create edgeFallback: %v", err)
	}

	// Access evidence edge
	accEv := graph.AccessEvidence{
		Observation:   obs,
		CheckID:       "chk-anon-001",
		Operation:     "list_models",
		TargetID:      serviceNode.Node.Identity().ID(),
		Outcome:       graph.OutcomeSuccess,
		Reason:        "http 200 without auth",
		Anonymous:     true,
		OperationKind: graph.EnumerationOperation,
	}
	edgeAccess, err := graph.NewAccessEdge(graph.UnauthenticatedAccess, vantage.Reference(), serviceNode.Node.Identity().Reference(), accEv)
	if err != nil {
		t.Fatalf("create edgeAccess: %v", err)
	}

	// Evidence sidecar records
	obsCheck := sampleObservation(t, vantage, "ev-check-001", tObs)
	evCheck, err := evidence.NewCheckResultRecord(graph.CheckResult{
		Observation: obsCheck,
		CheckID:     "chk-anon-001",
		Operation:   "list_models",
		TargetID:    serviceNode.Node.Identity().ID(),
		Outcome:     graph.OutcomeSuccess,
		Reason:      "success",
	}, map[string]any{"status_code": 200})
	if err != nil {
		t.Fatalf("create check record: %v", err)
	}

	obsFp := sampleObservation(t, vantage, "ev-fp-001", tObs)
	evFingerprint, err := evidence.NewFingerprintRecord(evidence.FingerprintInput{
		Observation:     obsFp,
		TargetID:        serviceNode.Node.Identity().ID(),
		Product:         "Ollama",
		Vendor:          "Ollama Inc",
		SoftwareVersion: "0.1.32",
		Method:          "http_banner",
		Confidence:      "high",
		Details:         map[string]any{"header": "Ollama/0.1.32"},
	})
	if err != nil {
		t.Fatalf("create fingerprint record: %v", err)
	}

	obsTLS := sampleObservation(t, vantage, "ev-tls-001", tObs)
	evTLS, err := evidence.NewTLSRecord(evidence.TLSRecordInput{
		Observation:        obsTLS,
		TargetID:           serviceNode.Node.Identity().ID(),
		CertFingerprint:    "SHA256:11223344556677889900AABBCCDDEEFF",
		Issuer:             "CN=Lab Root CA",
		Subject:            "CN=ai-server-01.lab.local",
		SANs:               []string{"ai-server-01.lab.local", "192.0.2.50"},
		ValidFrom:          "2026-01-01T00:00:00Z",
		ValidTo:            "2027-01-01T00:00:00Z",
		VerificationResult: "valid",
		NegotiatedVersion:  "TLS 1.3",
	})
	if err != nil {
		t.Fatalf("create TLS record: %v", err)
	}

	obsRedir := sampleObservation(t, vantage, "ev-redir-001", tObs)
	evRedirect, err := evidence.NewRedirectRecord(evidence.RedirectRecordInput{
		Observation: obsRedir,
		FromURL:     "http://ai-server-01.lab.local:11434",
		ToURL:       "https://ai-server-01.lab.local:11434",
		StatusCode:  301,
		Authorized:  true,
		Reason:      "scope_match",
	})
	if err != nil {
		t.Fatalf("create redirect record: %v", err)
	}

	obsCorr := sampleObservation(t, vantage, "ev-corr-001", tObs)
	evCorrelation, err := evidence.NewCorrelationRecord(correlate.Evidence{
		OriginalTarget:   "ai-server-01.lab.local",
		NormalizedTarget: "ai-server-01.lab.local",
		TargetType:       graph.DNSTarget,
		Verified:         true,
		Correlation: graph.Correlation{
			MatchMethod: "ad_suffix_fqdn",
			MatchValue:  "AI-SERVER-01.LAB.LOCAL",
			Confidence:  "high",
		},
	}, obsCorr)
	if err != nil {
		t.Fatalf("create correlation record: %v", err)
	}

	origNodes := []emitter.NodeItem{serviceNode, modelNode1, modelNode2}
	origEdges := []graph.Edge{edgeModel1, edgeModel2, edgeObservedAt, edgeFallback, edgeAccess}
	origEvidence := []evidence.Record{evCheck, evFingerprint, evTLS, evRedirect, evCorrelation}

	// 2. Write to Journal
	var journalBuf bytes.Buffer
	j, err := checkpoint.NewWriter(&journalBuf, header)
	if err != nil {
		t.Fatalf("new journal writer: %v", err)
	}

	res := checkpoint.Result{
		Target:      "http://ai-server-01.lab.local:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       origNodes,
		Edges:       origEdges,
		Evidence:    origEvidence,
	}

	if err := j.RecordResult(res); err != nil {
		t.Fatalf("record result: %v", err)
	}
	if err := j.Flush(); err != nil {
		t.Fatalf("flush journal: %v", err)
	}

	// 3. Replay Journal multiple times and verify determinism
	state1, err := checkpoint.Replay(bytes.NewReader(journalBuf.Bytes()))
	if err != nil {
		t.Fatalf("replay 1: %v", err)
	}
	state2, err := checkpoint.Replay(bytes.NewReader(journalBuf.Bytes()))
	if err != nil {
		t.Fatalf("replay 2: %v", err)
	}

	replayedNodes1 := state1.Nodes()
	replayedNodes2 := state2.Nodes()
	if len(replayedNodes1) != len(origNodes) || len(replayedNodes2) != len(origNodes) {
		t.Fatalf("node count mismatch: want %d, got %d and %d", len(origNodes), len(replayedNodes1), len(replayedNodes2))
	}
	for i := range replayedNodes1 {
		if replayedNodes1[i].Node.Identity().ID() != replayedNodes2[i].Node.Identity().ID() {
			t.Fatalf("replay non-deterministic at node %d", i)
		}
		if replayedNodes1[i].Node.Identity().ID() != origNodes[i].Node.Identity().ID() {
			t.Fatalf("replayed node %d ID mismatch: want %s, got %s", i, origNodes[i].Node.Identity().ID(), replayedNodes1[i].Node.Identity().ID())
		}
	}

	replayedEdges := state1.Edges()
	if len(replayedEdges) != len(origEdges) {
		t.Fatalf("edge count mismatch: want %d, got %d", len(origEdges), len(replayedEdges))
	}
	for i := range replayedEdges {
		if replayedEdges[i].Kind() != origEdges[i].Kind() {
			t.Fatalf("replayed edge %d kind mismatch: want %s, got %s", i, origEdges[i].Kind(), replayedEdges[i].Kind())
		}
		if replayedEdges[i].Start().ID() != origEdges[i].Start().ID() {
			t.Fatalf("replayed edge %d start ID mismatch: want %s, got %s", i, origEdges[i].Start().ID(), replayedEdges[i].Start().ID())
		}
		if replayedEdges[i].End().ID() != origEdges[i].End().ID() {
			t.Fatalf("replayed edge %d end ID mismatch: want %s, got %s", i, origEdges[i].End().ID(), replayedEdges[i].End().ID())
		}
		if replayedEdges[i].TouchesNative() != origEdges[i].TouchesNative() {
			t.Fatalf("replayed edge %d TouchesNative mismatch", i)
		}
		if replayedEdges[i].SourceKind() != origEdges[i].SourceKind() {
			t.Fatalf("replayed edge %d SourceKind mismatch", i)
		}
	}

	replayedEvidence := state1.Evidence()
	if len(replayedEvidence) != len(origEvidence) {
		t.Fatalf("evidence count mismatch: want %d, got %d", len(origEvidence), len(replayedEvidence))
	}
	for i := range replayedEvidence {
		if replayedEvidence[i].EvidenceID != origEvidence[i].EvidenceID {
			t.Fatalf("replayed evidence %d ID mismatch: want %s, got %s", i, origEvidence[i].EvidenceID, replayedEvidence[i].EvidenceID)
		}
		if replayedEvidence[i].RecordType != origEvidence[i].RecordType {
			t.Fatalf("replayed evidence %d type mismatch: want %s, got %s", i, origEvidence[i].RecordType, replayedEvidence[i].RecordType)
		}
	}

	// 4. Golden Test: Emit directly vs Emit from Replayed state -> must be 100% BYTE-FOR-BYTE IDENTICAL
	tmpDir := t.TempDir()
	dirDirect := filepath.Join(tmpDir, "direct")
	dirReplayed := filepath.Join(tmpDir, "replayed")

	artDirect, err := emitter.EmitScan(dirDirect, "scan", origNodes, origEdges, origEvidence)
	if err != nil {
		t.Fatalf("emit direct: %v", err)
	}

	artReplayed, err := emitter.EmitScan(dirReplayed, "scan", replayedNodes1, replayedEdges, replayedEvidence)
	if err != nil {
		t.Fatalf("emit replayed: %v", err)
	}

	compareFiles := func(name, path1, path2 string) {
		b1, err := os.ReadFile(path1)
		if err != nil {
			t.Fatalf("read %s path1: %v", name, err)
		}
		b2, err := os.ReadFile(path2)
		if err != nil {
			t.Fatalf("read %s path2: %v", name, err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("file %s differs between direct and replayed emission!\nDirect:\n%s\nReplayed:\n%s", name, string(b1), string(b2))
		}
	}

	compareFiles("base payload", artDirect.BasePayloadPath, artReplayed.BasePayloadPath)
	compareFiles("linking payload", artDirect.LinkingPayloadPath, artReplayed.LinkingPayloadPath)
	compareFiles("evidence sidecar", artDirect.EvidenceSidecarPath, artReplayed.EvidenceSidecarPath)
}

func TestCrashInterruptionRecovery(t *testing.T) {
	header := sampleHeader()
	scope := header.DeploymentScope
	vantage := sampleVantage(t, scope, header.VantageKey)
	obs := sampleObservation(t, vantage, "ev-crash-001", time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC))

	var buf bytes.Buffer
	j, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	// Record 2 complete results
	node1 := sampleServiceNode(t, scope, vantage, "http://host1.lab:11434")
	node2 := sampleServiceNode(t, scope, vantage, "http://host2.lab:11434")

	if err := j.RecordResult(checkpoint.Result{
		Target:      "http://host1.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node1},
	}); err != nil {
		t.Fatalf("record result 1: %v", err)
	}

	if err := j.RecordResult(checkpoint.Result{
		Target:      "http://host2.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node2},
	}); err != nil {
		t.Fatalf("record result 2: %v", err)
	}

	// Simulate crash: append truncated line at EOF
	buf.WriteString(`{"entry_type":"result","target":"http://host3.lab:11434","surfa`)

	// Replay must recover results 1 & 2 and return TruncatedEntryError
	state, err := checkpoint.Replay(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected TruncatedEntryError, got nil")
	}

	var truncErr *checkpoint.TruncatedEntryError
	if !errors.As(err, &truncErr) {
		t.Fatalf("expected TruncatedEntryError, got %T: %v", err, err)
	}
	if truncErr.Line != 4 {
		t.Fatalf("expected truncated line 4, got %d", truncErr.Line)
	}

	if state == nil {
		t.Fatal("expected state populated up to crash point, got nil")
	}

	nodes := state.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes recovered prior to crash, got %d", len(nodes))
	}
	if !state.IsCompleted("http://host1.lab:11434", "ollama") {
		t.Fatal("expected host1 completed")
	}
	if !state.IsCompleted("http://host2.lab:11434", "ollama") {
		t.Fatal("expected host2 completed")
	}
}

func TestTargetStatusTracking(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	// Target 1: started then completed
	if err := j.RecordTarget(checkpoint.TargetRecord{
		Target:  "10.0.0.1:11434",
		Surface: "ollama",
		Status:  checkpoint.TargetStatusStarted,
	}); err != nil {
		t.Fatalf("record target 1 started: %v", err)
	}

	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	obs := sampleObservation(t, vantage, "ev-t1", time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC))
	if err := j.RecordResult(checkpoint.Result{
		Target:      "10.0.0.1:11434",
		Surface:     "ollama",
		Observation: obs,
	}); err != nil {
		t.Fatalf("record result 1: %v", err)
	}

	// Target 2: failed
	failedObs := obs
	failedObs.Coverage = graph.CoverageFailed
	failedObs.CoverageReason = "connection refused"
	if err := j.RecordResult(checkpoint.Result{
		Target:      "10.0.0.2:11434",
		Surface:     "ollama",
		Observation: failedObs,
		Error:       "connection refused",
	}); err != nil {
		t.Fatalf("record result 2: %v", err)
	}

	// Target 3: skipped
	if err := j.RecordTarget(checkpoint.TargetRecord{
		Target:  "10.0.0.3:11434",
		Surface: "ollama",
		Status:  checkpoint.TargetStatusSkipped,
		Error:   "excluded by policy",
	}); err != nil {
		t.Fatalf("record target 3: %v", err)
	}

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	completed := state.CompletedTargets()
	if len(completed) != 1 || completed[0] != "10.0.0.1:11434" {
		t.Fatalf("unexpected completed targets: %v", completed)
	}
	if !state.IsCompleted("10.0.0.1:11434", "ollama") {
		t.Fatal("expected target 1 completed")
	}
	if state.IsCompleted("10.0.0.2:11434", "ollama") {
		t.Fatal("target 2 should not be completed")
	}
	if state.IsCompleted("10.0.0.3:11434", "ollama") {
		t.Fatal("target 3 should not be completed")
	}

	targets := state.Targets()
	if targets["10.0.0.2:11434|ollama"].Status != checkpoint.TargetStatusFailed {
		t.Fatalf("expected target 2 status failed, got %s", targets["10.0.0.2:11434|ollama"].Status)
	}
	if targets["10.0.0.3:11434|ollama"].Status != checkpoint.TargetStatusSkipped {
		t.Fatalf("expected target 3 status skipped, got %s", targets["10.0.0.3:11434|ollama"].Status)
	}
}

func TestFileJournalLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sub", "test.journal.jsonl")

	header := sampleHeader()
	fj, err := checkpoint.CreateFile(path, header)
	if err != nil {
		t.Fatalf("create file journal: %v", err)
	}

	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	node := sampleServiceNode(t, header.DeploymentScope, vantage, "http://host-file.lab:11434")
	obs := sampleObservation(t, vantage, "ev-file-01", time.Date(2026, 9, 30, 11, 0, 0, 0, time.UTC))

	if err := fj.RecordResult(checkpoint.Result{
		Target:      "http://host-file.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node},
	}); err != nil {
		t.Fatalf("record result: %v", err)
	}

	if err := fj.Close(); err != nil {
		t.Fatalf("close file journal: %v", err)
	}

	// Replay from file
	state, err := checkpoint.ReplayFile(path)
	if err != nil {
		t.Fatalf("replay file: %v", err)
	}
	if len(state.Nodes()) != 1 {
		t.Fatalf("expected 1 node, got %d", len(state.Nodes()))
	}

	// Open existing to append
	fjAppend, err := checkpoint.OpenFile(path)
	if err != nil {
		t.Fatalf("open file journal for append: %v", err)
	}

	node2 := sampleServiceNode(t, header.DeploymentScope, vantage, "http://host-file-2.lab:11434")
	if err := fjAppend.RecordResult(checkpoint.Result{
		Target:      "http://host-file-2.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node2},
	}); err != nil {
		t.Fatalf("record second result: %v", err)
	}
	_ = fjAppend.Close()

	stateAfter, err := checkpoint.ReplayFile(path)
	if err != nil {
		t.Fatalf("replay file after append: %v", err)
	}
	if len(stateAfter.Nodes()) != 2 {
		t.Fatalf("expected 2 nodes after append, got %d", len(stateAfter.Nodes()))
	}
}

func TestConcurrentWriters(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	const numWorkers = 10
	const itemsPerWorker = 20

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < itemsPerWorker; i++ {
				target := fmt.Sprintf("http://worker-%d-host-%d.lab:11434", workerID, i)
				node := sampleServiceNode(t, header.DeploymentScope, vantage, target)
				obs := sampleObservation(t, vantage, fmt.Sprintf("ev-%d-%d", workerID, i), time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
				if err := j.RecordResult(checkpoint.Result{
					Target:      target,
					Surface:     "ollama",
					Observation: obs,
					Nodes:       []emitter.NodeItem{node},
				}); err != nil {
					t.Errorf("worker %d item %d: %v", workerID, i, err)
				}
			}
		}(w)
	}

	wg.Wait()
	_ = j.Flush()

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatalf("replay concurrent output: %v", err)
	}

	expectedCount := numWorkers * itemsPerWorker
	if len(state.Nodes()) != expectedCount {
		t.Fatalf("expected %d nodes from concurrent workers, got %d", expectedCount, len(state.Nodes()))
	}
	if len(state.Results()) != expectedCount {
		t.Fatalf("expected %d results from concurrent workers, got %d", expectedCount, len(state.Results()))
	}
}

func TestMaxEntrySizeExceeded(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	// Set small entry size limit: 512 bytes
	j, err := checkpoint.NewWriter(&buf, header, checkpoint.WithMaxEntryBytes(512))
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	node := sampleServiceNode(t, header.DeploymentScope, vantage, "http://host.lab:11434")
	obs := sampleObservation(t, vantage, "ev-001", time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	// Result with details that serialize to > 512 bytes
	hugeMap := make(map[string]any)
	for i := 0; i < 50; i++ {
		hugeMap[fmt.Sprintf("key_%d", i)] = fmt.Sprintf("value_number_%d_data", i)
	}

	res := checkpoint.Result{
		Target:      "http://host.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node},
		Details:     hugeMap,
	}

	err = j.RecordResult(res)
	if err == nil {
		t.Fatal("expected ErrEntryTooLarge, got nil")
	}
	if !errors.Is(err, checkpoint.ErrEntryTooLarge) {
		t.Fatalf("expected ErrEntryTooLarge, got %v", err)
	}
}

func TestGranularRecordsReplay(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, err := checkpoint.NewWriter(&buf, header)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	scope := header.DeploymentScope
	vantage := sampleVantage(t, scope, header.VantageKey)
	tObs := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	obs := sampleObservation(t, vantage, "ev-granular-01", tObs)

	// Record individual target
	if err := j.RecordTarget(checkpoint.TargetRecord{
		Target:  "10.10.10.1:11434",
		Surface: "ollama",
		Status:  checkpoint.TargetStatusCompleted,
		Observation: &checkpoint.ObservationRecord{
			SchemaVersion: "1", ScanID: obs.ScanID, CollectorVersion: obs.CollectorVersion,
			EvidenceID: obs.EvidenceID, Source: obs.Source, Surface: obs.Surface,
			ObservedAt: tObs.Format(time.RFC3339), VantageKey: vantage.ID(), Coverage: string(graph.CoverageComplete),
		},
	}); err != nil {
		t.Fatalf("record target: %v", err)
	}

	// Record individual node
	node := sampleServiceNode(t, scope, vantage, "http://10.10.10.1:11434")
	if err := j.RecordNode(node); err != nil {
		t.Fatalf("record node: %v", err)
	}

	// Record individual edge
	model := sampleModelNode(t, scope, node.Node.Identity(), vantage, "llama3:latest")
	edge, err := graph.NewTopologyEdge(graph.ProvidesModel, node.Node.Identity().Reference(), model.Node.Identity().Reference(), obs)
	if err != nil {
		t.Fatalf("create edge: %v", err)
	}
	if err := j.RecordEdge(edge); err != nil {
		t.Fatalf("record edge: %v", err)
	}

	// Record individual evidence
	ev, err := evidence.NewCheckResultRecord(graph.CheckResult{
		Observation: obs,
		CheckID:     "chk-001",
		Operation:   "ping",
		TargetID:    node.Node.Identity().ID(),
		Outcome:     graph.OutcomeSuccess,
		Reason:      "ok",
	}, nil)
	if err != nil {
		t.Fatalf("create check record: %v", err)
	}
	if err := j.RecordEvidence(ev); err != nil {
		t.Fatalf("record evidence: %v", err)
	}

	_ = j.Flush()

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if len(state.Nodes()) != 1 {
		t.Fatalf("expected 1 node, got %d", len(state.Nodes()))
	}
	if len(state.Edges()) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(state.Edges()))
	}
	if len(state.Evidence()) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(state.Evidence()))
	}
	if !state.IsCompleted("10.10.10.1:11434", "ollama") {
		t.Fatal("expected target completed")
	}
}

func TestCorruptedIntermediateLine(t *testing.T) {
	header := sampleHeader()
	var buf bytes.Buffer
	j, _ := checkpoint.NewWriter(&buf, header)
	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	node := sampleServiceNode(t, header.DeploymentScope, vantage, "http://host.lab:11434")
	obs := sampleObservation(t, vantage, "ev-001", time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC))

	_ = j.RecordResult(checkpoint.Result{
		Target:      "http://host.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node},
	})
	_ = j.Flush()

	// Inject malformed line in middle, followed by valid line
	corrupted := buf.String()
	corrupted += "THIS_IS_NOT_VALID_JSON\n"
	corrupted += `{"entry_type":"target","target":{"target":"10.0.0.1","status":"completed"}}` + "\n"

	state, err := checkpoint.Replay(strings.NewReader(corrupted))
	if err == nil {
		t.Fatal("expected error for corrupted intermediate line, got nil")
	}
	var truncErr *checkpoint.TruncatedEntryError
	if errors.As(err, &truncErr) {
		t.Fatal("corrupted intermediate line must not be classified as TruncatedEntryError")
	}
	if !strings.Contains(err.Error(), "invalid JSON entry") {
		t.Fatalf("unexpected error message: %v", err)
	}
	_ = state
}

func TestMultiSurfaceTargetTracking(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	obs := sampleObservation(t, vantage, "ev-01", time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC))

	// Ollama completed on 10.0.0.1
	_ = j.RecordResult(checkpoint.Result{
		Target:      "10.0.0.1",
		Surface:     "ollama",
		Observation: obs,
	})

	// Jupyter failed on 10.0.0.1
	failedObs := obs
	failedObs.Surface = "jupyter"
	failedObs.Coverage = graph.CoverageFailed
	failedObs.CoverageReason = "port closed"
	_ = j.RecordResult(checkpoint.Result{
		Target:      "10.0.0.1",
		Surface:     "jupyter",
		Observation: failedObs,
	})
	_ = j.Flush()

	state, err := checkpoint.Replay(&buf)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if !state.IsCompleted("10.0.0.1", "ollama") {
		t.Fatal("expected ollama completed on 10.0.0.1")
	}
	if state.IsCompleted("10.0.0.1", "jupyter") {
		t.Fatal("expected jupyter NOT completed on 10.0.0.1")
	}
}

func TestEmptyJournalAndMissingHeader(t *testing.T) {
	// Empty reader
	_, err := checkpoint.Replay(strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "empty journal") {
		t.Fatalf("expected empty journal error, got: %v", err)
	}

	// First line is not header
	nonHeader := `{"entry_type":"target","target":{"target":"10.0.0.1","status":"completed"}}` + "\n"
	_, err = checkpoint.Replay(strings.NewReader(nonHeader))
	if err == nil || !strings.Contains(err.Error(), "first entry must be \"header\"") {
		t.Fatalf("expected first entry must be header error, got: %v", err)
	}
}

func TestReplayStreamHandler(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	vantage := sampleVantage(t, header.DeploymentScope, header.VantageKey)
	node := sampleServiceNode(t, header.DeploymentScope, vantage, "http://host.lab:11434")
	obs := sampleObservation(t, vantage, "ev-stream", time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC))

	_ = j.RecordResult(checkpoint.Result{
		Target:      "http://host.lab:11434",
		Surface:     "ollama",
		Observation: obs,
		Nodes:       []emitter.NodeItem{node},
	})
	_ = j.Flush()

	headerCalled := false
	resultCalled := false

	handler := checkpoint.ReplayHandler{
		OnHeader: func(h checkpoint.Header) error {
			headerCalled = true
			if h.ScanID != header.ScanID {
				t.Fatalf("header mismatch: %s vs %s", h.ScanID, header.ScanID)
			}
			return nil
		},
		OnResult: func(res checkpoint.Result) error {
			resultCalled = true
			if res.Target != "http://host.lab:11434" {
				t.Fatalf("result target mismatch: %s", res.Target)
			}
			return nil
		},
	}

	if err := checkpoint.ReplayStream(&buf, handler); err != nil {
		t.Fatalf("replay stream: %v", err)
	}
	if !headerCalled {
		t.Fatal("expected OnHeader called")
	}
	if !resultCalled {
		t.Fatal("expected OnResult called")
	}
}

func TestNestedRedactionAndBounding(t *testing.T) {
	input := map[string]any{
		"nested": map[string]any{
			"api_key": "nested-secret",
			"items": []any{
				map[string]any{
					"password": "item-password",
					"value":    "safe",
				},
				"simple_item",
			},
		},
		"token_list": []string{"secret_token_1", "secret_token_2"},
	}

	sanitized := checkpoint.SanitizeMap(input, 50)
	nested := sanitized["nested"].(map[string]any)
	if nested["api_key"] != checkpoint.RedactedPlaceholder {
		t.Fatalf("nested api_key not redacted: %v", nested["api_key"])
	}
	items := nested["items"].([]any)
	firstItem := items[0].(map[string]any)
	if firstItem["password"] != checkpoint.RedactedPlaceholder {
		t.Fatalf("item password not redacted: %v", firstItem["password"])
	}
	if firstItem["value"] != "safe" {
		t.Fatalf("item value corrupted: %v", firstItem["value"])
	}
}

func TestClosedJournal(t *testing.T) {
	var buf bytes.Buffer
	header := sampleHeader()
	j, _ := checkpoint.NewWriter(&buf, header)
	_ = j.Close()

	if err := j.RecordResult(checkpoint.Result{}); !errors.Is(err, checkpoint.ErrClosedJournal) {
		t.Fatalf("expected ErrClosedJournal, got: %v", err)
	}
	if err := j.RecordTarget(checkpoint.TargetRecord{}); !errors.Is(err, checkpoint.ErrClosedJournal) {
		t.Fatalf("expected ErrClosedJournal, got: %v", err)
	}
	if err := j.RecordNode(emitter.NodeItem{}); !errors.Is(err, checkpoint.ErrClosedJournal) {
		t.Fatalf("expected ErrClosedJournal, got: %v", err)
	}
	if err := j.RecordEdge(graph.Edge{}); !errors.Is(err, checkpoint.ErrClosedJournal) {
		t.Fatalf("expected ErrClosedJournal, got: %v", err)
	}
	if err := j.RecordEvidence(evidence.Record{}); !errors.Is(err, checkpoint.ErrClosedJournal) {
		t.Fatalf("expected ErrClosedJournal, got: %v", err)
	}
}
