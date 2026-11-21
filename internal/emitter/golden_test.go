package emitter_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x3df/LLMHound/internal/config"
	"github.com/0x3df/LLMHound/internal/correlate"
	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
	"github.com/0x3df/LLMHound/internal/targets"
)

func TestGoldenEmission(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Prepare configuration and targets
	cfg := config.Defaults()
	cfg.Scope = "corp-scope"
	cfg.VantageKey = "vantage-dc01"
	cfg.Targets = []string{"ollama.corp.local"}
	mappingFile := filepath.Join(tempDir, "assets.csv")
	if err := os.WriteFile(mappingFile, []byte("ollama.corp.local,S-1-5-21-9999-8888-7777-1001,Computer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Correlation.MappingFile = mappingFile

	prepared, err := targets.Prepare(cfg.TargetInput())
	if err != nil {
		t.Fatalf("targets.Prepare: %v", err)
	}
	if len(prepared) != 1 || prepared[0] != "ollama.corp.local" {
		t.Fatalf("unexpected prepared targets: %v", prepared)
	}

	// 2. Attach the target to the existing node the asset mapping names
	resolver, err := correlate.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("correlate.NewFromConfig: %v", err)
	}

	corrResult, err := resolver.Resolve(cfg.Scope, prepared[0])
	if err != nil {
		t.Fatalf("resolver.Resolve: %v", err)
	}
	if !corrResult.Target().IsNative() {
		t.Fatalf("expected target to attach to the mapped native node")
	}

	// 3. Build graph observation and identities

	fixedTime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	obs := graph.Observation{
		SchemaVersion:    "1",
		ScanID:           "golden-scan-001",
		CollectorVersion: "0.1.0",
		EvidenceID:       "ev-golden-001",
		Source:           "http://ollama.corp.local:11434/api/tags",
		Surface:          "ollama",
		ObservedAt:       fixedTime,
		DeploymentScope:  cfg.Scope,
		VantageKey:       cfg.VantageKey,
		Coverage:         graph.CoverageComplete,
	}

	ep, err := graph.ParseEndpoint("http://ollama.corp.local:11434", "")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	srvID, err := graph.NewServiceIdentity(cfg.Scope, graph.OllamaInstance, ep)
	if err != nil {
		t.Fatalf("NewServiceIdentity: %v", err)
	}
	srvNode, err := graph.NewNode(srvID, obs)
	if err != nil {
		t.Fatalf("NewNode service: %v", err)
	}

	modelID, err := graph.NewResourceIdentity(cfg.Scope, graph.AIModel, srvID, "llama3:latest")
	if err != nil {
		t.Fatalf("NewResourceIdentity model: %v", err)
	}
	modelNode, err := graph.NewNode(modelID, obs)
	if err != nil {
		t.Fatalf("NewNode model: %v", err)
	}

	// Anonymous access is a flat property set on the service, never an edge.
	accessEvidence := graph.AccessEvidence{
		Observation:   obs,
		CheckID:       "ollama_tags_check",
		Operation:     "ollama_tags",
		TargetID:      srvID.ID(),
		Outcome:       graph.OutcomeSuccess,
		Reason:        "tags listed anonymously",
		Anonymous:     true,
		OperationKind: graph.EnumerationOperation,
	}
	srvProps := map[string]any{
		"name":             "OLLAMA · ollama.corp.local:11434",
		"endpoint_host":    "ollama.corp.local",
		"endpoint_port":    11434,
		"product":          "Ollama",
		"vendor":           "Ollama",
		"software_version": "0.3.12",
		"vantage_key":      cfg.VantageKey,
	}
	for k, v := range graph.SummarizeAccess([]graph.AccessEvidence{accessEvidence}).Properties() {
		srvProps[k] = v
	}
	srvItem, err := emitter.NewNodeItem(srvNode, srvProps)
	if err != nil {
		t.Fatal(err)
	}

	modelItem, err := emitter.NewNodeItem(modelNode, map[string]any{
		"name":   "LLAMA3:LATEST",
		"digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 4. Build edges
	// Topology edge: Service -> Model (owned edge)
	modelEdge, err := graph.NewTopologyEdge(graph.ProvidesModel, srvID.Reference(), modelID.Reference(), obs)
	if err != nil {
		t.Fatalf("NewTopologyEdge: %v", err)
	}

	// Correlation edge: Service -> Computer (linking edge!)
	linkingEdge, err := corrResult.ObservedAt(srvID, obs)
	if err != nil {
		t.Fatalf("corrResult.ObservedAt: %v", err)
	}

	nodes := []emitter.NodeItem{srvItem, modelItem}
	edges := []graph.Edge{modelEdge, linkingEdge}

	// 5. Build evidence records
	corrRec, err := evidence.NewCorrelationRecord(corrResult.Evidence(), obs)
	if err != nil {
		t.Fatal(err)
	}
	checkRec, err := evidence.NewAccessEvidenceRecord(accessEvidence, map[string]any{
		"http_status": 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	fpRec, err := evidence.NewFingerprintRecord(evidence.FingerprintInput{
		Observation:     obs,
		TargetID:        srvID.ID(),
		Product:         "Ollama",
		Vendor:          "Ollama",
		SoftwareVersion: "0.3.12",
		Method:          "api_version",
		Confidence:      "exact",
	})
	if err != nil {
		t.Fatal(err)
	}
	records := []evidence.Record{corrRec, checkRec, fpRec}

	// 6. Emit scan artifacts
	artifacts, err := emitter.EmitScan(tempDir, "llmhound-golden", nodes, edges, records)
	if err != nil {
		t.Fatalf("EmitScan: %v", err)
	}

	// Verify generated files exist
	baseBytes, err := os.ReadFile(artifacts.BasePayloadPath)
	if err != nil {
		t.Fatalf("read base payload: %v", err)
	}
	linkingBytes, err := os.ReadFile(artifacts.LinkingPayloadPath)
	if err != nil {
		t.Fatalf("read linking payload: %v", err)
	}
	evidenceBytes, err := os.ReadFile(artifacts.EvidenceSidecarPath)
	if err != nil {
		t.Fatalf("read evidence sidecar: %v", err)
	}

	goldenDir := filepath.Join("testdata", "golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(goldenDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(goldenDir, "golden-base.json"), baseBytes, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(goldenDir, "golden-linking.json"), linkingBytes, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(goldenDir, "golden.evidence.jsonl"), evidenceBytes, 0644); err != nil {
			t.Fatal(err)
		}
		t.Log("Updated golden files")
		return
	}

	expectedBase, err := os.ReadFile(filepath.Join(goldenDir, "golden-base.json"))
	if err != nil {
		t.Fatalf("missing golden base file: %v", err)
	}
	if string(baseBytes) != string(expectedBase) {
		t.Errorf("base payload differs from golden file")
	}

	expectedLinking, err := os.ReadFile(filepath.Join(goldenDir, "golden-linking.json"))
	if err != nil {
		t.Fatalf("missing golden linking file: %v", err)
	}
	if string(linkingBytes) != string(expectedLinking) {
		t.Errorf("linking payload differs from golden file")
	}

	expectedEvidence, err := os.ReadFile(filepath.Join(goldenDir, "golden.evidence.jsonl"))
	if err != nil {
		t.Fatalf("missing golden evidence file: %v", err)
	}
	if string(evidenceBytes) != string(expectedEvidence) {
		t.Errorf("evidence sidecar differs from golden file")
	}
}
