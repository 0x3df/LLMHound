package emitter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

// BuildBasePayload builds the source-owned OpenGraph payload with metadata.source_kind: "LLMHound".
// It enforces M0 Q5 safety: NO edges touching native Computers may be included in this payload,
// to prevent BloodHound CE from applying the source_kind label to AD Computers and deleting them
// on source cleanup.
func BuildBasePayload(nodes []NodeItem, edges []graph.Edge) (Payload, error) {
	nodePayloads := make([]NodePayload, 0, len(nodes))
	for _, item := range nodes {
		id := strings.ToUpper(item.Node.Identity().ID())
		if id == "" {
			return Payload{}, errors.New("node requires a non-empty ID")
		}
		if strings.Contains(id, ":") {
			return Payload{}, fmt.Errorf("node id %q cannot contain colons", id)
		}

		rawKinds := item.Node.Kinds()
		if len(rawKinds) == 0 || len(rawKinds) > 3 {
			return Payload{}, fmt.Errorf("node %s must have 1 to 3 kinds, got %d", id, len(rawKinds))
		}

		kinds := make([]string, 0, len(rawKinds))
		for _, k := range rawKinds {
			emitted, err := k.Emitted()
			if err != nil {
				return Payload{}, fmt.Errorf("node %s kind %s: %w", id, k, err)
			}
			if tagPrefixPattern.MatchString(emitted) {
				return Payload{}, fmt.Errorf("node %s kind %q uses reserved tag_ prefix", id, emitted)
			}
			kinds = append(kinds, emitted)
		}

		nodePayloads = append(nodePayloads, NodePayload{
			ID:         id,
			Kinds:      kinds,
			Properties: item.Properties,
		})
	}

	edgePayloads := make([]EdgePayload, 0, len(edges))
	for _, edge := range edges {
		if edge.TouchesNative() {
			return Payload{}, errors.New("base payload cannot contain edges that touch native Computer nodes (M0 Q5 source-isolation requirement; use linking payload)")
		}
		ep, err := formatEdge(edge)
		if err != nil {
			return Payload{}, err
		}
		edgePayloads = append(edgePayloads, ep)
	}

	return Payload{
		Metadata: &Metadata{SourceKind: graph.SourceKind},
		Graph: GraphPayload{
			Nodes: nodePayloads,
			Edges: edgePayloads,
		},
	}, nil
}

// BuildLinkingPayload builds the sourceless linking payload for native Computer edges.
// It enforces M0 Q5 safety: metadata.source_kind MUST be omitted, and only edges touching
// native nodes are included.
func BuildLinkingPayload(edges []graph.Edge) (Payload, error) {
	edgePayloads := make([]EdgePayload, 0, len(edges))
	for _, edge := range edges {
		if !edge.TouchesNative() {
			return Payload{}, errors.New("linking payload can only contain edges that touch native Computer nodes")
		}
		ep, err := formatEdge(edge)
		if err != nil {
			return Payload{}, err
		}
		edgePayloads = append(edgePayloads, ep)
	}

	return Payload{
		Metadata: nil, // Must NOT declare source_kind
		Graph: GraphPayload{
			Nodes: []NodePayload{},
			Edges: edgePayloads,
		},
	}, nil
}

// Emit writes an OpenGraph Payload formatted as indented JSON.
func Emit(w io.Writer, p Payload) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(p)
}

// EmitBasePayload builds and writes the base payload to w.
func EmitBasePayload(w io.Writer, nodes []NodeItem, edges []graph.Edge) error {
	p, err := BuildBasePayload(nodes, edges)
	if err != nil {
		return err
	}
	return Emit(w, p)
}

// EmitLinkingPayload builds and writes the linking payload to w.
func EmitLinkingPayload(w io.Writer, edges []graph.Edge) error {
	p, err := BuildLinkingPayload(edges)
	if err != nil {
		return err
	}
	return Emit(w, p)
}

// EmitSplit automatically splits edges into owned and native-linking sets and writes
// the base payload to baseWriter and linking payload to linkingWriter.
func EmitSplit(baseWriter, linkingWriter io.Writer, nodes []NodeItem, edges []graph.Edge) error {
	var ownedEdges, linkingEdges []graph.Edge
	for _, e := range edges {
		if e.TouchesNative() {
			linkingEdges = append(linkingEdges, e)
		} else {
			ownedEdges = append(ownedEdges, e)
		}
	}

	if err := EmitBasePayload(baseWriter, nodes, ownedEdges); err != nil {
		return fmt.Errorf("emit base payload: %w", err)
	}

	if len(linkingEdges) > 0 {
		if err := EmitLinkingPayload(linkingWriter, linkingEdges); err != nil {
			return fmt.Errorf("emit linking payload: %w", err)
		}
	}
	return nil
}

// ScanArtifacts records output files emitted during a scan.
type ScanArtifacts struct {
	BasePayloadPath     string
	LinkingPayloadPath  string
	EvidenceSidecarPath string
}

// EmitScan emits all scan artifacts:
// - Base payload JSON: <dir>/<prefix>.json (or <dir>/<prefix>-base.json if linking edges exist)
// - Linking payload JSON: <dir>/<prefix>-linking.json (if linking edges exist)
// - Evidence sidecar JSONL: <dir>/<prefix>.evidence.jsonl
func EmitScan(dir, prefix string, nodes []NodeItem, edges []graph.Edge, records []evidence.Record) (ScanArtifacts, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return ScanArtifacts{}, fmt.Errorf("create output directory: %w", err)
	}

	var ownedEdges, linkingEdges []graph.Edge
	for _, e := range edges {
		if e.TouchesNative() {
			linkingEdges = append(linkingEdges, e)
		} else {
			ownedEdges = append(ownedEdges, e)
		}
	}

	artifacts := ScanArtifacts{}

	// Write base payload
	baseFilename := prefix + ".json"
	if len(linkingEdges) > 0 {
		baseFilename = prefix + "-base.json"
	}
	artifacts.BasePayloadPath = filepath.Join(dir, baseFilename)
	bf, err := os.OpenFile(artifacts.BasePayloadPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return ScanArtifacts{}, fmt.Errorf("create base payload file: %w", err)
	}
	defer bf.Close()

	if err := EmitBasePayload(bf, nodes, ownedEdges); err != nil {
		return ScanArtifacts{}, fmt.Errorf("write base payload: %w", err)
	}

	// Write linking payload if there are linking edges
	if len(linkingEdges) > 0 {
		artifacts.LinkingPayloadPath = filepath.Join(dir, prefix+"-linking.json")
		lf, err := os.OpenFile(artifacts.LinkingPayloadPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return ScanArtifacts{}, fmt.Errorf("create linking payload file: %w", err)
		}
		defer lf.Close()

		if err := EmitLinkingPayload(lf, linkingEdges); err != nil {
			return ScanArtifacts{}, fmt.Errorf("write linking payload: %w", err)
		}
	}

	// Write evidence sidecar
	artifacts.EvidenceSidecarPath = filepath.Join(dir, prefix+".evidence.jsonl")
	ef, err := os.OpenFile(artifacts.EvidenceSidecarPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return ScanArtifacts{}, fmt.Errorf("create evidence sidecar file: %w", err)
	}
	defer ef.Close()

	writer := evidence.NewWriter(ef)
	if err := writer.WriteAll(records); err != nil {
		return ScanArtifacts{}, fmt.Errorf("write evidence sidecar: %w", err)
	}

	return artifacts, nil
}
