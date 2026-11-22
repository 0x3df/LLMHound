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

	"github.com/0x3df/LLMHound/internal/securefile"
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
	return emitJSON(w, p, true)
}

// EmitCompact writes an OpenGraph Payload as compact (non-indented) JSON,
// reducing large payload sizes by ~40%.
func EmitCompact(w io.Writer, p Payload) error {
	return emitJSON(w, p, false)
}

func emitJSON(w io.Writer, p Payload, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	enc.SetEscapeHTML(false)
	return enc.Encode(p)
}

// EmitBasePayload builds and writes the base payload to w.
func EmitBasePayload(w io.Writer, nodes []NodeItem, edges []graph.Edge) error {
	return emitBasePayload(w, nodes, edges, true)
}

func emitBasePayload(w io.Writer, nodes []NodeItem, edges []graph.Edge, indent bool) error {
	p, err := BuildBasePayload(nodes, edges)
	if err != nil {
		return err
	}
	return emitJSON(w, p, indent)
}

// EmitLinkingPayload builds and writes the linking payload to w.
func EmitLinkingPayload(w io.Writer, edges []graph.Edge) error {
	return emitLinkingPayload(w, edges, true)
}

func emitLinkingPayload(w io.Writer, edges []graph.Edge, indent bool) error {
	p, err := BuildLinkingPayload(edges)
	if err != nil {
		return err
	}
	return emitJSON(w, p, indent)
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

// EmitScanOptions controls formatting during EmitScanWithOptions.
type EmitScanOptions struct {
	CompactJSON bool
}

// EmitScan emits all scan artifacts using indented JSON formatting.
func EmitScan(dir, prefix string, nodes []NodeItem, edges []graph.Edge, records []evidence.Record) (ScanArtifacts, error) {
	return EmitScanWithOptions(dir, prefix, nodes, edges, records, EmitScanOptions{})
}

// EmitScanWithOptions emits all scan artifacts with configurable formatting:
// - Base payload JSON: <dir>/<prefix>.json (or <dir>/<prefix>-base.json if linking edges exist)
// - Linking payload JSON: <dir>/<prefix>-linking.json (if linking edges exist)
// - Evidence sidecar JSONL: <dir>/<prefix>.evidence.jsonl
func EmitScanWithOptions(dir, prefix string, nodes []NodeItem, edges []graph.Edge, records []evidence.Record, opts EmitScanOptions) (ScanArtifacts, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return ScanArtifacts{}, fmt.Errorf("create output directory: %w", err)
	}

	indent := !opts.CompactJSON

	var ownedEdges, linkingEdges []graph.Edge
	for _, e := range edges {
		if e.TouchesNative() {
			linkingEdges = append(linkingEdges, e)
		} else {
			ownedEdges = append(ownedEdges, e)
		}
	}

	artifacts := ScanArtifacts{}
	baseName := prefix + ".json"
	if len(linkingEdges) > 0 {
		baseName = prefix + "-base.json"
	}
	artifacts.BasePayloadPath = filepath.Join(dir, baseName)
	if len(linkingEdges) > 0 {
		artifacts.LinkingPayloadPath = filepath.Join(dir, prefix+"-linking.json")
	}
	artifacts.EvidenceSidecarPath = filepath.Join(dir, prefix+".evidence.jsonl")

	all := []string{
		filepath.Join(dir, prefix+".json"),
		filepath.Join(dir, prefix+"-base.json"),
		filepath.Join(dir, prefix+"-linking.json"),
		artifacts.EvidenceSidecarPath,
	}
	for _, p := range all {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ScanArtifacts{}, fmt.Errorf("remove stale artifact: %w", err)
		}
	}

	fail := func(err error) (ScanArtifacts, error) {
		for _, p := range all {
			_ = os.Remove(p)
		}
		return ScanArtifacts{}, err
	}

	if err := writeFile(artifacts.BasePayloadPath, func(w io.Writer) error {
		return emitBasePayload(w, nodes, ownedEdges, indent)
	}); err != nil {
		return fail(fmt.Errorf("write base payload: %w", err))
	}

	if len(linkingEdges) > 0 {
		if err := writeFile(artifacts.LinkingPayloadPath, func(w io.Writer) error {
			return emitLinkingPayload(w, linkingEdges, indent)
		}); err != nil {
			return fail(fmt.Errorf("write linking payload: %w", err))
		}
	}

	if err := writeFile(artifacts.EvidenceSidecarPath, func(w io.Writer) error {
		return evidence.NewWriter(w).WriteAll(records)
	}); err != nil {
		return fail(fmt.Errorf("write evidence sidecar: %w", err))
	}

	return artifacts, nil
}

func writeFile(path string, write func(io.Writer) error) (err error) {
	f, err := securefile.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return write(f)
}
