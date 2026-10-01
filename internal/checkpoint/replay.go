package checkpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

// TruncatedEntryError is returned when the last line in a journal is incomplete (e.g. from a process kill).
type TruncatedEntryError struct {
	Line int
	Err  error
}

func (e *TruncatedEntryError) Error() string {
	return fmt.Sprintf("truncated journal entry at line %d: %v", e.Line, e.Err)
}

func (e *TruncatedEntryError) Unwrap() error {
	return e.Err
}

// State represents the accumulated state replayed from a checkpoint journal.
type State struct {
	header   Header
	vantage  graph.Identity
	targets  map[string]TargetRecord
	results  []Result
	nodes    []emitter.NodeItem
	edges    []graph.Edge
	evidence []evidence.Record

	nodeMap     map[string]int
	edgeMap     map[string]int
	evidenceMap map[string]int
}

func newState(header Header, vantage graph.Identity) *State {
	return &State{
		header:      header,
		vantage:     vantage,
		targets:     make(map[string]TargetRecord),
		nodeMap:     make(map[string]int),
		edgeMap:     make(map[string]int),
		evidenceMap: make(map[string]int),
	}
}

func (s *State) Header() Header {
	return s.header
}

func (s *State) Targets() map[string]TargetRecord {
	cp := make(map[string]TargetRecord, len(s.targets))
	for k, v := range s.targets {
		cp[k] = v
	}
	return cp
}

// CompletedTargets lists targets that have at least one recorded surface and
// whose every recorded surface is fully completed. Surface-less records never count.
// The journal records what happened and cannot attest surfaces that were never
// recorded, so this is not proof a target was fully scanned: a resume must derive
// the expected surfaces from config/targets and check IsCompleted per surface
// rather than skip targets based on this list.
func (s *State) CompletedTargets() []string {
	complete := make(map[string]bool)
	for _, tr := range s.targets {
		if tr.Surface == "" {
			continue
		}
		done, seen := complete[tr.Target]
		complete[tr.Target] = (done || !seen) && surfaceCompleted(tr)
	}
	var out []string
	for target, done := range complete {
		if done {
			out = append(out, target)
		}
	}
	sort.Strings(out)
	return out
}

// IsCompleted reports whether the given surface of target was recorded as fully covered.
// A surface with no record is never completed; the journal cannot attest surfaces it
// never saw, so resume must ask this per expected surface.
func (s *State) IsCompleted(target, surface string) bool {
	if surface == "" {
		return false
	}
	tr, ok := s.targets[targetKey(target, surface)]
	return ok && surfaceCompleted(tr)
}

func surfaceCompleted(tr TargetRecord) bool {
	if tr.Status != TargetStatusCompleted {
		return false
	}
	return tr.Observation != nil && tr.Observation.Coverage == string(graph.CoverageComplete)
}

func (s *State) Results() []Result {
	return append([]Result(nil), s.results...)
}

func (s *State) Nodes() []emitter.NodeItem {
	return append([]emitter.NodeItem(nil), s.nodes...)
}

func (s *State) Edges() []graph.Edge {
	return append([]graph.Edge(nil), s.edges...)
}

func (s *State) Evidence() []evidence.Record {
	return append([]evidence.Record(nil), s.evidence...)
}

func targetKey(target, surface string) string {
	if surface == "" {
		return target
	}
	return target + "|" + surface
}

func edgeKey(edge graph.Edge) string {
	return string(edge.Kind()) + ":" + edge.Start().ID() + ":" + edge.End().ID()
}

func (s *State) addNode(item emitter.NodeItem) {
	id := item.Node.Identity().ID()
	if idx, exists := s.nodeMap[id]; exists {
		// Existing node: merge additional properties if any
		for k, v := range item.Properties {
			if _, ok := s.nodes[idx].Properties[k]; !ok {
				s.nodes[idx].Properties[k] = v
			}
		}
		return
	}
	s.nodeMap[id] = len(s.nodes)
	s.nodes = append(s.nodes, item)
}

func (s *State) addEdge(edge graph.Edge) {
	k := edgeKey(edge)
	if _, exists := s.edgeMap[k]; exists {
		return
	}
	s.edgeMap[k] = len(s.edges)
	s.edges = append(s.edges, edge)
}

func (s *State) addEvidence(ev evidence.Record) {
	if _, exists := s.evidenceMap[ev.EvidenceID]; exists {
		return
	}
	s.evidenceMap[ev.EvidenceID] = len(s.evidence)
	s.evidence = append(s.evidence, ev)
}

func (s *State) addResult(res Result) {
	s.results = append(s.results, res)

	// Update target status based on result coverage
	key := targetKey(res.Target, res.Surface)
	status := statusForCoverage(res.Observation.Coverage)

	obsRec := toObservationRecord(res.Observation, DefaultMaxEntryBytes)
	s.targets[key] = TargetRecord{
		Target:      res.Target,
		Surface:     res.Surface,
		Status:      status,
		Observation: &obsRec,
		Error:       res.Error,
		Details:     res.Details,
	}

	for _, n := range res.Nodes {
		s.addNode(n)
	}
	for _, e := range res.Edges {
		s.addEdge(e)
	}
	for _, ev := range res.Evidence {
		s.addEvidence(ev)
	}
}

func (s *State) addTargetRecord(tr TargetRecord) {
	key := targetKey(tr.Target, tr.Surface)
	s.targets[key] = tr
}

// ReplayHandler defines callback hooks for streaming journal replay.
type ReplayHandler struct {
	OnHeader   func(Header) error
	OnTarget   func(TargetRecord) error
	OnResult   func(Result) error
	OnNode     func(emitter.NodeItem) error
	OnEdge     func(graph.Edge) error
	OnEvidence func(evidence.Record) error
}

// ReplayStream reads entries from r and invokes the corresponding hook in handler.
func ReplayStream(r io.Reader, handler ReplayHandler, opts ...Option) error {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	reader := bufio.NewReader(r)
	lineNum := 0
	var vantage graph.Identity
	var header Header
	headerSeen := false

	for {
		lineNum++
		lineBytes, err := readLine(reader)
		if err != nil && len(lineBytes) == 0 {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read line %d: %w", lineNum, err)
		}

		// Skip empty lines (blank lines between records)
		trimmed := bytes.TrimSpace(lineBytes)
		if len(trimmed) == 0 {
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}

		if len(trimmed) > o.maxEntryBytes {
			return fmt.Errorf("line %d: %w", lineNum, ErrEntryTooLarge)
		}

		var entry JournalEntry
		if decErr := json.Unmarshal(trimmed, &entry); decErr != nil {
			isEOF := errors.Is(err, io.EOF)
			if !isEOF {
				_, peekErr := reader.Peek(1)
				if errors.Is(peekErr, io.EOF) {
					isEOF = true
				}
			}
			if isEOF && (errors.Is(decErr, io.ErrUnexpectedEOF) || strings.Contains(decErr.Error(), "unexpected end of JSON input")) {
				return &TruncatedEntryError{Line: lineNum, Err: decErr}
			}
			return fmt.Errorf("line %d: invalid JSON entry: %w", lineNum, decErr)
		}

		if !headerSeen {
			if entry.EntryType != EntryHeader || entry.Header == nil {
				return fmt.Errorf("line %d: first entry must be %q, got %q", lineNum, EntryHeader, entry.EntryType)
			}
			if err := entry.Header.Validate(); err != nil {
				return fmt.Errorf("line %d: invalid header: %w", lineNum, err)
			}
			header = *entry.Header
			v, err := graph.NewVantageIdentity(header.DeploymentScope, header.VantageKey)
			if err != nil {
				return fmt.Errorf("line %d: invalid vantage: %w", lineNum, err)
			}
			vantage = v
			headerSeen = true

			if handler.OnHeader != nil {
				if err := handler.OnHeader(header); err != nil {
					return fmt.Errorf("handle header: %w", err)
				}
			}
			continue
		}

		switch entry.EntryType {
		case EntryResult:
			if entry.Result == nil {
				return fmt.Errorf("line %d: result entry missing body", lineNum)
			}
			res, err := fromResultRecord(*entry.Result, vantage)
			if err != nil {
				return fmt.Errorf("line %d: restore result: %w", lineNum, err)
			}
			if handler.OnResult != nil {
				if err := handler.OnResult(res); err != nil {
					return fmt.Errorf("handle result: %w", err)
				}
			}

		case EntryTarget:
			if entry.Target == nil {
				return fmt.Errorf("line %d: target entry missing body", lineNum)
			}
			if err := entry.Target.Validate(); err != nil {
				return fmt.Errorf("line %d: invalid target record: %w", lineNum, err)
			}
			if err := entry.Target.validateObservation(vantage); err != nil {
				return fmt.Errorf("line %d: invalid target record: %w", lineNum, err)
			}
			if handler.OnTarget != nil {
				if err := handler.OnTarget(*entry.Target); err != nil {
					return fmt.Errorf("handle target: %w", err)
				}
			}

		case EntryNode:
			if entry.Node == nil {
				return fmt.Errorf("line %d: node entry missing body", lineNum)
			}
			node, err := fromNodeRecord(*entry.Node, vantage)
			if err != nil {
				return fmt.Errorf("line %d: restore node: %w", lineNum, err)
			}
			if handler.OnNode != nil {
				if err := handler.OnNode(node); err != nil {
					return fmt.Errorf("handle node: %w", err)
				}
			}

		case EntryEdge:
			if entry.Edge == nil {
				return fmt.Errorf("line %d: edge entry missing body", lineNum)
			}
			edge, err := fromEdgeRecord(*entry.Edge, vantage)
			if err != nil {
				return fmt.Errorf("line %d: restore edge: %w", lineNum, err)
			}
			if handler.OnEdge != nil {
				if err := handler.OnEdge(edge); err != nil {
					return fmt.Errorf("handle edge: %w", err)
				}
			}

		case EntryEvidence:
			if entry.Evidence == nil {
				return fmt.Errorf("line %d: evidence entry missing body", lineNum)
			}
			if err := entry.Evidence.Validate(); err != nil {
				return fmt.Errorf("line %d: invalid evidence: %w", lineNum, err)
			}
			if handler.OnEvidence != nil {
				if err := handler.OnEvidence(*entry.Evidence); err != nil {
					return fmt.Errorf("handle evidence: %w", err)
				}
			}

		default:
			return fmt.Errorf("line %d: unknown entry_type %q", lineNum, entry.EntryType)
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	if !headerSeen {
		return errors.New("empty journal: no header entry found")
	}

	return nil
}

// Replay reads the entire journal from r into an accumulated State.
// If the journal terminates with a truncated entry at EOF, Replay returns the
// accumulated State along with a *TruncatedEntryError.
func Replay(r io.Reader, opts ...Option) (*State, error) {
	var state *State

	handler := ReplayHandler{
		OnHeader: func(h Header) error {
			v, err := graph.NewVantageIdentity(h.DeploymentScope, h.VantageKey)
			if err != nil {
				return err
			}
			state = newState(h, v)
			return nil
		},
		OnResult: func(res Result) error {
			if state != nil {
				state.addResult(res)
			}
			return nil
		},
		OnTarget: func(tr TargetRecord) error {
			if state != nil {
				state.addTargetRecord(tr)
			}
			return nil
		},
		OnNode: func(item emitter.NodeItem) error {
			if state != nil {
				state.addNode(item)
			}
			return nil
		},
		OnEdge: func(edge graph.Edge) error {
			if state != nil {
				state.addEdge(edge)
			}
			return nil
		},
		OnEvidence: func(ev evidence.Record) error {
			if state != nil {
				state.addEvidence(ev)
			}
			return nil
		},
	}

	err := ReplayStream(r, handler, opts...)
	if err != nil {
		var truncErr *TruncatedEntryError
		if errors.As(err, &truncErr) && state != nil {
			return state, err
		}
		return state, err
	}

	return state, nil
}

// ReplayFile replays an entire journal file into State.
func ReplayFile(path string, opts ...Option) (*State, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open journal file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return Replay(f, opts...)
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if len(chunk) > 0 {
			line = append(line, chunk...)
		}
		if err != nil {
			return line, err
		}
		if !isPrefix {
			break
		}
	}
	return line, nil
}
