package checkpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/0x3df/LLMHound/internal/emitter"
	"github.com/0x3df/LLMHound/internal/evidence"
	"github.com/0x3df/LLMHound/internal/graph"
)

var (
	ErrEntryTooLarge = errors.New("journal entry exceeds maximum allowed size")
	ErrClosedJournal = errors.New("cannot write to closed journal")
)

// Journal is the interface collectors consume to record scan results.
type Journal interface {
	// Header returns the journal's metadata header.
	Header() Header

	// RecordResult records a completed or partial collector result for a target and surface.
	RecordResult(result Result) error

	// RecordTarget records target-level progress (started, completed, failed, skipped).
	RecordTarget(record TargetRecord) error

	// RecordNode records an individual OpenGraph node with its properties.
	RecordNode(node emitter.NodeItem) error

	// RecordEdge records an individual graph edge.
	RecordEdge(edge graph.Edge) error

	// RecordEvidence records an individual evidence sidecar record.
	RecordEvidence(record evidence.Record) error

	// Flush ensures all buffered data is written to the underlying storage.
	Flush() error

	// Close flushes and closes the journal.
	Close() error
}

type options struct {
	maxStringSize int
	maxEntryBytes int
}

func defaultOptions() options {
	return options{
		maxStringSize: DefaultMaxStringSize,
		maxEntryBytes: DefaultMaxEntryBytes,
	}
}

// Option configures journal behavior.
type Option func(*options)

// WithMaxStringSize sets the maximum length for bounded string fields before truncation.
func WithMaxStringSize(size int) Option {
	return func(o *options) {
		if size > 0 {
			o.maxStringSize = size
		}
	}
}

// WithMaxEntryBytes sets the maximum byte size of a single serialized journal entry line.
func WithMaxEntryBytes(bytes int) Option {
	return func(o *options) {
		if bytes > 0 {
			o.maxEntryBytes = bytes
		}
	}
}

// WriterJournal implements Journal over any io.Writer.
type WriterJournal struct {
	mu      sync.Mutex
	w       io.Writer
	header  Header
	vantage vantageContext
	opts    options
	closed  bool
	failed  error
}

// NewWriter creates a Journal writing to w and emits the Header entry.
func NewWriter(w io.Writer, header Header, opts ...Option) (*WriterJournal, error) {
	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	j := &WriterJournal{
		w:       w,
		header:  header,
		vantage: vantageOf(header),
		opts:    o,
	}

	// Write header as the first entry
	headerEntry := JournalEntry{
		EntryType: EntryHeader,
		Header:    &header,
	}
	if err := j.writeEntryLocked(headerEntry); err != nil {
		return nil, fmt.Errorf("write header entry: %w", err)
	}

	return j, nil
}

func (j *WriterJournal) Header() Header {
	return j.header
}

// RecordResult records a completed or partial collection result.
func (j *WriterJournal) RecordResult(res Result) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return ErrClosedJournal
	}

	if err := j.validateResultLocked(res); err != nil {
		return fmt.Errorf("invalid result: %w", err)
	}

	rec := toResultRecord(res, j.opts.maxStringSize)
	return j.writeEntryLocked(JournalEntry{
		EntryType: EntryResult,
		Result:    &rec,
	})
}

// RecordTarget records target-level progress.
func (j *WriterJournal) RecordTarget(target TargetRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return ErrClosedJournal
	}

	if err := target.Validate(); err != nil {
		return fmt.Errorf("invalid target record: %w", err)
	}
	if target.Observation != nil {
		if err := target.validateObservation(j.vantage); err != nil {
			return fmt.Errorf("invalid target record: %w", err)
		}
		obs := *target.Observation
		obs.Source = boundString(SanitizeURL(obs.Source), j.opts.maxStringSize)
		obs.CoverageReason = sanitizeText(obs.CoverageReason, j.opts.maxStringSize)
		target.Observation = &obs
	}
	target.Target = boundString(SanitizeTarget(target.Target), j.opts.maxStringSize)
	target.Error = sanitizeText(target.Error, j.opts.maxStringSize)
	target.Details = SanitizeMap(target.Details, j.opts.maxStringSize)

	return j.writeEntryLocked(JournalEntry{
		EntryType: EntryTarget,
		Target:    &target,
	})
}

// RecordNode records an individual OpenGraph node with its properties.
func (j *WriterJournal) RecordNode(item emitter.NodeItem) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return ErrClosedJournal
	}

	if err := j.validateNodeLocked(item); err != nil {
		return err
	}

	rec := toNodeRecord(item, j.opts.maxStringSize)
	return j.writeEntryLocked(JournalEntry{
		EntryType: EntryNode,
		Node:      &rec,
	})
}

// RecordEdge records an individual graph edge.
func (j *WriterJournal) RecordEdge(edge graph.Edge) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return ErrClosedJournal
	}

	if err := j.validateEdgeLocked(edge); err != nil {
		return err
	}

	rec := toEdgeRecord(edge, j.opts.maxStringSize)
	return j.writeEntryLocked(JournalEntry{
		EntryType: EntryEdge,
		Edge:      &rec,
	})
}

// RecordEvidence records an individual evidence sidecar record.
func (j *WriterJournal) RecordEvidence(record evidence.Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return ErrClosedJournal
	}

	if err := j.validateEvidenceLocked(record); err != nil {
		return err
	}

	record = sanitizeEvidence(record, j.opts.maxStringSize)

	return j.writeEntryLocked(JournalEntry{
		EntryType: EntryEvidence,
		Evidence:  &record,
	})
}

func (j *WriterJournal) validateObservationLocked(obs graph.Observation) error {
	if err := obs.Validate(j.header.DeploymentScope); err != nil {
		return err
	}
	if obs.VantageKey != j.vantage.key {
		return errors.New("observation vantage does not match journal vantage")
	}
	return nil
}

func (j *WriterJournal) validateNodeLocked(item emitter.NodeItem) error {
	id := item.Node.Identity()
	if id.ID() == "" {
		return errors.New("node requires identity")
	}
	if id.Scope() != j.header.DeploymentScope {
		return errors.New("node scope does not match journal deployment scope")
	}
	if err := j.validateObservationLocked(item.Node.Observation()); err != nil {
		return fmt.Errorf("node observation: %w", err)
	}
	return nil
}

func (j *WriterJournal) validateEdgeLocked(edge graph.Edge) error {
	if edge.Kind() == "" {
		return errors.New("edge requires kind")
	}
	for _, ref := range []graph.Reference{edge.Start(), edge.End()} {
		if !ref.IsNative() && ref.Scope() != j.header.DeploymentScope {
			return errors.New("edge endpoint scope does not match journal deployment scope")
		}
	}
	if err := j.validateObservationLocked(edge.Observation()); err != nil {
		return fmt.Errorf("edge observation: %w", err)
	}
	return nil
}

func (j *WriterJournal) validateEvidenceLocked(rec evidence.Record) error {
	if err := rec.Validate(); err != nil {
		return fmt.Errorf("invalid evidence record: %w", err)
	}
	if rec.DeploymentScope != j.header.DeploymentScope {
		return errors.New("evidence record scope does not match journal deployment scope")
	}
	if rec.VantageKey != "" && rec.VantageKey != j.vantage.key {
		return errors.New("evidence record vantage does not match journal vantage")
	}
	return nil
}

func (j *WriterJournal) validateResultLocked(res Result) error {
	if err := res.Validate(j.header.DeploymentScope); err != nil {
		return err
	}
	if err := j.validateObservationLocked(res.Observation); err != nil {
		return fmt.Errorf("result observation: %w", err)
	}
	for i, n := range res.Nodes {
		if err := j.validateNodeLocked(n); err != nil {
			return fmt.Errorf("result node %d: %w", i, err)
		}
	}
	for i, e := range res.Edges {
		if err := j.validateEdgeLocked(e); err != nil {
			return fmt.Errorf("result edge %d: %w", i, err)
		}
	}
	for i, ev := range res.Evidence {
		if err := j.validateEvidenceLocked(ev); err != nil {
			return fmt.Errorf("result evidence %d: %w", i, err)
		}
	}
	return nil
}

func (j *WriterJournal) writeEntryLocked(entry JournalEntry) error {
	if j.failed != nil {
		return j.failed
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}

	if len(data) > j.opts.maxEntryBytes {
		return ErrEntryTooLarge
	}

	data = append(data, '\n')
	if _, err = j.w.Write(data); err != nil {
		j.failed = fmt.Errorf("journal write failed, journal is unusable: %w", err)
		return err
	}
	return nil
}

func (j *WriterJournal) Flush() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if flusher, ok := j.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

func (j *WriterJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return nil
	}
	j.closed = true

	if flusher, ok := j.w.(interface{ Flush() error }); ok {
		_ = flusher.Flush()
	}
	if closer, ok := j.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// FileJournal wraps WriterJournal over an os.File.
type FileJournal struct {
	*WriterJournal
	file *os.File
	path string
}

func (f *FileJournal) Path() string {
	return f.path
}

func (f *FileJournal) Flush() error {
	if err := f.WriterJournal.Flush(); err != nil {
		return err
	}
	return f.file.Sync()
}

func (f *FileJournal) Close() error {
	flushErr := f.Flush()
	closeErr := f.WriterJournal.Close()
	return errors.Join(flushErr, closeErr)
}

// CreateFile creates a new journal file at path, writing header as the first entry.
func CreateFile(path string, header Header, opts ...Option) (*FileJournal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create journal directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open journal file: %w", err)
	}

	wj, err := NewWriter(f, header, opts...)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}

	return &FileJournal{
		WriterJournal: wj,
		file:          f,
		path:          path,
	}, nil
}

// OpenFile opens an existing journal file to append to it, validating its header.
func OpenFile(path string, opts ...Option) (*FileJournal, error) {
	fRead, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open journal file for inspection: %w", err)
	}

	scanner := bufio.NewScanner(fRead)
	if !scanner.Scan() {
		_ = fRead.Close()
		return nil, errors.New("empty journal file, missing header")
	}

	var headerEntry JournalEntry
	if err := json.Unmarshal(scanner.Bytes(), &headerEntry); err != nil {
		_ = fRead.Close()
		return nil, fmt.Errorf("corrupted journal header: %w", err)
	}
	_ = fRead.Close()

	if headerEntry.EntryType != EntryHeader || headerEntry.Header == nil {
		return nil, errors.New("first entry in journal is not a header")
	}
	if err := headerEntry.Header.Validate(); err != nil {
		return nil, fmt.Errorf("invalid journal header: %w", err)
	}

	fAppend, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open journal file for appending: %w", err)
	}
	if err := repairTornTail(fAppend); err != nil {
		_ = fAppend.Close()
		return nil, fmt.Errorf("repair journal tail: %w", err)
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	wj := &WriterJournal{
		w:       fAppend,
		header:  *headerEntry.Header,
		vantage: vantageOf(*headerEntry.Header),
		opts:    o,
	}

	return &FileJournal{
		WriterJournal: wj,
		file:          fAppend,
		path:          path,
	}, nil
}

// repairTornTail ensures the file ends on a line boundary so appended entries never
// join a partial line: a complete unterminated last entry is terminated, a partial one is dropped.
// Reads backwards from EOF in bounded chunks to avoid loading the entire journal into RAM.
func repairTornTail(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	if size == 0 {
		return nil
	}
	var lastByte [1]byte
	if _, err := f.ReadAt(lastByte[:], size-1); err != nil {
		return err
	}
	if lastByte[0] == '\n' {
		return nil
	}

	const chunkSize = int64(64 * 1024)
	maxTail := int64(DefaultMaxEntryBytes + chunkSize)
	minOffset := int64(0)
	if size > maxTail {
		minOffset = size - maxTail
	}

	lineStart := minOffset
	pos := size
	for pos > minOffset {
		start := pos - chunkSize
		if start < minOffset {
			start = minOffset
		}
		buf := make([]byte, pos-start)
		if _, err := f.ReadAt(buf, start); err != nil {
			return err
		}
		if idx := bytes.LastIndexByte(buf, '\n'); idx >= 0 {
			lineStart = start + int64(idx) + 1
			break
		}
		pos = start
	}

	tailLen := size - lineStart
	if tailLen <= int64(DefaultMaxEntryBytes) {
		tail := make([]byte, tailLen)
		if _, err := f.ReadAt(tail, lineStart); err != nil {
			return err
		}
		if json.Valid(bytes.TrimSpace(tail)) {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				return err
			}
			return f.Sync()
		}
	}
	if err := f.Truncate(lineStart); err != nil {
		return err
	}
	return f.Sync()
}
