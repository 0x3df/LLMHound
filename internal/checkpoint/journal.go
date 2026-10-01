package checkpoint

import (
	"bufio"
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
	vantage graph.Identity
	opts    options
	closed  bool
}

// NewWriter creates a Journal writing to w and emits the Header entry.
func NewWriter(w io.Writer, header Header, opts ...Option) (*WriterJournal, error) {
	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("invalid header: %w", err)
	}

	vantage, err := graph.NewVantageIdentity(header.DeploymentScope, header.VantageKey)
	if err != nil {
		return nil, fmt.Errorf("invalid vantage in header: %w", err)
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	j := &WriterJournal{
		w:       w,
		header:  header,
		vantage: vantage,
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

	if err := res.Validate(j.header.DeploymentScope); err != nil {
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

	target.Target = SanitizeTarget(target.Target)
	target.Error = boundString(target.Error, j.opts.maxStringSize)
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

	if item.Node.Identity().Scope() != j.header.DeploymentScope {
		return errors.New("node scope does not match journal deployment scope")
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

	if edge.Start().Scope() != j.header.DeploymentScope {
		return errors.New("edge start scope does not match journal deployment scope")
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

	if err := record.Validate(); err != nil {
		return fmt.Errorf("invalid evidence record: %w", err)
	}
	if record.DeploymentScope != j.header.DeploymentScope {
		return errors.New("evidence record scope does not match journal deployment scope")
	}

	record.Details = SanitizeMap(record.Details, j.opts.maxStringSize)
	record.Source = SanitizeURL(record.Source)

	return j.writeEntryLocked(JournalEntry{
		EntryType: EntryEvidence,
		Evidence:  &record,
	})
}

func (j *WriterJournal) writeEntryLocked(entry JournalEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}

	if len(data) > j.opts.maxEntryBytes {
		return ErrEntryTooLarge
	}

	data = append(data, '\n')
	_, err = j.w.Write(data)
	return err
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
	_ = f.Flush()
	return f.WriterJournal.Close()
}

// CreateFile creates a new journal file at path, writing header as the first entry.
func CreateFile(path string, header Header, opts ...Option) (*FileJournal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create journal directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
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

	fAppend, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open journal file for appending: %w", err)
	}

	vantage, err := graph.NewVantageIdentity(headerEntry.Header.DeploymentScope, headerEntry.Header.VantageKey)
	if err != nil {
		_ = fAppend.Close()
		return nil, fmt.Errorf("invalid vantage in header: %w", err)
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	wj := &WriterJournal{
		w:       fAppend,
		header:  *headerEntry.Header,
		vantage: vantage,
		opts:    o,
	}

	return &FileJournal{
		WriterJournal: wj,
		file:          fAppend,
		path:          path,
	}, nil
}
