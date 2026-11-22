package content

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Sink receives validated content-tier records.
type Sink interface {
	Write(Record) error
}

// DiscardSink validates content-tier records (so secret scanning can still run
// over bounded bodies) without persisting any bytes to disk. Used in secrets-only
// content mode.
type DiscardSink struct{}

func (DiscardSink) Write(r Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("invalid content record: %w", err)
	}
	return nil
}

// MemorySink collects content records in memory for unit tests.
type MemorySink struct {
	mu      sync.Mutex
	records []Record
}

func (m *MemorySink) Write(r Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("invalid content record: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, r)
	return nil
}

func (m *MemorySink) Records() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Record(nil), m.records...)
}

// Writer emits content records as line-delimited JSON.
type Writer struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Writer{w: w, enc: enc}
}

func (w *Writer) Write(r Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("invalid content record: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(r)
}

// LazyFileWriter creates its output file on the first Write with mode 0600 so
// scans with no collected content bodies do not create an empty file.
type LazyFileWriter struct {
	mu     sync.Mutex
	path   string
	append bool
	file   *os.File
	writer *Writer
	count  int
	closed bool
}

func NewLazyFileWriter(path string) *LazyFileWriter {
	return &LazyFileWriter{path: path}
}

// NewAppendLazyFileWriter opens an existing content file for appending on resume,
// or creates it with mode 0600 on the first write.
func NewAppendLazyFileWriter(path string) *LazyFileWriter {
	return &LazyFileWriter{path: path, append: true}
}

func (l *LazyFileWriter) Path() string { return l.path }

func (l *LazyFileWriter) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

func (l *LazyFileWriter) Write(r Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("invalid content record: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return fmt.Errorf("content writer %s is closed", l.path)
	}
	if l.file == nil {
		if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
			return fmt.Errorf("create content output directory: %w", err)
		}
		flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
		if l.append {
			flags = os.O_CREATE | os.O_APPEND | os.O_WRONLY
		}
		f, err := os.OpenFile(l.path, flags, 0o600)
		if err != nil {
			return fmt.Errorf("open content file: %w", err)
		}
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return fmt.Errorf("restrict content file permissions: %w", err)
		}
		l.file = f
		l.writer = NewWriter(f)
	}
	if err := l.writer.Write(r); err != nil {
		return err
	}
	l.count++
	return nil
}

func (l *LazyFileWriter) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file == nil {
		return nil
	}
	syncErr := l.file.Sync()
	closeErr := l.file.Close()
	l.file = nil
	l.writer = nil
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
