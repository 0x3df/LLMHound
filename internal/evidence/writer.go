package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Writer writes evidence records as line-delimited JSON (.evidence.jsonl).
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

// Write validates and writes a single Record as a JSON line.
func (w *Writer) Write(r Record) error {
	if err := r.Validate(); err != nil {
		return fmt.Errorf("invalid evidence record: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(r)
}

// WriteAll validates and writes multiple Records.
func (w *Writer) WriteAll(records []Record) error {
	for i, r := range records {
		if err := w.Write(r); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	return nil
}

// Ensure Writer implements a simple flush/close if the underlying writer supports it.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if flusher, ok := w.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// Close closes the underlying writer if it implements io.Closer.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if closer, ok := w.w.(io.Closer); ok {
		return closer.Close()
	}
	return errors.New("underlying writer does not implement io.Closer")
}
