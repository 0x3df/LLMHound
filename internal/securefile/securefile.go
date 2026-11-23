// Package securefile creates scan artifacts that only the account running the
// scan can read. Journals, payloads, evidence sidecars, and the content file
// can hold sensitive inventory (and, in content mode, service bodies), so
// invariant 5's "restricted file" must hold on every platform the collector
// ships for, including a Windows collection host running as a service account.
//
// On Unix the file mode is forced to 0600. On Windows, where Unix modes are
// ignored, files are created with a protected DACL that grants access only to
// the current user SID and SYSTEM, and inherited ACEs from the output
// directory are discarded.
package securefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OpenFile opens name with os.OpenFile flag semantics and restricts the file to
// the current user. An existing file opened for writing has its permissions
// re-restricted as well, so a looser pre-existing file never stays readable.
func OpenFile(name string, flag int) (*os.File, error) {
	f, err := openRestricted(name, flag)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// MkdirAll creates dir and any parents with owner/group-only permissions on
// Unix. On Windows directories inherit their parent's ACL; the files inside
// are protected individually by OpenFile.
func MkdirAll(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	return nil
}

// WriteFileAtomic writes data to path via a newly created restricted temporary
// file in the destination directory, flushes it to disk, and atomically replaces
// path. On Unix the destination is mode 0600; on Windows it has a protected
// DACL granting only the current user and SYSTEM.
func WriteFileAtomic(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("write file: path cannot be empty")
	}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("write file %s: target is a directory", path)
	}

	dir := filepath.Dir(path)
	if err := MkdirAll(dir); err != nil {
		return err
	}

	base := filepath.Base(path)
	var (
		f       *os.File
		tmpPath string
	)
	const maxAttempts = 16
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var rnd [8]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return fmt.Errorf("generate temp filename for %s: %w", path, err)
		}
		candidate := filepath.Join(dir, "."+base+"."+hex.EncodeToString(rnd[:])+".tmp")
		opened, err := OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
		if err == nil {
			f = opened
			tmpPath = candidate
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create temp file for %s: %w", path, err)
		}
	}
	if f == nil {
		return fmt.Errorf("create temp file for %s: exhausted unique filename attempts", path)
	}

	cleanup := func() {
		_ = os.Remove(tmpPath)
	}

	if err := writeAll(f, data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("write temp file for %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("sync temp file for %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file for %s: %w", path, err)
	}
	if err := replaceFile(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func writeAll(f *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := f.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
