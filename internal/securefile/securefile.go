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
	"fmt"
	"os"
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
