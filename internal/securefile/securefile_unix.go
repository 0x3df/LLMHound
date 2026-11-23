//go:build !windows

package securefile

import (
	"fmt"
	"os"
)

func openRestricted(name string, flag int) (*os.File, error) {
	f, err := os.OpenFile(name, flag, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("restrict permissions on %s: %w", name, err)
	}
	return f, nil
}

func replaceFile(tmpPath, destPath string) error {
	return os.Rename(tmpPath, destPath)
}
