//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerOnlyDescriptor builds a protected DACL ("P": no inherited ACEs) that
// grants full control to the current process user and to SYSTEM only.
func ownerOnlyDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("look up current user SID: %w", err)
	}
	sddl := "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build owner-only security descriptor: %w", err)
	}
	return sd, nil
}

func openRestricted(name string, flag int) (*os.File, error) {
	sd, err := ownerOnlyDescriptor()
	if err != nil {
		return nil, err
	}
	if flag&os.O_CREATE != 0 {
		err := createNew(name, sd)
		switch {
		case err == nil:
			// Created atomically with the restricted DACL; no window in which
			// the file carries the directory's inherited ACL.
		case errors.Is(err, os.ErrExist) && flag&os.O_EXCL == 0:
			if err := applyDescriptor(name, sd); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
		flag &^= os.O_CREATE | os.O_EXCL
	} else if flag&(os.O_WRONLY|os.O_RDWR) != 0 {
		if err := applyDescriptor(name, sd); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(name, flag, 0o600)
}

func createNew(name string, sd *windows.SECURITY_DESCRIPTOR) error {
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return &os.PathError{Op: "open", Path: name, Err: err}
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := windows.CreateFile(path, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: name, Err: err}
	}
	return windows.CloseHandle(h)
}

func applyDescriptor(name string, sd *windows.SECURITY_DESCRIPTOR) error {
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read owner-only DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict permissions on %s: %w", name, err)
	}
	return nil
}
