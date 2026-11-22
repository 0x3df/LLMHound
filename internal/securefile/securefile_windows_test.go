//go:build windows

package securefile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/0x3df/LLMHound/internal/securefile"
	"golang.org/x/sys/windows"
)

// The DACL must be protected (no inherited ACEs) and contain exactly two
// allow ACEs: the current process user and SYSTEM. SIDs are compared directly
// because SDDL text abbreviates well-known accounts (for example the built-in
// Administrator renders as "LA").
func TestOpenFileWindowsDACLIsOwnerAndSystemOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restricted.jsonl")
	f, err := securefile.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sd.String(), "D:P") {
		t.Fatalf("DACL must be protected from inheritance: %s", sd.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("DACL has %d ACEs, want 2: %s", dacl.AceCount, sd.String())
	}
	var sawUser, sawSystem bool
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected ACE type %d: %s", ace.Header.AceType, sd.String())
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(user.User.Sid):
			sawUser = true
		case sid.Equals(system):
			sawSystem = true
		default:
			t.Fatalf("DACL grants an unexpected principal %s: %s", sid.String(), sd.String())
		}
	}
	if !sawUser || !sawSystem {
		t.Fatalf("DACL must grant the current user and SYSTEM: %s", sd.String())
	}
}
