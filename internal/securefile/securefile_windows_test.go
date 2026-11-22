//go:build windows

package securefile_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x3df/LLMHound/internal/securefile"
	"golang.org/x/sys/windows"
)

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
	sddl := sd.String()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sddl, "D:P") {
		t.Fatalf("DACL must be protected from inheritance: %s", sddl)
	}
	if !strings.Contains(sddl, user.User.Sid.String()) || !strings.Contains(sddl, ";;;SY)") {
		t.Fatalf("DACL must grant the current user and SYSTEM: %s", sddl)
	}
	for _, broad := range []string{";;;WD)", ";;;BU)", ";;;AU)"} {
		if strings.Contains(sddl, broad) {
			t.Fatalf("DACL must not grant %s: %s", broad, sddl)
		}
	}
}
