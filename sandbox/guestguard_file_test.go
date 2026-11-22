package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

func guestGuardProgramOrSkip(t *testing.T) []byte {
	t.Helper()
	prog, err := guestguard.Program(runtime.GOARCH)
	if err != nil {
		t.Skipf("%v (the arm64 build is the named next step)", err)
	}
	return prog
}

// TestWriteGuestGuard: the file is the bytes inside plimsolld, named by their SHA-256, mode
// 0555; a second call finds it and answers the same path; a file changed in place, given
// another mode, or replaced by something other than a regular file is refused, never
// rewritten; and the folder holds nothing else afterwards (no temporary file left behind).
func TestWriteGuestGuard(t *testing.T) {
	prog := guestGuardProgramOrSkip(t)
	if runtime.GOOS != "linux" {
		t.Skip("the guest guard is written only on Linux")
	}
	dir := t.TempDir()
	path, err := writeGuestGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(prog)
	if want := filepath.Join(dir, "guest-guard-"+hex.EncodeToString(sum[:])); path != want {
		t.Fatalf("path %s, want %s", path, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o555 {
		t.Errorf("mode %v, want -r-xr-xr-x", fi.Mode())
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, prog) {
		t.Error("the file is not the program's bytes")
	}
	if again, err := writeGuestGuard(dir); err != nil || again != path {
		t.Errorf("second call: %q, %v", again, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the folder holds %d entries, want the guard alone", len(entries))
	}

	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := writeGuestGuard(dir); err == nil || !strings.Contains(err.Error(), "has mode") {
		t.Errorf("a guard file whose mode changed: %v", err)
	}
	if err := os.WriteFile(path, append(append([]byte{}, prog...), 0), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := writeGuestGuard(dir); err == nil || !strings.Contains(err.Error(), "was changed") {
		t.Errorf("a guard file whose bytes changed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", path); err != nil {
		t.Fatal(err)
	}
	if _, err := writeGuestGuard(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a guard file replaced by a link: %v", err)
	}
}

// TestWriteGuestGuardRefusesNoExecFolder (finding guest-guard-4): a folder on a filesystem
// mounted noexec is refused, with a message that names the folder, the mount option, what a
// container would do, and the setting that moves the folder; nothing is written. The refusal
// is checked through the flag reader, and on this machine's own noexec mounts when one is
// writable.
func TestWriteGuestGuardRefusesNoExecFolder(t *testing.T) {
	guestGuardProgramOrSkip(t)
	if runtime.GOOS != "linux" {
		t.Skip("the guest guard is written only on Linux")
	}
	check := func(dir string) {
		t.Helper()
		_, err := writeGuestGuard(dir)
		if err == nil {
			t.Fatalf("%s: written on a noexec filesystem", dir)
		}
		for _, want := range []string{dir, "mounted noexec", "exit 126", "exit 139", "TMPDIR"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q: %v", want, err)
			}
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("%s holds %d entries after the refusal", dir, len(entries))
		}
	}

	reader := guestGuardFolderNoExec
	if noexec, err := reader(t.TempDir()); err != nil || noexec {
		t.Logf("this machine's temporary folder: noexec %v, %v", noexec, err)
	}
	tried := false
	for _, root := range []string{"/run/lock", "/dev/shm", "/run/user"} {
		if noexec, err := reader(root); err != nil || !noexec {
			continue
		}
		dir, err := os.MkdirTemp(root, "plimsoll-guest-guard-test-")
		if err != nil {
			continue
		}
		tried = true
		check(dir)
		t.Logf("refused on %s, on a noexec mount of this machine", dir)
		_ = os.RemoveAll(dir)
	}
	if !tried {
		t.Log("no writable noexec mount here; the refusal is checked through the flag reader only")
	}

	guestGuardFolderNoExec = func(string) (bool, error) { return true, nil }
	t.Cleanup(func() { guestGuardFolderNoExec = reader })
	check(t.TempDir())
}
