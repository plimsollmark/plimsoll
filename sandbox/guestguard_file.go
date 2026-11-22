package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

// guestGuardName is the file name writeGuestGuard gives this machine's guard: guest-guard- and
// the SHA-256 of its bytes. An error names a machine with no guard.
var guestGuardName = sync.OnceValues(func() (string, error) {
	prog, err := guestguard.Program(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	return guardFolderFileName("guest-guard-", prog), nil
})

// guestGuardCheckName is the file name writeGuestGuardCheck gives this machine's guard check:
// guest-guard-check- and the SHA-256 of its bytes. An error names a machine with no check.
var guestGuardCheckName = sync.OnceValues(func() (string, error) {
	prog, err := guestguard.CheckProgram(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	return guardFolderFileName("guest-guard-check-", prog), nil
})

// guardFolderFileName is the name writePinnedProgram gives prog in the guard's folder: prefix
// and the SHA-256 of prog.
func guardFolderFileName(prefix string, prog []byte) string {
	sum := sha256.Sum256(prog)
	return prefix + hex.EncodeToString(sum[:])
}

// guestGuardPath is the one path in dir that writeGuestGuard writes this machine's guard to,
// and so the one source the refusing point lets a run mount at the guard's path
// (checkGuardedCommand, finding guest-guard-20).
func guestGuardPath(dir string) (string, error) {
	name, err := guestGuardName()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// guestGuardCheckPath is the one path in dir that writeGuestGuardCheck writes this machine's
// guard check to, and so the one source the refusing point lets the startup smoke test mount at
// the check's path (checkGuardedCommand).
func guestGuardCheckPath(dir string) (string, error) {
	name, err := guestGuardCheckName()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// guestGuardFileMode is the guard file's mode: read and run, by every user (a rootless
// daemon's user too), written by no one.
const guestGuardFileMode = 0o555

// writeGuestGuard writes the guest guard program for this machine (the bytes inside plimsolld,
// sandbox/internal/guestguard) into dir, a folder plimsolld owns, as guest-guard-<sha256>, mode
// 0555, and returns its path. A container gets it as one read-only bind mount and starts it
// first (the guard's design, decision 1 A). Called again on the same folder it checks the file
// in place of writing it, so it is also the periodic check: a file that is there with other
// bytes or another mode is an error, never rewritten, since only plimsolld's own user can write
// that folder.
//
// It refuses a folder on a filesystem mounted noexec (finding guest-guard-4): a bind mount keeps
// that mark, and no container could start the guard (measured: docker under runc refuses to start
// the container, exit 126; under gVisor the guard dies with a segmentation fault, exit 139, which
// no operator would connect to a mount option).
//
// The docker provider calls it at each Preflight (docker_preflight.go) and mounts the file it
// returns into every container (docker_guestguard.go).
func writeGuestGuard(dir string) (string, error) {
	prog, err := guestguard.Program(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	return writePinnedProgram(dir, "guest guard", "guest-guard-", prog)
}

// writeGuestGuardCheck writes the guard check for this machine (guestguard.CheckProgram: the
// program the startup smoke test starts as a guest's program is started, behind the guard, to
// prove the guard's filter is on it) into dir, the guard's own folder, as
// guest-guard-check-<sha256>, mode 0555, and returns its path, as writeGuestGuard writes the
// guard: checked in place when it is already there, never rewritten, and refused on a folder
// mounted noexec. The smoke test mounts it read-only into the containers it checks the guard
// from (smokeGuestGuard); no run's container gets it.
func writeGuestGuardCheck(dir string) (string, error) {
	prog, err := guestguard.CheckProgram(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	return writePinnedProgram(dir, "guest guard", "guest-guard-check-", prog)
}

// writePinnedProgram writes prog, a program plimsolld carries (the guest guard, the native
// helper), into dir as <prefix><sha256>, mode 0555, and returns its path; what names it in
// errors. A file already there is checked, never rewritten: other bytes, another mode or
// another kind of file is an error. A folder on a noexec filesystem is refused, since no
// container could start the program from it (finding guest-guard-4).
func writePinnedProgram(dir, what, prefix string, prog []byte) (string, error) {
	noexec, err := guestGuardFolderNoExec(dir)
	if err != nil {
		return "", fmt.Errorf("%s: cannot read the mount flags of %s: %w", what, dir, err)
	}
	if noexec {
		return "", fmt.Errorf("%s: %s is on a filesystem mounted noexec, so no container could start the program from it "+
			"(docker under runc refuses to start the container, exit 126; under gVisor it dies with a segmentation fault, exit 139); "+
			"start plimsolld with TMPDIR set to a folder on a filesystem mounted without noexec", what, dir)
	}
	path := filepath.Join(dir, guardFolderFileName(prefix, prog))
	if fi, err := os.Lstat(path); err == nil {
		got, rerr := os.ReadFile(path)
		switch {
		case !fi.Mode().IsRegular():
			return "", fmt.Errorf("%s: %s is not a regular file (%v); restart to make a new one", what, path, fi.Mode())
		case rerr != nil:
			return "", fmt.Errorf("%s: %s is unreadable (%w); restart to make a new one", what, path, rerr)
		case !bytes.Equal(got, prog):
			return "", fmt.Errorf("%s: %s was changed (%d bytes, not the %d inside plimsolld); restart to make a new one", what, path, len(got), len(prog))
		case fi.Mode().Perm() != guestGuardFileMode:
			return "", fmt.Errorf("%s: %s has mode %v, not %v; restart to make a new one", what, path, fi.Mode().Perm(), os.FileMode(guestGuardFileMode))
		}
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	// Written whole under a private name, then moved into place, so a reader (docker, another
	// check) never sees a partial file.
	tmp, err := os.CreateTemp(dir, prefix+"*.tmp")
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	fail := func(err error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("%s: %w", what, err)
	}
	if _, err := tmp.Write(prog); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(guestGuardFileMode); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return path, nil
}
