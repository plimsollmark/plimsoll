//go:build unix

package sandbox

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// The private directory stays locked for the process's life, the lock systemd-tmpfiles
// takes before aging a directory away fails, and the files' check sees one taken.
func TestDockerPrivateDirectoryIsLockedAgainstTmpfiles(t *testing.T) {
	files, err := dockerProcessFiles()
	if err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(files.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// systemd-tmpfiles takes an exclusive lock, without waiting, on what it would remove.
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		if err == nil {
			_ = syscall.Flock(int(other.Fd()), syscall.LOCK_UN)
		}
		t.Fatalf("an exclusive lock on the private directory: %v, want EWOULDBLOCK", err)
	}
	if err := checkGuestResolvConfFile(files.resolvConf); err != nil {
		t.Fatal(err)
	}
}
