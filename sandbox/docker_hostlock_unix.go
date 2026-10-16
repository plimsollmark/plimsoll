//go:build unix

package sandbox

import (
	"os"
	"syscall"
)

// holdHostDir takes a shared BSD lock on dir, held while f stays open. systemd-tmpfiles
// skips a directory, and everything below it, that a process holds such a lock on
// (tmpfiles.d(5), "the applications can take a BSD file lock themselves"), so a temp
// directory it ages (Ubuntu 24.04's default rule ages /tmp at 30 days) keeps the
// private directory's files for the process's life.
func holdHostDir(dir string) (*os.File, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
