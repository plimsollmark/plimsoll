package wslc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// rootLocks are the run roots this process holds, by the root's Windows path in lower case
// (Windows paths do not tell case apart). A lock is held until the process exits: a provider
// has no close, and a restarted provider in the same process uses the same root again.
var (
	rootLockMu sync.Mutex
	rootLocks  = map[string]*os.File{}
	// rootLockDir is where the lock files live: this distribution's temporary directory, not
	// the run root, which is a Windows folder where an advisory lock may not hold.
	rootLockDir = os.TempDir()
)

// rootLockName is the lock file of a run root (its lower-case Windows path).
func rootLockName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(rootLockDir, "plimsoll-wslc-root-"+hex.EncodeToString(sum[:8])+".lock")
}

// lockRoot takes this process's exclusive lock on a run root, or returns an error naming the
// root when another process on this WSL distribution holds it. The sweep ends every session
// under the root that its own process does not hold, so two processes sharing a root would
// end each other's runs; with the lock the second refuses to start instead. Limit: a process
// in another WSL distribution, or a native Windows one, is not seen by this lock.
func lockRoot(win string) error {
	key := strings.ToLower(win)
	rootLockMu.Lock()
	defer rootLockMu.Unlock()
	if _, ok := rootLocks[key]; ok {
		return nil
	}
	f, err := os.OpenFile(rootLockName(key), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("wslc: locking the run root %s: %w", win, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return fmt.Errorf("wslc: another process is using the run root %s (give each daemon its own SANDBOX_WSLC_RUN_ROOT): %w", win, err)
	}
	rootLocks[key] = f
	return nil
}

// releaseRootLocks gives up every run root this process holds. A daemon never calls it (a
// lock ends with its process); the live test that kills a helper process mid-run does, so
// the helper, standing in for the daemon before a restart, can take the root.
func releaseRootLocks() {
	rootLockMu.Lock()
	defer rootLockMu.Unlock()
	for k, f := range rootLocks {
		_ = f.Close()
		delete(rootLocks, k)
	}
}
