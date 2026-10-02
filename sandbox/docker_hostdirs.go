package sandbox

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// dockerHostDirPrefixes name the host directories the docker provider makes: those
// that hold a Unix socket mounted into a container (a run's broker, brokerForRun; a
// session's, startDockerSessionBroker; the smoke test's, startSmokeSocket), each
// removed when its owner closes it, and the process's docker client config
// (dockerClientConfig), which nothing removes at exit. Every one holds a socket its
// owner listens on while it lives, so one whose sockets all refuse a connection was
// left by a process that died.
var dockerHostDirPrefixes = []string{"crsbx-broker", "crsbx-session-broker", "crsbx-smoke-sock", "plimsoll-docker-config-"}

// hostDirMinAge is how old a directory must be before it is judged: its owner
// listens on its socket within moments of making it.
const hostDirMinAge = time.Minute

// reapDeadHostDirs removes, under root, the host directories that dead processes
// left, and returns how many. A directory is dead when it is older than
// hostDirMinAge and no socket in it accepts a connection (one an earlier version
// left without a socket counts as dead): a live owner's socket accepts one and sees
// it closed at once. A directory that cannot be read, or a socket that answers
// anything but a refusal, is left alone, so another user's directory (mode 0700) and
// another process's live one are never touched.
func reapDeadHostDirs(root string, now time.Time) int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	reaped := 0
	for _, e := range entries {
		if !e.IsDir() || !hasAnyPrefix(e.Name(), dockerHostDirPrefixes) {
			continue
		}
		dir := filepath.Join(root, e.Name())
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || now.Sub(info.ModTime()) < hostDirMinAge {
			continue
		}
		if !hostDirDead(dir) {
			continue
		}
		if os.RemoveAll(dir) == nil {
			reaped++
		}
	}
	return reaped
}

// hostDirDead reports whether no socket in dir has a listener.
func hostDirDead(dir string) bool {
	inner, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, f := range inner {
		if f.Type()&fs.ModeSocket == 0 {
			continue
		}
		c, err := net.DialTimeout("unix", filepath.Join(dir, f.Name()), time.Second)
		if err == nil {
			_ = c.Close()
			return false
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return false
		}
	}
	return true
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
