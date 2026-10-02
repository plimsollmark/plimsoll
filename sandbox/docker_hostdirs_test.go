package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A broker socket directory left by a process that died (older than a minute, its
// socket refusing connections) is removed; a live one, a young one and anything not
// plimsoll's are not. The name is short because the test's directory is in every
// socket path, which Unix caps at 108 bytes.
func TestReapDeadHostDirs(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-2 * time.Minute)
	mk := func(name string, listen bool, mtime time.Time) string {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("unix", filepath.Join(dir, "host-api.sock"))
		if err != nil {
			t.Fatal(err)
		}
		if listen {
			t.Cleanup(func() { _ = l.Close() })
		} else {
			l.(*net.UnixListener).SetUnlinkOnClose(false)
			_ = l.Close()
		}
		if err := os.Chtimes(dir, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	dead := mk("crsbx-session-broker111", false, old)
	deadRun := mk("crsbx-broker222", false, old)
	live := mk("crsbx-session-broker333", true, old)
	young := mk("crsbx-smoke-sock444", false, time.Now())
	other := mk("someone-elses-dir", false, old)

	if n := reapDeadHostDirs(root, time.Now()); n != 2 {
		t.Errorf("reaped %d directories, want 2", n)
	}
	for _, dir := range []string{dead, deadRun} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s survived (%v)", filepath.Base(dir), err)
		}
	}
	for _, dir := range []string{live, young, other} {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("%s was removed (%v)", filepath.Base(dir), err)
		}
	}
}

// A docker client config directory outlives its process on every exit, clean or not,
// since nothing removes it. One a dead process left is removed like a dead broker's:
// one this version left (its liveness socket refusing) and one an earlier version left
// (no socket at all).
func TestReapRemovesConfigDirsDeadProcessesLeft(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-2 * time.Minute)
	withSocket := filepath.Join(root, "plimsoll-docker-config-111")
	bare := filepath.Join(root, "plimsoll-docker-config-222")
	for _, dir := range []string{withSocket, bare} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("unix", filepath.Join(withSocket, "alive.sock"))
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	for _, dir := range []string{withSocket, bare} {
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if n := reapDeadHostDirs(root, time.Now()); n != 2 {
		t.Errorf("reaped %d directories, want 2", n)
	}
	for _, dir := range []string{withSocket, bare} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s survived (%v)", filepath.Base(dir), err)
		}
	}
}

// This process's own config directory is never taken for a dead one, however old: it
// holds a socket the process listens on for its life.
func TestReapKeepsThisProcessesConfigDir(t *testing.T) {
	dir, err := dockerClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	reapDeadHostDirs(filepath.Dir(dir), time.Now())
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("this process's config directory was removed: %v", err)
	}
}
