package wslc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// A session with this provider's prefix whose directory is not under this provider's run
// root is another provider's run on the machine: the startup sweep, which ends everything of
// its own, must leave it. Before this rule the sweep ended every session with the prefix, so
// two daemons on one Windows machine refused each other's runs with "Session not found".
func TestPerRunSweepSparesAnotherProvidersSession(t *testing.T) {
	f := newFake(t, goodSetup(t))
	root := f.runRoot()
	mine, theirs := SessionPrefix+"00112233445566aa", SessionPrefix+"00112233445566bb"
	if err := os.MkdirAll(filepath.Join(root, mine), 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, theirs), 0o755); err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"sessions": map[string]any{
		mine:   map[string]any{"dir": filepath.Join(root, mine), "bootID": "11111111-2222-4333-8444-555555555555"},
		theirs: map[string]any{"dir": filepath.Join(elsewhere, theirs), "bootID": "66666666-2222-4333-8444-555555555555"},
	}}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(f.dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	p := f.provider(perRun)
	if err := p.SmokeTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := f.state()
	if _, ok := st.Sessions[mine]; ok || !slices.Contains(st.Terminated, mine) {
		t.Fatalf("this provider's own orphan was not ended: %+v", st)
	}
	if _, ok := st.Sessions[theirs]; !ok || slices.Contains(st.Terminated, theirs) {
		t.Fatalf("the sweep ended another provider's session: %+v", st)
	}
	// And on a run's give-up path (sweep(false)) too.
	if _, err := p.sweep(false); err != nil {
		t.Fatal(err)
	}
	if st := f.state(); slices.Contains(st.Terminated, theirs) {
		t.Fatalf("a run's sweep ended another provider's session: %+v", st)
	}
}

// One process to a run root: when another holder has the root's lock, a provider refuses to
// use the root and says which root; the same process may take its own root again.
func TestRunRootIsLockedToOneProcess(t *testing.T) {
	const win = "C:/Users/someone/AppData/Local/plimsoll-wslc-locktest"
	// Another holder: a second open of the lock file, as another process would have.
	other, err := os.OpenFile(rootLockName(strings.ToLower(win)), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := lockRoot(win); err == nil || !strings.Contains(err.Error(), win) || !strings.Contains(err.Error(), "another process") {
		t.Fatalf("a root another holder has locked: %v", err)
	}
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lockRoot(win); err != nil {
		t.Fatalf("a free root: %v", err)
	}
	if err := lockRoot(strings.ToUpper(win[:2]) + win[2:]); err != nil {
		t.Fatalf("this process's own root, taken again: %v", err)
	}
}
