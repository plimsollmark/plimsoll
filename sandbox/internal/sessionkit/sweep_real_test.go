package sessionkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The sweep kills every process but its own ancestors, so it is run here only inside a PID
// namespace of its own, where it can see nothing else: unshare makes one (with a user
// namespace mapping this user to itself, so node runs as this user with no capability, and
// the kernel checks the folders' modes against it as it does against the guest). A machine
// that refuses unprivileged user namespaces skips; the docker suite runs the same case in a
// container (sandbox's TestDockerSweepWalkKeepsAFolderModeTheGuestSet).
func sweepWalk(t *testing.T, maxEntries int, dirs ...string) (exit int, out sweepSummary) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on this machine's PATH")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare (util-linux) on this machine's PATH")
	}
	argv := []string{"--user", "--map-current-user", "--pid", "--fork", "--mount-proc", node}
	argv = append(argv, NodeArgv("-e", SweepScript, strconv.Itoa(1<<30), strconv.Itoa(maxEntries), string(MeasureWalk))[1:]...)
	argv = append(argv, strings.Join(dirs, ","))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, unshare, argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr) && exitErr.Exited():
		exit = exitErr.ExitCode()
	default:
		t.Fatalf("unshare: %v (%s)", err, stderr.String())
	}
	if exit == 1 && bytes.Contains(stderr.Bytes(), []byte("unshare")) {
		t.Skipf("this machine refuses a user and PID namespace of this user's: %s", bytes.TrimSpace(stderr.Bytes()))
	}
	if exit == 0 {
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("the sweep's summary %q: %v", stdout.String(), err)
		}
	}
	return exit, out
}

type sweepSummary struct {
	Entries int   `json:"entries"`
	Bytes   int64 `json:"bytes"`
}

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// A folder the guest closed (mode 000), and one inside it, are measured, their entries counted
// as before (the walk opens each to read it), and both are mode 000 again after the sweep: the
// next call meets them as the guest left them (OpenShell's conformance case
// FileListingNamesAFolderItCannotEnter failed when the walk left them 0700). A folder that is
// readable but not searchable (644) is read but its entries cannot be looked at, so they are not
// counted, and it keeps its mode too.
func TestSweepWalkMeasuresAClosedFolderAndLeavesItClosed(t *testing.T) {
	w := t.TempDir()
	for _, d := range []string{"shut/inner", "nosearch/d", "open"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"shut/b": "bee", "shut/inner/c": "sea", "open/x": "ex"} {
		if err := os.WriteFile(filepath.Join(w, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	modes := map[string]os.FileMode{"shut/inner": 0, "shut": 0, "nosearch": 0o644}
	for _, d := range []string{"shut/inner", "shut", "nosearch"} {
		if err := os.Chmod(filepath.Join(w, d), modes[d]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, d := range []string{"shut", "shut/inner", "nosearch"} {
			_ = os.Chmod(filepath.Join(w, d), 0o755)
		}
	})
	exit, out := sweepWalk(t, MaxDiskEntries, w)
	if exit != SweepClean {
		t.Fatalf("the sweep exited %d; want %d", exit, SweepClean)
	}
	// shut, nosearch, open; shut/b, shut/inner; shut/inner/c; open/x. nosearch/d is read but
	// cannot be looked at, so it is not counted.
	if out.Entries != 7 {
		t.Errorf("the sweep counted %d entries; want 7 (every entry beneath the closed folders included)", out.Entries)
	}
	if out.Bytes <= 0 {
		t.Errorf("the sweep counted %d bytes", out.Bytes)
	}
	if _, err := os.ReadDir(filepath.Join(w, "shut")); err == nil {
		t.Error("the closed folder is readable after the sweep")
	}
	// shut/inner can be looked at only once shut is opened, so it is checked last.
	for _, d := range []string{"shut", "nosearch", "shut/inner"} {
		if d == "shut/inner" {
			if err := os.Chmod(filepath.Join(w, "shut"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if got := modeOf(t, filepath.Join(w, d)); got != modes[d] {
			t.Errorf("%s is mode %#o after the sweep; want %#o, as the guest set it", d, got, modes[d])
		}
	}
}

// A walk that ends inside closed folders (here past the entry bound, at the fourth entry, two
// closed folders deep) puts every folder it opened back before it exits: the verdict is the
// bound's, and both folders are mode 000 again.
func TestSweepWalkPutsBackWhatItOpenedWhenItStopsInside(t *testing.T) {
	w := t.TempDir()
	if err := os.MkdirAll(filepath.Join(w, "shut", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"shut/b", "shut/inner/c"} {
		if err := os.WriteFile(filepath.Join(w, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"shut/inner", "shut"} {
		if err := os.Chmod(filepath.Join(w, d), 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(w, "shut"), 0o755)
		_ = os.Chmod(filepath.Join(w, "shut", "inner"), 0o755)
	})
	// shut, then shut/b and shut/inner in either order, then shut/inner/c: the fourth.
	if exit, _ := sweepWalk(t, 3, w); exit != SweepOverBudget {
		t.Fatalf("the sweep exited %d; want %d (past the entry bound)", exit, SweepOverBudget)
	}
	if got := modeOf(t, filepath.Join(w, "shut")); got != 0 {
		t.Errorf("shut is mode %#o after the sweep stopped inside it; want 0", got)
	}
	_ = os.Chmod(filepath.Join(w, "shut"), 0o700)
	if got := modeOf(t, filepath.Join(w, "shut", "inner")); got != 0 {
		t.Errorf("shut/inner is mode %#o after the sweep stopped inside it; want 0", got)
	}
}
