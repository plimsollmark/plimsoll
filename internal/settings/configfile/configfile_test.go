//go:build unix

package configfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// place writes a file of mode fileMode in a fresh directory of mode dirMode (chmod after
// creation, so the umask does not change either) and returns the file's path.
func place(t *testing.T, dirMode, fileMode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "clients.json")
	if err := os.WriteFile(path, []byte(`{"clients":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, fileMode)
	chmod(t, dir, dirMode)
	return path
}

func chmod(t *testing.T, path string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, m); err != nil {
		t.Fatal(err)
	}
	// Restore what TempDir's cleanup needs to remove the tree.
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) })
}

// requireClean reads path and fails unless nothing lets another user change it. The
// test's own temporary directory must pass first: on a machine whose temporary
// directory is itself loose, the test says so rather than blaming the rule.
func requireClean(t *testing.T, path string) {
	t.Helper()
	raw, found, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"clients":[]}` {
		t.Fatalf("read %q, not the file's content", raw)
	}
	if found != nil {
		t.Fatalf("finding on a file nobody else can change: %s", found)
	}
}

func requireFinding(t *testing.T, path string, want ...string) {
	t.Helper()
	raw, found, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"clients":[]}` {
		t.Fatalf("read %q, not the file's content", raw)
	}
	if found == nil {
		t.Fatalf("no finding for %s", path)
	}
	for _, w := range want {
		if !strings.Contains(found.String(), w) {
			t.Fatalf("finding %q does not say %q", found, w)
		}
	}
	if strings.Contains(found.String(), "clients\":") {
		t.Fatalf("finding quotes the file's content: %q", found)
	}
}

// The temporary directory this test machine gives must itself pass, or every other case
// here would be judging the machine rather than the rule.
func TestTempDirChainIsClean(t *testing.T) {
	requireClean(t, place(t, 0o700, 0o600))
}

// The file's own write bits for its group and for every other user are refused; its read
// bits are not, so a Kubernetes secret mounted with fsGroup (0440, 0640) is accepted.
func TestFileWriteBits(t *testing.T) {
	for _, m := range []os.FileMode{0o600, 0o640, 0o440, 0o644, 0o444, 0o400} {
		t.Run("accepts "+mode(m), func(t *testing.T) { requireClean(t, place(t, 0o700, m)) })
	}
	for m, who := range map[os.FileMode]string{0o620: "its group", 0o660: "its group", 0o602: "every other user", 0o666: "its group and every other user"} {
		t.Run("refuses "+mode(m), func(t *testing.T) {
			requireFinding(t, place(t, 0o700, m), "has mode "+mode(m), who)
		})
	}
}

// A directory on the path that its group or every other user can write lets them put a
// file of their own in the file's place, unless its sticky bit is set.
func TestDirectoryWriteBits(t *testing.T) {
	for _, m := range []os.FileMode{0o770, 0o730, 0o707, 0o777} {
		t.Run("refuses "+mode(m), func(t *testing.T) {
			path := place(t, m, 0o600)
			requireFinding(t, path, "directory "+filepath.Dir(path)+" has mode "+mode(m), "replace what it holds")
		})
	}
	for _, m := range []os.FileMode{0o700, 0o750, 0o755, 0o710} {
		t.Run("accepts "+mode(m), func(t *testing.T) { requireClean(t, place(t, m, 0o600)) })
	}
	t.Run("accepts sticky 1777", func(t *testing.T) { requireClean(t, place(t, 0o777|os.ModeSticky, 0o600)) })
}

// A file reached through a symbolic link is judged by what it points to and by the
// link's own directory.
func TestSymbolicLinks(t *testing.T) {
	t.Run("the target's directory", func(t *testing.T) {
		target := place(t, 0o777, 0o600) // a loose directory holds the real file
		linkDir := filepath.Join(t.TempDir(), "etc")
		if err := os.Mkdir(linkDir, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(linkDir, "clients.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		requireFinding(t, link, "directory "+filepath.Dir(target)+" has mode 0777")
	})
	t.Run("the target file", func(t *testing.T) {
		target := place(t, 0o700, 0o666)
		link := filepath.Join(t.TempDir(), "clients.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		requireFinding(t, link, "has mode 0666")
	})
	t.Run("the link's directory", func(t *testing.T) {
		target := place(t, 0o700, 0o600)
		linkDir := filepath.Join(t.TempDir(), "etc")
		if err := os.Mkdir(linkDir, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(linkDir, "clients.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		chmod(t, linkDir, 0o770)
		requireFinding(t, link, "directory "+linkDir+" has mode 0770")
	})
	t.Run("a relative link that climbs", func(t *testing.T) {
		base := t.TempDir()
		for _, d := range []string{"a", "b"} {
			if err := os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		target := filepath.Join(base, "b", "clients.json")
		if err := os.WriteFile(target, []byte(`{"clients":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "a", "clients.json")
		if err := os.Symlink("../b/clients.json", link); err != nil {
			t.Fatal(err)
		}
		requireClean(t, link)
		chmod(t, filepath.Join(base, "b"), 0o707)
		requireFinding(t, link, "directory "+filepath.Join(base, "b")+" has mode 0707")
	})
}

// kubernetesVolume lays out a secret or config map volume as the kubelet does: a sticky,
// world-writable root (0o1777, as listed in kubernetes/kubernetes issue 34982) holding a
// timestamped directory, a "..data" link to it and one link per key into "..data".
func kubernetesVolume(t *testing.T, fileMode os.FileMode) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "plimsoll")
	ts := filepath.Join(root, "..2026_11_20_06_15_00.000000001")
	if err := os.MkdirAll(ts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ts, "clients.json"), []byte(`{"clients":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	chmod(t, filepath.Join(ts, "clients.json"), fileMode)
	if err := os.Symlink(filepath.Base(ts), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/clients.json", filepath.Join(root, "clients.json")); err != nil {
		t.Fatal(err)
	}
	chmod(t, root, 0o777|os.ModeSticky)
	return filepath.Join(root, "clients.json")
}

// A Kubernetes secret or config map mounted read-only for the group (0440 with fsGroup)
// is accepted; one mounted group-writable (0660: a defaultMode that grants it) is not.
func TestKubernetesVolume(t *testing.T) {
	for _, m := range []os.FileMode{0o644, 0o440, 0o640, 0o400} {
		t.Run("accepts "+mode(m), func(t *testing.T) { requireClean(t, kubernetesVolume(t, m)) })
	}
	t.Run("refuses 0660", func(t *testing.T) { requireFinding(t, kubernetesVolume(t, 0o660), "has mode 0660", "its group") })
}

// The mode comes from the opened descriptor: a name that is not a regular file is said,
// and a file that cannot be opened is an error, not a finding.
func TestNotARegularFileAndMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(dir); err == nil {
		t.Fatal("reading a directory succeeded")
	}
	if _, _, err := Read(filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("reading a missing file succeeded")
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if p := judge(dir, info); len(p) == 0 || !strings.Contains(strings.Join(p, ";"), "is not a regular file") {
		t.Fatalf("a directory judged as %q", p)
	}
}

// asAnotherUser judges files as a daemon running as a user who owns none of them: every
// file and directory the test made is then another user's.
func asAnotherUser(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root, which owns the files and is always trusted")
	}
	mine := os.Geteuid()
	daemonUID = func() int { return mine + 1 }
	t.Cleanup(func() { daemonUID = os.Geteuid })
}

// The file and every directory on its path must be owned by root or the daemon's user:
// another owner can chmod them at will.
func TestOwners(t *testing.T) {
	path := place(t, 0o700, 0o600)
	asAnotherUser(t)
	requireFinding(t, path, "file "+path+" is owned by uid", "directory "+filepath.Dir(path)+" is owned by uid")
}

// In a sticky directory others can write, a symbolic link must itself be owned by root or
// the daemon's user, or another user could have made it.
func TestLinkInAStickyDirectory(t *testing.T) {
	path := kubernetesVolume(t, 0o644)
	asAnotherUser(t)
	requireFinding(t, path, "symbolic link "+path+" is owned by uid")
}

// The file the walk reaches must be the one opened: judged against another file's
// descriptor, the walk says the path changed.
func TestWalkMustReachTheOpenedFile(t *testing.T) {
	a, b := place(t, 0o700, 0o600), place(t, 0o700, 0o600)
	f, err := os.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if p := strings.Join(judge(a, info), ";"); !strings.Contains(p, "changed while it was read") {
		t.Fatalf("judged as %q", p)
	}
}
