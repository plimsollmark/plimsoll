package sandbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The native helper an E2B session's open puts in its machine (e2b_session_files.go,
// session-files-11), on the stand-in: what the open refuses at the helper's path, what it
// installs, and that file calls then run. The conformance suite's file cases run on the
// stand-in in TestE2BSessionDockerConformance.

// e2bHelperAtOpen is what a session's machine shows of the helper and the work folder, read
// by the guest.
type e2bHelperAtOpen struct {
	Mode, UID, GID int
	Writable       string
	WorkMounted    bool
	// WorkDevice is every line of the guest's mountinfo of the work mount's device: what a
	// second mount of it, through which a held folder could be moved out (review finding
	// session-files-15), would show up among.
	WorkDevice []string
}

func readHelperAtOpen(t *testing.T, s sandbox.Session) e2bHelperAtOpen {
	t.Helper()
	res := e2bSnippet(t, s, `const fs = require("fs");
const st = fs.statSync("/usr/lib/plimsoll/plimsoll-helper");
let writable = "no"; try { fs.closeSync(fs.openSync("/usr/lib/plimsoll/plimsoll-helper", "r+")); writable = "yes" } catch (e) { writable = e.code }
try { fs.writeFileSync("/usr/lib/plimsoll/planted", "x"); writable += " folder" } catch {}
const lines = fs.readFileSync("/proc/self/mountinfo", "latin1").split("\n").filter(Boolean);
const work = lines.filter((l) => l.split(" ")[4] === "/work").pop();
const dev = work ? work.split(" ")[2] : "";
console.log(JSON.stringify({mode: st.mode & 0o7777, uid: st.uid, gid: st.gid, writable, workMounted: !!work,
  workDevice: lines.filter((l) => l.split(" ")[2] === dev)}))`)
	var got e2bHelperAtOpen
	if err := json.Unmarshal([]byte(res.Stdout), &got); err != nil {
		t.Fatalf("snippet output %q: %v (stderr %q)", res.Stdout, err, res.Stderr)
	}
	return got
}

// On a template with nothing at the helper's path the open uploads the helper and installs
// it: the root's, mode 0711, closed to the guest, in a folder the guest cannot write, and
// non-dumpable from its exec (a process of the guest's that starts it cannot open its memory
// before its first call, session-files-14); the work folder is a mount of its own; and a file
// call runs through it.
func TestE2BSessionDockerInstallsTheHelper(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	s := openE2B(t, f.provider())
	got := readHelperAtOpen(t, s)
	if got.Mode != 0o711 || got.UID != 0 || got.GID != 0 || got.Writable != "EACCES" || !got.WorkMounted {
		t.Fatalf("after the open: %+v; want the helper the root's, mode 0711, closed to the guest, and /work a mount of its own", got)
	}
	probe := e2bSnippet(t, s, sandbox.HelperDumpableProbe("/bin/sleep", "/usr/lib/plimsoll/plimsoll-helper"))
	if probe.ExitCode != 0 {
		t.Fatalf("the dumpable probe: %+v", probe)
	}
	sandbox.CheckHelperDumpable(t, probe.Stdout, "/bin/sleep", "/usr/lib/plimsoll/plimsoll-helper")
	// The stand-in's measurement of session-files-15: the work mount's device is mounted at /
	// (the container's root) and at /work (the open's bind) alone, so nothing else shows the
	// work folder's files. The open's own check (workAlias) refuses a machine where another
	// mount does; this states what the guest sees here.
	t.Logf("the work mount's device in the guest's mountinfo: %q", got.WorkDevice)
	if len(got.WorkDevice) != 2 || strings.Fields(got.WorkDevice[0])[4] != "/" || strings.Fields(got.WorkDevice[1])[4] != "/work" {
		t.Errorf("the work mount's device is mounted %d times (%q); want at / and /work alone", len(got.WorkDevice), got.WorkDevice)
	}
	fr := s.(sandbox.FileRunner)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	w, err := fr.RunFiles(ctx, sandbox.FilesRequest{FilesCall: sandbox.FilesCall{Scope: sandbox.FilesScopeWork, Op: sandbox.FilesWrite,
		Path: []byte("a/b.txt"), Content: []byte("hello"), Mode: sandbox.FilesWriteCreateOnly, Parents: true}, Timeout: 20 * time.Second})
	if err != nil || w.Outcome != sandbox.ProjectOutcomeCompleted || w.Error != sandbox.FilesErrorNone || w.Written != 5 {
		t.Fatalf("a write through the installed helper: %+v, %v", w, err)
	}
	if r := e2bSnippet(t, s, `process.stdout.write(require("fs").readFileSync("a/b.txt", "latin1"))`); r.Stdout != "hello" {
		t.Fatalf("the guest read %q back", r.Stdout)
	}
	// The helper runs with the guest's permissions alone, though root starts it: a file and a
	// folder only root may read answer PERMISSION_DENIED in the sandbox scope.
	for _, c := range []sandbox.FilesCall{
		{Scope: sandbox.FilesScopeSandbox, Op: sandbox.FilesRead, Path: []byte("/etc/shadow"), MaxBytes: 4096},
		{Scope: sandbox.FilesScopeSandbox, Op: sandbox.FilesList, Path: []byte("/var/lib/plimsoll-stage"), Budget: 8192},
	} {
		r, err := fr.RunFiles(ctx, sandbox.FilesRequest{FilesCall: c, Timeout: 20 * time.Second})
		if err != nil || r.Outcome != sandbox.ProjectOutcomeCompleted || r.Error != sandbox.FilesErrorPermissionDenied || len(r.Content) != 0 || len(r.Entries) != 0 {
			t.Errorf("%s %s as the guest: %+v, %v; want PERMISSION_DENIED", c.Op, c.Path, r, err)
		}
	}
}

// A template that holds this build of the helper at its path (as an operator bakes it in)
// keeps it: nothing is uploaded or installed over it (its mode, 0511 here, is the template's,
// where an install makes 0711).
func TestE2BSessionDockerKeepsAMatchingHelper(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	// The stand-in's image is a project image of this tree, so its helper is this build
	// (the docker suite refuses images whose inputs label is not the tree's).
	img, err := e2bDerived(f.image, "RUN mkdir -p /usr/lib/plimsoll && cp /usr/local/libexec/plimsoll-helper /usr/lib/plimsoll/plimsoll-helper && chmod 511 /usr/lib/plimsoll/plimsoll-helper\n")
	if err != nil {
		t.Fatal(err)
	}
	f.image = img
	s := openE2B(t, f.provider())
	if got := readHelperAtOpen(t, s); got.Mode != 0o511 || got.UID != 0 {
		t.Fatalf("the template's helper after the open: %+v; want it kept as the template made it (mode 0511)", got)
	}
	if res := e2bSnippet(t, s, `process.stdout.write(String(require("fs").readdirSync("/usr/lib/plimsoll").length))`); res.Stdout != "1" {
		t.Fatalf("the helper's folder holds %s entries after the open; want the template's helper alone", res.Stdout)
	}
}

// A template that holds another build of the helper at its path, installed as an open would
// install it (root's, mode 0711), is refused by its bytes: the build pinned 1b403142 (file
// contract 5, the same size as this one, from git history) and this build with one byte of its
// identity changed. Each refusal is the helper's, not dispatched, and deletes its sandbox.
func TestE2BSessionDockerRefusesOtherBuilds(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	base := f.image
	builds := map[string][]byte{"same size": sandbox.SameSizeOtherHelperBuild(t)}
	if b, ok := sandbox.EarlierHelperBuild(t); ok {
		builds["1b403142"] = b
	}
	for name, content := range builds {
		t.Run(name, func(t *testing.T) {
			f.image = sandbox.ImageWithFile(t, base, content, "RUN mkdir -p /usr/lib/plimsoll && mv /plimsoll-test-file /usr/lib/plimsoll/plimsoll-helper && chmod 711 /usr/lib/plimsoll/plimsoll-helper\n")
			defer func() { f.image = base }()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			s, err := f.provider().OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
			if err == nil {
				_ = s.Close(context.Background())
				<-s.Done()
				t.Fatal("a session opened on a template holding another build of the helper")
			}
			if !errors.Is(err, sandbox.ErrE2BHelper) || !strings.Contains(err.Error(), "the file at its path has sha256 ") {
				t.Errorf("the refusal %q: want the helper's, naming the bytes", err)
			}
			if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
				t.Errorf("the refusal %q is marked %v, %v; want not dispatched, environment", err, reason, ok)
			}
		})
	}
	if n := f.containers(t); n != 0 {
		t.Errorf("the refused opens left %d sandboxes", n)
	}
}

// (The test names stay short: the stand-in's envd socket lives under the test's temporary
// folder, which carries the name, and a Unix socket's path is at most 107 bytes.)
//
// What the open refuses at the helper's path, each before any of the caller's code: a link
// (to a copy of this very build, so only the link itself is refused), a copy that is not this
// build, a folder, a copy the guest owns, a copy every user may read (dumpable from its exec,
// session-files-14), and a folder of the guest's or one every user may
// write. Each refusal is not dispatched, reason environment, and its sandbox is deleted.
func TestE2BSessionDockerHelperPathRefusals(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	base := f.image
	for _, c := range []struct {
		name, steps, says string
		helperErr         bool // the daemon's own check of the bytes, not the open's
	}{
		{"link", "RUN mkdir -p /usr/lib/plimsoll /opt/h && cp /usr/local/libexec/plimsoll-helper /opt/h/plimsoll-helper && chmod 555 /opt/h/plimsoll-helper && ln -s /opt/h/plimsoll-helper /usr/lib/plimsoll/plimsoll-helper\n",
			"other than a regular file", false},
		{"different copy", "RUN mkdir -p /usr/lib/plimsoll && printf 'not the helper' > /usr/lib/plimsoll/plimsoll-helper && chmod 711 /usr/lib/plimsoll/plimsoll-helper\n",
			"sha256", true},
		{"folder", "RUN mkdir -p /usr/lib/plimsoll/plimsoll-helper\n", "other than a regular file", false},
		{"guest-owned copy", "RUN mkdir -p /usr/lib/plimsoll && cp /usr/local/libexec/plimsoll-helper /usr/lib/plimsoll/plimsoll-helper && chown 61000:61000 /usr/lib/plimsoll/plimsoll-helper\n",
			"not the root's alone", false},
		{"readable copy", "RUN mkdir -p /usr/lib/plimsoll && cp /usr/local/libexec/plimsoll-helper /usr/lib/plimsoll/plimsoll-helper && chmod 755 /usr/lib/plimsoll/plimsoll-helper\n",
			"readable by the root alone", false},
		{"guest-owned folder", "RUN mkdir -p /usr/lib/plimsoll && chown 61000:61000 /usr/lib/plimsoll\n", "not the root's alone", false},
		{"folder every user may write", "RUN mkdir -p /usr/lib/plimsoll && chmod 1777 /usr/lib/plimsoll\n", "not the root's alone", false},
		{"link as the folder", "RUN mkdir -p /opt/hd && ln -s /opt/hd /usr/lib/plimsoll\n", "not a directory", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			img, err := e2bDerived(base, c.steps)
			if err != nil {
				t.Fatal(err)
			}
			// The cases run one after another, each on the stand-in with its image.
			f.image = img
			defer func() { f.image = base }()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			s, err := f.provider().OpenSession(ctx, sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 64 << 20})
			if err == nil {
				_ = s.Close(context.Background())
				<-s.Done()
				t.Fatal("a session opened")
			}
			if !errors.Is(err, sandbox.ErrUnsupported) || errors.Is(err, sandbox.ErrE2BHelper) != c.helperErr {
				t.Errorf("the refusal %q: ErrUnsupported %v, ErrE2BHelper %v (want %v)", err, errors.Is(err, sandbox.ErrUnsupported), errors.Is(err, sandbox.ErrE2BHelper), c.helperErr)
			}
			if reason, ok := sandbox.NotDispatchedReason(err); !ok || reason != sandbox.RefusalEnvironment {
				t.Errorf("the refusal %q is marked %v, %v; want not dispatched, environment", err, reason, ok)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("the refusal %q does not say %q", err, c.says)
			}
		})
	}
	if n := f.containers(t); n != 0 {
		t.Errorf("the refused opens left %d sandboxes", n)
	}
}

// A template that mounts its own /work and bind-mounts an outside folder below it, at
// /work/shared (review finding session-files-19, the reviewer's layout): the open's work-alias
// rule accepts it (the bind's device is not the work mount's), so the native helper's work
// scope is what keeps a call inside the work folder. Every call across the mount is
// PERMISSION_DENIED and nothing reaches the outside folder, though every user may write it; a
// recursive listing lists the mount's folder as one it could not enter; the sandbox scope
// reaches it.
func TestE2BSessionDockerWorkScopeNeverCrossesANestedMount(t *testing.T) {
	t.Parallel()
	f := newE2BFake(t)
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "dir"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "dir", "x"), []byte("outside\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{outside, filepath.Join(outside, "dir"), filepath.Join(outside, "dir", "x")} {
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	f.runArgs = []string{"--tmpfs", "/work:rw,exec,mode=1777,size=64m", "--mount", "type=bind,source=" + outside + ",target=/work/shared"}
	s := openE2B(t, f.provider())
	fr := s.(sandbox.FileRunner)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	call := func(c sandbox.FilesCall) sandbox.FilesResult {
		t.Helper()
		r, err := fr.RunFiles(ctx, sandbox.FilesRequest{FilesCall: c, Timeout: 20 * time.Second})
		if err != nil || r.Outcome != sandbox.ProjectOutcomeCompleted {
			t.Fatalf("%s %q: %+v, %v", c.Op, c.Path, r, err)
		}
		return r
	}
	work := sandbox.FilesScopeWork
	for _, c := range []sandbox.FilesCall{
		{Scope: work, Op: sandbox.FilesStat, Path: []byte("shared")},
		{Scope: work, Op: sandbox.FilesRead, Path: []byte("shared/dir/x"), MaxBytes: 64},
		{Scope: work, Op: sandbox.FilesWrite, Path: []byte("shared/dir/planted"), Content: []byte("p"), Mode: sandbox.FilesWriteReplace},
		{Scope: work, Op: sandbox.FilesWrite, Path: []byte("shared/dir/x"), Content: []byte("p"), Mode: sandbox.FilesWriteAppend},
		{Scope: work, Op: sandbox.FilesMakeDir, Path: []byte("shared/made")},
		{Scope: work, Op: sandbox.FilesRemove, Path: []byte("shared/dir/x")},
		{Scope: work, Op: sandbox.FilesList, Path: []byte("shared"), Budget: 8192},
	} {
		if r := call(c); r.Error != sandbox.FilesErrorPermissionDenied {
			t.Errorf("%s %q across the mount: error %v, want PERMISSION_DENIED", c.Op, c.Path, r.Error)
		}
	}
	l := call(sandbox.FilesCall{Scope: work, Op: sandbox.FilesList, Path: []byte("."), Recursive: true, Budget: 65536})
	var shared []sandbox.FilesEntry
	for _, e := range l.Entries {
		if strings.HasPrefix(string(e.Path), "shared") {
			shared = append(shared, e)
		}
	}
	if l.Error != sandbox.FilesErrorNone || len(shared) != 1 || string(shared[0].Path) != "shared" || shared[0].Type != sandbox.FilesTypeUnreadable {
		t.Errorf("a recursive listing of the work folder: %v, entries under shared %+v; want shared alone, unreadable", l.Error, shared)
	}
	r := call(sandbox.FilesCall{Scope: sandbox.FilesScopeSandbox, Op: sandbox.FilesRead, Path: []byte("/work/shared/dir/x"), MaxBytes: 64})
	if r.Error != sandbox.FilesErrorNone || string(r.Content) != "outside\n" {
		t.Errorf("the sandbox scope at the mount: %+v", r)
	}
	names, err := os.ReadDir(filepath.Join(outside, "dir"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(outside, "dir", "x"))
	if err != nil || len(names) != 1 || string(b) != "outside\n" {
		t.Errorf("the outside folder after the calls: %d entries, x holds %q (%v); want x alone, unchanged", len(names), b, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "made")); err == nil {
		t.Error("a folder was made in the outside folder")
	}
}
