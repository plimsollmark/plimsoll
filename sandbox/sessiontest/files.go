package sessiontest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The file cases: what every session provider that states file calls (sandbox.FileRunner on
// its sessions, PayloadEnvironment.FileScopes in its SessionEnvironments) must do with them.
// The statement itself is checked on every provider, so one that does not state file calls
// must not carry them either, and one that states a scope must carry exactly those.
//
// The cases are written with work-scope paths (work, read, write: relative to the work
// folder). A provider that states the work scope runs them so. One that states the sandbox
// scope alone (its work folder is not a mount of its own, so the helper refuses the work
// scope: OpenShell's) runs each in the sandbox scope instead, every work path named as the
// absolute path under the work folder (asStated); a case marked work tests what only the
// work scope promises (a link that leaves the work folder is refused) and is not run there,
// by the statement: FileCallsAreStatedWhereTheyRun names each case left out and why in its
// log. Not a t.Skip: a live suite fails on a skipped test, and a case the provider's own
// statement rules out is no coverage missing.

// fileCases are the cases a provider that states file calls runs.
var fileCases = []struct {
	name string
	// work: the case tests the work scope's confinement, so it runs only where the provider
	// states that scope.
	work bool
	run  func(*testing.T, sandbox.SessionProvider, Config)
}{
	{"FileOperationsRoundTrip", false, fileRoundTrips},
	{"FileLinksInsideFollowedLeavingRefused", true, fileLinks},
	{"FileSandboxScopeFollowsLinksOut", false, fileSandboxLinks},
	{"FileScopeNotStatedIsRefusedUndispatched", false, fileScopeRefused},
	{"FileListingPagesNamesOfAnyByte", false, fileListingPages},
	{"FileListingNamesAFolderItCannotEnter", false, fileUnreadableFolder},
	{"FilePipeAnswersAtOnce", false, filePipe},
	{"FileHardLinkReadsOnlyWhatTheGuestCan", false, fileHardLink},
	{"FileDeadlineLeavesNoHelperBehind", false, fileDeadline},
	{"FileCallCutMayHaveRun", false, fileCut},
	{"FileWritesAlonePastTheDiskBudgetEndTheSession", false, fileWritesPastDiskBudget},
	{"FileReadAnswersAKernelFileOfSizeZero", false, fileReadKernelFile},
}

// runFileCases runs every file case the provider's statement covers.
func runFileCases(p sandbox.SessionProvider, cfg Config, run func(string, func(*testing.T))) {
	scopes := p.SessionEnvironments().Project.FileScopes
	if len(scopes) == 0 {
		return
	}
	for _, c := range fileCases {
		if c.work && !slices.Contains(scopes, sandbox.FilesScopeWork) {
			continue
		}
		run(c.name, func(t *testing.T) { c.run(t, p, cfg) })
	}
}

// notRun are the file cases a statement of scopes rules out.
func notRun(scopes []sandbox.FilesScope) []string {
	var out []string
	for _, c := range fileCases {
		if len(scopes) > 0 && c.work && !slices.Contains(scopes, sandbox.FilesScopeWork) {
			out = append(out, c.name)
		}
	}
	return out
}

func scopeWords(scopes []sandbox.FilesScope) []string {
	var out []string
	for _, s := range scopes {
		switch s {
		case sandbox.FilesScopeWork:
			out = append(out, "work")
		case sandbox.FilesScopeSandbox:
			out = append(out, "sandbox")
		default:
			out = append(out, fmt.Sprintf("scope %d", s))
		}
	}
	return out
}

// filesStated checks that the provider states file calls exactly where its sessions carry
// them, in the same scopes in every environment a session states and on the session itself,
// in the wire's order, none twice.
func filesStated(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	env := p.SessionEnvironments()
	s := open(t, p, cfg.Lifetime)
	var runs []sandbox.FilesScope
	if fr, ok := s.(sandbox.FileRunner); ok {
		runs = fr.FileScopes()
		if len(runs) == 0 {
			t.Errorf("the session is a file runner that states no scope")
		}
		if !strings.HasPrefix(fr.WorkDir(), "/") {
			t.Errorf("the session's work folder %q is not an absolute path", fr.WorkDir())
		}
	}
	if len(runs) > 0 {
		want := slices.DeleteFunc([]sandbox.FilesScope{sandbox.FilesScopeWork, sandbox.FilesScopeSandbox},
			func(sc sandbox.FilesScope) bool { return !slices.Contains(runs, sc) })
		if !slices.Equal(runs, want) {
			t.Errorf("the session states the scopes %v; want work and sandbox, in that order, each once", scopeWords(runs))
		}
	}
	if left := notRun(env.Project.FileScopes); len(left) > 0 {
		t.Logf("the provider states file calls in the scopes %v, not the work scope, so the cases of the work scope's confinement are not run: %v",
			scopeWords(env.Project.FileScopes), left)
	}
	opened := s.Environments()
	for name, got := range map[string][]sandbox.FilesScope{
		"SessionEnvironments().JavaScript": env.JavaScript.FileScopes, "SessionEnvironments().Project": env.Project.FileScopes,
		"the session's JavaScript": opened.JavaScript.FileScopes, "the session's Project": opened.Project.FileScopes,
	} {
		if !slices.Equal(got, runs) {
			t.Errorf("%s states the file scopes %v; the session carries file calls in %v", name, scopeWords(got), scopeWords(runs))
		}
	}
}

// takesWork reports whether s states the work scope.
func takesWork(t *testing.T, s sandbox.Session) bool {
	return slices.Contains(fileRunner(t, s).FileScopes(), sandbox.FilesScopeWork)
}

// asStated is c as the session takes it: c itself where the session states the work scope or
// c names the sandbox scope; otherwise c in the sandbox scope, each work path (the path, a
// rename's destination, each of a read_many's) named as the absolute path under the work
// folder, "." as the work folder itself. Nothing else of c changes: a listing names its
// entries from the folder listed in both scopes, so its answer reads the same.
func asStated(t *testing.T, s sandbox.Session, c sandbox.FilesCall) sandbox.FilesCall {
	t.Helper()
	if c.Scope != sandbox.FilesScopeWork || takesWork(t, s) {
		return c
	}
	root := fileRunner(t, s).WorkDir()
	abs := func(p []byte) []byte {
		if p == nil {
			return nil
		}
		if string(p) == "." {
			return []byte(root)
		}
		return append([]byte(root+"/"), p...)
	}
	c.Scope = sandbox.FilesScopeSandbox
	c.Path, c.To = abs(c.Path), abs(c.To)
	if c.Paths != nil {
		paths := make([][]byte, len(c.Paths))
		for i, p := range c.Paths {
			paths[i] = abs(p)
		}
		c.Paths = paths
	}
	return c
}

func fileRunner(t *testing.T, s sandbox.Session) sandbox.FileRunner {
	t.Helper()
	fr, ok := s.(sandbox.FileRunner)
	if !ok {
		t.Fatal("the session carries no file calls, although its provider states them")
	}
	return fr
}

// file runs one file call with timeout and fails the test on an error (not an answered one).
func file(t *testing.T, s sandbox.Session, c sandbox.FilesCall, timeout time.Duration) sandbox.FilesResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+60*time.Second)
	defer cancel()
	res, err := fileRunner(t, s).RunFiles(ctx, sandbox.FilesRequest{FilesCall: asStated(t, s, c), Timeout: timeout})
	if err != nil {
		t.Fatalf("%s %q: %v", c.Op, c.Path, err)
	}
	statesTier(t, s, "file call", res.Isolation)
	return res
}

func work(op sandbox.FilesOp, path string) sandbox.FilesCall {
	return sandbox.FilesCall{Scope: sandbox.FilesScopeWork, Op: op, Path: []byte(path)}
}

// done runs c and requires it answered with error want (FilesErrorNone for success).
func done(t *testing.T, s sandbox.Session, c sandbox.FilesCall, want sandbox.FilesError) sandbox.FilesResult {
	t.Helper()
	res := file(t, s, c, 20*time.Second)
	if res.Outcome != sandbox.ProjectOutcomeCompleted || res.Error != want {
		t.Fatalf("%s %q: outcome %v, error %v (%s); want completed, %v", c.Op, c.Path, res.Outcome, res.Error, res.Errno, want)
	}
	if want == sandbox.FilesErrorNone && res.Op != c.Op {
		t.Fatalf("%s %q: the answer names %q", c.Op, c.Path, res.Op)
	}
	return res
}

func write(path, content string, mode sandbox.FilesWriteMode, parents bool) sandbox.FilesCall {
	c := work(sandbox.FilesWrite, path)
	c.Content, c.Mode, c.Parents = []byte(content), mode, parents
	return c
}

func read(path string, offset uint64, max uint32) sandbox.FilesCall {
	c := work(sandbox.FilesRead, path)
	c.Offset, c.MaxBytes = offset, max
	return c
}

// Every operation, its answer, and the errors of the contract a caller meets most.
func fileRoundTrips(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	tok := token()
	done(t, s, write("notes/a.txt", tok, sandbox.FilesWriteReplace, false), sandbox.FilesErrorNotFound)
	if w := done(t, s, write("notes/a.txt", tok, sandbox.FilesWriteCreateOnly, true), sandbox.FilesErrorNone); w.Written != uint64(len(tok)) {
		t.Fatalf("write answered %d bytes for %d", w.Written, len(tok))
	}
	done(t, s, write("notes/a.txt", "again", sandbox.FilesWriteCreateOnly, false), sandbox.FilesErrorExists)
	done(t, s, write("notes/a.txt", "+tail", sandbox.FilesWriteAppend, false), sandbox.FilesErrorNone)
	if r := done(t, s, read("notes/a.txt", 0, 1<<20), sandbox.FilesErrorNone); string(r.Content) != tok+"+tail" || r.SizeAtOpen != uint64(len(tok)+5) {
		t.Fatalf("read %q (size %d)", r.Content, r.SizeAtOpen)
	}
	if r := done(t, s, read("notes/a.txt", 2, 3), sandbox.FilesErrorNone); string(r.Content) != tok[2:5] {
		t.Fatalf("a read at an offset got %q", r.Content)
	}
	// What a file call wrote, a snippet reads, and the other way round: one work folder.
	if got := js(t, s, `process.stdout.write(require("fs").readFileSync("notes/a.txt","utf8"))`, 10*time.Second); got.Stdout != tok+"+tail" {
		t.Fatalf("a snippet read %q", got.Stdout)
	}
	js(t, s, `require("fs").writeFileSync("from-js.bin", Buffer.from([0, 255, 10, 1]), {mode: 0o640})`, 10*time.Second)
	if r := done(t, s, read("from-js.bin", 0, 16), sandbox.FilesErrorNone); !bytes.Equal(r.Content, []byte{0, 255, 10, 1}) {
		t.Fatalf("read the snippet's bytes as %v", r.Content)
	}
	st := done(t, s, work(sandbox.FilesStat, "from-js.bin"), sandbox.FilesErrorNone)
	if st.Type != sandbox.FilesTypeFile || st.Size != 4 || st.Mode != 0o640 {
		t.Fatalf("stat: type %v, size %d, mode %o", st.Type, st.Size, st.Mode)
	}
	// replace keeps the file's permission bits.
	done(t, s, write("from-js.bin", "new", sandbox.FilesWriteReplace, false), sandbox.FilesErrorNone)
	if st := done(t, s, work(sandbox.FilesStat, "from-js.bin"), sandbox.FilesErrorNone); st.Mode != 0o640 || st.Size != 3 {
		t.Fatalf("after replace: mode %o, size %d", st.Mode, st.Size)
	}
	if st := done(t, s, work(sandbox.FilesStat, "."), sandbox.FilesErrorNone); st.Type != sandbox.FilesTypeDir {
		t.Fatalf("the work folder's stat: %v", st.Type)
	}
	done(t, s, work(sandbox.FilesStat, "missing"), sandbox.FilesErrorNotFound)
	done(t, s, read("notes", 0, 1), sandbox.FilesErrorIsDir)
	done(t, s, read("notes/a.txt/x", 0, 1), sandbox.FilesErrorNotDir)

	mk := work(sandbox.FilesMakeDir, "d/e")
	done(t, s, mk, sandbox.FilesErrorNotFound)
	mk.Parents = true
	done(t, s, mk, sandbox.FilesErrorNone)
	done(t, s, mk, sandbox.FilesErrorNone) // already there
	ren := work(sandbox.FilesRename, "notes/a.txt")
	ren.To = []byte("d/e/b.txt")
	done(t, s, ren, sandbox.FilesErrorNone)
	done(t, s, write("notes/c.txt", "c", sandbox.FilesWriteReplace, false), sandbox.FilesErrorNone)
	ren = work(sandbox.FilesRename, "notes/c.txt")
	ren.To = []byte("d/e/b.txt")
	done(t, s, ren, sandbox.FilesErrorExists)
	ren.Replace = true
	done(t, s, ren, sandbox.FilesErrorNone)

	many := sandbox.FilesCall{Scope: sandbox.FilesScopeWork, Op: sandbox.FilesReadMany, MaxBytes: 1 << 20, Budget: 1 << 20,
		Paths: [][]byte{[]byte("d/e/b.txt"), []byte("missing"), []byte("from-js.bin")}}
	m := done(t, s, many, sandbox.FilesErrorNone)
	if len(m.Items) != 3 || m.More || string(m.Items[0].Content) != "c" || m.Items[1].Error != sandbox.FilesErrorNotFound || string(m.Items[2].Content) != "new" {
		t.Fatalf("read_many: %+v", m)
	}

	rmDir := work(sandbox.FilesRemove, "d/e")
	rmDir.Dir = true
	done(t, s, rmDir, sandbox.FilesErrorNotEmpty)
	done(t, s, work(sandbox.FilesRemove, "d/e"), sandbox.FilesErrorIsDir)
	done(t, s, work(sandbox.FilesRemove, "d/e/b.txt"), sandbox.FilesErrorNone)
	done(t, s, rmDir, sandbox.FilesErrorNone)

	list := work(sandbox.FilesList, ".")
	list.Recursive, list.Budget = true, 1<<20
	l := done(t, s, list, sandbox.FilesErrorNone)
	var names []string
	for _, e := range l.Entries {
		names = append(names, string(e.Path))
	}
	want := []string{"d", "from-js.bin", "notes"}
	if !slices.Equal(names, want) || l.More {
		t.Fatalf("list: %q (more %v); want %q", names, l.More, want)
	}
	list.Match = []byte("**/*.bin")
	if l := done(t, s, list, sandbox.FilesErrorNone); len(l.Entries) != 1 || string(l.Entries[0].Path) != "from-js.bin" {
		t.Fatalf("list with a glob: %+v", l.Entries)
	}
	// The session goes on as before: a later call of another kind runs.
	if got := js(t, s, `console.log("after")`, 10*time.Second); strings.TrimSpace(got.Stdout) != "after" {
		t.Fatalf("a snippet after the file calls: %+v", got)
	}
}

// Links per docs/session-files.md ("Links, per operation"): in the work scope a link that stays
// inside the work folder is followed, at any part, and one that leaves it is refused (SYMLINK),
// nothing written through it; stat, remove, rename and a replace act on a link at the last part
// itself. In the sandbox scope the kernel follows them, as the guest's shell would. A listing
// names a link and never follows it.
func fileLinks(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	dir := fileRunner(t, s).WorkDir()
	res := js(t, s, `const fs = require("fs");
fs.mkdirSync("real/sub", { recursive: true });
fs.writeFileSync("real/sub/f", "inside");
fs.mkdirSync("/tmp/plimsoll-outside-files", { recursive: true });
fs.writeFileSync("/tmp/plimsoll-outside-files/f", "outside");
fs.symlinkSync("real", "first");
fs.symlinkSync("sub", "real/middle");
fs.symlinkSync("f", "real/sub/last");
fs.symlinkSync("../../../tmp/plimsoll-outside-files/f", "real/sub/up");
fs.symlinkSync("/tmp/plimsoll-outside-files", "out");
fs.symlinkSync("real/sub/f", "replaced");
console.log("made")`, 10*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("making the links: %+v", res)
	}
	for _, path := range []string{"first/sub/f", "real/middle/f", "real/sub/last"} {
		if r := done(t, s, read(path, 0, 64), sandbox.FilesErrorNone); string(r.Content) != "inside" {
			t.Fatalf("read %q through %s, a link inside the work folder", r.Content, path)
		}
		c := read(dir+"/"+path, 0, 64)
		c.Scope = sandbox.FilesScopeSandbox
		if r := done(t, s, c, sandbox.FilesErrorNone); string(r.Content) != "inside" {
			t.Fatalf("the sandbox scope read %q through %s", r.Content, path)
		}
	}
	for _, path := range []string{"out/f", "real/sub/up"} {
		done(t, s, read(path, 0, 64), sandbox.FilesErrorSymlink)
		done(t, s, write(path, "through", sandbox.FilesWriteAppend, false), sandbox.FilesErrorSymlink)
	}
	done(t, s, work(sandbox.FilesStat, "out/f"), sandbox.FilesErrorSymlink)
	done(t, s, write("out/f", "through", sandbox.FilesWriteReplace, false), sandbox.FilesErrorSymlink)
	done(t, s, write("out/new", "through", sandbox.FilesWriteCreateOnly, true), sandbox.FilesErrorSymlink)
	ren := work(sandbox.FilesRename, "real/sub/f")
	ren.To = []byte("out/moved")
	done(t, s, ren, sandbox.FilesErrorSymlink)
	// The last part's link itself: stat names it, an append goes through it (it stays inside),
	// a replace puts a file at its name.
	if r := done(t, s, work(sandbox.FilesStat, "real/sub/last"), sandbox.FilesErrorNone); r.Type != sandbox.FilesTypeLink {
		t.Fatalf("stat of a link at the last part: %v", r.Type)
	}
	done(t, s, write("real/sub/last", "+", sandbox.FilesWriteAppend, false), sandbox.FilesErrorNone)
	done(t, s, write("replaced", "a file now", sandbox.FilesWriteReplace, false), sandbox.FilesErrorNone)
	if r := done(t, s, work(sandbox.FilesStat, "replaced"), sandbox.FilesErrorNone); r.Type != sandbox.FilesTypeFile {
		t.Fatalf("a replace at a link's name left a %v", r.Type)
	}
	got := js(t, s, `const fs = require("fs"); process.stdout.write(fs.readFileSync("/tmp/plimsoll-outside-files/f", "utf8") + ":" + fs.readdirSync("/tmp/plimsoll-outside-files").join(",") + ":" + fs.readFileSync("real/sub/f", "utf8"))`, 10*time.Second)
	if got.Stdout != "outside:f:inside+" {
		t.Fatalf("something was written through a link: %q", got.Stdout)
	}
	st := work(sandbox.FilesStat, dir+"/first")
	st.Scope = sandbox.FilesScopeSandbox
	if r := done(t, s, st, sandbox.FilesErrorNone); r.Type != sandbox.FilesTypeLink {
		t.Fatalf("the sandbox scope's stat of a link: %v", r.Type)
	}
	list := work(sandbox.FilesList, ".")
	list.Recursive, list.Budget = true, 1<<20
	types := map[string]sandbox.FilesEntryType{}
	for _, e := range done(t, s, list, sandbox.FilesErrorNone).Entries {
		types[string(e.Path)] = e.Type
	}
	if types["first"] != sandbox.FilesTypeLink || types["out"] != sandbox.FilesTypeLink || types["real/sub/last"] != sandbox.FilesTypeLink {
		t.Fatalf("the listing's links: %v", types)
	}
	for name := range types {
		if strings.HasPrefix(name, "first/") || strings.HasPrefix(name, "out/") {
			t.Fatalf("the listing followed a link: %q", name)
		}
	}
}

// In the sandbox scope a link is followed wherever it leads, out of the work folder too, as
// the guest's own shell follows it (docs/session-files.md, "Scopes"): what a caller that
// confines paths by their names alone, on a provider that states the sandbox scope only,
// must know of a link the guest made inside the work folder. A listing still names the link
// and never follows it.
func fileSandboxLinks(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	dir := fileRunner(t, s).WorkDir()
	tok := token()
	outside := "/tmp/plimsoll-outside-" + tok
	res := js(t, s, `const fs = require("fs");
fs.mkdirSync(`+jsString(outside)+`, { recursive: true });
fs.writeFileSync(`+jsString(outside+"/f")+`, "outside");
fs.mkdirSync("in", { recursive: true });
fs.symlinkSync(`+jsString(outside)+`, "in/out");
console.log("made")`, 10*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("making the link: %+v", res)
	}
	sb := func(c sandbox.FilesCall) sandbox.FilesCall {
		c.Scope = sandbox.FilesScopeSandbox
		c.Path = append([]byte(dir+"/"), c.Path...)
		return c
	}
	if r := done(t, s, sb(read("in/out/f", 0, 64)), sandbox.FilesErrorNone); string(r.Content) != "outside" {
		t.Fatalf("the sandbox scope read %q through a link out of the work folder", r.Content)
	}
	done(t, s, sb(write("in/out/f", "+through", sandbox.FilesWriteAppend, false)), sandbox.FilesErrorNone)
	got := js(t, s, `process.stdout.write(require("fs").readFileSync(`+jsString(outside+"/f")+`, "utf8"))`, 10*time.Second)
	if got.Stdout != "outside+through" {
		t.Fatalf("an append through the link left %q outside", got.Stdout)
	}
	list := sb(work(sandbox.FilesList, "in"))
	list.Recursive, list.Budget = true, sessionkit.MinFileBudget
	l := done(t, s, list, sandbox.FilesErrorNone)
	if len(l.Entries) != 1 || string(l.Entries[0].Path) != "out" || l.Entries[0].Type != sandbox.FilesTypeLink {
		t.Fatalf("the listing of the folder holding the link: %+v", l.Entries)
	}
}

// jsString is s as a JavaScript string literal (s holds no quote or backslash here).
func jsString(s string) string { return `"` + s + `"` }

// A file call in a scope the session does not state is refused before anything starts,
// marked not dispatched, reason unsupported; a provider that states both scopes refuses none,
// so there the case checks that each scope answers.
func fileScopeRefused(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	fr := fileRunner(t, s)
	stated := fr.FileScopes()
	for _, scope := range []sandbox.FilesScope{sandbox.FilesScopeWork, sandbox.FilesScopeSandbox} {
		c := sandbox.FilesCall{Scope: scope, Op: sandbox.FilesStat, Path: []byte(".")}
		if scope == sandbox.FilesScopeSandbox {
			c.Path = []byte(fr.WorkDir())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
		res, err := fr.RunFiles(ctx, sandbox.FilesRequest{FilesCall: c, Timeout: 20 * time.Second})
		cancel()
		if slices.Contains(stated, scope) {
			if err != nil || res.Outcome != sandbox.ProjectOutcomeCompleted {
				t.Errorf("a stat in the stated %v scope: %+v, %v", scopeWords([]sandbox.FilesScope{scope}), res, err)
			}
			continue
		}
		if reason, marked := sandbox.NotDispatchedReason(err); !marked || reason != sandbox.RefusalUnsupported || !errors.Is(err, sandbox.ErrUnsupported) {
			t.Errorf("a stat in the %v scope, which the session does not state: %+v, %v (marked %v, %v); want refused, not dispatched, unsupported",
				scopeWords([]sandbox.FilesScope{scope}), res, err, marked, reason)
		}
	}
	if s.Err() != nil {
		t.Fatalf("the session ended: %v", s.Err())
	}
}

// A listing pages at its budget with nothing missed or repeated, and every name comes back as
// its bytes, a newline or a byte that is not UTF-8 included, so it can be named again.
func fileListingPages(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	names := []string{"plain.txt", "with\nnewline", "not-utf8-\xff\xfe", "sp ace", "dir\x01/inner\n", "dir\x01/z\x80z"}
	for i, n := range names {
		done(t, s, write(n, fmt.Sprintf("%d", i), sandbox.FilesWriteCreateOnly, true), sandbox.FilesErrorNone)
	}
	want := append(slices.Clone(names), "dir\x01", "pages")
	// Names long enough that the least budget (8 KiB) takes several pages.
	for i := range 60 {
		n := fmt.Sprintf("pages/%03d-%s", i, strings.Repeat("x", 190))
		done(t, s, write(n, "", sandbox.FilesWriteCreateOnly, true), sandbox.FilesErrorNone)
		want = append(want, n)
	}
	slices.Sort(want)
	var got []string
	list := work(sandbox.FilesList, ".")
	list.Recursive, list.Budget = true, sessionkit.MinFileBudget
	for pages := 0; ; pages++ {
		if pages > 2*len(want) {
			t.Fatalf("the listing did not end after %d pages: %q", pages, got)
		}
		l := done(t, s, list, sandbox.FilesErrorNone)
		for _, e := range l.Entries {
			got = append(got, string(e.Path))
		}
		if !l.More {
			break
		}
		if len(l.Entries) == 0 {
			t.Fatalf("a page with no entry asks for more: %q", got)
		}
		list.After = l.Entries[len(l.Entries)-1].Path
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("listed %q\nwant   %q", got, want)
	}
	for i, n := range names {
		if r := done(t, s, read(n, 0, 64), sandbox.FilesErrorNone); string(r.Content) != fmt.Sprintf("%d", i) {
			t.Fatalf("read %q back as %q", n, r.Content)
		}
	}
	if got := js(t, s, `process.stdout.write(require("fs").readFileSync(Buffer.from("not-utf8-\xff\xfe", "latin1")).toString())`, 10*time.Second); got.Stdout != "2" {
		t.Fatalf("a snippet read the name that is not UTF-8 as %q", got.Stdout)
	}
	// Each name the listing returned removes the file it names, a newline or 0xff in it.
	for _, n := range []string{"with\nnewline", "not-utf8-\xff\xfe", "dir\x01/z\x80z"} {
		done(t, s, work(sandbox.FilesRemove, n), sandbox.FilesErrorNone)
		done(t, s, work(sandbox.FilesStat, n), sandbox.FilesErrorNotFound)
	}
	if got := js(t, s, `process.stdout.write(String(require("fs").readdirSync(".", { encoding: "buffer" }).length))`, 10*time.Second); got.Stdout != "4" {
		t.Fatalf("after the removes the work folder holds %s entries, want 4", got.Stdout)
	}
}

// A recursive listing that meets a folder the guest may not enter (it may not read or search
// it) names that folder UNREADABLE and goes on past it, paging included, rather than ending the
// whole listing with PERMISSION_DENIED (which made a recursive listing of the sandbox's "/"
// answer nothing) or listing the folder as if it were empty. A flat listing enters nothing, so
// it names the folder a folder; a listing of the folder itself is PERMISSION_DENIED.
func fileUnreadableFolder(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	res := js(t, s, `const fs = require("fs");
for (const f of ["a/x", "shut/b", "shut/inner/c", "unsearchable/d", "z"]) { fs.mkdirSync(require("path").dirname(f), { recursive: true }); fs.writeFileSync(f, "1") }
fs.chmodSync("shut", 0o000); fs.chmodSync("unsearchable", 0o644);
let enters = true; try { fs.readdirSync("shut") } catch { enters = false }
process.stdout.write(String(enters))`, 10*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("making the folders: %+v", res)
	}
	defer js(t, s, `const fs = require("fs"); fs.chmodSync("shut", 0o755); fs.chmodSync("unsearchable", 0o755)`, 10*time.Second)
	if res.Stdout == "true" {
		t.Skip("the guest enters a folder of mode 000 (it holds a capability that passes file permissions), so no folder is closed to it here")
	}
	want := map[string]sandbox.FilesEntryType{"a": sandbox.FilesTypeDir, "a/x": sandbox.FilesTypeFile, "shut": sandbox.FilesTypeUnreadable,
		"unsearchable": sandbox.FilesTypeUnreadable, "z": sandbox.FilesTypeFile}
	list := work(sandbox.FilesList, ".")
	list.Recursive, list.Budget = true, sessionkit.MinFileBudget
	whole := done(t, s, list, sandbox.FilesErrorNone)
	if whole.More || len(whole.Entries) != len(want) {
		t.Fatalf("a recursive listing over two folders the guest may not enter: %d entries, more %v: %+v", len(whole.Entries), whole.More, whole.Entries)
	}
	for _, e := range whole.Entries {
		if want[string(e.Path)] != e.Type || (e.Type == sandbox.FilesTypeUnreadable && e.Size != 0) {
			t.Errorf("%q listed as %v (size %d), want %v", e.Path, e.Type, e.Size, want[string(e.Path)])
		}
	}
	// The listing goes on after an unreadable folder, from a cursor at it as from anywhere.
	list.After = []byte("shut")
	if next := done(t, s, list, sandbox.FilesErrorNone); len(next.Entries) != 2 || string(next.Entries[0].Path) != "unsearchable" || string(next.Entries[1].Path) != "z" {
		t.Errorf("after the cursor at the unreadable folder: %+v", next.Entries)
	}
	flat := work(sandbox.FilesList, ".")
	flat.Budget = sessionkit.MinFileBudget
	for _, e := range done(t, s, flat, sandbox.FilesErrorNone).Entries {
		if e.Type == sandbox.FilesTypeUnreadable {
			t.Errorf("a flat listing, which enters nothing, named %q unreadable", e.Path)
		}
	}
	inside := work(sandbox.FilesList, "shut")
	inside.Recursive, inside.Budget = true, sessionkit.MinFileBudget
	done(t, s, inside, sandbox.FilesErrorPermissionDenied)
}

// A pipe planted at a path is not a file: a read answers NOT_REGULAR at once, never holding the
// call until its deadline.
func filePipe(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	if res := js(t, s, `require("child_process").execFileSync("mkfifo", ["pipe"])`, 10*time.Second); res.ExitCode != 0 {
		t.Fatalf("mkfifo: %+v", res)
	}
	start := time.Now()
	res := file(t, s, read("pipe", 0, 64), 30*time.Second)
	if res.Outcome != sandbox.ProjectOutcomeCompleted || res.Error != sandbox.FilesErrorNotRegular || time.Since(start) > 20*time.Second {
		t.Fatalf("a read of a pipe: %v, %v after %v; want NOT_REGULAR at once", res.Outcome, res.Error, time.Since(start))
	}
	many := sandbox.FilesCall{Scope: sandbox.FilesScopeWork, Op: sandbox.FilesReadMany, MaxBytes: 64, Budget: sessionkit.MinFileBudget, Paths: [][]byte{[]byte("pipe")}}
	if m := done(t, s, many, sandbox.FilesErrorNone); len(m.Items) != 1 || m.Items[0].Error != sandbox.FilesErrorNotRegular {
		t.Fatalf("read_many of a pipe: %+v", m.Items)
	}
}

// The work scope confines names, not inodes: a hard link the guest made to a file elsewhere
// reads as that file, and only when the guest may read it.
func fileHardLink(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	res := js(t, s, `const fs = require("fs"); let linked = false, readable = false;
try { fs.linkSync("/etc/shadow", "h"); linked = true } catch {}
try { fs.readFileSync("/etc/shadow"); readable = true } catch {}
console.log(JSON.stringify({linked, readable}))`, 10*time.Second)
	out := strings.TrimSpace(res.Stdout)
	r := file(t, s, read("h", 0, 1<<20), 20*time.Second)
	switch {
	case strings.Contains(out, `"linked":false`):
		if r.Error != sandbox.FilesErrorNotFound {
			t.Fatalf("no link was made (%s), yet the read answered %v", out, r.Error)
		}
	case strings.Contains(out, `"readable":false`):
		if r.Outcome != sandbox.ProjectOutcomeCompleted || r.Error != sandbox.FilesErrorPermissionDenied || len(r.Content) != 0 {
			t.Fatalf("a link to a file the guest cannot read (%s): %v, %v, %d bytes", out, r.Outcome, r.Error, len(r.Content))
		}
	default:
		t.Logf("the guest may read /etc/shadow here (%s), so the link reads what it could", out)
	}
}

// stopHelpers is a cell whose interpreter, which a session keeps between calls, keeps a thread
// that stops every process of the helper's file commands it sees, the env that starts one
// included: what code of the session can do to a helper (the same user may signal it), and
// how a test holds one past its deadline. A thread, since a cell's child processes die with
// the cell and a timer of the event loop is too slow for a command that takes a millisecond.
const stopHelpers = `globalThis.stopper = new (require("worker_threads").Worker)(` + "`" + `
const fs = require("fs");
for (;;) {
  for (const d of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(d)) continue;
    let c = ""; try { c = fs.readFileSync("/proc/" + d + "/cmdline", "latin1") } catch { continue }
    if (c.includes("plimsoll-helper\0files\0")) { try { process.kill(+d, "SIGSTOP") } catch {} }
  }
}` + "`" + `, { eval: true }); "stopping"`

func stopping(t *testing.T, s sandbox.Session) {
	t.Helper()
	if res := cell(t, s, sandbox.LanguageJavaScript, stopHelpers, 30*time.Second); res.ExitCode != 0 {
		t.Fatalf("the stopping cell: %+v", res)
	}
}

func unstop(t *testing.T, s sandbox.Session) {
	t.Helper()
	cell(t, s, sandbox.LanguageJavaScript, "globalThis.stopper.terminate(); 1", 30*time.Second)
}

// A file call whose helper is held past the call's deadline times out, and the sweep after it
// leaves no helper behind: a docker exec client that goes away does not stop its process.
// The thread can miss a helper that ends at once, so the call is tried a few times.
func fileDeadline(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	stopping(t, s)
	var res sandbox.FilesResult
	for try := 0; try < 5; try++ {
		if res = file(t, s, work(sandbox.FilesStat, "."), 3*time.Second); res.Outcome != sandbox.ProjectOutcomeCompleted {
			break
		}
	}
	if cfg.ExecsWalledOff && res.Outcome == sandbox.ProjectOutcomeCompleted {
		t.Logf("the provider keeps each exec's processes from the others', so the cell could not stop the helper: %+v", res)
		return
	}
	if res.Outcome != sandbox.ProjectOutcomeTimedOut {
		t.Fatalf("a held helper: %+v; want timed out", res)
	}
	unstop(t, s)
	if got := strings.TrimSpace(js(t, s, procsRunning("plimsoll-helper"), 10*time.Second).Stdout); got != "[]" {
		t.Fatalf("a helper outlived its call's deadline: %s", got)
	}
	if s.Err() != nil {
		t.Fatalf("the session ended: %v", s.Err())
	}
	done(t, s, work(sandbox.FilesStat, "."), sandbox.FilesErrorNone)
}

// A file call cut after it started (the session closed under it) is an error with no mark:
// it may have run (a write may have landed), so a caller must not take it for one that did
// not, and a daemon records it as a call that may have run.
func fileCut(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	for try := 0; try < 5; try++ {
		s := open(t, p, cfg.Lifetime)
		fr := fileRunner(t, s)
		stopping(t, s)
		type ended struct {
			res sandbox.FilesResult
			err error
		}
		endc := make(chan ended, 1)
		call := asStated(t, s, write("cut.txt", "maybe", sandbox.FilesWriteReplace, false))
		go func() {
			res, err := fr.RunFiles(context.Background(), sandbox.FilesRequest{FilesCall: call, Timeout: time.Minute})
			endc <- ended{res, err}
		}()
		var got ended
		select {
		case got = <-endc:
			// The thread missed the helper, which answered: try again.
			_ = s.Close(context.Background())
			continue
		case <-time.After(2 * time.Second):
		}
		if err := s.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case got = <-endc:
		case <-time.After(cfg.Teardown + time.Minute):
			t.Fatal("the cut call did not return")
		}
		if got.err == nil {
			t.Fatalf("a call cut by the session's close answered %+v; want an error", got.res)
		}
		if reason, marked := sandbox.NotDispatchedReason(got.err); marked {
			t.Fatalf("a call cut after it started is marked not dispatched (%v): %v", reason, got.err)
		}
		return
	}
	if cfg.ExecsWalledOff {
		t.Log("the provider keeps each exec's processes from the others', so the cell could not hold the helper")
		return
	}
	t.Fatal("the helper answered every time before it could be held")
}

// A session of file writes alone is held to its disk budget (64 MiB here), as a session of
// project calls is (diskBudgetEndsSession): the sweep after an answered write measures what the
// session leaves, so the write that takes it past the budget ends it with disk_exceeded. Before
// review finding session-files-17 an answered write was followed by no sweep, so on docker a
// session of writes grew to its work tmpfs's size and went on.
func fileWritesPastDiskBudget(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	fr := fileRunner(t, s)
	piece := strings.Repeat("x", sessionkit.MaxFileWrite)
	const pieces = 18 // 72 MiB of 4 MiB pieces on a 64 MiB budget
	wrote := 0
	for ; wrote < pieces; wrote++ {
		c := asStated(t, s, write(fmt.Sprintf("disk/%02d.bin", wrote), piece, sandbox.FilesWriteReplace, true))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		res, err := fr.RunFiles(ctx, sandbox.FilesRequest{FilesCall: c, Timeout: time.Minute})
		cancel()
		if errors.Is(err, sandbox.ErrSessionEnded) {
			break
		}
		if err != nil {
			t.Fatalf("write %d: %v", wrote, err)
		}
		if res.Outcome != sandbox.ProjectOutcomeCompleted || res.Error != sandbox.FilesErrorNone {
			t.Fatalf("write %d: outcome %v, error %v (%s)", wrote, res.Outcome, res.Error, res.Errno)
		}
		if wrote == 9 && s.Err() != nil {
			t.Fatalf("after 40 MiB of writes on a 64 MiB budget the session must go on: %v", s.Err())
		}
	}
	select {
	case <-s.Done():
	case <-time.After(cfg.Teardown + 60*time.Second):
		t.Fatalf("the session did not end after %d writes of 4 MiB on a 64 MiB budget", wrote)
	}
	if got := sandbox.SessionEndReason(s.Err()); got != sandbox.SessionDiskExceeded {
		t.Fatalf("the session ended with %v (%v) after %d writes; want disk_exceeded", got, s.Err(), wrote)
	}
	if wrote < 15 {
		t.Fatalf("the session ended after %d writes of 4 MiB, under its 64 MiB budget", wrote)
	}
}

// A file of the kernel's states size 0 at its open and has content: read answers that content,
// with the size at open as it was seen, as read_many does (review finding session-files-18,
// helper contract version 6). /proc/self/status is the helper's own.
func fileReadKernelFile(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	if !slices.Contains(p.SessionEnvironments().Project.FileScopes, sandbox.FilesScopeSandbox) {
		t.Fatal("the case reads /proc in the sandbox scope, which the provider does not state")
	}
	s := open(t, p, cfg.Lifetime)
	c := sandbox.FilesCall{Scope: sandbox.FilesScopeSandbox, Op: sandbox.FilesRead, Path: []byte("/proc/self/status"), MaxBytes: 65536}
	res := done(t, s, c, sandbox.FilesErrorNone)
	if res.SizeAtOpen != 0 || !bytes.HasPrefix(res.Content, []byte("Name:\tplimsoll-helpe")) {
		t.Fatalf("read of /proc/self/status: size at open %d, content %q; want 0 and the helper's status", res.SizeAtOpen, res.Content)
	}
	c.Offset, c.MaxBytes = 6, 8
	if res := done(t, s, c, sandbox.FilesErrorNone); string(res.Content) != "plimsoll" {
		t.Fatalf("read of /proc/self/status from 6: %q; want plimsoll", res.Content)
	}
	many := sandbox.FilesCall{Scope: sandbox.FilesScopeSandbox, Op: sandbox.FilesReadMany, MaxBytes: 65536, Budget: 65536,
		Paths: [][]byte{[]byte("/proc/self/status")}}
	if m := done(t, s, many, sandbox.FilesErrorNone); len(m.Items) != 1 || !bytes.HasPrefix(m.Items[0].Content, []byte("Name:\tplimsoll-helpe")) {
		t.Fatalf("read_many of /proc/self/status: %+v", m.Items)
	}
}
