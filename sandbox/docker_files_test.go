package sandbox_test

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The native helper's file commands (docs/session-files.md), driven one by one inside a real
// docker session, as a session's project call starts a program: as the guest, in the work
// folder, on the image's read-only root, under the runtime the suite selects (runc, or gVisor
// with SANDBOX_DOCKER_RUNTIME=runsc). Each answer is parsed by its framing alone.

const filesCmd = sandbox.NativeHelperPath + " files work"

type frame struct {
	tag     byte
	payload string
}

// parseFrames reads an answer of the helper's file commands: frames of a tag byte, the decimal
// length, ":" and the payload, the last one "." or "+" with the count of entries before it,
// each entry group frames. It fails the test on anything else.
func parseFrames(t *testing.T, out string, group int) ([][]frame, bool) {
	t.Helper()
	var all []frame
	for i := 0; i < len(out); {
		colon := strings.IndexByte(out[i+1:], ':')
		if colon < 0 {
			t.Fatalf("no length at byte %d of %q", i, out)
		}
		digits := out[i+1 : i+1+colon]
		n, err := strconv.Atoi(digits)
		if err != nil || n < 0 || (len(digits) > 1 && digits[0] == '0') {
			t.Fatalf("a bad length %q at byte %d of %q", digits, i, out)
		}
		start := i + 1 + colon + 1
		if start+n > len(out) {
			t.Fatalf("a frame at byte %d runs past the answer %q", i, out)
		}
		all = append(all, frame{out[i], out[start : start+n]})
		i = start + n
	}
	if len(all) == 0 {
		t.Fatalf("an answer with no frames: %q", out)
	}
	last := all[len(all)-1]
	body := all[:len(all)-1]
	count, err := strconv.Atoi(last.payload)
	if (last.tag != '.' && last.tag != '+') || err != nil || count*group != len(body) {
		t.Fatalf("the end frame %q does not count %d entries of %d frames in %q", last.payload, len(body), group, out)
	}
	var entries [][]frame
	for k := 0; k < len(body); k += group {
		for _, f := range body[k : k+group] {
			if f.tag == '.' || f.tag == '+' {
				t.Fatalf("an end frame inside the answer %q", out)
			}
		}
		entries = append(entries, body[k:k+group])
	}
	return entries, last.tag == '.'
}

type filesCall struct {
	t *testing.T
	s sandbox.Session
}

// run runs one shell step in the session (after writing files) and returns its stdout and
// exit code.
func (c filesCall) run(step string, files ...sandbox.File) (string, int) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r, err := c.s.RunProject(ctx, sandbox.ProjectRequest{Files: files, Steps: []string{step}, Timeout: 50 * time.Second})
	if err != nil {
		c.t.Fatalf("%s: %v", step, err)
	}
	if r.Outcome != sandbox.ProjectOutcomeCompleted || len(r.Steps) != 1 {
		c.t.Fatalf("%s: outcome %v (%s), %d steps", step, r.Outcome, r.Detail, len(r.Steps))
	}
	st := r.Steps[0]
	if st.StdoutTruncated {
		c.t.Fatalf("%s: stdout past the step's output cap", step)
	}
	return st.Stdout, st.ExitCode
}

// code runs a file command and wants its exit code; stdout must be empty unless it is 0.
func (c filesCall) code(args string, want int, files ...sandbox.File) string {
	c.t.Helper()
	out, code := c.run(filesCmd+" "+args, files...)
	if code != want {
		c.t.Fatalf("files %s: exit %d, want %d (stdout %q)", args, code, want, out)
	}
	if code != 0 && out != "" {
		c.t.Fatalf("files %s: exit %d with stdout %q", args, code, out)
	}
	return out
}

func TestDockerSessionHelperFileCommands(t *testing.T) {
	t.Parallel()
	d := sessionDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	c := filesCall{t, openDockerSession(t, d)}

	// write: new, replace, append; the folders on the way are made; the content is stdin.
	c.code("write notes/a.txt create-only 1 < in", 0, sandbox.File{Path: "in", Content: "one\n"})
	c.code("write notes/a.txt create-only 1 < in", 84, sandbox.File{Path: "in", Content: "again\n"})
	c.code("write notes/a.txt append 1 < in", 0, sandbox.File{Path: "in", Content: "two\n"})
	e, _ := parseFrames(t, c.code("read notes/a.txt 0 100", 0), 2)
	if e[0][0] != (frame{'s', "8"}) || e[0][1] != (frame{'b', "one\ntwo\n"}) {
		t.Fatalf("read after append: %v", e)
	}
	c.code("write notes/a.txt replace 1 < in", 0, sandbox.File{Path: "in", Content: "three\n"})
	e, _ = parseFrames(t, c.code("read notes/a.txt 2 3", 0), 2)
	if e[0][0] != (frame{'s', "6"}) || e[0][1] != (frame{'b', "ree"}) {
		t.Fatalf("read at an offset: %v", e)
	}
	e, _ = parseFrames(t, c.code("read notes/a.txt 99 3", 0), 2)
	if e[0][1] != (frame{'b', ""}) {
		t.Fatalf("read past the end: %v", e)
	}

	// The guest's own: the file is the session user's, as one its shell writes.
	owner, _ := c.run("stat -c %u notes/a.txt; id -u")
	if f := strings.Fields(owner); len(f) != 2 || f[0] != f[1] {
		t.Fatalf("the helper's file is owned by %q, not the guest", owner)
	}

	// stat: kind, size, mode, time; a folder, the work folder.
	e, _ = parseFrames(t, c.code("stat notes/a.txt", 0), 4)
	if e[0][0] != (frame{'k', "f"}) || e[0][1] != (frame{'s', "6"}) || e[0][2].tag != 'm' || e[0][3].tag != 't' {
		t.Fatalf("stat: %v", e)
	}
	e, _ = parseFrames(t, c.code("stat notes", 0), 4)
	if e[0][0] != (frame{'k', "d"}) {
		t.Fatalf("stat of a folder: %v", e)
	}
	parseFrames(t, c.code("stat .", 0), 4)

	// The errors.
	c.code("stat nothing", 81)
	c.code("read notes 0 1", 82)
	c.code("read notes/a.txt/below 0 1", 83)
	c.code("write notes/a.txt/below create-only 1 < in", 83, sandbox.File{Path: "in", Content: "x"})
	c.code("mkdir notes/a.txt 1", 84)
	c.run("mkfifo pipe")
	c.code("read pipe 0 1", 85)
	c.code("write pipe replace 1 < in", 85, sandbox.File{Path: "in", Content: "x"})
	c.run("mkdir locked && echo keep > locked/f && chmod 555 locked && echo ro > ro.txt && chmod 444 ro.txt")
	c.code("write ro.txt replace 1 < in", 86, sandbox.File{Path: "in", Content: "x"})
	c.code("write locked/new create-only 1 < in", 86, sandbox.File{Path: "in", Content: "x"})
	c.code("remove locked/f 0", 86)
	c.run("chmod 755 locked")
	c.code("remove notes 1", 88)
	c.code("remove notes/a.txt 1", 83)
	c.code("remove notes 0", 82)
	for _, bad := range []string{"../etc/passwd", "/etc/passwd", "a/../b", "./a", "a//b", "''"} {
		c.code("read "+bad+" 0 1", 2)
	}

	// Links (docs/session-files.md, "Links, per operation"): one that stays inside the work
	// folder is followed, at any part, by openat2's RESOLVE_BENEATH (measured here under each
	// runtime: a kernel or gVisor without openat2 would refuse every work-scope call); one that leaves it
	// is refused and nothing is written through it; stat, remove and a replace act on a link at
	// the last part itself.
	c.run("ln -s /etc out && ln -s notes inner && ln -s /tmp/planted dangling && mkdir -p a/b && ln -s / a/b/root && ln -s ../../notes/a.txt a/b/up")
	for _, p := range []string{"out/passwd", "a/b/root/etc/passwd", "dangling"} {
		c.code("read "+p+" 0 10", 80)
		c.code("write "+p+" append 0 < in", 80, sandbox.File{Path: "in", Content: "x"})
	}
	for _, p := range []string{"inner/a.txt", "a/b/up"} {
		if e, _ := parseFrames(t, c.code("read "+p+" 0 10", 0), 2); e[0][1] != (frame{'b', "three\n"}) {
			t.Fatalf("read %s, a link inside the work folder: %v", p, e)
		}
	}
	c.code("stat out/passwd", 80)
	c.code("remove out/passwd 0", 80)
	c.code("write out/passwd replace 1 < in", 80, sandbox.File{Path: "in", Content: "x"})
	c.code("mkdir out/made 1", 80)
	c.code("list out 0 8192", 80)
	if e, _ := parseFrames(t, c.code("stat dangling", 0), 4); e[0][0] != (frame{'k', "l"}) {
		t.Fatalf("stat of a link at the last part: %v", e)
	}
	c.code("write dangling replace 0 < in", 0, sandbox.File{Path: "in", Content: "a file now"})
	if out, _ := c.run("test ! -e /tmp/planted && test ! -e /etc/made && test -f dangling && test ! -L dangling && echo clean"); out != "clean\n" {
		t.Fatalf("a write went through a link: %q", out)
	}
	// The work scope's other rule: a work folder that is not a mount of its own is refused
	// (here a folder under /tmp, which is a mount but whose subfolders are not).
	if out, code := c.run("mkdir -p /tmp/notamount && cd /tmp/notamount && " + filesCmd + " stat . 2>&1"); code != 1 || !strings.HasPrefix(out, "EXDEV: ") {
		t.Fatalf("a work folder that is not a mount: exit %d, %q", code, out)
	}
	// And it never crosses a mount below the work folder (session-files-19): a folder held there
	// could be moved out of the work folder within that other file system. A session's /work
	// has none and the guest cannot make one, so the work scope starts in /dev, a mount of its
	// own with /dev/shm (a tmpfs the guest may write) below it: every command across it is 86,
	// nothing lands there, and a recursive listing lists it "u" and does not enter it.
	nested := "cd /dev && for c in 'stat shm' 'write shm/planted replace 0' 'write shm/planted append 0' 'mkdir shm/made 0' " +
		"'list shm 0 8192' 'read shm/x 0 1' 'remove shm 1'; do printf x | " + filesCmd + " $c >/dev/null 2>&1; echo \"$c: $?\"; done; " +
		filesCmd + " list . 1 65536 </dev/null; echo; test ! -e /dev/shm/planted && test ! -e /dev/shm/made && echo clean"
	out, code := c.run(nested)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) != 9 || lines[8] != "clean" || !strings.Contains(lines[7], "p3:shmk1:us1:0") {
		t.Fatalf("the work scope at a mount below it: exit %d, %q", code, out)
	}
	for _, l := range lines[:7] {
		if !strings.HasSuffix(l, ": 86") {
			t.Fatalf("the work scope at a mount below it: %q, want 86 (all: %q)", l, out)
		}
	}

	// list: every entry with its kind and size, links listed as links and never followed;
	// a name holding a newline is one name.
	c.run(`mkdir -p tree/x && printf 12345 > tree/x/f && printf '' > "tree/$(printf 'two\nlines')" && ln -s /etc tree/l`)
	e, whole := parseFrames(t, c.code("list tree 1 8192 < /dev/null", 0), 3)
	var got []string
	for _, en := range e {
		got = append(got, fmt.Sprintf("%s %s %s", en[0].payload, en[1].payload, en[2].payload))
	}
	want := []string{"l l 0", "two\nlines f 0", "x d 0", "x/f f 5"}
	if !whole || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("list tree: %q (whole %v), want %q", got, whole, want)
	}

	// Paging: 300 files of 100-byte names at the least budget (8 KiB) come back in pages, each
	// continued from the last path, with nothing missed or repeated.
	c.run("mkdir big && cd big && for d in 1 2 3; do mkdir d$d; for f in $(seq 1 100); do : > d$d/$(printf %0100d $f).txt; done; done")
	var paths []string
	after := ""
	pages := 0
	for {
		out := c.code("list big 1 8192 < cursor", 0, sandbox.File{Path: "cursor", Content: after})
		page, whole := parseFrames(t, out, 3)
		pages++
		for _, en := range page {
			paths = append(paths, en[0].payload)
		}
		if whole {
			break
		}
		if len(page) == 0 || pages > 100 {
			t.Fatalf("a page stopped with %d entries after %d pages", len(page), pages)
		}
		after = page[len(page)-1][0].payload
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			t.Fatalf("%s listed twice", p)
		}
		seen[p] = true
	}
	if len(paths) != 303 || pages < 4 {
		t.Fatalf("%d entries in %d pages, want 303 in at least 4", len(paths), pages)
	}

	// readmany: each file framed by its size at open and the bytes read, a link or a missing
	// file skipped with its code, one past MAX skipped with 87, and a batch past its budget
	// continued.
	c.run("printf abc > r1 && printf %09000d 0 > r2")
	in := "r1\x00out/passwd\x00none\x00r2\x00"
	e, whole = parseFrames(t, c.code("readmany 100 8192 < in", 0, sandbox.File{Path: "in", Content: in}), 3)
	if !whole || len(e) != 4 || e[0][1] != (frame{'s', "3"}) || e[0][2] != (frame{'b', "abc"}) || e[1][2] != (frame{'e', "80"}) ||
		e[2][2] != (frame{'e', "81"}) || e[3][2] != (frame{'e', "87"}) || e[3][1] != (frame{'s', "0"}) {
		t.Fatalf("readmany: %v", e)
	}
	e, whole = parseFrames(t, c.code("readmany 10000 8192 < in", 0, sandbox.File{Path: "in", Content: "r1\x00r2\x00"}), 3)
	if whole || len(e) != 1 || e[0][0] != (frame{'p', "r1"}) {
		t.Fatalf("a batch past its budget: %v (whole %v)", e, whole)
	}
	if !bytes.Contains([]byte(c.code("list . 0 65536 < /dev/null", 0)), []byte("p2:r1")) {
		t.Fatal("the flat listing lacks r1")
	}

	// rename, replacing only when asked; a glob listing; the sandbox scope, absolute and
	// following links; a planted pipe answers at once.
	c.code("rename r1 r2 0", 84)
	c.code("rename r1 r3 0", 0)
	c.code("rename r3 r2 1", 0)
	c.code("rename r2 out/r2 1", 80)
	e, _ = parseFrames(t, c.code("list tree 1 8192 '**/f' < /dev/null", 0), 3)
	if len(e) != 1 || e[0][0].payload != "x/f" {
		t.Fatalf("a glob listing: %v", e)
	}
	work, _ := c.run("pwd")
	work = strings.TrimSpace(work)
	out, code = c.run(sandbox.NativeHelperPath + " files sandbox read " + work + "/inner/a.txt 0 100")
	if code != 0 || !strings.Contains(out, "b6:three\n") {
		t.Fatalf("the sandbox scope through a link: exit %d, %q", code, out)
	}
	// Names, not inodes: a hard link the guest makes to a file it may not read reads as that
	// file, so it is refused (86); the kernel refuses the link itself first when
	// fs.protected_hardlinks is on (81: nothing there).
	c.run("ln /etc/shadow shadow 2>/dev/null; true")
	if out, code := c.run(filesCmd + " read shadow 0 100"); (code != 81 && code != 86) || out != "" {
		t.Fatalf("a hard link to /etc/shadow: exit %d, %q", code, out)
	}
	// A replace leaves no temporary file behind.
	if out, _ := c.run("ls -A | grep -c '^.plimsoll-write-' || true"); strings.TrimSpace(out) != "0" {
		t.Fatalf("a temporary file was left: %q", out)
	}
	start := time.Now()
	c.code("read pipe 0 1", 85)
	c.code("write pipe append 0 < in", 85, sandbox.File{Path: "in", Content: "x"})
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("a planted pipe took %v to answer", took)
	}
}
