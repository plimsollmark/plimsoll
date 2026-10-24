package runsclog

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The fixtures are runsc release-20260907.0 boot logs from kind (the gvisor-receipt runtime
// class: --debug --strace with Syscalls(), --strace-log-size=16, the JSON format), one per
// fixture package installed offline with npm and then imported.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/" + name + ".boot.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func read(t *testing.T, b []byte) *Trace {
	t.Helper()
	tr, err := Read(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// outside lists the files written, and the opens for writing, outside the places a quiet
// install writes.
func outside(tr *Trace) (written, opened []string) {
	in := func(path string) bool {
		for _, p := range []string{"/work/", "/cache/", "/tmp/node-compile-cache/", "/dev/null"} {
			if strings.HasPrefix(path, p) {
				return true
			}
		}
		return false
	}
	for _, w := range tr.Written {
		if !in(w.Path) {
			written = append(written, w.Path)
		}
	}
	for _, o := range tr.Opened {
		if !in(o.Path) || o.Reached != "" && !in(o.Reached) {
			s := o.Path
			if o.Reached != "" && o.Reached != o.Path {
				s += " reached " + o.Reached
			}
			opened = append(opened, s+" "+o.Result)
		}
	}
	return written, opened
}

func programs(tr *Trace) map[string]*Process {
	out := map[string]*Process{}
	for _, p := range tr.Processes {
		for _, g := range p.Programs {
			out[strings.Join(g.Argv, " ")] = p
		}
	}
	return out
}

func TestFixtures(t *testing.T) {
	for _, name := range []string{"quiet", "builds", "canary", "network", "child"} {
		tr := read(t, fixture(t, name))
		if tr.Runsc != "release-20260907.0" || len(tr.Unclear) != 0 {
			t.Errorf("%s: runsc %q, unclear %+v", name, tr.Runsc, tr.Unclear)
		}
		progs := programs(tr)
		npm := progs["node /usr/local/bin/npm install --offline --cache /cache --no-audit --no-fund /fixtures/plimsoll-fixture-"+name+"-1.0.0.tgz"]
		if npm == nil {
			t.Fatalf("%s: npm did not start: %v", name, progs)
		}
		for _, p := range tr.Processes {
			for _, g := range p.Programs {
				if strings.HasPrefix(g.Path, "/usr/local/sbin/") || strings.Contains(g.Path, "/.bin/") {
					t.Errorf("%s: a failed try on the search path counts as started: %s", name, g.Path)
				}
			}
		}
		script := progs["node install.js"]
		written, opened := outside(tr)
		switch name {
		case "quiet":
			if script != nil || written != nil || opened != nil {
				t.Errorf("quiet: install script %v, wrote outside %v, opened outside %v", script, written, opened)
			}
		case "builds":
			if written != nil || opened != nil {
				t.Errorf("builds wrote outside %v, opened outside %v", written, opened)
			}
			found := false
			for _, w := range tr.Written {
				found = found || w.Path == "/work/node_modules/plimsoll-fixture-builds/build/out.txt" && w.Bytes == 6 && w.PID == script.PID
			}
			if !found || script.Parent != npm.PID {
				t.Errorf("builds: out.txt not written by the install script (pid %d, parent %d)", script.PID, script.Parent)
			}
		case "canary":
			if want := []string{"/root/.canary", "/etc/canary-target"}; !slices.Equal(written, want) {
				t.Errorf("canary wrote outside\n got %q\nwant %q", written, want)
			}
			want := []string{"/root/.canary ok", "/tmp/canary-dir/link reached /etc/canary-target ok", "/proc/canary errno=1 (operation not permitted)"}
			if !slices.Equal(opened, want) {
				t.Errorf("canary opened outside\n got %q\nwant %q", opened, want)
			}
			var changes []string
			for _, c := range tr.Changes {
				if c.PID == script.PID {
					changes = append(changes, fmt.Sprintf("%s %s %s %s", c.Kind, c.Path, c.Path2, c.Result))
				}
			}
			wantChanges := []string{
				"mkdir /tmp/canary-dir  ok",
				"symlink /etc/canary-target /tmp/canary-dir/link ok",
				"rename /root/.canary /root/.canary-moved ok",
				"unlink /root/.canary-moved  ok",
			}
			if !slices.Equal(changes, wantChanges) {
				t.Errorf("canary changes\n got %q\nwant %q", changes, wantChanges)
			}
		case "network":
			var connect, dns, hidden int
			for _, n := range tr.Network {
				switch {
				case n.Kind == "connect" && n.Addr == "203.0.113.7" && n.Port == 443 && n.PID == script.PID && n.Result == "errno=115 (operation now in progress)":
					connect++
				case n.Kind == "send" && n.Addr == "10.96.0.10" && n.Port == 53:
					dns++
				case n.Kind == "send" && strings.HasPrefix(n.Note, "sendmsg:"):
					hidden++
				}
			}
			if connect != 1 || dns == 0 || hidden != 1 {
				t.Errorf("network: connect %d, DNS sends %d, sends without a destination %d", connect, dns, hidden)
			}
		case "child":
			sh := progs["/bin/sh -c id > /dev/null; uname -a > /tmp/uname.txt"]
			id := progs["id"]
			uname := progs["uname -a"]
			if sh == nil || id == nil || uname != sh || sh.Parent != script.PID || id.Parent != sh.PID {
				t.Fatalf("child: the process tree is wrong: %v", progs)
			}
			if !slices.Equal(written, []string{"/tmp/uname.txt"}) || !slices.Equal(opened, []string{"/tmp/uname.txt ok"}) {
				t.Errorf("child wrote outside %v, opened outside %v", written, opened)
			}
		}
	}
}

// A log built from entries, between runsc's own first and last lines.
func logOf(msgs ...string) []byte {
	all := append([]string{"cli.go:276] Version release-20260907.0, go1.26.3, amd64, 24 CPUs, linux, PID 1, PPID 0, UID 0, GID 0"}, msgs...)
	all = append(all, "cli.go:317] Exiting with status: 0")
	var b bytes.Buffer
	for _, m := range all {
		e, _ := json.Marshal(map[string]string{"msg": m, "level": "info", "time": "2026-10-23T17:00:00.000000000Z"})
		b.Write(e)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// sx is one strace entry for process ns (root id ns+1) on thread tid.
func sx(ns, tid int, comm, line string) string {
	return fmt.Sprintf("strace.go:607] [%4d(%4d):%4d(%4d)] %s %s", ns+1, ns, tid+1, tid, comm, line)
}

func TestExecAndReadOnlyReopenEndOldDescriptorAssociations(t *testing.T) {
	for name, middle := range map[string][]string{
		"exec then read-only reuse": {
			sx(1, 1, "node", `E execve(0x10000 /bin/cat, 0x20000 ["cat"], 0x30000 [])`),
			sx(1, 1, "cat", `X execve(0x10000 /bin/cat, 0x20000 ["cat"], 0x30000 []) = 0 (0x0) (1us)`),
			sx(1, 1, "cat", `E open(0x10000 /tmp/benign, O_RDONLY, 0o0)`),
			sx(1, 1, "cat", `X open(0x10000 /tmp/benign, O_RDONLY, 0o0) = 5 (0x5) (1us)`),
		},
		"read-only reopen": {
			sx(1, 1, "node", `E open(0x10000 /tmp/benign, O_RDONLY, 0o0)`),
			sx(1, 1, "node", `X open(0x10000 /tmp/benign, O_RDONLY, 0o0) = 5 (0x5) (1us)`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			lines := []string{
				sx(1, 1, "node", `E open(0x10000 /tmp/link, O_WRONLY|O_TRUNC|O_CLOEXEC, 0o0)`),
				sx(1, 1, "node", `X open(0x10000 /tmp/link, O_WRONLY|O_TRUNC|O_CLOEXEC, 0o0) = 5 (0x5) (1us)`),
			}
			lines = append(lines, middle...)
			lines = append(lines, sx(1, 1, "cat", `E close(0x5 /tmp/benign)`),
				sx(1, 1, "cat", `X close(0x5 /tmp/benign) = 0 (0x0) (1us)`))
			tr := read(t, logOf(lines...))
			if len(tr.Opened) != 1 || tr.Opened[0].Reached != "" {
				t.Fatalf("old open acquired a reused descriptor's file name: %+v", tr.Opened)
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	good := fixture(t, "quiet")
	closing := bytes.LastIndex(good, []byte(`{"msg":"cli.go:317] Exiting with status`))
	marker := bytes.Index(good[len(good)/2:], []byte("\n")) + len(good)/2 + 1
	for _, c := range []struct {
		name string
		log  []byte
		want error
	}{
		{"empty", nil, ErrNotJSON},
		{"the text form", []byte("I1023 17:36:52.337236       1 strace.go:569] [   9(   8):   9(   8)] node E execve(0x1 /bin/x, 0x2 [], 0x3 [])\n"), ErrNotJSON},
		{"cut inside an entry", good[:len(good)/2+17], ErrIncomplete},
		{"no closing line", good[:closing], ErrIncomplete},
		{"a lost-lines marker", slices.Concat(good[:marker], []byte("\n*** Dropped 3 log messages ***\n"), good[marker:]), ErrIncomplete},
		{"another runsc release", bytes.Replace(good, []byte("Version release-20260907.0"), []byte("Version release-20990101.0"), 1), ErrUnsupported},
	} {
		if _, err := Read(bytes.NewReader(c.log)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if closing < 0 || marker <= len(good)/2 {
		t.Fatal("the fixture lacks its closing line")
	}
}

// Text the package chooses (a file name, a process name) cannot add an event, hide one, or
// change one's kind.
func TestNamesCannotAddEvents(t *testing.T) {
	fake := "\nI1023 17:00:00.000000       1 strace.go:604] [   1(   1):   1(   1)] node X connect(0x5 socket:[1], 0x6 {Family: AF_INET, Addr: 6.6.6.6, Port: 443}, 0x10) = 0 (0x0) (1us)"
	tr := read(t, logOf(
		sx(1, 1, "node", "X open(0x10000 /tmp/a"+fake+", O_WRONLY|O_CREAT|O_TRUNC, 0o666) = 3 (0x3) (1us)"),
		// A path ending in what looks like read-only flags still reads as the write it was.
		sx(1, 1, "node", "X open(0x10000 /tmp/b, O_RDONLY, 0o0, O_WRONLY|O_CREAT, 0o644) = 4 (0x4) (1us)"),
		// A first path holding ", 0xADDR /etc/x" fits two readings of a rename.
		sx(1, 1, "node", "X rename(0x10000 /tmp/c, 0x20000 /etc/x, 0x30000 /tmp/d) = 0 (0x0) (1us)"),
		// A process name holding a call marker.
		sx(1, 2, "x X unlink(", "X unlink(0x10000 /root/.bashrc) = 0 (0x0) (1us)"),
		// A process name holding the marker of a call the reader follows, on one it does not:
		// flagged, not read as a removal of "/ X futex(...".
		sx(1, 2, "y X rmdir(0x1 /", "X futex(0x7f00, FUTEX_WAKE, 0x1) = 0 (0x0) (1us)"),
	))
	if len(tr.Network) != 0 {
		t.Errorf("a file name added a network event: %+v", tr.Network)
	}
	var paths []string
	for _, o := range tr.Opened {
		paths = append(paths, o.Path)
	}
	if !slices.Equal(paths, []string{"/tmp/a" + fake, "/tmp/b, O_RDONLY, 0o0"}) {
		t.Errorf("files %q", paths)
	}
	var why []string
	for _, u := range tr.Unclear {
		why = append(why, u.Call+": "+u.Why)
	}
	want := []string{"rename: more than one reading of its arguments fits", "unlink: the process name holds a call marker", "rmdir: the process name holds a call marker"}
	if !slices.Equal(why, want) || len(tr.Changes) != 0 {
		t.Errorf("unclear %q, changes %+v; want %q and no change", why, tr.Changes, want)
	}
}

// A program counts as started only when gVisor's loader logs a stack for the thread.
func TestStartedOnlyWithANewStack(t *testing.T) {
	tr := read(t, logOf(
		sx(1, 1, "node", `X execve(0x10000 /usr/local/sbin/npm, 0x20000 ["npm"], 0x30000 ["SECRET=x"]) = 0 (0x0) (1us)`),
		sx(1, 1, "node", `X execve(0x10000 /usr/local/bin/npm, 0x20000 ["npm", "install"], 0x30000 ["SECRET=x"]) = 0 (0x0) (1us)`),
		"syscalls.go:281] [   2(   1):   2(   1)] Allocating stack with size of 8388608 bytes",
	))
	got := tr.Processes[0].Programs
	if len(got) != 1 || got[0].Path != "/usr/local/bin/npm" || !slices.Equal(got[0].Argv, []string{"npm", "install"}) {
		t.Errorf("programs %+v", got)
	}
	if b, _ := json.Marshal(tr); bytes.Contains(b, []byte("SECRET")) {
		t.Error("the environment reached the trace")
	}
}

// Results do not depend on the order threads' entries reached the log.
func TestOrderBetweenThreads(t *testing.T) {
	tr := read(t, logOf(
		// The child's first entry comes before its parent's fork returns.
		sx(9, 9, "sh", "X chdir(0x10000 /work) = 0 (0x0) (1us)"),
		sx(1, 1, "node", "X fork() = 9 (0x9) (1us)"),
		// Thread 1 opens a symlink and is given descriptor 3; before its exit line is logged,
		// thread 2 closes 3 and opens another file as 3. Thread 1's open must not be tied to
		// the other file.
		sx(1, 1, "node", "E open(0x10000 /work/link, O_WRONLY|O_CREAT, 0o644)"),
		sx(1, 2, "node", "E close(0x3 /tmp/victim)"),
		sx(1, 2, "node", "X close(0x3 /tmp/victim) = 0 (0x0) (1us)"),
		sx(1, 2, "node", "E open(0x10000 /work/safe, O_WRONLY|O_CREAT, 0o644)"),
		sx(1, 2, "node", "X open(0x10000 /work/safe, O_WRONLY|O_CREAT, 0o644) = 3 (0x3) (1us)"),
		sx(1, 1, "node", "X open(0x10000 /work/link, O_WRONLY|O_CREAT, 0o644) = 3 (0x3) (1us)"),
		sx(1, 2, "node", "X write(0x3 /work/safe, ..., 0x2) = 2 (0x2) (1us)"),
		sx(1, 1, "node", "X write(0x3 /work/safe, ..., 0x1) = 1 (0x1) (1us)"),
	))
	var child *Process
	for _, p := range tr.Processes {
		if p.PID == 9 {
			child = p
		}
	}
	if child == nil || child.Parent != 1 {
		t.Errorf("the child's parent was lost: %+v", child)
	}
	var opened []string
	for _, o := range tr.Opened {
		opened = append(opened, o.Path+" -> "+o.Reached)
	}
	if want := []string{"/work/safe -> /work/safe", "/work/link -> "}; !slices.Equal(opened, want) {
		t.Errorf("opened %q, want %q", opened, want)
	}
	if len(tr.Written) != 1 || tr.Written[0].Bytes != 3 {
		t.Errorf("written %+v", tr.Written)
	}
}

// Each of the reader's rules from the review of 2026-10-23, one entry at a time.
func TestReviewCases(t *testing.T) {
	tr := read(t, logOf(
		// A path is joined to the directory and never cleaned: d may be a symlink.
		sx(1, 1, "node", "X chdir(0x10000 /work/pkg) = 0 (0x0) (1us)"),
		sx(1, 1, "node", "X unlink(0x10000 d/../victim) = 0 (0x0) (1us)"),
		// A message header changed during the call: the entry line's copy decides.
		sx(1, 1, "node", "E sendmsg(0x5 socket:[2], 0x10000 {name=0x2, namelen=16, iovecs=0x3 {base=0x4, len=2, \"hi\"}, control={0x0 }, flags=0}, 0x0)"),
		sx(1, 1, "node", "X sendmsg(0x5 socket:[2], 0x10000 {name=0x2, namelen=0, iovecs=0x3 {base=0x4, len=2}, control=0x0, control_len=0, flags=0}, 0x0) = 2 (0x2) (1us)"),
		// A mode with extra bits.
		sx(1, 1, "node", "X open(0x10000 /tmp/out, O_WRONLY|O_CREAT, S_ISUID|0o755) = 4 (0x4) (1us)"),
		// Two children write through a descriptor they inherited.
		sx(1, 1, "node", "X fork() = 5 (0x5) (1us)"),
		sx(1, 1, "node", "X fork() = 6 (0x6) (1us)"),
		sx(5, 5, "node", "X write(0x4 /tmp/out, ..., 0x1) = 1 (0x1) (1us)"),
		sx(6, 6, "node", "X write(0x4 /tmp/out, ..., 0x1) = 1 (0x1) (1us)"),
		// An execve entry made unclear keeps its environment out of the trace.
		sx(1, 1, "x X open(", `X execve(0x10000 /bin/sh, 0x20000 ["sh"], 0x30000 ["TOKEN=secret"]) = 0 (0x0) (1us)`),
	))
	if len(tr.Changes) != 1 || tr.Changes[0].Path != "/work/pkg/d/../victim" {
		t.Errorf("changes %+v", tr.Changes)
	}
	if len(tr.Network) != 1 || !strings.Contains(tr.Network[0].Note, "changed during the call") {
		t.Errorf("network %+v", tr.Network)
	}
	if len(tr.Opened) != 1 || tr.Opened[0].Path != "/tmp/out" {
		t.Errorf("opened %+v", tr.Opened)
	}
	var writers []int
	for _, w := range tr.Written {
		writers = append(writers, w.PID)
	}
	if !slices.Equal(writers, []int{5, 6}) {
		t.Errorf("written by %v, want each child on its own", writers)
	}
	if b, _ := json.Marshal(tr); bytes.Contains(b, []byte("TOKEN")) || len(tr.Unclear) != 1 {
		t.Errorf("unclear %+v", tr.Unclear)
	}
}

// A path made of separators cannot make the reader work without bound.
func TestManySeparatorsStayBounded(t *testing.T) {
	sep := strings.Repeat(", 0x1 ", 3000)
	start := time.Now()
	tr := read(t, logOf(sx(1, 1, "node", "X rename(0x10000 /a"+sep+", 0x20000 /b"+sep+") = 0 (0x0) (1us)")))
	if len(tr.Unclear) != 1 || len(tr.Changes) != 0 {
		t.Errorf("unclear %d, changes %+v", len(tr.Unclear), tr.Changes)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("one entry took %v", d)
	}
}

func TestSyscallsAreTheSpecs(t *testing.T) {
	got := Syscalls()
	if !slices.IsSorted(got) || len(got) != len(specs) || !slices.Contains(got, "execve") || !slices.Contains(got, "sendmsg") {
		t.Errorf("Syscalls() = %v", got)
	}
}

// A program started after an execve entry the reader could not read is marked unclear, not
// passed off as runsc's own first program; openat2's flags are read from its open_how.
func TestHiddenStartsAndOpenat2(t *testing.T) {
	tr := read(t, logOf(
		"syscalls.go:281] [   2(   1):   2(   1)] Allocating stack with size of 8388608 bytes",
		sx(1, 1, "a X open(", `X execve(0x10000 /tmp/evil, 0x20000 ["evil"], 0x30000 []) = 0 (0x0) (1us)`),
		"syscalls.go:281] [   2(   1):   2(   1)] Allocating stack with size of 8388608 bytes",
		sx(1, 1, "evil", "X openat2(AT_FDCWD /work, 0x10000 out.txt, 0x20000 flags O_WRONLY|O_CREAT|O_CLOEXEC mode 0o644 resolve 0x0, 0x18) = 3 (0x3) (1us)"),
		sx(1, 1, "evil", "X openat(AT_FDCWD /work, 0x10000 (error decoding path: bad address), O_WRONLY, 0o0) = -1 errno=14 (bad address) (1us)"),
	))
	got := tr.Processes[0].Programs
	if len(got) != 2 || !got[0].ByRunsc || !got[1].Unclear || got[1].ByRunsc {
		t.Errorf("programs %+v", got)
	}
	var files []string
	for _, o := range tr.Opened {
		files = append(files, o.Path+" "+o.Result)
	}
	if want := []string{"/work/out.txt ok", "(error decoding path: bad address) errno=14 (bad address)"}; !slices.Equal(files, want) {
		t.Errorf("files %q, want %q", files, want)
	}
}

// Whatever a package makes its calls look like, the reader returns or refuses; it never
// panics.
func FuzzEntry(f *testing.F) {
	for _, s := range []string{
		`X open(0x10000 /tmp/a, O_WRONLY|O_CREAT, 0o644) = 3 (0x3) (1us)`,
		`X rename(0x10000 /a, 0x20000 /b) = 0 (0x0) (1us)`,
		`X execve(0x10000 /bin/sh, 0x20000 ["sh", "-c", "x"], 0x30000 []) = 0 (0x0) (1us)`,
		`X connect(0x3 socket:[1], 0x10000 {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 0x10) = -1 errno=115 (operation now in progress) (1us)`,
		`X write(0x3 /tmp/a, ..., 0x2) = 2 (0x2) (1us)`,
		`E close(0x3 /tmp/a)`,
		`X sendmsg(0x3 socket:[1], 0x10000 {name=0x1, namelen=16, iovecs=0x2 {base=0x3, len=2}, control=0x0, control_len=0, flags=0}, 0x0) = 2 (0x2) (1us)`,
	} {
		f.Add("node", s)
	}
	f.Fuzz(func(t *testing.T, comm, line string) {
		_, _ = Read(bytes.NewReader(logOf(sx(1, 1, comm, line), sx(2, 2, "x", line))))
	})
}

// The handler's options name exactly the calls the reader follows.
func TestHandlerTracesTheSpecs(t *testing.T) {
	b, err := os.ReadFile("../fixtures/runsc-receipt.toml")
	if err != nil {
		t.Fatal(err)
	}
	want := `strace-syscalls = "` + strings.Join(Syscalls(), ",") + `"`
	if !bytes.Contains(b, []byte(want)) || !bytes.Contains(b, []byte(`debug-log-format = "json"`)) {
		t.Errorf("runsc-receipt.toml does not hold %s and the JSON format", want)
	}
}
