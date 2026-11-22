package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The moment before the guard loads (finding rust-native-helper-14). Each guarded control
// program of a docker session (the sweep, the quiesce, a cell relay) starts as the guest
// user, under /usr/bin/env and then sh, and is dumpable until the runner guard's constructor
// runs in node: from exec to that constructor a process of the guest user may open its
// descriptors (the guard tests saw it). These tests try, in that moment and from a kept
// Python interpreter, everything that would let session code steer the program afterwards:
//
//   - attach as a debugger (PTRACE_SEIZE): an attachment made before PR_SET_DUMPABLE=0
//     survives it and every later exec, so it would let code rewrite the sweep's exit status;
//   - open /proc/<pid>/mem for writing, read its memory with process_vm_readv, and copy its
//     descriptors with pidfd_getfd: each would outlive the moment too;
//   - open each descriptor it holds, for reading and for writing, and say what it is.
//
// The first three are checked by the kernel as an attach (PTRACE_MODE_ATTACH), so Yama's
// ptrace_scope of 1 refuses them for a process that is not a descendant of the tracer, and a
// control program started by docker exec is never a descendant of the session's code (its
// parent is outside the container). The docker session refuses to open on a host whose
// ptrace_scope reads 0 (sessionkit.Baseline); under gVisor the rule is gVisor's own, which
// its kernel sets to 1 as it starts, whatever the host's. Descriptor opens are checked as a read
// (PTRACE_MODE_READ), which Yama leaves alone, so they succeed while the program is dumpable;
// what they reach is the exec's own standard input, output and error (pipes under runc, the
// host descriptors runsc hands the exec under gVisor), whose content
// plimsoll never reads for a verdict (the sweep and the quiesce are read by exit status
// alone), and for a relay the pipes the session conformance suite already forges frames into
// (sessiontest's forged-relay cases).
//
// Each test runs under the suite's runtime, and under runc once per seccomp setting an
// operator may choose: the shipped profile (which also refuses ptrace, process_vm_* and
// pidfd_open), docker's built-in default (which allows them), and unconfined. Under gVisor
// plimsoll applies no profile (seccompPolicySkippedRunsc), so there it runs once. A control
// cell in each session tells the two refusals apart: an attach to the watcher's own child,
// which Yama allows and only seccomp can refuse, and one to the container's main process, a
// dumpable process of the same user that is not a descendant, which Yama refuses.

// guardWindowPy is Python for a kept interpreter: plimsoll_window_watch(script, log, act)
// starts a thread that scans /proc as fast as it can for any process whose argv holds script
// as one of its arguments (so it sees the program while it is still env and sh, as well as
// node), and samples each one: the owner of /proc/<pid>/environ before and after (the guest
// uid while the process is dumpable), then the attach, the memory, process_vm_readv,
// pidfd_getfd, and every descriptor. With act, an open that succeeds reads what is waiting
// (non-blocking) or writes a line, once per process, so the test shows what a write gives;
// for a relay act is off, since its first request may already be waiting. Samples go to
// plimsoll_window["seen"], and to log as JSON lines when log is set (for the quiesce, which
// kills the interpreter). plimsoll_window_controls() reports the controls.
const guardWindowPy = `import ctypes, errno, json, os, platform, threading, time
_lc = ctypes.CDLL(None, use_errno=True)
_lc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
_lc.ptrace.restype = ctypes.c_long
_lc.syscall.restype = ctypes.c_long
class _iov(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
_VMREAD = {"x86_64": 310, "aarch64": 270}.get(platform.machine(), -1)
def _e(n=None):
    n = ctypes.get_errno() if n is None else n
    return errno.errorcode.get(n, str(n))
def _seize(pid):
    if _lc.ptrace(0x4206, pid, None, None) != 0:
        return _e()
    _lc.ptrace(0x4207, pid, None, None)
    try:
        os.waitpid(pid, 0x40000000)
    except OSError:
        pass
    _lc.ptrace(17, pid, None, None)
    return "ok"
def _mem(pid):
    try:
        os.close(os.open("/proc/%d/mem" % pid, os.O_RDWR))
        return "open"
    except OSError as x:
        return _e(x.errno)
def _vm(pid):
    buf = ctypes.create_string_buffer(8)
    loc, rem = _iov(ctypes.addressof(buf), 8), _iov(0x1000, 8)
    L = ctypes.c_long
    r = _lc.syscall(L(_VMREAD), L(pid), ctypes.byref(loc), L(1), ctypes.byref(rem), L(1), L(0))
    return "ok" if r >= 0 else _e()
def _getfd(pid):
    p = _lc.syscall(ctypes.c_long(434), ctypes.c_long(pid), ctypes.c_long(0))
    if p < 0:
        return "pidfd_open " + _e()
    g = _lc.syscall(ctypes.c_long(438), ctypes.c_long(p), ctypes.c_long(1), ctypes.c_long(0))
    r = "ok" if g >= 0 else _e()
    if g >= 0:
        os.close(g)
    os.close(p)
    return r
def _owner(pid):
    try:
        return os.stat("/proc/%d/environ" % pid).st_uid
    except OSError:
        return None
def _sample(pid, argv, act, acted):
    r = {"pid": pid, "phase": os.path.basename(argv[0].decode("latin1")), "t": time.monotonic_ns() // 1000}
    r["owner"] = _owner(pid)
    if r["owner"] is None:
        return None
    r["uid"] = os.getuid()
    r["ptrace"], r["mem"], r["vm"], r["getfd"] = _seize(pid), _mem(pid), _vm(pid), _getfd(pid)
    fds = {}
    try:
        names = os.listdir("/proc/%d/fd" % pid)
    except OSError as x:
        names, r["fdlist"] = [], _e(x.errno)
    for n in names:
        f = {}
        try:
            f["is"] = os.readlink("/proc/%d/fd/%s" % (pid, n))
        except OSError as x:
            f["is"] = _e(x.errno)
        for mode, flag in (("r", os.O_RDONLY), ("w", os.O_WRONLY)):
            try:
                fd = os.open("/proc/%d/fd/%s" % (pid, n), flag | os.O_NONBLOCK)
            except OSError as x:
                f[mode] = _e(x.errno)
                continue
            f[mode] = "open"
            try:
                f[mode + "is"] = os.readlink("/proc/self/fd/%d" % fd)
            except OSError as x:
                f[mode + "is"] = _e(x.errno)
            if act and (pid, n, mode) not in acted:
                acted.add((pid, n, mode))
                try:
                    if mode == "r":
                        f["got"] = len(os.read(fd, 65536))
                    else:
                        f["wrote"] = os.write(fd, b"written by session code in the window\n")
                except OSError as x:
                    f["got" if mode == "r" else "wrote"] = _e(x.errno)
            os.close(fd)
        fds[n] = f
    r["fds"] = fds
    r["owner_after"] = _owner(pid)
    return r
plimsoll_window = {"seen": {}, "on": True, "passes": 0}
def plimsoll_window_watch(script, log, act):
    want, acted, me = script.encode(), set(), os.getpid()
    def loop():
        st = plimsoll_window
        while st["on"]:
            st["passes"] += 1
            for d in os.listdir("/proc"):
                if not d.isdigit() or int(d) == me:
                    continue
                try:
                    with open("/proc/%s/cmdline" % d, "rb") as c:
                        argv = c.read().split(b"\0")[:-1]
                except OSError:
                    continue
                if want not in argv:
                    continue
                got = st["seen"].setdefault(d, [])
                if len(got) >= 40:
                    continue
                r = _sample(int(d), argv, act, acted)
                if r is None:
                    continue
                got.append(r)
                if log:
                    with open(log, "a") as f:
                        f.write(json.dumps(r) + "\n")
    threading.Thread(target=loop, daemon=True).start()
    return "watching"
def plimsoll_window_controls():
    import subprocess
    c = {"uid": os.getuid()}
    try:
        c["scope"] = open("/proc/sys/kernel/yama/ptrace_scope").read().strip()
    except OSError as x:
        c["scope"] = _e(x.errno)
    child = subprocess.Popen(["sleep", "30"])
    time.sleep(0.05)
    c["child_ptrace"] = _seize(child.pid)
    child.kill()
    child.wait()
    main = None
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                if open("/proc/%s/cmdline" % d, "rb").read() == b"sleep\x002147483647\x00":
                    main = int(d)
            except OSError:
                pass
    c["main_owner"] = _owner(main) if main else None
    if main:
        c["main_ptrace"], c["main_mem"], c["main_vm"], c["main_getfd"] = _seize(main), _mem(main), _vm(main), _getfd(main)
    return json.dumps(c)
`

// windowSample is one sample guardWindowPy took.
type windowSample struct {
	PID        int                      `json:"pid"`
	Phase      string                   `json:"phase"`
	T          int64                    `json:"t"` // microseconds, monotonic
	Owner      *int                     `json:"owner"`
	OwnerAfter *int                     `json:"owner_after"`
	UID        int                      `json:"uid"`
	Ptrace     string                   `json:"ptrace"`
	Mem        string                   `json:"mem"`
	VM         string                   `json:"vm"`
	GetFD      string                   `json:"getfd"`
	FDList     string                   `json:"fdlist"`
	FDs        map[string]windowFDTrial `json:"fds"`
}

type windowFDTrial struct {
	Is    string `json:"is"` // what /proc/<pid>/fd/<n> named when it was listed
	R     string `json:"r"`
	W     string `json:"w"`
	RIs   string `json:"ris"` // what the open reached: the descriptor can change between the two
	WIs   string `json:"wis"`
	Got   any    `json:"got"`
	Wrote any    `json:"wrote"`
}

// inWindow reports whether the program was dumpable for the whole sample: the kernel listed
// its environ as the guest's before the first attempt and after the last.
func (s windowSample) inWindow() bool {
	return s.Owner != nil && s.OwnerAfter != nil && *s.Owner == s.UID && *s.OwnerAfter == s.UID
}

// windowControls is plimsoll_window_controls's report.
type windowControls struct {
	UID         int    `json:"uid"`
	Scope       string `json:"scope"`
	ChildPtrace string `json:"child_ptrace"`
	MainOwner   *int   `json:"main_owner"`
	MainPtrace  string `json:"main_ptrace"`
	MainMem     string `json:"main_mem"`
	MainVM      string `json:"main_vm"`
	MainGetFD   string `json:"main_getfd"`
}

// windowTally is what the rounds of one program saw.
type windowTally struct {
	rounds, seen, caught, samples, windowSamples int
	phases                                       map[string]int
	results                                      map[string]int // "attempt=result" over window samples
	fds                                          map[string]int // "fd is r/w" over window samples
}

func newWindowTally() *windowTally {
	return &windowTally{phases: map[string]int{}, results: map[string]int{}, fds: map[string]int{}}
}

// add judges one program's samples: nothing that outlives the moment may have been reached,
// and every descriptor that opened must be one of the exec's three standard pipes.
func (w *windowTally) add(t *testing.T, what string, byPID map[string][]windowSample) {
	t.Helper()
	w.seen += len(byPID)
	for pid, samples := range byPID {
		caught := false
		for _, s := range samples {
			w.samples++
			if s.Ptrace == "ok" || s.Mem == "open" || s.VM == "ok" || s.VM == "EFAULT" || s.GetFD == "ok" {
				t.Errorf("the %s (pid %s, as %s, dumpable %v): session code reached it in a way that outlives the moment: attach %s, memory %s, process_vm_readv %s, pidfd_getfd %s", what, pid, s.Phase, s.inWindow(), s.Ptrace, s.Mem, s.VM, s.GetFD)
			}
			if !s.inWindow() {
				continue
			}
			caught = true
			w.windowSamples++
			w.phases[s.Phase]++
			for k, v := range map[string]string{"attach": s.Ptrace, "memory": s.Mem, "process_vm_readv": s.VM, "pidfd_getfd": s.GetFD} {
				w.results[k+"="+v]++
			}
			for n, f := range s.FDs {
				kind := f.Is
				if i := strings.IndexByte(kind, '['); i > 0 {
					kind = kind[:i]
				}
				w.fds[fmt.Sprintf("fd %s %s r=%s w=%s", n, kind, f.R, f.W)]++
				for _, o := range []struct{ got, is string }{{f.R, f.RIs}, {f.W, f.WIs}} {
					if o.got != "open" {
						continue
					}
					if kind := o.is; strings.HasPrefix(kind, "/") {
						w.fds["opened "+kind]++
					}
					if !windowHarmlessFD(n, o.is) {
						t.Errorf("the %s (pid %s, as %s): descriptor %s opened in the moment before the guard and reached %q, which is neither one of the exec's standard pipes nor a file of the image's read-only root: %+v", what, pid, s.Phase, n, o.is, f)
					}
				}
			}
		}
		if caught {
			w.caught++
		}
	}
}

// windowHarmlessFD reports whether a descriptor that opened in the moment is one of the two
// kinds measured there: the exec's standard input, output and error (0 to 2), and a
// library the dynamic loader holds open while it maps node, a file of the image's read-only
// root that the guest can open by its name anyway. Anything else is a new fact for the test
// to report, not a pass.
func windowHarmlessFD(n, is string) bool {
	// Under runc the exec's standard streams are pipes; under gVisor they are the host's
	// descriptors runsc hands the exec (host:[N]).
	if strings.HasPrefix(is, "pipe:") || strings.HasPrefix(is, "host:") {
		return n == "0" || n == "1" || n == "2"
	}
	if !strings.HasPrefix(is, "/") || strings.HasPrefix(is, "/proc/") || strings.HasPrefix(is, "/dev/") {
		return false
	}
	for _, d := range dockerSessionDirs {
		if is == d || strings.HasPrefix(is, d+"/") {
			return false
		}
	}
	return true
}

func (w *windowTally) report(t *testing.T, what string) {
	t.Helper()
	keys := func(m map[string]int) string {
		var out []string
		for k, v := range m {
			out = append(out, fmt.Sprintf("%s: %d", k, v))
		}
		sort.Strings(out)
		return strings.Join(out, "; ")
	}
	t.Logf("%s: the %s: %d rounds, %d processes seen, %d caught while dumpable (%d of %d samples); phases: %s; attempts: %s; descriptors: %s",
		t.Name(), what, w.rounds, w.seen, w.caught, w.windowSamples, w.samples, keys(w.phases), keys(w.results), keys(w.fds))
}

// guardWindowProfiles is the seccomp settings the window tests run under: under runc each
// setting an operator may choose; under gVisor one, since plimsoll applies none there.
func guardWindowProfiles(t *testing.T) []struct {
	name string
	set  func(*DockerSandbox)
} {
	shipped := func(d *DockerSandbox) { shippedSeccomp(t, d) }
	if testDocker().Runtime == "runsc" {
		return []struct {
			name string
			set  func(*DockerSandbox)
		}{{"gVisor, no profile applied", shipped}}
	}
	return []struct {
		name string
		set  func(*DockerSandbox)
	}{
		{"shipped profile", shipped},
		{"docker default profile", func(d *DockerSandbox) { d.Seccomp = "" }},
		{"unconfined", func(d *DockerSandbox) { d.Seccomp = "unconfined" }},
	}
}

// guardWindowSession opens a session on the Python image under set and checks the controls:
// the host's Yama setting as the session sees it, and which mechanism refuses an attach.
func guardWindowSession(t *testing.T, set func(*DockerSandbox)) Session {
	t.Helper()
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	d.MaxOutputBytes = 8 << 20 // the watcher's report of every sample
	requireProjectImage(t, d)
	set(d)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 10 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	if got := pyCell(t, s, guardWindowPy+"'loaded'"); got != "'loaded'" {
		t.Fatalf("loading the watcher printed %q", got)
	}
	var c windowControls
	if out := pyCell(t, s, "print(plimsoll_window_controls())"); json.Unmarshal([]byte(out), &c) != nil {
		t.Fatalf("the controls printed %q", out)
	}
	// The controls are why the window's attempts fail: Yama (scope 1 or more, which the
	// session's open requires) refuses the main process, a dumpable non-descendant of the
	// same user, whatever the profile; the child, which Yama allows, shows whether the
	// profile refuses ptrace on its own.
	if c.MainOwner == nil || *c.MainOwner != c.UID {
		t.Fatalf("the control process (the container's main sleep) is not a dumpable process of the guest user: %+v", c)
	}
	if c.MainPtrace == "ok" || c.MainMem == "open" || c.MainVM == "ok" || c.MainVM == "EFAULT" || c.MainGetFD == "ok" {
		t.Errorf("session code reached the container's main process, a dumpable process of its own user that it did not start: %+v", c)
	}
	t.Logf("%s: controls: ptrace_scope %s; attach to the watcher's own child: %s; to the main process: attach %s, memory %s, process_vm_readv %s, pidfd_getfd %s", t.Name(), c.Scope, c.ChildPtrace, c.MainPtrace, c.MainMem, c.MainVM, c.MainGetFD)
	return s
}

func pyCell(t *testing.T, s Session, code string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := s.RunCell(ctx, CellRequest{Language: LanguagePython, Code: code, Timeout: 60 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Python cell: %+v, %v", res, err)
	}
	return strings.TrimSpace(res.Stdout)
}

// readWindowSeen reads plimsoll_window["seen"] from the kept interpreter.
func readWindowSeen(t *testing.T, s Session) map[string][]windowSample {
	t.Helper()
	out := pyCell(t, s, `plimsoll_window["on"] = False
print(json.dumps(plimsoll_window["seen"]))`)
	var seen map[string][]windowSample
	if err := json.Unmarshal([]byte(out), &seen); err != nil {
		t.Fatalf("the watcher's report %q: %v", out, err)
	}
	return seen
}

const (
	guardWindowSweepRounds   = 40
	guardWindowQuiesceRounds = 15
	guardWindowRelayRounds   = 15
)

// TestDockerGuardWindowSweep: in the moment before the sweep's guard loads, session code
// can open its standard pipes and nothing more; a line written into them changes nothing,
// and the session goes on.
func TestDockerGuardWindowSweep(t *testing.T) {
	t.Parallel()
	for _, p := range guardWindowProfiles(t) {
		t.Run(p.name, func(t *testing.T) {
			heavyDockerTest(t)
			s := guardWindowSession(t, p.set)
			if got := pyCell(t, s, "plimsoll_window_watch("+jsString(t, sessionkit.SweepScript)+", '', True)"); got != "'watching'" {
				t.Fatalf("starting the watcher printed %q", got)
			}
			w := newWindowTally()
			// Every call is followed by a sweep, which the next call waits for.
			for i := 0; i < guardWindowSweepRounds; i++ {
				pyCell(t, s, "1")
				w.rounds++
			}
			w.add(t, "sweep", readWindowSeen(t, s))
			w.report(t, "sweep")
			// The writes into the sweep's pipes did not end the session: the sweeps' exit
			// statuses, the only thing plimsoll reads of them, stayed clean.
			if got := pyCell(t, s, "2 + 2"); got != "4" {
				t.Fatalf("a cell after the rounds printed %q", got)
			}
		})
	}
}

// TestDockerGuardWindowQuiesce: the same for the quiesce before a project call, which kills
// the watcher, so each round starts one and the project call's step reads its log.
func TestDockerGuardWindowQuiesce(t *testing.T) {
	t.Parallel()
	for _, p := range guardWindowProfiles(t) {
		t.Run(p.name, func(t *testing.T) {
			heavyDockerTest(t)
			s := guardWindowSession(t, p.set)
			w := newWindowTally()
			seen := map[string][]windowSample{}
			for i := 0; i < guardWindowQuiesceRounds; i++ {
				log := fmt.Sprintf("/tmp/plimsoll-window-quiesce-%d.log", i)
				if i > 0 { // the quiesce killed the interpreter the watcher was loaded in
					pyCell(t, s, guardWindowPy+"'loaded'")
				}
				if got := pyCell(t, s, "plimsoll_window_watch("+jsString(t, sessionkit.QuiesceScript)+", "+jsString(t, log)+", True)"); got != "'watching'" {
					t.Fatalf("starting the watcher printed %q", got)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				res, err := s.RunProject(ctx, ProjectRequest{Steps: []string{"cat " + log + " 2>/dev/null || true"}, Timeout: 30 * time.Second})
				cancel()
				if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
					t.Fatalf("round %d: the project call after the watcher: %+v, %v", i, res, err)
				}
				for _, line := range strings.Split(strings.TrimSpace(res.Steps[0].Stdout), "\n") {
					var sample windowSample
					if json.Unmarshal([]byte(line), &sample) == nil && sample.PID > 0 {
						k := fmt.Sprintf("%d", sample.PID)
						seen[k] = append(seen[k], sample)
					}
				}
				w.rounds++
			}
			w.add(t, "quiesce", seen)
			w.report(t, "quiesce")
		})
	}
}

// TestDockerGuardWindowRelay: the same for a new cell relay. The Python watcher is kept; each
// round's JavaScript cell ends its own interpreter, so the next starts a new interpreter and a
// new relay. Opens only: what a write into a relay gives is the conformance suite's forged-relay
// cases.
func TestDockerGuardWindowRelay(t *testing.T) {
	t.Parallel()
	argv := sessionkit.RelayArgv(string(LanguageJavaScript), dockerSessionWork)
	for _, p := range guardWindowProfiles(t) {
		t.Run(p.name, func(t *testing.T) {
			heavyDockerTest(t)
			s := guardWindowSession(t, p.set)
			if got := pyCell(t, s, "plimsoll_window_watch("+jsString(t, argv[3])+", '', False)"); got != "'watching'" {
				t.Fatalf("starting the watcher printed %q", got)
			}
			w := newWindowTally()
			for i := 0; i < guardWindowRelayRounds; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				res, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: "process.exit(0)", Timeout: 30 * time.Second})
				cancel()
				if err != nil || !res.InterpreterEnded {
					t.Fatalf("round %d: the cell that ends its interpreter: %+v, %v", i, res, err)
				}
				w.rounds++
			}
			w.add(t, "relay", readWindowSeen(t, s))
			w.report(t, "relay")
			if got := guardCell(t, s, "2 + 2"); got != "4" {
				t.Fatalf("a JavaScript cell after the rounds printed %q", got)
			}
		})
	}
}
