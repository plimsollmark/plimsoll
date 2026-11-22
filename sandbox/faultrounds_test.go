package sandbox

// The fault rounds: the docker provider run against a docker CLI that fails on purpose.
//
// The provider starts the docker CLI by name, through dockerCommand, so the CLI is whatever
// "docker" comes first on the process's PATH. TestFaultRounds puts a stand-in there: this
// test binary itself, linked under the name docker (TestMain below runs the stand-in when it
// is started under that name). The stand-in counts the docker commands it is given and passes
// each to the real docker unchanged, except command number N, where it does one fault:
//
//   - refuse: exits 1 with a docker-like error, the real command never run;
//   - hang: never returns until killed, the real command never run;
//   - slow: waits a stated time, then runs the real command;
//   - ransaidno: runs the real command, then exits non-zero;
//   - ranhung: runs the real command, then never returns.
//
// One round is one scenario under one fault at one N. Everything a round chooses comes from
// its seed, printed with the round, so PLIMSOLL_FAULT_SEED=<seed> replays it. After each
// round the test asserts what is left behind: containers, processes, temporary directories,
// goroutines; that each call returned within its bound; that a refusal marked not dispatched
// is one after which nothing had run; and that the same provider then opens and closes
// cleanly. Run it with make docker-faults (ROUNDS=, SEED=, START=); it is not in the gate.

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain runs the docker stand-in when this binary was started as "docker" (a link the
// fault rounds make), and the tests otherwise. After the tests it drains every docker sandbox
// they built through testDocker or DrainAtExit, so no session container whose removal is
// still under way outlives the binary (drainAtExit says why).
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "docker" {
		os.Exit(faultStandIn())
	}
	code := m.Run()
	if err := drainTestSandboxes(2*time.Minute, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "draining the tests' docker sandboxes after the run: %v\n", err)
		code = cmp.Or(code, 1)
	}
	os.Exit(code)
}

// faultControl is the stand-in's instructions, a file beside its link: the stand-in is given
// PATH and nothing else (dockerCLIEnv), so its link's directory is where it looks.
type faultControl struct {
	Real  string `json:"real"`  // the real docker CLI
	Armed bool   `json:"armed"` // count and log commands; false passes every command through uncounted
	N     int    `json:"n"`     // the command to fault, counted from 1; 0 faults none
	Kind  string `json:"kind"`  // one of faultKinds
	Slow  int64  `json:"slow"`  // slow's wait, in milliseconds
	// Scope, when set, is added as a label filter to the orphan pass's listing (a ps with the
	// lifetime label), so a round's pass sees the containers the round planted and no other
	// run's: the pass otherwise removes every expired container on the host.
	Scope string `json:"scope"`
}

// faultEntry is one line of the stand-in's log: a command's number, its first arguments
// (never a file's contents: the docker CLI is given none on its command line) and what the
// stand-in did with it.
type faultEntry struct {
	N     int      `json:"n"`
	PID   int      `json:"pid"`
	Child int      `json:"child,omitempty"`
	Args  []string `json:"args"`
	Did   string   `json:"did"`
	At    int64    `json:"at"` // Unix milliseconds
}

const (
	faultRefuse    = "refuse"
	faultHang      = "hang"
	faultSlow      = "slow"
	faultRanSaidNo = "ransaidno"
	faultRanHung   = "ranhung"

	faultPassed       = "passed"
	faultRanAfterSlow = "ran after the wait"
)

// faultReachedDocker is whether a logged command reached the real docker.
func faultReachedDocker(did string) bool {
	return did == faultPassed || did == faultRanAfterSlow || did == faultRanSaidNo || did == faultRanHung
}

var faultKinds = []string{faultRefuse, faultHang, faultSlow, faultRanSaidNo, faultRanHung}

// faultStandIn is the stand-in's whole program.
func faultStandIn() int {
	runtime.LockOSThread() // Pdeathsig belongs to the thread that starts the child
	// The provider starts "docker" by name, so argv[0] is the bare name: the stand-in's
	// directory is the first on PATH holding its control file, and argv[0] becomes the full
	// link, so each of its processes names it.
	var dir string
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if _, err := os.Stat(filepath.Join(p, "control.json")); err == nil {
			dir = p
			break
		}
	}
	os.Args[0] = filepath.Join(dir, "docker")
	args := os.Args[1:]
	b, err := os.ReadFile(filepath.Join(dir, "control.json"))
	var c faultControl
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.Real == "" {
		fmt.Fprintf(os.Stderr, "docker stand-in: no control file: %v\n", err)
		return 125
	}
	if !c.Armed {
		return standInExec(c.Real, args)
	}
	if c.Scope != "" && slices.Contains(args, "ps") && slices.Contains(args, "label="+dockerExpiresLabel) {
		i := slices.Index(args, "ps")
		args = slices.Insert(slices.Clone(args), i+1, "--filter", "label="+c.Scope)
	}
	n, logLine := standInCount(dir)
	entry := faultEntry{N: n, PID: os.Getpid(), Args: standInArgs(args), At: time.Now().UnixMilli()}
	if n != c.N {
		entry.Did = faultPassed
		logLine(entry)
		return standInExec(c.Real, args)
	}
	entry.Did = c.Kind
	switch c.Kind {
	case faultRefuse:
		logLine(entry)
		fmt.Fprintln(os.Stderr, "Error response from daemon: a fault made on purpose (the command was not run)")
		return 1
	case faultHang:
		logLine(entry)
		for {
			time.Sleep(time.Hour)
		}
	case faultSlow:
		entry.Did = fmt.Sprintf("slow %dms", c.Slow)
		logLine(entry)
		// fixed-wait: the wait is the fault itself, a docker command that answers late by the round's stated time; nothing is waited for
		time.Sleep(time.Duration(c.Slow) * time.Millisecond)
		entry.Did, entry.At = faultRanAfterSlow, time.Now().UnixMilli()
		logLine(entry)
		return standInExec(c.Real, args)
	case faultRanSaidNo, faultRanHung:
		cmd := exec.Command(c.Real, args...)
		cmd.Args[0] = os.Args[0]
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "docker stand-in: %v\n", err)
			return 125
		}
		entry.Child = cmd.Process.Pid
		logLine(entry)
		err := cmd.Wait()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		if c.Kind == faultRanHung {
			for {
				time.Sleep(time.Hour)
			}
		}
		fmt.Fprintln(os.Stderr, "Error response from daemon: a fault made on purpose (the command was run)")
		if code > 0 {
			return code
		}
		return 1
	}
	fmt.Fprintf(os.Stderr, "docker stand-in: unknown fault %q\n", c.Kind)
	return 125
}

// standInExec replaces the stand-in by the real docker, under the stand-in's own name, so
// its process (the same process id) is still told apart as this run's.
func standInExec(real string, args []string) int {
	err := syscall.Exec(real, append([]string{os.Args[0]}, args...), os.Environ())
	fmt.Fprintf(os.Stderr, "docker stand-in: exec %s: %v\n", real, err)
	return 125
}

// standInCount takes the next command number under a lock on the counter file (commands
// arrive in parallel) and returns it with a function that appends the command's log line
// under the same lock.
func standInCount(dir string) (int, func(faultEntry)) {
	f, err := os.OpenFile(filepath.Join(dir, "count"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return -1, func(faultEntry) {}
	}
	lock := func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
	unlock := func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
	lock()
	b, _ := os.ReadFile(f.Name())
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	n++
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(n)), 0)
	unlock()
	return n, func(e faultEntry) {
		lock()
		defer unlock()
		line, _ := json.Marshal(e)
		if l, err := os.OpenFile(filepath.Join(dir, "log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
			_, _ = l.Write(append(line, '\n'))
			_ = l.Close()
		}
	}
}

// standInArgs is what the log keeps of a command: the private config flag and the daemon
// address dropped, then the subcommand and at most three words after it, each cut to 40
// bytes.
func standInArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if (args[i] == "--config" || args[i] == "--host") && i+1 < len(args) {
			i++
			continue
		}
		out = append(out, args[i])
	}
	if len(out) > 4 {
		out = out[:4]
	}
	for i, a := range out {
		if len(a) > 40 {
			out[i] = a[:40]
		}
	}
	return out
}

// faultRig is the stand-in as a test sees it.
type faultRig struct {
	dir, link, real string
}

func newFaultRig(t *testing.T) *faultRig {
	t.Helper()
	real, err := exec.LookPath("docker")
	if err != nil {
		infraSkip(t, "docker not available")
	}
	if real, err = filepath.Abs(real); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := &faultRig{dir: dir, link: filepath.Join(dir, "docker"), real: real}
	if err := os.Symlink(self, r.link); err != nil {
		t.Fatal(err)
	}
	r.set(t, faultControl{})
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if got, err := exec.LookPath("docker"); err != nil || got != r.link {
		t.Fatalf("docker on PATH is %q (%v); want the stand-in %s", got, err, r.link)
	}
	return r
}

// set writes the control file; the count and the log start again when armed.
func (r *faultRig) set(t *testing.T, c faultControl) {
	t.Helper()
	c.Real = r.real
	if c.Armed {
		_ = os.Remove(filepath.Join(r.dir, "count"))
		_ = os.Remove(filepath.Join(r.dir, "log"))
	}
	b, _ := json.Marshal(c)
	tmp := filepath.Join(r.dir, "control.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(r.dir, "control.json")); err != nil {
		t.Fatal(err)
	}
}

// count is the number of commands given so far while armed.
func (r *faultRig) count() int {
	b, _ := os.ReadFile(filepath.Join(r.dir, "count"))
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// entries is the log so far.
func (r *faultRig) entries() []faultEntry {
	f, err := os.Open(filepath.Join(r.dir, "log"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []faultEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e faultEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b faultEntry) int { return a.N - b.N })
	return out
}

// realDocker runs the real docker CLI, never the stand-in: the test's own looks at the host.
func (r *faultRig) realDocker(args ...string) ([]byte, error) {
	return exec.Command(r.real, args...).Output()
}

// alive is each process still running under the stand-in's name: a stand-in, or a real
// docker it became or started.
func (r *faultRig) alive(entries []faultEntry) []string {
	var out []string
	for _, e := range entries {
		for _, pid := range []int{e.PID, e.Child} {
			if pid == 0 {
				continue
			}
			b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
			if err != nil || !bytes.HasPrefix(b, []byte(r.link+"\x00")) {
				continue
			}
			if st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
				if f := strings.Fields(string(st[bytes.LastIndexByte(st, ')')+1:])); len(f) > 0 && f[0] == "Z" {
					continue // a zombie has ended; its parent has yet to read its status
				}
			}
			out = append(out, fmt.Sprintf("pid %d (command %d %v, %s)", pid, e.N, e.Args, e.Did))
		}
	}
	return out
}

func (r *faultRig) kill(entries []faultEntry) {
	for _, e := range entries {
		for _, pid := range []int{e.PID, e.Child} {
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); pid != 0 && err == nil && bytes.HasPrefix(b, []byte(r.link+"\x00")) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
}

// ofThisProcess is each container on the host with a mount from this process's private
// docker directory (dockerProcessFiles): every container the provider starts mounts its
// resolv.conf from there, and so does every container a round plants, so another run's
// container on the same host is never one of them.
func (r *faultRig) ofThisProcess(t *testing.T) []faultContainer {
	t.Helper()
	files, err := dockerProcessFiles()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := r.realDocker("ps", "-aq", "--no-trunc")
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	if len(bytes.Fields(ids)) == 0 {
		return nil
	}
	out, _ := r.realDocker(append([]string{"inspect"}, strings.Fields(string(ids))...)...)
	var all []faultContainer
	if err := json.Unmarshal(out, &all); err != nil {
		t.Fatalf("docker inspect: %v", err)
	}
	var mine []faultContainer
	for _, c := range all {
		if slices.ContainsFunc(c.Mounts, func(m struct{ Source string }) bool { return strings.HasPrefix(m.Source, files.dir+"/") }) {
			c.Name = strings.TrimPrefix(c.Name, "/")
			mine = append(mine, c)
		}
	}
	return mine
}

type faultContainer struct {
	ID     string
	Name   string
	State  struct{ Status string }
	Mounts []struct{ Source string }
}

func (r *faultRig) remove(name string) {
	_, _ = r.realDocker("unpause", name)
	_, _ = r.realDocker("rm", "-f", name)
}

// The scenarios. Each runs on a fresh provider made and preflighted before the fault is armed
// (except snippet-cold, whose Preflight is part of the round), and records every provider
// call it makes.

type faultCall struct {
	what     string
	err      error
	took     time.Duration
	bound    time.Duration
	from, to int // the command numbers given before and after the call
	// ran is whether the call's guest code ran: "yes", "no", or "" when it cannot be told.
	ran string
}

type faultRound struct {
	rig     *faultRig
	d       *DockerSandbox
	token   string
	calls   []faultCall
	planted []string
}

// faultCallBudget is each provider call's context: long enough for a slow fault and the
// slowest open under gVisor, short enough that a hang costs a round about a minute.
const faultCallBudget = 45 * time.Second

// faultBound is how long a call given faultCallBudget may take: its context, then one whole
// removal budget, since a call whose container was started removes it on a budget of its own
// after its context ends (removeOrHold, a failed open), then 5 s for the host.
const faultBound = faultCallBudget + dockerRemoveBudget + 5*time.Second

// call runs f under a fresh faultCallBudget context and records it.
func (fr *faultRound) call(what string, bound time.Duration, f func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), faultCallBudget)
	defer cancel()
	c := faultCall{what: what, bound: bound, from: fr.rig.count()}
	start := time.Now()
	c.err = f(ctx)
	c.took = time.Since(start)
	c.to = fr.rig.count()
	fr.calls = append(fr.calls, c)
	return c.err
}

func (fr *faultRound) cellCode() string {
	return fmt.Sprintf("process.getBuiltinModule('fs').writeFileSync('%s/ran-%s', '1'); 6 * 7", dockerSessionWork, fr.token)
}

// cell runs one JavaScript cell that leaves a marker file, then, with the session's turn
// held (so no sweep runs), asks the real docker whether the marker is there: whether the
// cell's code ran, when the container is still there to ask.
func (fr *faultRound) cell(s *dockerSession, what string) error {
	err := fr.call(what, faultBound, func(ctx context.Context) error {
		res, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: fr.cellCode(), Timeout: 20 * time.Second})
		if err == nil && (res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42") {
			return fmt.Errorf("the cell answered exit %d, stdout %q, stderr %q", res.ExitCode, res.Stdout, res.Stderr)
		}
		return err
	})
	c := &fr.calls[len(fr.calls)-1]
	hctx, cancel := context.WithTimeout(context.Background(), faultCallBudget)
	defer cancel()
	release, herr := s.life.Hold(hctx)
	if herr != nil {
		return err // the session ended: the container cannot be asked
	}
	defer release()
	path := fmt.Sprintf("%s/ran-%s", dockerSessionWork, fr.token)
	out, xerr := exec.Command(fr.rig.real, "exec", s.name, "/bin/sh", "-c", "test -e "+path+" && echo yes || echo no; rm -f "+path).Output()
	if xerr == nil {
		c.ran = strings.TrimSpace(string(out))
	}
	return err
}

func (fr *faultRound) open(opts SessionOptions) (*dockerSession, error) {
	var s *dockerSession
	err := fr.call("open", faultBound, func(ctx context.Context) error {
		opened, err := fr.d.OpenSession(ctx, opts)
		if err == nil {
			s = opened.(*dockerSession)
		}
		return err
	})
	return s, err
}

// closeAndWait closes s and waits for its Done: the provider has confirmed the container gone.
func (fr *faultRound) closeAndWait(s *dockerSession, what string) {
	bound := dockerRemoveBudget + 10*time.Second
	_ = fr.call(what, bound, func(ctx context.Context) error {
		_ = s.Close(ctx)
		select {
		case <-s.Done():
			return nil
		case <-time.After(bound + 5*time.Second):
			return errors.New("Done did not close")
		}
	})
}

type faultScenario struct {
	name string
	cold bool // the round's Preflight is part of it
	run  func(fr *faultRound)
}

var faultScenarios = []faultScenario{
	{"snippet", false, func(fr *faultRound) { fr.snippet("snippet") }},
	{"snippet-cold", true, func(fr *faultRound) { fr.snippet("snippet with its Preflight") }},
	{"session-call", false, func(fr *faultRound) {
		s, err := fr.open(SessionOptions{Lifetime: 2 * time.Minute})
		if err != nil {
			return
		}
		_ = fr.cell(s, "cell")
		fr.closeAndWait(s, "close")
	}},
	{"suspend-resume", false, func(fr *faultRound) {
		s, err := fr.open(SessionOptions{Lifetime: 2 * time.Minute})
		if err != nil {
			return
		}
		_ = fr.cell(s, "cell")
		_ = fr.call("suspend", faultBound, func(ctx context.Context) error { _, err := s.Suspend(ctx); return err })
		_ = fr.cell(s, "cell after resume")
		fr.closeAndWait(s, "close")
	}},
	{"suspend-close", false, func(fr *faultRound) {
		s, err := fr.open(SessionOptions{Lifetime: 2 * time.Minute})
		if err != nil {
			return
		}
		_ = fr.cell(s, "cell")
		_ = fr.call("suspend", faultBound, func(ctx context.Context) error { _, err := s.Suspend(ctx); return err })
		fr.closeAndWait(s, "close while suspended")
	}},
	{"lifetime", false, func(fr *faultRound) {
		s, err := fr.open(SessionOptions{Lifetime: 15 * time.Second})
		if err != nil {
			return
		}
		_ = fr.cell(s, "cell")
		bound := time.Until(s.ExpiresAt()) + dockerRemoveBudget + 10*time.Second
		_ = fr.call("lifetime end", bound, func(context.Context) error {
			select {
			case <-s.Done():
				return nil
			case <-time.After(bound + 5*time.Second):
				return errors.New("Done did not close")
			}
		})
	}},
	{"pool", false, func(fr *faultRound) {
		s, err := fr.open(SessionOptions{Lifetime: time.Minute, Languages: []Language{LanguageJavaScript}})
		if err != nil {
			return
		}
		_ = fr.cell(s, "cell")
		fr.closeAndWait(s, "close")
	}},
	{"orphan-pass", false, func(fr *faultRound) {
		_ = fr.call("orphan pass", 30*time.Second+5*time.Second, func(context.Context) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // plimsolld's pass
			defer cancel()
			_, err := fr.d.ReconcileOrphans(ctx)
			return err
		})
	}},
}

func (fr *faultRound) snippet(what string) {
	_ = fr.call(what, faultBound, func(ctx context.Context) error {
		res, err := fr.d.RunJavaScript(ctx, Request{Code: "console.log(6 * 7)", Timeout: 20 * time.Second})
		if err == nil && (res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42") {
			return fmt.Errorf("the snippet answered exit %d, stdout %q", res.ExitCode, res.Stdout)
		}
		return err
	})
	c := &fr.calls[len(fr.calls)-1]
	// A snippet's container is gone when the call returns, so whether its code ran is read
	// from the log: the snippet's docker run reached the real docker.
	c.ran = "no"
	for _, e := range fr.rig.entries() {
		if e.N > c.from && e.N <= c.to && len(e.Args) > 0 && e.Args[0] == "run" && faultReachedDocker(e.Did) {
			c.ran = "yes"
		}
	}
}

// faultChoice is what a seed chooses: the scenario and the fault (in turn, so consecutive
// seeds cover every pair), the fault's place as a fraction of the scenario's command count,
// and slow's wait.
type faultChoice struct {
	scenario, kind int
	place          float64
	slow           time.Duration
}

func chooseFault(seed int64) faultChoice {
	rng := rand.New(rand.NewPCG(uint64(seed), 0x666175))
	u := uint64(seed)
	return faultChoice{
		scenario: int(u % uint64(len(faultScenarios))),
		kind:     int(u / uint64(len(faultScenarios)) % uint64(len(faultKinds))),
		place:    rng.Float64(),
		slow:     time.Duration(500+rng.IntN(12000)) * time.Millisecond,
	}
}

// faultRegressionSeeds are rounds that found a defect, replayed first by every run: each
// fails its "check reason" until that defect is fixed (a cell answered "not supported" after
// one docker command failed at its interpreter's start).
var faultRegressionSeeds = []int64{1002, 1067, 1125, 2004, 2027}

func TestFaultRounds(t *testing.T) {
	if testing.Short() {
		t.Skip("the fault rounds run docker; make docker-faults runs them")
	}
	rounds, _ := strconv.Atoi(os.Getenv("PLIMSOLL_FAULT_ROUNDS"))
	replay := os.Getenv("PLIMSOLL_FAULT_SEED")
	if rounds <= 0 && replay == "" {
		t.Skip("set PLIMSOLL_FAULT_ROUNDS (make docker-faults ROUNDS=n) or PLIMSOLL_FAULT_SEED to run the fault rounds")
	}
	images := testDocker()
	requireProjectImage(t, images)
	requireSnippetImage(t, images)
	rig := newFaultRig(t)
	// The checks first: each must fail on a round that leaves its thing behind.
	if !t.Run("control", func(t *testing.T) { faultControlRound(t, rig) }) {
		t.Fatal("a check did not fail on the control round, so the rounds would prove nothing")
	}

	var seeds []int64
	if replay != "" {
		for _, f := range strings.Split(replay, ",") {
			s, err := strconv.ParseInt(strings.TrimSpace(f), 10, 64)
			if err != nil {
				t.Fatalf("PLIMSOLL_FAULT_SEED %q: %v", replay, err)
			}
			seeds = append(seeds, s)
		}
	} else {
		start := time.Now().UnixNano() % 1_000_000_000
		if s := os.Getenv("PLIMSOLL_FAULT_START"); s != "" {
			var err error
			if start, err = strconv.ParseInt(s, 10, 64); err != nil {
				t.Fatalf("PLIMSOLL_FAULT_START %q: %v", s, err)
			}
		}
		// Start on a multiple of the scenario count, so a run covers scenarios evenly.
		start -= start % int64(len(faultScenarios))
		t.Logf("fault rounds: %d rounds from seed %d (replay one with PLIMSOLL_FAULT_SEED=<seed>, the run with PLIMSOLL_FAULT_START=%d)", rounds, start, start)
		seeds = append(slices.Clone(faultRegressionSeeds), func() []int64 {
			out := make([]int64, rounds)
			for i := range out {
				out[i] = start + int64(i)
			}
			return out
		}()...)
	}

	// Each scenario once with no fault, to learn how many docker commands it gives, so each
	// round's N lands on a real command. Every check must pass here, or the tool is wrong.
	counts := map[int]int{}
	for i, sc := range faultScenarios {
		var n int
		t.Run(fmt.Sprintf("count-%s", sc.name), func(t *testing.T) {
			var failed []string
			n, failed = runFaultRound(t, rig, -1-int64(i), sc, faultControl{Armed: true})
			for _, f := range failed {
				t.Error(f)
			}
		})
		if n == 0 {
			t.Fatalf("scenario %s gave no docker command with no fault", sc.name)
		}
		counts[i] = n
	}
	for _, seed := range seeds {
		ch := chooseFault(seed)
		sc := faultScenarios[ch.scenario]
		n := 1 + int(ch.place*float64(counts[ch.scenario]))
		ctl := faultControl{Armed: true, N: n, Kind: faultKinds[ch.kind], Slow: ch.slow.Milliseconds()}
		t.Run(fmt.Sprintf("seed-%d-%s-%s-N%d", seed, sc.name, ctl.Kind, n), func(t *testing.T) {
			_, failed := runFaultRound(t, rig, seed, sc, ctl)
			for _, f := range failed {
				t.Error(f)
			}
		})
	}
}

// faultChecks collects a round's failed checks, so the control below can require that each
// check fails when what it looks for is there.
type faultChecks struct {
	t      *testing.T
	failed []string
}

func (ck *faultChecks) Errorf(format string, args ...any) {
	ck.failed = append(ck.failed, fmt.Sprintf(format, args...))
}

// The control: a round that leaves behind, on purpose, one of each thing the checks look for
// (a container of this process, a process under the stand-in's name, a directory under
// TMPDIR, a goroutine), and records a call past its bound, a call marked not dispatched whose
// code ran, and an answer whose code did not run. Each check must fail on it: a check that
// stays quiet here would stay quiet on a real defect too.
func faultControlRound(t *testing.T, rig *faultRig) {
	stop := make(chan struct{})
	leaky := faultScenario{name: "leaks", run: func(fr *faultRound) {
		fr.plant(t, "io.plimsoll.faultround="+fr.token, 10*time.Minute) // not expired, so no orphan pass on the host (another run's included) removes it
		// A stand-in that hangs: armed with command 1 hung, then given a command.
		fr.rig.set(t, faultControl{Armed: true, N: 1, Kind: faultHang})
		hung := exec.Command(fr.rig.link, "version")
		if err := hung.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { _ = hung.Wait() }()
		for fr.rig.count() < 1 {
			time.Sleep(20 * time.Millisecond)
		}
		if err := os.Mkdir(filepath.Join(os.TempDir(), "plimsoll-faults-control-"+fr.token), 0o700); err != nil {
			t.Fatal(err)
		}
		go func() { <-stop }()
		fr.calls = append(fr.calls,
			faultCall{what: "a call past its bound", took: 2 * time.Second, bound: time.Second},
			faultCall{what: "a call marked not dispatched whose code ran", err: NotDispatched(RefusalEnvironment, errors.New("control")), ran: "yes"},
			faultCall{what: "an answer whose code did not run", ran: "no"},
			faultCall{what: "a call answered not supported after the fault", err: NotDispatched(RefusalEnvironment, fmt.Errorf("%w: control", ErrUnsupported))})
	}}
	_, failed := runFaultRound(t, rig, 0, leaky, faultControl{Armed: true, N: 1, Kind: faultHang}) // the fault is leaky's hung stand-in
	close(stop)
	for _, d := range tmpEntries() {
		if strings.HasPrefix(d, "plimsoll-faults-control-") {
			_ = os.Remove(filepath.Join(os.TempDir(), d))
		}
	}
	for _, check := range []string{"check bound:", "check truth: a call marked", "check truth: an answer", "check reason:", "check host:", "check processes:", "check tmp:", "check goroutines:"} {
		if !slices.ContainsFunc(failed, func(f string) bool { return strings.HasPrefix(f, check) }) {
			t.Errorf("the control left what %q looks for, and that check did not fail; the failures: %q", check, failed)
		}
	}
	for _, f := range failed {
		t.Logf("the control failed, as it must: %.200s", f)
	}
}

// runFaultRound runs one round and its checks, and returns how many docker commands the
// scenario gave while armed and each check that failed.
func runFaultRound(t *testing.T, rig *faultRig, seed int64, sc faultScenario, ctl faultControl) (int, []string) {
	ck := &faultChecks{t: t}
	if left := rig.ofThisProcess(t); len(left) > 0 {
		for _, c := range left {
			rig.remove(c.Name)
		}
		t.Fatalf("before the round, containers of this process are on the host (an earlier round's, now removed): %v", left)
	}
	tmpBefore := tmpEntries()
	runtime.GC()
	goBefore := runtime.NumGoroutine()

	d := testDocker()
	fr := &faultRound{rig: rig, d: d, token: fmt.Sprintf("r%d", time.Now().UnixNano())}
	if !sc.cold {
		frozen := time.Now()
		d.preflightNow = func() time.Time { return frozen } // one Preflight serves the round, so its count does not depend on timing
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := d.Preflight(ctx)
		cancel()
		if err != nil {
			t.Fatalf("Preflight before the round: %v", err)
		}
	}
	switch sc.name {
	case "pool":
		d.stateMu.Lock()
		d.projectLanguages = []Language{LanguageJavaScript} // what the smoke test finds; it is not run here
		d.stateMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := d.StartSessionPool(ctx, 1, 2*time.Minute)
		cancel()
		if err != nil {
			t.Fatalf("StartSessionPool: %v", err)
		}
	case "orphan-pass":
		ctl.Scope = "io.plimsoll.faultround=" + fr.token
		fr.plant(t, ctl.Scope, -10*time.Minute)
	}

	rig.set(t, ctl)
	t.Logf("seed %d: scenario %s, fault %s at command %d (slow %dms); runtime %q", seed, sc.name, ctl.Kind, ctl.N, ctl.Slow, d.Runtime)
	sc.run(fr)
	n := rig.count()
	entries := rig.entries()
	rig.set(t, faultControl{})

	for _, e := range entries {
		t.Logf("  command %d %v: %s", e.N, e.Args, e.Did)
	}
	faulted := ctl.N > 0 && ctl.N <= n
	if ctl.N > 0 && !faulted {
		t.Logf("the fault was not reached: the scenario gave %d commands this time", n)
	}
	for _, c := range fr.calls {
		mark := ""
		if reason, ok := NotDispatchedReason(c.err); ok {
			mark = fmt.Sprintf(" [marked not dispatched: %s]", reason)
		}
		t.Logf("  call %s: %v%s in %v (commands %d to %d), its code ran: %q", c.what, c.err, mark, c.took.Round(time.Millisecond), c.from+1, c.to, c.ran)
	}

	// The call's bound.
	for _, c := range fr.calls {
		if c.took > c.bound {
			ck.Errorf("check bound: %s took %v, past its bound %v", c.what, c.took.Round(time.Millisecond), c.bound)
		}
	}
	// The result tells the truth: a call marked not dispatched ran nothing.
	for _, c := range fr.calls {
		if _, marked := NotDispatchedReason(c.err); marked && c.ran == "yes" {
			ck.Errorf("check truth: %s was refused as not dispatched (%v), and its code ran", c.what, c.err)
		}
		if c.err == nil && c.ran == "no" {
			ck.Errorf("check truth: %s answered, and its code did not run", c.what)
		}
		// Every scenario's image runs what it asks for, so a call answered "not supported"
		// after a docker command failed is told the wrong reason: the failure was docker's.
		if faulted && errors.Is(c.err, ErrUnsupported) {
			ck.Errorf("check reason: %s was answered as not supported after one docker command failed: %v", c.what, c.err)
		}
	}
	if !faulted {
		// A round whose fault never fired: every call must succeed.
		for _, c := range fr.calls {
			if c.err != nil {
				ck.Errorf("check no-fault: %s failed with no fault: %v", c.what, c.err)
			}
		}
	}
	if sc.name == "orphan-pass" {
		fr.afterOrphanPass(t, ck)
	}

	// The provider is not poisoned: a fault-free open, cell and close on it work.
	follow := &faultRound{rig: rig, d: d, token: fr.token + "f"}
	if s, err := follow.open(SessionOptions{Lifetime: time.Minute}); err != nil {
		ck.Errorf("check after: a fault-free open on the same provider failed: %v", err)
	} else {
		if err := follow.cell(s, "cell"); err != nil {
			ck.Errorf("check after: a fault-free cell on the same provider failed: %v", err)
		}
		follow.closeAndWait(s, "close")
		if err := follow.calls[len(follow.calls)-1].err; err != nil {
			ck.Errorf("check after: a fault-free close on the same provider: %v", err)
		}
	}
	if sc.name == "snippet" || sc.name == "snippet-cold" {
		follow.snippet("snippet")
		if err := follow.calls[len(follow.calls)-1].err; err != nil {
			ck.Errorf("check after: a fault-free snippet on the same provider failed: %v", err)
		}
	}
	dctx, dcancel := context.WithTimeout(context.Background(), dockerRemoveBudget+30*time.Second)
	if err := d.Drain(dctx); err != nil {
		ck.Errorf("check after: Drain: %v", err)
	}
	dcancel()

	// Nothing left on the host. A container the provider still holds in its quarantine is
	// one it knows it has not removed; the orphan pass would try again, so the round tries
	// once, by name, without the fault, and only one still there after that is a leftover
	// the provider would never remove.
	settle := time.Now().Add(time.Minute)
	left := rig.ofThisProcess(t)
	for len(left) > 0 && time.Now().Before(settle) {
		time.Sleep(2 * time.Second)
		left = rig.ofThisProcess(t)
	}
	held := d.quarantine.Names()
	if len(held) > 0 {
		t.Logf("the quarantine holds %v; retrying each by name, without the fault", held)
		host := d.pinnedDaemon()
		confirmed, err := d.quarantine.Retry(func(name string) error {
			ctx, cancel := context.WithTimeout(context.Background(), dockerRemoveBudget)
			defer cancel()
			return removeContainer(ctx, host, name)
		})
		if err != nil {
			ck.Errorf("check host: quarantined containers not confirmed gone by a fault-free retry: %v (%d confirmed)", err, confirmed)
		}
		left = rig.ofThisProcess(t)
	}
	for _, c := range left {
		ck.Errorf("check host: container %s (%s) is still on the host, and the provider does not hold it in its quarantine", c.Name, c.State.Status)
		rig.remove(c.Name)
	}

	// No process of the round still runs.
	var alive []string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if alive = rig.alive(entries); len(alive) == 0 || time.Now().After(deadline) {
			break
		}
	}
	for _, a := range alive {
		ck.Errorf("check processes: still running 10 s after the round: %s", a)
	}
	rig.kill(entries)

	// No temporary directory of the provider is left.
	var newTmp []string
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		newTmp = newTmp[:0]
		for _, e := range tmpEntries() {
			if !slices.Contains(tmpBefore, e) {
				newTmp = append(newTmp, e)
			}
		}
		if len(newTmp) == 0 || time.Now().After(deadline) {
			break
		}
	}
	for _, e := range newTmp {
		ck.Errorf("check tmp: %s was left under TMPDIR", e)
	}

	// Goroutines back to the count before the round: compared after up to 20 s.
	var goAfter int
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		runtime.GC()
		if goAfter = runtime.NumGoroutine(); goAfter <= goBefore || time.Now().After(deadline) {
			break
		}
	}
	if goAfter > goBefore {
		buf := make([]byte, 1<<20)
		ck.Errorf("check goroutines: %d before the round, %d 20 s after it; the goroutines now:\n%s", goBefore, goAfter, buf[:runtime.Stack(buf, true)])
	}
	return n, ck.failed
}

// plant starts two containers as a dead daemon would have left them: the lifetime label at
// expiresIn from now (10 minutes past, for an orphan pass to remove), a mount from this process's private directory (so the round tells them
// apart), the round's own label (the stand-in scopes the pass's listing to it), one of the
// two paused, both under the round's runtime.
func (fr *faultRound) plant(t *testing.T, scope string, expiresIn time.Duration) {
	t.Helper()
	files, err := dockerProcessFiles()
	if err != nil {
		t.Fatal(err)
	}
	expired := strconv.FormatInt(time.Now().Add(expiresIn).Unix(), 10)
	for i := range 2 {
		name := fmt.Sprintf("plimsoll-faults-%s-%d", fr.token, i)
		args := []string{"run", "-d", "--name", name, "--network", "none",
			"--label", dockerExpiresLabel + "=" + expired, "--label", scope,
			"--mount", "type=bind,src=" + files.resolvConf + ",dst=/etc/fault-mark,ro", "--entrypoint", "sleep"}
		if fr.d.Runtime != "" {
			args = append(args, "--runtime", fr.d.Runtime)
		}
		args = append(args, fr.d.ProjectImage, "600")
		if out, err := exec.Command(fr.rig.real, args...).CombinedOutput(); err != nil {
			t.Fatalf("planting %s: %v: %s", name, err, out)
		}
		if i == 1 {
			if out, err := exec.Command(fr.rig.real, "pause", name).CombinedOutput(); err != nil {
				t.Fatalf("pausing %s: %v: %s", name, err, out)
			}
		}
		fr.planted = append(fr.planted, name)
	}
}

// afterOrphanPass: what one faulted pass left of the planted containers, a second pass
// without the fault must remove (the pass runs every minute in plimsolld).
func (fr *faultRound) afterOrphanPass(t *testing.T, ck *faultChecks) {
	t.Helper()
	still := func() []string {
		var out []string
		for _, c := range fr.rig.ofThisProcess(t) {
			if slices.Contains(fr.planted, c.Name) {
				out = append(out, c.Name)
			}
		}
		return out
	}
	if left := still(); len(left) > 0 {
		t.Logf("the faulted pass left %v; a second pass without the fault", left)
		fr.rig.set(t, faultControl{Armed: true, Scope: "io.plimsoll.faultround=" + fr.token})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := fr.d.ReconcileOrphans(ctx)
		cancel()
		fr.rig.set(t, faultControl{})
		if left := still(); len(left) > 0 {
			ck.Errorf("check orphan: a fault-free pass after the faulted one left %v (its error: %v)", left, err)
		}
	}
}

// tmpEntries names what is under TMPDIR now.
func tmpEntries() []string {
	des, _ := os.ReadDir(os.TempDir())
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}
