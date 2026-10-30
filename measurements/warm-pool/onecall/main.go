// Command onecall measures the one-call path (RunRequest.prefer_warm) end to end: from
// a client of plimsolld, the time for a Run of one cell served by a waiting pool member,
// the same Run in a sandbox made for it (no prefer_warm), a prefer_warm Run sent when no
// member is free (the miss, which runs fresh), and for comparison a session opened
// warm-only, one cell run in it and the session closed. Unlike the other programs here
// it goes through the daemon: it builds plimsolld from this checkout, starts it on a
// loopback port with a pool of -pool members, and calls it with the Go client.
//
//	go run ./measurements/warm-pool/onecall                    # docker, runc
//	go run ./measurements/warm-pool/onecall -runtime runsc     # docker, gVisor
//	go run ./measurements/warm-pool/onecall -provider openshell # SANDBOX_OPENSHELL_* naming a gateway
//
// Every repetition runs each measured call once per language, in the same order, with
// an untimed pause before each so the pool has made its next member. Each warm sample
// must answer warm, and each fresh, session and miss sample is checked the same way;
// a sample that does not is a failure, not a dropped point.
//
// A fresh run on docker re-runs the provider's Preflight (its checks of the docker
// daemon, the runtime and the images) when the last one is 5 seconds old or more, and a
// warm one never does. The pause is longer than that, so the fresh run and the miss are
// each measured twice: as they come after the pause, Preflight due, and right after a
// GET /readyz has refreshed it (untimed; its own time is recorded), Preflight cached.
//
// Run it from the repository root, with the images make docker-images builds, and with
// nothing else using docker if the numbers are to be compared. It writes
// docs/measurements/warm-pool/onecall-<runtime>[-<tag>].json (-tag repeat for a second
// set of the same runtime), which report.py renders, and keeps the daemon's log in tmp/.
// An interrupt or a failure stops the daemon, which removes its pool, before exiting.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// Sample is one measured call: every repetition's wall time in ms, and per repetition
// what the daemon said ran it (Warm) and the containers docker created while it ran
// (FreshCreates: a run's own sandbox; MemberCreates: a session container, which is a
// pool member being made or a session's). The docker counts are empty on openshell,
// whose gateway's containers carry no plimsoll label.
type Sample struct {
	Name          string    `json:"name"`
	Language      string    `json:"language"`
	Ms            []float64 `json:"ms"`
	Warm          []bool    `json:"warm"`
	FreshCreates  []int     `json:"freshCreates,omitempty"`
	MemberCreates []int     `json:"memberCreates,omitempty"`
}

// Load is /proc/loadavg's 1, 5 and 15 minute averages.
type Load [3]float64

// Run is one daemon's measurements.
type Run struct {
	Provider string    `json:"provider"`
	Runtime  string    `json:"runtime"`
	Tier     string    `json:"tier"`
	Image    string    `json:"image"`
	ImageID  string    `json:"imageId,omitempty"`
	Docker   string    `json:"docker,omitempty"`
	Machine  string    `json:"machine"`
	When     time.Time `json:"when"`
	Ended    time.Time `json:"ended"`
	Reps     int       `json:"reps"`
	PauseMs  int64     `json:"pauseMs"`
	Pool     int       `json:"pool"`
	Code     string    `json:"code"`
	// LoadStart and LoadEnd are the machine's load averages as the timed repetitions
	// began and ended; RepLoad1 is the 1-minute average as each repetition began.
	LoadStart Load      `json:"loadStart"`
	LoadEnd   Load      `json:"loadEnd"`
	RepLoad1  []float64 `json:"repLoad1"`
	Samples   []Sample  `json:"samples"`
	// AuditWarm counts the daemon's own audit lines for cell Runs by their warm
	// attribute, over the whole run (warm-up included): a cross-check of the answers.
	AuditWarm map[string]int `json:"auditWarm"`
	// Unexpected lists each sample during which docker created a different number of
	// run containers than the call makes (none for a warm call or a session, one for a
	// fresh run or a miss), with what it created: the plimsoll containers of any process
	// on the machine count, so an extra one can be another program's.
	Unexpected []string `json:"unexpected"`
	// ClockJumps lists each sample during which the wall clock moved more than 20 ms
	// against the monotonic clock the samples are timed on (the samples are unaffected).
	ClockJumps []string `json:"clockJumps"`
	// Leftover names plimsoll containers (any process's) that existed after the daemon
	// stopped and not before it started: empty when it cleaned up after itself.
	Leftover []string `json:"leftover"`
}

const cellCode = "6 * 7"

func main() {
	provider := flag.String("provider", "docker", "docker or openshell")
	rt := flag.String("runtime", "", "docker runtime (runsc for gVisor)")
	reps := flag.Int("reps", 17, "repetitions per measured call")
	pause := flag.Duration("pause", 5200*time.Millisecond, "untimed pause before each measured call: the pool makes its next member, and Preflight's 5-second cache runs out")
	poolSize := flag.Int("pool", 1, "SANDBOX_SESSION_POOL: members the daemon keeps waiting")
	tag := flag.String("tag", "", "suffix for the output file, for a repeated run")
	image := flag.String("image", "plimsoll/sandbox-python:latest", "project image (docker) or SANDBOX_OPENSHELL_IMAGE (openshell)")
	flag.Parse()
	ctx := context.Background()

	name := *provider
	switch {
	case *provider == "docker" && *rt == "":
		name = "runc"
	case *provider == "docker":
		name = *rt
	case *provider != "openshell":
		die("unknown provider %q", *provider)
	}
	if *tag != "" {
		name += "-" + *tag
	}
	out := filepath.Join("docs", "measurements", "warm-pool", "onecall-"+name+".json")
	// An interrupt ends the run as a failure does: the daemon is stopped (it removes its
	// pool and sessions) before the program exits, never left running.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { die("interrupted: %v", <-sig) }()

	scratch, err := os.MkdirTemp("tmp", "onecall-")
	if err != nil {
		die("scratch directory under tmp/ (run from the repository root): %v", err)
	}
	atExit(func() { os.RemoveAll(scratch) })
	binary := filepath.Join(scratch, "plimsolld")
	if b, err := exec.Command("go", "build", "-o", binary, "./cmd/plimsolld").CombinedOutput(); err != nil {
		die("build plimsolld: %v\n%s", err, b)
	}
	token := randomHex(32)
	env := []string{
		"SANDBOX_PROVIDER=" + *provider,
		"PLIMSOLL_TOKEN=" + token,
		"SANDBOX_MAX_SESSIONS=4",
		"SANDBOX_SESSION_POOL=" + strconv.Itoa(*poolSize),
		// Every call of a repetition comes from one caller, faster than the default
		// 30 a minute: the limiter would decide the timing, not the sandbox.
		"SANDBOX_RATE_PER_MIN=0",
	}
	switch *provider {
	case "docker":
		env = append(env, "SANDBOX_DOCKER_PROJECT_IMAGE="+*image, "SANDBOX_DOCKER_RUNTIME="+*rt)
	case "openshell":
		for _, k := range []string{"SANDBOX_OPENSHELL_GATEWAY_URL", "SANDBOX_OPENSHELL_CA_FILE", "SANDBOX_OPENSHELL_CERT_FILE", "SANDBOX_OPENSHELL_KEY_FILE"} {
			if os.Getenv(k) == "" {
				die("-provider openshell needs %s (docs/openshell.md)", k)
			}
			env = append(env, k+"="+os.Getenv(k))
		}
		env = append(env, "SANDBOX_OPENSHELL_IMAGE="+*image)
	}

	var before []string
	if *provider == "docker" {
		before = plimsollContainers()
	}
	daemonLog := filepath.Join(scratch, "plimsolld.log")
	// The daemon's log (its audit lines) is kept in tmp/ when the run ends, whichever way:
	// registered before the daemon's stop, so it runs after it.
	atExit(func() {
		if b, err := os.ReadFile(daemonLog); err == nil {
			_ = os.WriteFile(filepath.Join("tmp", "onecall-"+name+"-plimsolld.log"), b, 0o644)
		}
	})
	d, err := startDaemon(ctx, binary, env, daemonLog)
	if err != nil {
		die("%v", err)
	}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if err := d.stop(2 * time.Minute); err != nil {
				log.Printf("stopping plimsolld: %v", err)
			}
		})
	}
	atExit(stop)
	fail := die

	remote, err := client.New(d.baseURL, client.WithToken(token))
	if err != nil {
		fail("client: %v", err)
	}
	info, err := remote.Describe(ctx)
	if err != nil {
		fail("Describe: %v", err)
	}
	if info.SessionPool != *poolSize {
		fail("the daemon states a pool of %d, not %d", info.SessionPool, *poolSize)
	}
	run := Run{Provider: *provider, Runtime: *rt, Tier: info.Isolation.String(), Image: *image, Machine: machine(),
		Reps: *reps, PauseMs: pause.Milliseconds(), Pool: *poolSize, Code: cellCode, AuditWarm: map[string]int{}, Unexpected: []string{}, ClockJumps: []string{}, Leftover: []string{}}
	if run.Runtime == "" {
		run.Runtime = "runc"
	}
	if *provider == "docker" {
		run.ImageID = strings.TrimSpace(output("docker", "image", "inspect", "-f", "{{.Id}}", *image))
		run.Docker = strings.TrimSpace(output("docker", "version", "-f", "{{.Server.Version}}"))
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

	cell := func(lang sandbox.Language, preferWarm bool) (sandbox.CellResult, error) {
		res, err := remote.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: cellCode, Timeout: 30 * time.Second}, client.CellOptions{PreferWarm: preferWarm})
		if err == nil && (res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42") {
			err = fmt.Errorf("exit %d, stdout %q, stderr %q", res.ExitCode, res.Stdout, res.Stderr)
		}
		return res, err
	}
	// refresh asks /readyz, which re-runs the provider's Preflight unless its last result
	// is under 5 seconds old (docker), as a fresh run does before it dispatches; so a
	// fresh run right after it finds Preflight cached. It returns how long it took.
	refresh := func() (time.Duration, error) {
		start := time.Now()
		resp, err := http.Get(d.baseURL + "/readyz")
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("/readyz answered %s", resp.Status)
		}
		return time.Since(start), nil
	}
	// take is a prefer_warm Run that must be served by the only waiting member, so the
	// call after it finds none.
	take := func(l sandbox.Language) error {
		if res, err := cell(l, true); err != nil || !res.Warm {
			return fmt.Errorf("the call that takes the member: warm %v, %v", res.Warm, err)
		}
		return nil
	}
	// Each measured call times what a caller waits for its answer and reports whether
	// a pool member served it; the session times its open, its cell and its close.
	// Whatever it does first (refresh, take) is untimed.
	type measured struct {
		total time.Duration
		parts []time.Duration // the session's open, cell and close
		warm  bool
		ready time.Duration // the refresh before it, when it made one
	}
	timedCell := func(l sandbox.Language, preferWarm bool) (measured, error) {
		start := time.Now()
		res, err := cell(l, preferWarm)
		return measured{total: time.Since(start), warm: res.Warm}, err
	}
	calls := []struct {
		name string
		want bool // whether a member must have served it
		do   func(sandbox.Language) (measured, error)
	}{
		{"warm", true, func(l sandbox.Language) (measured, error) { return timedCell(l, true) }},
		// A fresh run after the pause, which is longer than Preflight's 5-second cache:
		// it re-runs Preflight first, as any fresh run more than 5 s after the last does.
		{"fresh", false, func(l sandbox.Language) (measured, error) { return timedCell(l, false) }},
		// The same run with Preflight just refreshed, as on a daemon busy enough that
		// some fresh run or readiness check ran in the last 5 s.
		{"fresh, Preflight cached", false, func(l sandbox.Language) (measured, error) {
			ready, err := refresh()
			if err != nil {
				return measured{}, err
			}
			m, err := timedCell(l, false)
			m.ready = ready
			return m, err
		}},
		// The miss: take the only member, then the timed prefer_warm Run as soon as that
		// answers, while the pool is still making the next member. It runs fresh, so it
		// is measured with Preflight due and cached, as the fresh run is.
		{"miss", false, func(l sandbox.Language) (measured, error) {
			if err := take(l); err != nil {
				return measured{}, err
			}
			return timedCell(l, true)
		}},
		{"miss, Preflight cached", false, func(l sandbox.Language) (measured, error) {
			ready, err := refresh()
			if err != nil {
				return measured{}, err
			}
			if err := take(l); err != nil {
				return measured{}, err
			}
			m, err := timedCell(l, true)
			m.ready = ready
			return m, err
		}},
		// A session claimed from the pool (warm-only, so a session that had to be made is
		// a refusal, not a slow sample), one cell, closed: the one call as three.
		{"session", true, func(l sandbox.Language) (measured, error) {
			start := time.Now()
			s, err := remote.OpenSession(ctx, client.SessionOptions{WarmOnly: true, Languages: []sandbox.Language{l}})
			if err != nil {
				return measured{}, fmt.Errorf("warm-only open: %w", err)
			}
			opened := time.Now()
			res, err := s.RunCell(ctx, sandbox.CellRequest{Language: l, Code: cellCode, Timeout: 30 * time.Second})
			answered := time.Now()
			if err == nil && (res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42") {
				err = fmt.Errorf("exit %d, stdout %q, stderr %q", res.ExitCode, res.Stdout, res.Stderr)
			}
			_, cerr := s.Close(ctx)
			closed := time.Now()
			return measured{total: answered.Sub(start), parts: []time.Duration{opened.Sub(start), answered.Sub(opened), closed.Sub(answered)}, warm: true},
				errors.Join(err, cerr)
		}},
	}
	langs := []sandbox.Language{sandbox.LanguagePython, sandbox.LanguageJavaScript}
	samples := map[string]*Sample{}
	var order []string
	sample := func(key, lang string) *Sample {
		if s, ok := samples[key]; ok {
			return s
		}
		s := &Sample{Name: key, Language: lang}
		samples[key] = s
		order = append(order, key)
		return s
	}

	// Warm-up, untimed: one of each call per language, so no first-use cost of the
	// image, the page cache or the daemon's own start lands in a sample.
	for _, l := range langs {
		for _, c := range calls {
			time.Sleep(*pause)
			if _, err := c.do(l); err != nil {
				fail("warm-up %s %s: %v", c.name, l, err)
			}
		}
	}

	run.When = time.Now().UTC()
	run.LoadStart = loadavg()
	for i := 0; i < *reps; i++ {
		run.RepLoad1 = append(run.RepLoad1, loadavg()[0])
		for _, l := range langs {
			for _, c := range calls {
				time.Sleep(*pause)
				t0 := time.Now()
				m, err := c.do(l)
				t1 := time.Now()
				if err != nil {
					fail("repetition %d, %s %s: %v", i+1, c.name, l, err)
				}
				// Samples are timed on the monotonic clock; docker stamps events with the
				// wall clock, which this machine's clock sync can move during a sample.
				if jump := t1.Round(0).Sub(t0.Round(0)) - t1.Sub(t0); jump > 20*time.Millisecond || jump < -20*time.Millisecond {
					run.ClockJumps = append(run.ClockJumps, fmt.Sprintf("repetition %d, %s %s: the wall clock moved %v against the monotonic one", i+1, c.name, l, jump))
				}
				if m.warm != c.want {
					fail("repetition %d, %s %s: answered warm %v, expected %v (load %.2f)", i+1, c.name, l, m.warm, c.want, loadavg()[0])
				}
				s := sample(c.name+" "+string(l), string(l))
				s.Ms = append(s.Ms, ms(m.total))
				s.Warm = append(s.Warm, m.warm)
				if *provider == "docker" {
					// The window holds the call's untimed preparation too (a take, a
					// refresh), neither of which makes a run container.
					fresh, member, names := dockerCreates(t0, t1)
					s.FreshCreates = append(s.FreshCreates, fresh)
					s.MemberCreates = append(s.MemberCreates, member)
					if want := map[bool]int{true: 0, false: 1}[c.want]; fresh != want {
						u := fmt.Sprintf("repetition %d, %s %s: %d run containers created, not %d: %s", i+1, c.name, l, fresh, want, strings.Join(names, "; "))
						run.Unexpected = append(run.Unexpected, u)
						fmt.Println(u)
					}
				}
				if m.ready > 0 {
					r := sample("readyz before "+c.name+" "+string(l), string(l))
					r.Ms = append(r.Ms, ms(m.ready))
				}
				for j, part := range []string{"open", "cell", "close"}[:len(m.parts)] {
					p := sample(c.name+" "+string(l)+" ("+part+")", string(l))
					p.Ms = append(p.Ms, ms(m.parts[j]))
					p.Warm = append(p.Warm, m.warm)
				}
			}
		}
		fmt.Printf("repetition %d of %d, load %.2f\n", i+1, *reps, run.RepLoad1[i])
	}
	run.LoadEnd = loadavg()
	run.Ended = time.Now().UTC()
	for _, k := range order {
		s := samples[k]
		run.Samples = append(run.Samples, *s)
		fmt.Printf("%-34s median %7.1f ms  p10 %7.1f  p90 %7.1f  (n=%d)\n", k, quantile(s.Ms, 0.5), quantile(s.Ms, 0.1), quantile(s.Ms, 0.9), len(s.Ms))
	}

	stop()
	run.AuditWarm = auditWarm(daemonLog)
	if *provider == "docker" {
		for _, c := range plimsollContainers() {
			if !slices.Contains(before, c) {
				run.Leftover = append(run.Leftover, c)
			}
		}
	}
	fmt.Printf("load %v at start, %v at end; audit lines by warm: %v; containers left: %v; unexpected creates: %d; clock jumps: %d\n",
		run.LoadStart, run.LoadEnd, run.AuditWarm, run.Leftover, len(run.Unexpected), len(run.ClockJumps))
	body, _ := json.MarshalIndent(run, "", "  ")
	if err := os.WriteFile(out, append(body, '\n'), 0o644); err != nil {
		die("%v", err)
	}
	fmt.Println("wrote", out)
	runExits()
}

var (
	exitMu sync.Mutex
	exits  []func()
)

// atExit registers f to run, last registered first, when the program ends: normally
// (runExits) or through die.
func atExit(f func()) {
	exitMu.Lock()
	defer exitMu.Unlock()
	exits = append(exits, f)
}

// runExits runs what atExit registered, once.
func runExits() {
	exitMu.Lock()
	fs := exits
	exits = nil
	exitMu.Unlock()
	for i := len(fs) - 1; i >= 0; i-- {
		fs[i]()
	}
}

// die stops the daemon and removes the scratch directory (runExits), then exits with
// the message: no failure leaves a daemon, and its pool, running.
func die(format string, args ...any) {
	runExits()
	log.Fatalf(format, args...)
}

// daemon is a running plimsolld.
type daemon struct {
	baseURL string
	cmd     *exec.Cmd
	exited  chan error
}

// startDaemon runs binary with only env (and PATH, HOME, DOCKER_HOST), so no setting of
// this shell reaches it, on a free loopback port with the metrics listener off, its log
// in logPath, and waits for /readyz, reporting at once a daemon that exits first.
func startDaemon(ctx context.Context, binary string, env []string, logPath string) (*daemon, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := l.Addr().String()
	_ = l.Close()
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(env, "PLIMSOLL_ADDR="+addr, "PLIMSOLL_METRICS_ADDR=off")
	for _, k := range []string{"PATH", "HOME", "DOCKER_HOST"} {
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// A process group of its own, so a terminal's Ctrl-C reaches this program alone and
	// stop's SIGTERM is the daemon's only signal: plimsolld force-quits its drain, and
	// leaves its pool member, on a second one.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start plimsolld: %w", err)
	}
	d := &daemon{baseURL: "http://" + addr, cmd: cmd, exited: make(chan error, 1)}
	go func() { d.exited <- cmd.Wait(); logFile.Close() }()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case err := <-d.exited:
			b, _ := os.ReadFile(logPath)
			return nil, fmt.Errorf("plimsolld exited before it was ready: %v\n%s", err, b)
		default:
		}
		if resp, err := http.Get(d.baseURL + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return d, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = d.stop(time.Minute)
	return nil, errors.New("plimsolld was not ready within 3 minutes")
}

// stop sends SIGTERM (the daemon drains, removing its pool and sessions) and kills it
// after grace.
func (d *daemon) stop(grace time.Duration) error {
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-d.exited:
		return nil
	case <-time.After(grace):
		_ = d.cmd.Process.Kill()
		<-d.exited
		return fmt.Errorf("plimsolld did not exit within %v of SIGTERM and was killed", grace)
	}
}

// dockerCreates counts the plimsoll containers (those with a lifetime label) docker
// created between t0 and t1: those without the session label (a run's own sandbox) and
// those with it (a pool member or a session's container). It is asked right after each
// sample, since docker keeps only its most recent events. Docker stamps events with the
// wall clock, which this machine's clock sync steps by about a second now and then, so
// each end of the window is taken from whichever clock reaches further, and the start a
// second earlier still; the pause before a sample is longer than that, and the previous
// call's containers were made before it. names lists every container counted, as name
// and image.
func dockerCreates(t0, t1 time.Time) (fresh, member int, names []string) {
	elapsed := t1.Sub(t0)
	w0, w1 := t0.Round(0), t1.Round(0)
	since, until := w0, w1
	if s := w1.Add(-elapsed); s.Before(since) {
		since = s
	}
	if u := w0.Add(elapsed); u.After(until) {
		until = u
	}
	since = since.Add(-time.Second)
	for _, line := range strings.Split(strings.TrimSpace(output("docker", "events", "--since", unix(since), "--until", unix(until),
		"--filter", "type=container", "--filter", "event=create", "--filter", "label=io.plimsoll.expires",
		"--format", `{{.Actor.Attributes.name}} {{.Actor.Attributes.image}} session={{index .Actor.Attributes "io.plimsoll.session"}}`)), "\n") {
		if line == "" {
			continue
		}
		names = append(names, line)
		if strings.HasSuffix(line, " session=") {
			fresh++
		} else {
			member++
		}
	}
	return fresh, member, names
}

// plimsollContainers names every container with plimsoll's lifetime label, running or
// not.
func plimsollContainers() []string {
	return strings.Fields(output("docker", "ps", "-a", "--filter", "label=io.plimsoll.expires", "--format", "{{.Names}}"))
}

// auditWarm counts the daemon's run audit lines for cells by their warm attribute.
func auditWarm(path string) map[string]int {
	counts := map[string]int{}
	f, err := os.Open(path)
	if err != nil {
		return counts
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, []byte(`"warm"`)) && !bytes.Contains(line, []byte(" warm=")) {
			continue
		}
		var rec map[string]any
		if json.Unmarshal(line, &rec) == nil {
			if w, ok := rec["warm"].(bool); ok {
				counts[strconv.FormatBool(w)]++
			}
			continue
		}
		for _, f := range strings.Fields(string(line)) {
			if v, ok := strings.CutPrefix(f, "warm="); ok {
				counts[v]++
			}
		}
	}
	return counts
}

func unix(t time.Time) string {
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}

func output(name string, args ...string) string {
	b, err := exec.Command(name, args...).Output()
	if err != nil {
		die("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(b)
}

func loadavg() Load {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return Load{}
	}
	var l Load
	for i, f := range strings.Fields(string(b))[:3] {
		l[i], _ = strconv.ParseFloat(f, 64)
	}
	return l
}

func machine() string {
	mem := ""
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		if f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0]); len(f) >= 2 {
			kb, _ := strconv.ParseFloat(f[1], 64)
			mem = fmt.Sprintf(", %.0f GiB memory", kb/(1<<20))
		}
	}
	return fmt.Sprintf("%s/%s, %d CPUs%s, %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), mem, runtime.Version())
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		die("%v", err)
	}
	return hex.EncodeToString(b)
}

// quantile is the nearest-rank q-quantile of ms.
func quantile(ms []float64, q float64) float64 {
	s := slices.Clone(ms)
	slices.Sort(s)
	i := int(float64(len(s))*q+0.999999) - 1
	return s[max(0, min(i, len(s)-1))]
}
