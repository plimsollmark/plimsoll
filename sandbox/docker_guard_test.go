package sandbox

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The runner guard (docker/guard/runner.c, installed as dockerRunnerGuard) is a library
// plimsoll loads through LD_PRELOAD into five of its programs in a docker sandbox: the
// project runner, the granted-run forwarder in front of it, and through guarded a
// session's sweep, its quiesce before a project call and every cell relay. It makes each
// one non-dumpable, so code of the guest user, which those programs share a uid with,
// can neither open their descriptors nor read their memory. A loader that cannot find
// the library starts the program without it and without a word (measured on the Alpine
// image, 2026-11-19, rust-native-helper-1), so these tests catch each program as plimsoll
// starts it and check, from a process of the guest user, two things: the kernel lists
// its /proc/<pid>/environ as no longer the guest's (the dumpable flag is off: the kernel
// gives that entry of a non-dumpable process to root, under runc and under gVisor, where
// /proc/<pid>/fd stays the guest's either way), and opening its input and output and
// reading its /proc/<pid>/maps are refused for permission. Two things that look like signs
// are not: under gVisor a process of the same user can list a guarded program's
// /proc/<pid>/fd, and on this host opening /proc/<pid>/mem is refused even for a dumpable
// program (Yama), so neither decides here (noexec-setting-15). They run under the suite's
// runtime, so the docker suite under gVisor (SANDBOX_DOCKER_RUNTIME=runsc) runs them there too.

// guardInspectJS defines plimsollArgv(pid), a process's command line as a list (null when
// it is gone), and plimsollInspect(pid), what a process of the guest user sees of pid:
// the uid its /proc/<pid>/environ is listed under, what opening its descriptors 0 and 1,
// reading its maps and opening its memory gave, and guarded, true only when the owner is
// not the guest and the descriptor opens and the maps read were refused for permission
// (memory is recorded, never counted). A descriptor that is a socket fails to open with
// ENXIO whether or not the process is dumpable, so the owner is the deciding fact.
const guardInspectJS = `function plimsollArgv(pid){try{return require("node:fs").readFileSync("/proc/"+pid+"/cmdline","latin1").split("\0").slice(0,-1)}catch{return null}}
function plimsollInspect(pid){const fs=require("node:fs");const r={pid:+pid};
try{r.owner=fs.statSync("/proc/"+pid+"/environ").uid}catch(e){return null}r.t=Date.now();
const open=(p,f)=>{try{fs.closeSync(fs.openSync(p,f));return "open"}catch(e){return e.code||"unknown"}};
r.fd0=open("/proc/"+pid+"/fd/0",fs.constants.O_RDONLY);r.fd1=open("/proc/"+pid+"/fd/1",fs.constants.O_WRONLY);
r.mem=open("/proc/"+pid+"/mem",fs.constants.O_RDONLY);r.uid=process.getuid();
try{fs.readFileSync("/proc/"+pid+"/maps");r.maps="read"}catch(e){r.maps=e.code||"unknown"}
r.guarded=r.owner!==r.uid&&["fd0","fd1","maps"].every(k=>r[k]==="EACCES"||r[k]==="EPERM");return r}
function plimsollParent(pid){try{const st=require("node:fs").readFileSync("/proc/"+pid+"/stat","latin1");return +st.slice(st.lastIndexOf(")")+2).split(" ")[1]}catch{return 0}}
`

// guardSample is one plimsollInspect result.
type guardSample struct {
	PID     int    `json:"pid"`
	Owner   int    `json:"owner"`
	UID     int    `json:"uid"`
	FD0     string `json:"fd0"`
	FD1     string `json:"fd1"`
	Mem     string `json:"mem"`
	Maps    string `json:"maps"`
	Guarded bool   `json:"guarded"`
	T       int64  `json:"t"` // when it was taken, in milliseconds
}

// jsString is s as a JavaScript string literal.
func jsString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// guardWatcher is a cell that installs, in the session's interpreter, a timer that scans
// /proc as fast as it can for a process whose command line starts node -e script and
// samples it at every pass. log, when not empty, is a file each sample is appended to as
// a JSON line, for a program (the quiesce) that kills the interpreter itself.
func guardWatcher(t *testing.T, script, log string) string {
	t.Helper()
	return guardInspectJS + `globalThis.plimsollGuard = {want: ` + jsString(t, script) + `, log: ` + jsString(t, log) + `, seen: {}};
globalThis.plimsollGuardTimer = setInterval(() => {
  const fs = require("node:fs"), g = globalThis.plimsollGuard;
  for (const d of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(d)) continue;
    const a = plimsollArgv(d);
    if (!a || a[0] !== "node" || a[1] !== "--disable-sigusr1" || a[2] !== "-e" || a[3] !== g.want) continue;
    const r = plimsollInspect(d);
    if (!r) continue;
    (g.seen[d] = g.seen[d] || []).length < 2000 && g.seen[d].push(r);
    if (g.log) fs.appendFileSync(g.log, JSON.stringify(r) + "\n");
  }
}, 0);
console.log("watching")`
}

// judgeGuardSamples fails the test unless at least one process of what was seen, and
// every one of them, had a sample that was guarded. A guarded program can be seen once
// before its guard has loaded (between its start and the library's first instruction),
// so a dumpable sample next to guarded ones is that window; a program seen only
// dumpable never loaded the guard.
func judgeGuardSamples(t *testing.T, what string, byPID map[int][]guardSample) {
	t.Helper()
	if len(byPID) == 0 {
		t.Fatalf("the %s was never seen running, so its guard was not checked", what)
	}
	for pid, samples := range byPID {
		guarded := 0
		for _, s := range samples {
			if s.Guarded {
				guarded++
			}
		}
		if guarded == 0 {
			t.Fatalf("the %s (pid %d) ran dumpable: %d samples from a process of the guest user over %d ms, none guarded; first %+v, last %+v", what, pid, len(samples), samples[len(samples)-1].T-samples[0].T, samples[0], samples[len(samples)-1])
		}
		t.Logf("the %s (pid %d): %d of %d samples guarded, over %d ms", what, pid, guarded, len(samples), samples[len(samples)-1].T-samples[0].T)
	}
}

// guardSession opens a docker session under the suite's runtime.
func guardSession(t *testing.T) Session {
	t.Helper()
	d := testDocker()
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func guardCell(t *testing.T, s Session, code string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: code, Timeout: 30 * time.Second})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("cell: %+v, %v", res, err)
	}
	return strings.TrimSpace(res.Stdout)
}

// TestDockerGuardKeepsTheSweepUninspectable: the sweep after a call, which decides
// whether the session's boundary holds, runs guarded. The watcher lives in the
// interpreter, which the sweep keeps, and the next cell reads what it saw.
func TestDockerGuardKeepsTheSweepUninspectable(t *testing.T) {
	t.Parallel()
	s := guardSession(t)
	if got := guardCell(t, s, guardWatcher(t, sessionkit.SweepScript, "")); got != "watching" {
		t.Fatalf("installing the watcher printed %q", got)
	}
	// Two more calls, so at least two sweeps have run while the watcher scanned.
	guardCell(t, s, "1")
	out := guardCell(t, s, `clearInterval(globalThis.plimsollGuardTimer); console.log(JSON.stringify(globalThis.plimsollGuard.seen))`)
	var seen map[int][]guardSample
	if err := json.Unmarshal([]byte(out), &seen); err != nil {
		t.Fatalf("the watcher's report %q: %v", out, err)
	}
	judgeGuardSamples(t, "sweep", seen)
}

// TestDockerGuardKeepsTheQuiesceUninspectable: the quiesce before a project call, which
// kills every process of the session's while plimsoll starts the runner, runs guarded.
// It kills the watcher too, so the watcher writes each sample to a file as it takes it,
// and the project call's step reads the file.
func TestDockerGuardKeepsTheQuiesceUninspectable(t *testing.T) {
	t.Parallel()
	s := guardSession(t)
	const log = "/tmp/plimsoll-guard-quiesce.log"
	if got := guardCell(t, s, guardWatcher(t, sessionkit.QuiesceScript, log)); got != "watching" {
		t.Fatalf("installing the watcher printed %q", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := s.RunProject(ctx, ProjectRequest{Steps: []string{"cat " + log}, Timeout: 30 * time.Second})
	if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("the project call after the watcher: %+v, %v", res, err)
	}
	seen := map[int][]guardSample{}
	for _, line := range strings.Split(strings.TrimSpace(res.Steps[0].Stdout), "\n") {
		var sample guardSample
		if json.Unmarshal([]byte(line), &sample) == nil && sample.PID > 0 {
			seen[sample.PID] = append(seen[sample.PID], sample)
		}
	}
	judgeGuardSamples(t, "quiesce", seen)
}

// TestDockerGuardKeepsTheRelayUninspectable: a cell's relay, whose frames carry every
// cell's result, runs guarded. A cell finds its own relay by its exact command line.
func TestDockerGuardKeepsTheRelayUninspectable(t *testing.T) {
	t.Parallel()
	s := guardSession(t)
	argv, err := json.Marshal(sessionkit.RelayArgv(string(LanguageJavaScript), dockerSessionWork))
	if err != nil {
		t.Fatal(err)
	}
	out := guardCell(t, s, guardInspectJS+`const want = JSON.stringify(`+string(argv)+`), found = {};
for (const d of require("node:fs").readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d) || JSON.stringify(plimsollArgv(d)) !== want) continue;
  const r = plimsollInspect(d);
  if (r) found[d] = [r];
}
console.log(JSON.stringify(found))`)
	var seen map[int][]guardSample
	if err := json.Unmarshal([]byte(out), &seen); err != nil {
		t.Fatalf("the cell's report %q: %v", out, err)
	}
	judgeGuardSamples(t, "relay", seen)
}

// guardAncestorsJS is a step that walks up from itself and prints, as JSON, what it sees
// of each ancestor whose command line starts with one of the given prefixes, keyed by
// the prefix's name.
func guardAncestorsJS(t *testing.T, prefixes map[string][]string) string {
	t.Helper()
	b, err := json.Marshal(prefixes)
	if err != nil {
		t.Fatal(err)
	}
	return guardInspectJS + `const want = ` + string(b) + `, found = {};
for (let pid = process.ppid, i = 0; pid > 0 && i < 16; pid = plimsollParent(pid), i++) {
  const a = plimsollArgv(pid);
  if (!a) continue;
  for (const [name, prefix] of Object.entries(want)) {
    if (prefix.every((p, j) => a[j] === p) && !found[name]) { const r = plimsollInspect(pid); if (r) found[name] = {[pid]: [r]}; }
  }
}
console.log(JSON.stringify(found))`
}

func judgeAncestors(t *testing.T, stdout string, names ...string) {
	t.Helper()
	var found map[string]map[int][]guardSample
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &found); err != nil {
		t.Fatalf("the step's report %q: %v", stdout, err)
	}
	for _, name := range names {
		judgeGuardSamples(t, name, found[name])
	}
}

// TestDockerGuardKeepsTheSessionRunnerUninspectable: a session's project call starts the
// runner by docker exec (runnerArgv), not as a container's first process, and the
// runner runs guarded there too. The runner also proves this of itself before it reads
// its plan; this test is the outside view of the same fact.
func TestDockerGuardKeepsTheSessionRunnerUninspectable(t *testing.T) {
	t.Parallel()
	s := guardSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := s.RunProject(ctx, ProjectRequest{
		Files:   []File{{Path: "guard.js", Content: guardAncestorsJS(t, map[string][]string{"runner": dockerProjectRunner})}},
		Steps:   []string{"node guard.js"},
		Timeout: 30 * time.Second,
	})
	if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("the project call: %+v, %v", res, err)
	}
	judgeAncestors(t, res.Steps[0].Stdout, "runner")
}

// TestDockerGuardKeepsTheForwarderUninspectable: a granted run whose profile asks for
// the local address (sdk_env) starts the runner behind plimsoll's loopback forwarder,
// which holds the same descriptors the runner does; both run guarded. The step walks up
// to both.
func TestDockerGuardKeepsTheForwarderUninspectable(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	upstream, _ := newSDKUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	step := guardAncestorsJS(t, map[string][]string{
		"forwarder": sessionkit.NodeArgv("--eval", hostForwarderWrapperJS),
		"runner":    dockerProjectRunner,
	})
	res, err := d.RunProject(ctx, ProjectRequest{
		Files:   []File{{Path: "guard.js", Content: step}},
		Steps:   []string{"node guard.js"},
		Grant:   sdkStyleGrant(upstream.URL, "minted-for-this-run"),
		Timeout: 30 * time.Second,
	})
	if err != nil || res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("the granted project run: %+v, %v", res, err)
	}
	judgeAncestors(t, res.Steps[0].Stdout, "forwarder", "runner")
}

// TestDockerSmokeRefusesAnImageWithoutTheGuard: SmokeTest refuses a project image whose
// guard library is missing, and one whose file at that path loads but does not make the
// program non-dumpable, naming the image and the missing protection; plimsolld then
// serves nothing (EnsureReady).
func TestDockerSmokeRefusesAnImageWithoutTheGuard(t *testing.T) {
	t.Parallel()
	base := testDocker()
	requireSnippetImage(t, base)
	for _, c := range []struct {
		name, tag, run, want string
	}{
		{"missing", throwawayTag("no-guard"), "rm " + dockerRunnerGuard,
			"the image has no runner guard library at " + dockerRunnerGuard},
		{"not the guard", throwawayTag("wrong-guard"), "cp /usr/lib/libgcc_s.so.1 " + dockerRunnerGuard,
			"is still dumpable: the kernel lists its /proc/<pid>/environ as the guest user's"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			build := exec.Command("docker", "build", "-q", "-t", c.tag, "-")
			build.Stdin = strings.NewReader("FROM " + base.ProjectImage + "\nUSER root\nRUN " + c.run + "\nUSER node\n")
			if out, err := build.CombinedOutput(); err != nil {
				infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
			}
			t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", c.tag).Run() })
			d := testDocker()
			d.ProjectImage = c.tag
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			err := d.SmokeTest(ctx)
			if err == nil {
				t.Fatal("SmokeTest passed an image whose guard does not protect a session's control programs")
			}
			t.Logf("SmokeTest refused: %v", err)
			for _, want := range []string{`guard smoke failed for image "` + c.tag + `"`, c.want} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("SmokeTest: %v\nwant it to say %q", err, want)
				}
			}
		})
	}
}

// TestDockerGuardReportRefusals: each way the guard check's report can fall short is a
// refusal that says what is missing; the report of a guarded program passes. No docker.
func TestDockerGuardReportRefusals(t *testing.T) {
	t.Parallel()
	n := func(i int) *int { return &i }
	for _, c := range []struct {
		name string
		r    guardReport
		want string
	}{
		{"guarded", guardReport{Lib: "file", UID: n(61000), Owner: n(0), FD0: "EACCES", FD1: "EACCES"}, ""},
		{"no library", guardReport{Lib: "ENOENT", UID: n(61000), Owner: n(61000), FD0: "open", FD1: "open"}, "no runner guard library at " + dockerRunnerGuard + " (ENOENT)"},
		{"directory", guardReport{Lib: "not a file", UID: n(61000), Owner: n(0), FD0: "EACCES", FD1: "EACCES"}, "no runner guard library"},
		{"dumpable", guardReport{Lib: "file", UID: n(61000), Owner: n(61000), FD0: "open", FD1: "open"}, "is still dumpable"},
		{"owner unread", guardReport{Lib: "file", UID: n(61000), Owner: n(-1), OwnerError: "ENOENT"}, "could not read the guarded program's /proc entry (ENOENT)"},
		{"no owner", guardReport{Lib: "file", UID: n(61000)}, "reported no uid or no owner"},
		{"input opened", guardReport{Lib: "file", UID: n(61000), Owner: n(0), FD0: "open", FD1: "EACCES"}, "input descriptor got \"open\""},
		{"output odd", guardReport{Lib: "file", UID: n(61000), Owner: n(0), FD0: "EPERM", FD1: "ENXIO"}, "output descriptor got \"ENXIO\""},
	} {
		err := c.r.check()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v, want it to pass", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
