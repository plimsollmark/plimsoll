package sandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The promise these tests defend: code being judged cannot write its own result. A step runs
// as the same user as plimsoll's own programs beside it (the project runner, the granted-run
// forwarder, and in a session the relays and the session's control programs), so it may send
// them signals. The runner was a node program until 2026-11-21; it is the native helper now,
// which has no debugger, and these tests still signal it (PLIMSOLL_RUNNER_PID).
// Node opens its debugger on SIGUSR1, on 127.0.0.1:9229, which the sandbox's own loopback
// reaches; a step that did that on 2026-11-20 replaced its output in the runner's report
// and read the key the report is signed with, under runc and gVisor, in a run and in a
// session (finding rust-native-helper-26). plimsoll now starts every node program of its
// own with --disable-sigusr1 (sessionkit.NodeArgv).
//
// The steps below do only the first half of that attack, which is the whole door. The
// second step leaves a process behind, as the measured attack did: it signals the runner
// and every other node process it can see that is not its own and not the guest's cell
// interpreter (in a session, the relay), and the step ends once the signals are sent; the
// process then looks for a debugger on the port for ten seconds, while the next step runs,
// since the runner, which runs each step synchronously, acts on the signal only between
// steps (measured 2026-11-20: a signal that arrived during a step opened nothing until it
// ended). It also records whether each of those
// processes catches SIGUSR1 (/proc/PID/status, SigCgt); gVisor's status file has no SigCgt
// line (measured 2026-11-20), so under runsc only the signal and the port are checked. The
// third step reads what it found, and the last proves the runner went on and reported every
// step's own output.
const nodeSignalStep = `const fs = require("node:fs"), net = require("node:net");
const procs = [];
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d) || d === String(process.pid)) continue;
  let argv, status;
  try { argv = fs.readFileSync("/proc/" + d + "/cmdline", "latin1").split("\0"); status = fs.readFileSync("/proc/" + d + "/status", "latin1"); } catch { continue; }
  if (!/(^|\/)node$/.test(argv[0])) continue;
  const m = /SigCgt:\s*([0-9a-f]+)/.exec(status);
  procs.push({ pid: d, usr1: m ? Number((BigInt("0x" + m[1]) >> 9n) & 1n) : -1, guest: argv.includes("--expose-internals"), runner: d === process.env.PLIMSOLL_RUNNER_PID, forwarder: argv.includes("--eval"), interp: argv.some((a) => a.startsWith("/tmp/.plimsoll-interp/")) });
}
const targets = new Set([process.env.PLIMSOLL_RUNNER_PID, ...procs.filter((p) => !p.guest).map((p) => p.pid)]);
for (const pid of targets) process.kill(Number(pid), "SIGUSR1");
fs.writeFileSync("signalled", "");
const done = (state) => { fs.writeFileSync("signal.tmp", JSON.stringify({ procs, debugger: state })); fs.renameSync("signal.tmp", "signal.json"); };
const look = (n) => {
  const s = net.connect(9229, "127.0.0.1");
  s.on("connect", () => { s.destroy(); done("open"); });
  s.on("error", () => { if (n > 0) setTimeout(() => look(n - 1), 100); else done("shut"); });
};
look(100);
`

type nodeSignalReport struct {
	Procs []struct {
		PID       string `json:"pid"`
		USR1      int    `json:"usr1"`
		Guest     bool   `json:"guest"`
		Runner    bool   `json:"runner"`
		Interp    bool   `json:"interp"` // the relay, or with Guest the interpreter itself
		Forwarder bool   `json:"forwarder"`
	} `json:"procs"`
	Debugger string `json:"debugger"`
}

var nodeSignalRequest = ProjectRequest{
	Files: []File{{Path: "signal.js", Content: nodeSignalStep}},
	Steps: []string{
		"echo honest",
		"node signal.js </dev/null >/dev/null 2>&1 & i=0; while [ ! -f signalled ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done",
		"i=0; while [ ! -f signal.json ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done; cat signal.json",
		"echo after",
	},
	Timeout: 60 * time.Second,
}

// checkNodeSignalResult holds a run of nodeSignalRequest to an honest report: every step's
// own output and exit, the debugger shut, and no node program of plimsoll's catching the
// signal.
func checkNodeSignalResult(t *testing.T, res ProjectResult) nodeSignalReport {
	t.Helper()
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 4 {
		t.Fatalf("outcome %s (%s), steps %+v; want completed with all four steps", res.Outcome, res.Detail, res.Steps)
	}
	for i, want := range map[int]string{0: "honest\n", 1: "", 3: "after\n"} {
		if s := res.Steps[i]; s.Stdout != want || s.ExitCode != 0 {
			t.Errorf("step %d reported stdout %q exit %d; want its own output %q, exit 0", i+1, s.Stdout, s.ExitCode, want)
		}
	}
	s := res.Steps[2]
	var rep nodeSignalReport
	if err := json.Unmarshal([]byte(s.Stdout), &rep); err != nil || s.ExitCode != 0 {
		t.Fatalf("the signal report %q (exit %d, stderr %q): %v", s.Stdout, s.ExitCode, s.Stderr, err)
	}
	if rep.Debugger != "shut" {
		t.Errorf("a step's SIGUSR1 opened a debugger on 127.0.0.1:9229 (%q): a node program of plimsoll's can be made to run the step's code", rep.Debugger)
	}
	for _, p := range rep.Procs {
		if p.Runner {
			t.Errorf("the runner (PLIMSOLL_RUNNER_PID %s) is a node process; the project runner is the native helper, which has no debugger", p.PID)
		}
		if !p.Guest && p.USR1 == 1 {
			t.Errorf("node process %s catches SIGUSR1: a node program of plimsoll's started without %s", p.PID, "--disable-sigusr1")
		}
	}
	t.Logf("node processes the step saw: %+v; debugger %s", rep.Procs, rep.Debugger)
	return rep
}

func TestDockerProjectStepCannotOpenTheRunnerDebugger(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := d.RunProject(ctx, nodeSignalRequest)
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	checkNodeSignalResult(t, res)
}

// In a session the runner is not the container's first process, so the kernel does not
// drop the signal on its behalf, and a cell first starts the session's interpreter and its
// relay, both node, beside the call.
func TestDockerSessionStepCannotOpenTheRunnerDebugger(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	heavyDockerTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 10 * time.Minute, DiskBytes: 96 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	cell, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: "1 + 1", Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("RunCell: %v", err)
	}
	if !strings.Contains(cell.Stdout, "2") {
		t.Fatalf("the cell answered %+v", cell)
	}
	res, err := s.RunProject(ctx, nodeSignalRequest)
	if err != nil {
		t.Fatalf("session RunProject: %v", err)
	}
	checkNodeSignalResult(t, res)
}

// A granted run whose profile asks for the local address starts the runner behind plimsoll's
// loopback forwarder, a node program that holds the runner's standard input and output.
func TestDockerGrantedProjectStepCannotOpenTheForwarderDebugger(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	upstream, _ := newSDKUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req := nodeSignalRequest
	req.Grant = sdkStyleGrant(upstream.URL, "minted-for-this-run")
	res, err := d.RunProject(ctx, req)
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	rep := checkNodeSignalResult(t, res)
	forwarder := false
	for _, p := range rep.Procs {
		forwarder = forwarder || p.Forwarder
	}
	if !forwarder {
		t.Errorf("the step saw no forwarder among %+v", rep.Procs)
	}
}
