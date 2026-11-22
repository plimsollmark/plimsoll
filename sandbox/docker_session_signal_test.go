package sandbox_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The promise this test defends: code a session keeps alive between calls cannot make a
// program of plimsoll's that runs between calls report anything but the truth. A session's
// interpreter is guest code and it runs between calls (a timer), as the same user as the
// sweep after every call and the quiesce before a project call, so it may send them signals,
// and node opens its debugger on SIGUSR1 at 127.0.0.1:9229, which the sandbox's loopback
// reaches (finding rust-native-helper-26). A debugger in the sweep could make it exit clean
// with a process of the guest's left running; in the quiesce, start a call with one. Every
// such program starts with --disable-sigusr1 (sessionkit.NodeArgv).
//
// A timer in the JavaScript interpreter scans for node processes that are not its own as
// fast as it can, signals each again on every pass while it lives, and tries the debugger
// port on every pass. It signals a process only once node has set SIGUSR1 up (blocked or
// caught, from /proc/PID/status; gVisor's status file has no signal lines, so there 60 ms
// after it first sees it), since a SIGUSR1 that arrives before node has started only kills
// the process, which the session reports as an unproven boundary, not a lie. While it runs,
// the session makes cells in both languages (each followed by a sweep; the Python one starts
// an interpreter and its relay, whose identities the check confirms) and a project call (the
// quiesce, which kills the timer with its interpreter). Every call must report its own
// result, no debugger may open, and the timer must have reached the sweep and the quiesce.
//
// What it cannot reach: the identity check runs as another user (checkerUser), so its
// signals are refused (EPERM), which the log records; the lister runs once, in a container
// no call has touched, before any guest code exists. Both carry the flag on their command
// lines (sessionkit tests).
const betweenCallsSignaller = `globalThis.betweenCalls = (() => {
  const fs = require("fs"), net = require("net"), crypto = require("crypto");
  const firstSeen = new Map(), reported = new Set();
  const log = (o) => fs.appendFileSync("/work/.between-calls.log", JSON.stringify(o) + "\n");
  return setInterval(() => {
    const now = Date.now();
    for (const d of fs.readdirSync("/proc")) {
      if (!/^[0-9]+$/.test(d) || d === String(process.pid)) continue;
      let argv, status;
      try { argv = fs.readFileSync("/proc/" + d + "/cmdline", "latin1").split("\0"); status = fs.readFileSync("/proc/" + d + "/status", "latin1"); } catch { continue; }
      if (!/(^|\/)node$/.test(argv[0])) continue;
      if (!firstSeen.has(d)) firstSeen.set(d, now);
      const mask = (name) => { const m = new RegExp("^" + name + ":\\s*([0-9a-f]+)", "m").exec(status); return m ? (BigInt("0x" + m[1]) >> 9n) & 1n : null; };
      const blk = mask("SigBlk"), cgt = mask("SigCgt");
      const ready = blk === null ? now - firstSeen.get(d) >= 60 : blk === 1n || cgt === 1n;
      if (!ready) continue;
      let sent = "sent";
      try { process.kill(Number(d), "SIGUSR1"); } catch (e) { sent = e.code; }
      const i = argv.indexOf("-e");
      const script = i >= 0 ? crypto.createHash("sha256").update(argv[i + 1]).digest("hex") : argv.slice(1, 3).join(" ");
      const key = d + " " + script + " " + sent;
      if (!reported.has(key)) { reported.add(key); log({ pid: d, script, sent }); }
    }
    const s = net.connect(9229, "127.0.0.1");
    s.on("connect", () => { s.destroy(); log({ debugger: "open" }); });
    s.on("error", () => {});
  }, 1);
})();
"signalling"`

func TestDockerSessionCodeBetweenCallsCannotOpenAControlProgramDebugger(t *testing.T) {
	t.Parallel()
	sandbox.HeavyDockerTest(t)
	d := pythonSessionDocker(t)
	s := openDockerSession(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cell := func(lang sandbox.Language, code, want string) {
		t.Helper()
		res, err := s.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: code, Timeout: 30 * time.Second})
		if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, want) {
			t.Fatalf("%s cell %q: %+v, %v; want its own answer %q from a session that goes on", lang, code, res, err, want)
		}
	}
	cell(sandbox.LanguageJavaScript, betweenCallsSignaller, "signalling")
	for i := range 4 {
		cell(sandbox.LanguageJavaScript, "6 * 7", "42")
		if i == 1 {
			cell(sandbox.LanguagePython, "6 * 7", "42")
		}
	}
	project, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"echo honest"}, Timeout: 30 * time.Second})
	if err != nil || project.Outcome != sandbox.ProjectOutcomeCompleted || len(project.Steps) != 1 || project.Steps[0].Stdout != "honest\n" {
		t.Fatalf("the project call after the quiesce: %+v, %v; want its own output", project, err)
	}
	cell(sandbox.LanguageJavaScript, "typeof globalThis.betweenCalls", "undefined") // the quiesce ended the timer's interpreter
	read, err := s.RunProject(ctx, sandbox.ProjectRequest{Steps: []string{"cat .between-calls.log"}, Timeout: 30 * time.Second})
	if err != nil || read.Outcome != sandbox.ProjectOutcomeCompleted || len(read.Steps) != 1 {
		t.Fatalf("reading the log: %+v, %v", read, err)
	}
	names := map[string]string{}
	for name, script := range map[string]string{"sweep": sessionkit.SweepScript, "quiesce": sessionkit.QuiesceScript,
		"check": sessionkit.CheckScript, "lister": sessionkit.ListScript, "relay": sessionkit.RelayArgv("javascript", "/work")[3]} {
		sum := sha256.Sum256([]byte(script))
		names[hex.EncodeToString(sum[:])] = name
	}
	reached := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(read.Steps[0].Stdout), "\n") {
		var e struct{ PID, Script, Sent, Debugger string }
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if e.Debugger != "" {
			t.Errorf("guest code between calls opened a debugger on 127.0.0.1:9229: a node program of plimsoll's that runs beside it started without %s", sessionkit.NodeSignalFlag)
			continue
		}
		name := names[e.Script]
		if name == "" {
			name = "other node (" + e.Script[:min(len(e.Script), 16)] + ")"
		}
		reached[name] += e.Sent + " "
	}
	t.Logf("node programs the guest signalled between calls: %v", reached)
	for _, name := range []string{"sweep", "quiesce"} {
		if !strings.Contains(reached[name], "sent") {
			t.Errorf("the guest's timer never signalled the %s (%v): the test did not reach what it defends", name, reached)
		}
	}
	if strings.Contains(reached["check"], "sent") {
		t.Errorf("the guest signalled the identity check (%v); it runs as another user", reached)
	}
}
