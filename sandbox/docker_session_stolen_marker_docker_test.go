package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stolenMarkerThief is a cell that leaves a thread in the session's kept interpreter: it watches
// /proc for the next command that carries a call's start marker on its command line (the guard,
// env and the start script all do, and the pid stays the same across their execs), opens that
// process's standard error for reading through /proc/<pid>/fd/2 as soon as the kernel lets it, and
// blocks in read(). Whatever the start script then writes, it takes off the pipe ahead of docker,
// once per command, and when that held a start marker it leaves /work/stolen for the call's own
// code to find. What it could not do it notes in /work/thief.log.
const stolenMarkerThief = `const { Worker } = require("node:worker_threads");
globalThis.plimsollThief = new Worker(` + "`" + `
const fs = require("node:fs");
const note = (s) => { try { fs.appendFileSync("/work/thief.log", s + String.fromCharCode(10)); } catch {} };
const self = String(process.pid), seen = new Set();
note("started " + self);
for (;;) {
  let pids;
  try { pids = fs.readdirSync("/proc").filter((d) => /^[0-9]+$/.test(d) && d !== self); } catch { continue; }
  for (const p of pids) {
    if (seen.has(p)) continue;
    let cmd;
    try { cmd = fs.readFileSync("/proc/" + p + "/cmdline", "latin1"); } catch { continue; }
    if (!cmd.includes("plimsoll-started:")) continue;
    seen.add(p);
    let fd = -1, why = "";
    for (let i = 0; i < 20000 && fd < 0; i++) {
      try { fd = fs.openSync("/proc/" + p + "/fd/2", "r"); } catch (e) { why = e.code; }
    }
    if (fd < 0) { note("open " + p + ": " + why); continue; }
    const buf = Buffer.alloc(4096);
    let n = 0;
    try { n = fs.readSync(fd, buf, 0, buf.length, null); } catch (e) { note("read " + p + ": " + e.code); }
    try { fs.closeSync(fd); } catch {}
    const got = buf.toString("latin1", 0, n);
    if (got.includes("plimsoll-started:")) fs.writeFileSync("/work/stolen", got);
    else note("read " + p + ": " + JSON.stringify(got));
  }
}` + "`" + `, { eval: true });
globalThis.plimsollThiefError = "";
globalThis.plimsollThief.on("error", (e) => { globalThis.plimsollThiefError = String(e); });
globalThis.plimsollThief.on("exit", (c) => { globalThis.plimsollThiefError += " exit " + c; });
console.log("watching");`

// stolenMarkerCall is the later snippet call of the same author: it does its work, then, when the
// thread took its start marker, writes the guest guard's line to standard error and exits with
// the guard's code for that line; otherwise it answers normally.
const stolenMarkerCall = `const fs = require("node:fs");
const wait = new Int32Array(new SharedArrayBuffer(4));
for (const end = Date.now() + 3000; Date.now() < end && !fs.existsSync("/work/stolen"); ) Atomics.wait(wait, 0, 0, 10);
if (fs.existsSync("/work/stolen")) {
  fs.writeSync(2, "plimsoll guest guard: exec: errno 2\n");
  process.exit(124);
}
console.log("kept");`

// TestDockerSessionCallThatRanIsNeverMarkedFromItsStderr (finding hunt-security-30, the scan's F4):
// code alive in a held docker session from an earlier cell takes a later snippet call's start
// marker off that call's standard error, and the call, which ran, writes the guest guard's line
// and exits with its code. The call must not come back marked not dispatched: no mark means the
// code may have run, and here it did. The session ends, boundary failed, unmarked.
//
// Under runc a docker exec's standard error is a pipe the guest's uid owns, so the thread can
// reopen it; the test requires the attempt to land there, or it proves nothing. Under gVisor the
// thread's attempt is logged as it went (measured, not assumed), and every call that kept its
// marker must be an ordinary result.
func TestDockerSessionCallThatRanIsNeverMarkedFromItsStderr(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 3 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	cell, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: stolenMarkerThief, Timeout: 30 * time.Second})
	if err != nil || strings.TrimSpace(cell.Stdout) != "watching" {
		t.Fatalf("the cell that leaves the thread: %+v, %v", cell, err)
	}
	const attempts = 8
	for i := 1; i <= attempts; i++ {
		r, err := s.RunJavaScript(ctx, Request{Code: stolenMarkerCall, Timeout: 20 * time.Second})
		if err == nil {
			if strings.TrimSpace(r.Stdout) != "kept" || r.ExitCode != 0 {
				t.Fatalf("attempt %d kept its marker but answered %+v", i, r)
			}
			continue
		}
		// The call ran (only its own code writes the guard's line here: no seam is set), and its
		// marker was taken.
		if reason, marked := NotDispatchedReason(err); marked {
			t.Fatalf("attempt %d: a call that ran came back marked not dispatched (reason %v): %v", i, reason, err)
		}
		var end *SessionEndedError
		if !errors.As(err, &end) || end.Reason != SessionBoundaryFailed {
			t.Fatalf("attempt %d: %v; want the session ended, boundary failed, unmarked", i, err)
		}
		if s.Err() == nil {
			t.Fatalf("attempt %d: the session is still open", i)
		}
		t.Logf("attempt %d: the thread took the start marker; the call came back unmarked: %v", i, err)
		return
	}
	logged := "(no log)"
	if r, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: `let l; try { l = require("node:fs").readFileSync("/work/thief.log", "latin1") } catch (e) { l = e.code } console.log(l + " | worker: " + globalThis.plimsollThiefError + " | cwd " + process.cwd() + " uid " + process.getuid())`, Timeout: 30 * time.Second}); err == nil {
		logged = strings.TrimSpace(r.Stdout)
	}
	if d.Runtime == "runsc" {
		t.Logf("under gVisor the thread took no start marker in %d calls; what it met: %s", attempts, logged)
		return
	}
	t.Fatalf("under %q the thread took no start marker in %d calls, so the test proves nothing; what it met: %s", d.Runtime, attempts, logged)
}
