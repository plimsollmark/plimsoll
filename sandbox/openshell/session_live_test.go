package openshell

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/sessiontest"
)

// TestOpenShellSessionConformanceLive runs the session conformance suite against a
// live gateway: the suite every session provider must pass before it states
// sessions.
//
// The smoke test runs first, so its language probe decides which languages the
// cell cases run in: both with plimsoll/sandbox-python as the image.
func TestOpenShellSessionConformanceLive(t *testing.T) {
	p := liveProvider(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := p.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	langs := p.SessionEnvironments().Project.Languages
	t.Logf("cell languages: %v", langs)
	sessiontest.Run(t, p, sessiontest.Config{Lifetime: 5 * time.Minute, ShortLifetime: 20 * time.Second, Languages: langs})
}

func openLive(t *testing.T, p *Provider, opts sandbox.SessionOptions) *session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	s, err := p.OpenSession(ctx, opts)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Logf("opened %s in %v", s.(*session).b.name, time.Since(start).Round(time.Millisecond))
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s.(*session)
}

func waitEnd(t *testing.T, s *session, want sandbox.SessionEnd) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(30 * time.Second):
		t.Fatalf("the session did not end; want %v", want)
	}
	if got := sandbox.SessionEndReason(s.Err()); got != want {
		t.Fatalf("the session ended with %v, want %v", s.Err(), want)
	}
}

// TestOpenShellSessionDiskBudgetLive: a call that leaves more than the budget under
// /tmp ends the session after it returns.
func TestOpenShellSessionDiskBudgetLive(t *testing.T) {
	p := liveProvider(t, nil)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute, DiskBytes: 1 << 20})
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `require("fs").writeFileSync("/tmp/big",Buffer.alloc(2<<20,1));console.log("wrote")`})
	if err != nil || strings.TrimSpace(res.Stdout) != "wrote" {
		t.Fatalf("the call itself: %+v, %v", res, err)
	}
	waitEnd(t, s, sandbox.SessionDiskExceeded)
	t.Logf("ended: %v", s.Err())
}

// TestOpenShellSessionMainProcessLive: code that kills the sandbox's main process
// ends the session, reported as that and not as an infrastructure failure. The gateway
// marks the sandbox a moment after the kill, and the sweep after the killing call can
// finish first and find it clean (failed so on 2026-09-28 and 2026-09-29), so the end
// is noticed by that call's check or, at the latest, by the next call's read-back,
// which must refuse the call as not dispatched.
func TestOpenShellSessionMainProcessLive(t *testing.T) {
	p := liveProvider(t, nil)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `const fs=require("fs");
for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d))continue;
let c="";try{c=fs.readFileSync("/proc/"+d+"/cmdline","latin1").split("\0").join(" ").trim()}catch{continue}
if(c==="sleep 2147483647"){process.kill(+d,"SIGKILL");console.log("killed "+d)}}`})
	t.Logf("the killing call: %+v, %v", res, err)
	select {
	case <-s.Done():
		t.Log("noticed after the killing call")
	case <-time.After(5 * time.Second):
		_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log("ran")`})
		if _, ok := sandbox.NotDispatchedReason(err); !ok {
			t.Fatalf("the call after the kill was not refused as not dispatched: %v", err)
		}
		t.Log("noticed by the next call's read-back")
	}
	waitEnd(t, s, sandbox.SessionMainProcessEnded)
	t.Logf("ended: %v", s.Err())
}

// TestOpenShellSessionOutOfBandChangeLive: a sandbox changed between calls by another
// gateway client (here, stopped behind the session's back) is caught before the next
// call runs, which is refused as not dispatched.
func TestOpenShellSessionOutOfBandChangeLive(t *testing.T) {
	p := liveProvider(t, nil)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := p.client.DeleteSandbox(ctx, connect.NewRequest(&openshellv1.DeleteSandboxRequest{WorkspaceScope: ws(), Name: s.b.name})); err != nil {
		t.Fatal(err)
	}
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(2)`})
	if _, ok := sandbox.NotDispatchedReason(err); !ok {
		t.Fatalf("a call on a sandbox deleted out of band: %v", err)
	}
	t.Logf("refused: %v; session: %v", err, s.Err())
}

// TestOpenShellSessionPIDOneLive records what code in a session's sandbox can see of
// PID 1, the in-sandbox supervisor, which runs as the same user. Measurement for the
// security notes; it asserts only that the session survives the look.
func TestOpenShellSessionPIDOneLive(t *testing.T) {
	p := liveProvider(t, nil)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `const fs=require("fs");const out={};
const tryit=(k,f)=>{try{out[k]=f()}catch(e){out[k]="ERR "+e.code}};
tryit("status",()=>fs.readFileSync("/proc/1/status","latin1").split("\n").filter(l=>/^(Uid|Gid|Seccomp|NoNewPrivs|CapEff|CapBnd)/.test(l)).join("; "));
tryit("self",()=>fs.readFileSync("/proc/self/status","latin1").split("\n").filter(l=>/^(Uid|Seccomp|NoNewPrivs|CapEff)/.test(l)).join("; "));
tryit("fds",()=>fs.readdirSync("/proc/1/fd").length);
tryit("fd0",()=>fs.readlinkSync("/proc/1/fd/0"));
tryit("mem",()=>{const fd=fs.openSync("/proc/1/mem","r");fs.closeSync(fd);return "opened"});
tryit("environ",()=>fs.readFileSync("/proc/1/environ","latin1").length);
tryit("ptrace_scope",()=>fs.readFileSync("/proc/sys/kernel/yama/ptrace_scope","latin1").trim());
tryit("signal0",()=>{process.kill(1,0);return "allowed"});
console.log(JSON.stringify(out))`})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PID 1 as seen from a session call: %s (stderr %q)", strings.TrimSpace(res.Stdout), res.Stderr)
	if got := js(t, s, `console.log("alive")`); got != "alive" {
		t.Fatalf("after the look: %q", got)
	}
}

func js(t *testing.T, s *session, code string) string {
	t.Helper()
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(res.Stdout)
}

// TestOpenShellSessionTimingLive measures what a session call costs against a run:
// the verification before, the sweep after, and a resume from a suspend.
func TestOpenShellSessionTimingLive(t *testing.T) {
	p := liveProvider(t, nil)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	var calls []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		js(t, s, `console.log(1)`)
		calls = append(calls, time.Since(start).Round(time.Millisecond))
	}
	start := time.Now()
	res, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`})
	run := time.Since(start).Round(time.Millisecond)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("run: %+v, %v", res, err)
	}
	start = time.Now()
	if _, err := s.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	suspend := time.Since(start).Round(time.Millisecond)
	start = time.Now()
	js(t, s, `console.log(1)`)
	resumed := time.Since(start).Round(time.Millisecond)
	t.Logf("session calls %v; a per-run snippet %v; suspend %v; the call after it %v", calls, run, suspend, resumed)
}

// TestOpenShellSessionZombieLive: a zombie child left by a call does not stop the
// sweep converging (killing a zombie does nothing, so a sweep that treated one as
// alive would loop until its rounds ran out and restart the sandbox for nothing),
// and the session stays open with its files.
func TestOpenShellSessionZombieLive(t *testing.T) {
	p := liveProvider(t, nil)
	s := openLive(t, p, sandbox.SessionOptions{Lifetime: 2 * time.Minute})
	js(t, s, `require("fs").writeFileSync("/tmp/z.txt","kept")`)
	// The outer sleep never waits, so its background child becomes a zombie under it.
	res, err := s.RunJavaScript(context.Background(), sandbox.Request{
		Code: `require("child_process").spawnSync("sh",["-c","setsid sh -c 'sleep 0.2 & exec sleep 300' >/dev/null 2>&1 </dev/null &"]);
setTimeout(() => console.log("left a zombie behind"), 600);`,
		Timeout: 20 * time.Second,
	})
	if err != nil || !strings.Contains(res.Stdout, "left a zombie") {
		t.Fatalf("the call that leaves a zombie: %+v, %v", res, err)
	}
	if s.Err() != nil {
		t.Fatalf("the session ended: %v", s.Err())
	}
	if got := js(t, s, `const fs=require("fs");let alive=0,zombies=0;
for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||+d===process.pid)continue;
let st;try{st=fs.readFileSync("/proc/"+d+"/stat","latin1")}catch{continue}
const f=st.slice(st.lastIndexOf(")")+2).split(" ");const cmd=(()=>{try{return fs.readFileSync("/proc/"+d+"/cmdline","latin1").split("\0").join(" ").trim()}catch{return ""}})();
if(f[0]==="Z")zombies++;else if(cmd.startsWith("sleep 3")||cmd.startsWith("sleep 0"))alive++}
console.log(fs.readFileSync("/tmp/z.txt","utf8")+" alive="+alive+" zombies="+zombies)`); !strings.HasPrefix(got, "kept alive=0") {
		t.Fatalf("after the sweep: %q", got)
	} else {
		t.Logf("after the sweep: %s", got)
	}
}
