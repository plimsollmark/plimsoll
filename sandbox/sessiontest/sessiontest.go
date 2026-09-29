// Package sessiontest is the session conformance suite: the behavior every
// sandbox.SessionProvider promises, checked with node snippets and project steps
// through the provider itself. A provider states sessions only once it passes.
// The suite needs a provider whose image runs node and sh, as every provider
// that runs projects does.
package sessiontest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// Config is what the suite needs besides the provider.
type Config struct {
	// Lifetime is given to every session the suite opens except the lifetime
	// case's own; it must outlast the slowest case (about a minute).
	Lifetime time.Duration
	// ShortLifetime is the lifetime case's: long enough to open the session and
	// make one call, short enough to wait out.
	ShortLifetime time.Duration
}

// Run runs every case against p, each in its own session.
func Run(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	if !p.SupportsSessions() {
		t.Fatal("the provider does not support sessions")
	}
	for _, c := range []struct {
		name string
		run  func(*testing.T, sandbox.SessionProvider, Config)
	}{
		{"FilesPersistAcrossCallsAndKinds", filesPersist},
		{"SessionsDoNotShareFiles", sessionsIsolated},
		{"NoProcessOutlivesItsCall", noProcessOutlivesCall},
		{"DeadlineEndsTheCallNotTheSession", deadlineEndsCall},
		{"HeldOutputEndsAtTheDeadline", heldOutput},
		{"SuspendKeepsFiles", suspendKeepsFiles},
		{"FloorAboveTheTierIsRefusedBeforeDispatch", floorRefused},
		{"CloseEndsTheSession", closeEnds},
		{"LifetimeEndsTheSession", lifetimeEnds},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, p, cfg) })
	}
}

func open(t *testing.T, p sandbox.SessionProvider, lifetime time.Duration) sandbox.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := p.OpenSession(ctx, sandbox.SessionOptions{Lifetime: lifetime, DiskBytes: 64 << 20})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

func js(t *testing.T, s sandbox.Session, code string, timeout time.Duration) sandbox.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+60*time.Second)
	defer cancel()
	res, err := s.RunJavaScript(ctx, sandbox.Request{Code: code, Timeout: timeout})
	if err != nil {
		t.Fatalf("RunJavaScript(%.60q): %v", code, err)
	}
	return res
}

func token(t *testing.T) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// procsRunning is a snippet that prints the command lines of every process whose
// command line contains one of the markers.
func procsRunning(markers ...string) string {
	return fmt.Sprintf(`const fs=require("fs");const m=%q.split(",");const hits=[];
for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d)||+d===process.pid)continue;
let c="";try{c=fs.readFileSync("/proc/"+d+"/cmdline","latin1").split("\0").join(" ").trim()}catch{continue}
if(m.some(x=>c.includes(x)))hits.push(d+": "+c)}
console.log(JSON.stringify(hits))`, strings.Join(markers, ","))
}

func filesPersist(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	tok := token(t)
	res := js(t, s, fmt.Sprintf(`require("fs").mkdirSync("/tmp/st",{recursive:true});require("fs").writeFileSync("/tmp/st/a.txt",%q);console.log("wrote")`, tok), 10*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("write: exit %d, stderr %q", res.ExitCode, res.Stderr)
	}
	if got := js(t, s, `process.stdout.write(require("fs").readFileSync("/tmp/st/a.txt","utf8"))`, 10*time.Second); got.Stdout != tok {
		t.Fatalf("a snippet read %q, want %q (stderr %q)", got.Stdout, tok, got.Stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pr, err := s.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "b.txt", Content: tok + "-b"}},
		Steps: []string{"cat /tmp/st/a.txt", "cat b.txt"},
	})
	if err != nil || pr.Outcome != sandbox.ProjectOutcomeCompleted || len(pr.Steps) != 2 {
		t.Fatalf("project: %+v, %v", pr, err)
	}
	if pr.Steps[0].Stdout != tok || pr.Steps[1].Stdout != tok+"-b" {
		t.Fatalf("project steps read %q and %q", pr.Steps[0].Stdout, pr.Steps[1].Stdout)
	}
	// The project's own files persist for a later snippet too.
	if got := js(t, s, `const fs=require("fs");const d=fs.readdirSync("/tmp",{recursive:true}).filter(f=>f.endsWith("b.txt"));process.stdout.write(d.length?fs.readFileSync("/tmp/"+d[0],"utf8"):"none")`, 10*time.Second); got.Stdout != tok+"-b" {
		t.Fatalf("a snippet after the project read %q", got.Stdout)
	}
}

func sessionsIsolated(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	a := open(t, p, cfg.Lifetime)
	b := open(t, p, cfg.Lifetime)
	js(t, a, `require("fs").writeFileSync("/tmp/only-a.txt","a")`, 10*time.Second)
	if got := js(t, b, `console.log(require("fs").existsSync("/tmp/only-a.txt"))`, 10*time.Second); strings.TrimSpace(got.Stdout) != "false" {
		t.Fatalf("session b sees session a's file: %q", got.Stdout)
	}
}

func noProcessOutlivesCall(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	// A detached child, a setsid grandchild and a plain background child.
	res := js(t, s, `const cp=require("child_process");
cp.spawn("sleep",["7771"],{detached:true,stdio:"ignore"}).unref();
cp.spawnSync("sh",["-c","setsid sleep 7772 >/dev/null 2>&1 < /dev/null & sleep 7773 >/dev/null 2>&1 < /dev/null &"]);
console.log("started")`, 10*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("spawn: exit %d, stderr %q", res.ExitCode, res.Stderr)
	}
	if got := strings.TrimSpace(js(t, s, procsRunning("sleep 777"), 10*time.Second).Stdout); got != "[]" {
		t.Fatalf("processes of the previous call are still running: %s", got)
	}
}

func deadlineEndsCall(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	js(t, s, `require("fs").writeFileSync("/tmp/before.txt","kept")`, 10*time.Second)
	res := js(t, s, `require("fs").writeFileSync("/tmp/spin.txt","x");for(;;){}`, 2*time.Second)
	if !res.TimedOut {
		t.Fatalf("an endless call did not time out: %+v", res)
	}
	got := js(t, s, `const fs=require("fs");console.log(fs.readFileSync("/tmp/before.txt","utf8")+" "+fs.existsSync("/tmp/spin.txt"))`, 10*time.Second)
	if strings.TrimSpace(got.Stdout) != "kept true" {
		t.Fatalf("after a timed-out call the session reads %q", got.Stdout)
	}
	if s.Err() != nil {
		t.Fatalf("the session ended: %v", s.Err())
	}
}

func heldOutput(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	// A detached child that inherits stdout keeps the call's output open.
	res := js(t, s, `require("child_process").spawn("sleep",["7781"],{detached:true,stdio:["ignore","inherit","inherit"]}).unref();console.log("hi")`, 3*time.Second)
	if !res.TimedOut || !strings.Contains(res.Stdout, "hi") {
		t.Logf("held output: %+v (a provider may also end such a call on its own terms)", res)
	}
	if got := strings.TrimSpace(js(t, s, procsRunning("sleep 7781"), 10*time.Second).Stdout); got != "[]" {
		t.Fatalf("the process holding the output survived: %s", got)
	}
}

func suspendKeepsFiles(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	tok := token(t)
	js(t, s, fmt.Sprintf(`require("fs").writeFileSync("/tmp/s.txt",%q)`, tok), 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := time.Now()
	if err := s.Suspend(ctx); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	suspended := time.Since(start)
	start = time.Now()
	got := js(t, s, `process.stdout.write(require("fs").readFileSync("/tmp/s.txt","utf8"))`, 10*time.Second)
	t.Logf("suspend took %v; the next call, resume included, %v", suspended.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	if got.Stdout != tok {
		t.Fatalf("after suspend the session reads %q, want %q", got.Stdout, tok)
	}
}

func floorRefused(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	if s.Isolation() >= sandbox.IsolationVM {
		t.Skip("the session is already at the highest tier")
	}
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`, MinimumIsolation: s.Isolation() + 1})
	if !errors.Is(err, sandbox.ErrInsufficientIsolation) {
		t.Fatalf("a floor above the session's tier: %v", err)
	}
	if r, ok := sandbox.NotDispatchedReason(err); !ok || r != sandbox.RefusalIsolation {
		t.Fatalf("the refusal is not marked as not dispatched for isolation: %v", err)
	}
	if got := js(t, s, `console.log("still open")`, 10*time.Second); strings.TrimSpace(got.Stdout) != "still open" {
		t.Fatalf("after the refusal: %q", got.Stdout)
	}
}

func closeEnds(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	js(t, s, `console.log(1)`, 10*time.Second)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done was not closed after Close")
	}
	if sandbox.SessionEndReason(s.Err()) != sandbox.SessionClosed {
		t.Fatalf("Err after Close: %v", s.Err())
	}
	_, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`})
	if !errors.Is(err, sandbox.ErrSessionEnded) {
		t.Fatalf("a call after Close: %v", err)
	}
	if _, ok := sandbox.NotDispatchedReason(err); !ok {
		t.Fatalf("a call after Close is not marked as not dispatched: %v", err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
}

func lifetimeEnds(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.ShortLifetime)
	js(t, s, `console.log(1)`, 5*time.Second)
	select {
	case <-s.Done():
	case <-time.After(time.Until(s.ExpiresAt()) + 30*time.Second):
		t.Fatalf("the session outlived its lifetime (expires %v)", s.ExpiresAt())
	}
	if sandbox.SessionEndReason(s.Err()) != sandbox.SessionExpired {
		t.Fatalf("Err after the lifetime: %v", s.Err())
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: `console.log(1)`}); !errors.Is(err, sandbox.ErrSessionEnded) {
		t.Fatalf("a call after the lifetime: %v", err)
	}
}
