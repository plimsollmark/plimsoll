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
	"slices"
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
	// Languages are the cell languages the provider's image runs; the cell cases run
	// for each. Empty means JavaScript only, which every session provider runs.
	Languages []sandbox.Language
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
		{"FilesPersistAcrossCallsAndKinds", filesPersist}, // every call runs in one work directory
		{"SessionsDoNotShareFiles", sessionsIsolated},
		{"NoProcessOutlivesItsCall", noProcessOutlivesCall},
		{"DeadlineEndsTheCallNotTheSession", deadlineEndsCall},
		{"HeldOutputEndsAtTheDeadline", heldOutput},
		{"SuspendKeepsFiles", suspendKeepsFiles},
		{"FloorAboveTheTierIsRefusedBeforeDispatch", floorRefused},
		{"CloseEndsTheSession", closeEnds},
		{"LifetimeEndsTheSession", lifetimeEnds},
		{"CellChildrenDoNotOutliveTheCall", cellChildrenDie},
		{"CellFilesLandInTheWorkDirectory", cellFiles},
		{"CellFilesThatCannotBeWrittenAreRefused", cellFilesRefused},
		{"KilledInterpreterIsStartedAgain", cellInterpreterKilled},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, p, cfg) })
	}
	langs := cfg.Languages
	if len(langs) == 0 {
		langs = []sandbox.Language{sandbox.LanguageJavaScript}
	}
	for _, lang := range langs {
		for _, c := range []struct {
			name string
			run  func(*testing.T, sandbox.SessionProvider, Config, sandbox.Language)
		}{
			{"CellStateSurvivesCalls", cellStateSurvives},
			{"CellErrorKeepsTheState", cellErrorKeepsState},
			{"CellDeadlineEndsTheInterpreter", cellDeadline},
		} {
			t.Run(c.name+"/"+string(lang), func(t *testing.T) { c.run(t, p, cfg, lang) })
		}
	}
	if slices.Contains(langs, sandbox.LanguagePython) {
		t.Run("InterpreterIdentityCannotBeSubstituted", func(t *testing.T) { interpreterNotSubstituted(t, p, cfg) })
	}
}

// A live interpreter can write anything in the sandbox, including the ready file the
// launcher of a second language's interpreter waits on. Here a JavaScript cell's timer
// waits for the Python interpreter's directory to appear (its launch, during the next
// call), starts a detached process, writes that process's PID into the ready file over
// and over for half a second, then writes the real interpreter's PID back. The Python cell answers
// from its own interpreter, the sweep after it kills the process, and the interpreter
// it kept is the real one: a later Python cell still has its state. The case races the
// launcher it tests, so a launcher that read the PID from the file escaped it in 1 of 7
// runs (Docker and OpenShell, 2026-10-01); sessionkit's
// TestLaunchIdentityIsTheProcessItStarted orders the writes and catches that every time.
func interpreterNotSubstituted(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	arm := cell(t, s, sandbox.LanguageJavaScript, `const fs = require("fs"), cp = require("child_process");
const dir = "/tmp/.plimsoll-interp/python", ready = dir + "/ready";
globalThis.decoy = 0;
const spoof = setInterval(() => {
  if (!fs.existsSync(dir)) return;
  clearInterval(spoof);
  const c = cp.spawn("sleep", ["7792"], { detached: true, stdio: "ignore" }); c.unref(); decoy = c.pid;
  for (const end = Date.now() + 500; Date.now() < end;) try { fs.writeFileSync(ready, String(decoy)); } catch {}
  for (const d of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(d)) continue;
    let c = ""; try { c = fs.readFileSync("/proc/" + d + "/cmdline", "latin1"); } catch { continue; }
    if (c.endsWith(dir + "\0")) try { fs.writeFileSync(ready, d); } catch {}
  }
}, 1);
"armed"`, 30*time.Second)
	if arm.ExitCode != 0 {
		t.Fatalf("arm: %+v", arm)
	}
	py := cell(t, s, sandbox.LanguagePython, "plimsoll_x = 41\nplimsoll_x + 1", 60*time.Second)
	if py.ExitCode != 0 || strings.TrimSpace(py.Stdout) != "42" {
		t.Fatalf("the Python cell launched while its ready file was overwritten: %+v", py)
	}
	if d := cell(t, s, sandbox.LanguageJavaScript, "decoy", 30*time.Second); d.InterpreterStarted || strings.TrimSpace(d.Stdout) == "0" {
		t.Fatalf("the timer never wrote into the Python interpreter's ready file, so this case tested nothing: %+v", d)
	}
	if got := strings.TrimSpace(js(t, s, procsRunning("sleep 7792"), 10*time.Second).Stdout); got != "[]" {
		t.Fatalf("a process whose PID was written into the Python interpreter's ready file outlived the sweep: %s", got)
	}
	again := cell(t, s, sandbox.LanguagePython, "plimsoll_x + 1", 30*time.Second)
	if again.InterpreterStarted || strings.TrimSpace(again.Stdout) != "42" {
		t.Fatalf("the sweep did not keep the real Python interpreter: %+v", again)
	}
}

func cell(t *testing.T, s sandbox.Session, lang sandbox.Language, code string, timeout time.Duration, files ...sandbox.File) sandbox.CellResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+60*time.Second)
	defer cancel()
	res, err := s.RunCell(ctx, sandbox.CellRequest{Language: lang, Code: code, Timeout: timeout, Files: files})
	if err != nil {
		t.Fatalf("RunCell(%s, %.60q): %v", lang, code, err)
	}
	return res
}

// cellCode is each case's code per language: what defines state, what reads it,
// what raises, what never ends.
var cellCode = map[sandbox.Language]struct{ define, redefine, read, raise, spin string }{
	sandbox.LanguageJavaScript: {
		define:   "const base = 40; let count = 1; function add(x) { return x + base; }",
		redefine: "const base = 41; base",
		read:     "add(count)",
		raise:    `throw new Error("cell-error-marker")`,
		spin:     "for (;;) {}",
	},
	sandbox.LanguagePython: {
		define:   "base = 40\ncount = 1\ndef add(x):\n    return x + base",
		redefine: "base = 41\nbase",
		read:     "add(count)",
		raise:    `raise ValueError("cell-error-marker")`,
		spin:     "while True:\n    pass",
	},
}

func cellStateSurvives(t *testing.T, p sandbox.SessionProvider, cfg Config, lang sandbox.Language) {
	s := open(t, p, cfg.Lifetime)
	code := cellCode[lang]
	first := cell(t, s, lang, code.define, 30*time.Second)
	if first.ExitCode != 0 || !first.InterpreterStarted {
		t.Fatalf("the defining cell: %+v", first)
	}
	again := cell(t, s, lang, code.redefine, 30*time.Second)
	if again.ExitCode != 0 || again.InterpreterStarted || strings.TrimSpace(again.Stdout) != "41" {
		t.Fatalf("a cell that defines a name again: %+v", again)
	}
	// A snippet between the cells ends its own processes, not the interpreter.
	js(t, s, `console.log("between")`, 10*time.Second)
	got := cell(t, s, lang, code.read, 30*time.Second)
	if got.ExitCode != 0 || got.InterpreterStarted || strings.TrimSpace(got.Stdout) != "42" {
		t.Fatalf("a later cell read %+v, want 42 from the same interpreter", got)
	}
}

func cellErrorKeepsState(t *testing.T, p sandbox.SessionProvider, cfg Config, lang sandbox.Language) {
	s := open(t, p, cfg.Lifetime)
	code := cellCode[lang]
	cell(t, s, lang, code.define, 30*time.Second)
	bad := cell(t, s, lang, code.raise, 30*time.Second)
	if bad.ExitCode != 1 || bad.InterpreterEnded || !strings.Contains(bad.Stderr, "cell-error-marker") {
		t.Fatalf("a raising cell: %+v", bad)
	}
	if got := cell(t, s, lang, code.read, 30*time.Second); strings.TrimSpace(got.Stdout) != "41" || got.InterpreterStarted {
		t.Fatalf("after the error the interpreter read %+v, want 41", got)
	}
}

func cellDeadline(t *testing.T, p sandbox.SessionProvider, cfg Config, lang sandbox.Language) {
	s := open(t, p, cfg.Lifetime)
	code := cellCode[lang]
	cell(t, s, lang, code.define, 30*time.Second)
	spun := cell(t, s, lang, code.spin, 2*time.Second)
	if !spun.TimedOut || spun.ExitCode != 124 || !spun.InterpreterEnded {
		t.Fatalf("an endless cell: %+v", spun)
	}
	after := cell(t, s, lang, "1 + 1", 30*time.Second)
	if !after.InterpreterStarted || strings.TrimSpace(after.Stdout) != "2" {
		t.Fatalf("the cell after a deadline: %+v, want a fresh interpreter", after)
	}
	if s.Err() != nil {
		t.Fatalf("the session ended: %v", s.Err())
	}
}

func cellChildrenDie(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	res := cell(t, s, sandbox.LanguageJavaScript, `const cp = require("child_process");
cp.spawn("sleep", ["7791"], {detached: true, stdio: "ignore"}).unref();
globalThis.kept = "yes"; "spawned"`, 30*time.Second)
	if res.ExitCode != 0 {
		t.Fatalf("spawn: %+v", res)
	}
	if got := strings.TrimSpace(js(t, s, procsRunning("sleep 7791"), 10*time.Second).Stdout); got != "[]" {
		t.Fatalf("a child of the interpreter outlived its cell: %s", got)
	}
	if got := cell(t, s, sandbox.LanguageJavaScript, "kept", 30*time.Second); strings.TrimSpace(got.Stdout) != "'yes'" {
		t.Fatalf("the interpreter did not survive: %+v", got)
	}
}

func cellFiles(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	tok := token(t)
	res := cell(t, s, sandbox.LanguageJavaScript, `require("fs").readFileSync("in/data.csv", "utf8")`, 30*time.Second,
		sandbox.File{Path: "in/data.csv", Content: "a,b\n" + tok})
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, tok) {
		t.Fatalf("a cell read its file: %+v", res)
	}
	if got := js(t, s, `process.stdout.write(require("fs").readFileSync("in/data.csv","utf8"))`, 10*time.Second); !strings.Contains(got.Stdout, tok) {
		t.Fatalf("a later snippet read %q from the cell's file", got.Stdout)
	}
}

// A cell whose files cannot be written (here a directory is in the way) is refused,
// marked not dispatched: its code did not run, its interpreter keeps its state, and a
// file written before the failing one stays.
func cellFilesRefused(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	cell(t, s, sandbox.LanguageJavaScript, "globalThis.kept = 7", 30*time.Second, sandbox.File{Path: "d/x", Content: "1"})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	_, err := s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguageJavaScript, Code: "globalThis.ran = 1", Timeout: 30 * time.Second,
		Files: []sandbox.File{{Path: "first.txt", Content: "written"}, {Path: "d", Content: "2"}}})
	reason, ok := sandbox.NotDispatchedReason(err)
	if !ok || reason != sandbox.RefusalRequest || !errors.Is(err, sandbox.ErrInvalidRequest) || !strings.Contains(err.Error(), "file 2 of 2: EISDIR") {
		t.Fatalf("a cell whose second file is a directory: %v (reason %v, marked %v); want refused, request, naming file 2 and EISDIR", err, reason, ok)
	}
	got := cell(t, s, sandbox.LanguageJavaScript, `kept + ":" + typeof ran + ":" + require("fs").readFileSync("first.txt", "utf8")`, 30*time.Second)
	if got.InterpreterStarted || !strings.Contains(got.Stdout, "7:undefined:written") {
		t.Fatalf("after the refused cell: %+v; want the same interpreter, its state, no trace of the refused code, the first file", got)
	}
}

func cellInterpreterKilled(t *testing.T, p sandbox.SessionProvider, cfg Config) {
	s := open(t, p, cfg.Lifetime)
	cell(t, s, sandbox.LanguageJavaScript, "globalThis.marker = 1", 30*time.Second)
	// A snippet kills the interpreter (its command line names its directory).
	js(t, s, `const fs=require("fs");for(const d of fs.readdirSync("/proc")){if(!/^[0-9]+$/.test(d))continue;
let c="";try{c=fs.readFileSync("/proc/"+d+"/cmdline","latin1")}catch{continue}
if(c.includes("plimsoll-interp/javascript")&&+d!==process.pid)try{process.kill(+d,"SIGKILL")}catch{}}`, 10*time.Second)
	got := cell(t, s, sandbox.LanguageJavaScript, "typeof marker", 30*time.Second)
	if !got.InterpreterStarted || strings.TrimSpace(got.Stdout) != "'undefined'" {
		t.Fatalf("after its interpreter was killed a cell got %+v, want a fresh interpreter", got)
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
	// The project's own files persist for a later snippet too, which runs in the
	// same work directory.
	if got := js(t, s, `const fs=require("fs");process.stdout.write(fs.existsSync("b.txt")?fs.readFileSync("b.txt","utf8"):"none in "+process.cwd())`, 10*time.Second); got.Stdout != tok+"-b" {
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
	if _, err := s.Suspend(ctx); err != nil {
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
