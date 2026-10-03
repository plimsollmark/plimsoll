package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SessionSmokeTest proves a provider's sessions on this host, by behavior, before a
// daemon serves them, as SmokeTest proves its runs. A run's checks say nothing about
// what only a session does: the sweep between calls, the pause or stop of a suspend
// and the resume after it, an interpreter kept across calls, and a close. So it
// opens one session with opts and checks that
//   - a process a call leaves running, detached in a process group of its own, is
//     gone when the next call runs (the sweep killed it), and a file the call wrote
//     is there;
//   - in every cell language the provider states, a cell's interpreter keeps what the
//     cell before it defined (cellChecks has one check per language, and a stated
//     language without one fails the test, so no language is stated that startup did
//     not run);
//   - once the relays beside the interpreters are running, a call of the session cannot
//     open their input or output (docker makes a relay unreadable once it has started;
//     openshell walls each exec's processes off from the others'). A relay that a call
//     can reach can be fed forged answers, so a provider or gateway where the open
//     succeeds gets no sessions;
//   - after a suspend, the call that resumes the session finds the file, and a cell's
//     interpreter is either the one that holds the definition or one that says it is
//     new;
//   - a call whose code fails comes back as a result with its exit code, not an error:
//     a provider that cannot tell the code's exit from its own failure (on docker, an
//     image whose node writes to stderr before the call's start marker) would turn
//     every failing call into an error that says it may have run;
//   - Close ends the session, and Done closes.
//
// It creates one sandbox and removes it, so a daemon runs it once at startup, never
// on a poll path.
func SessionSmokeTest(ctx context.Context, sp SessionProvider, opts SessionOptions) (err error) {
	s, err := sp.OpenSession(ctx, opts)
	if err != nil {
		return fmt.Errorf("session smoke: open: %w", err)
	}
	defer func() {
		if cerr := s.Close(context.WithoutCancel(ctx)); err == nil && cerr != nil {
			err = fmt.Errorf("session smoke: close: %w", cerr)
		}
	}()
	js := func(step, code string) (string, error) {
		res, err := s.RunJavaScript(ctx, Request{Code: code, Timeout: 30 * time.Second})
		if err != nil {
			return "", fmt.Errorf("session smoke: %s: %w", step, err)
		}
		if res.ExitCode != 0 || res.TimedOut {
			return "", fmt.Errorf("session smoke: %s: exit %d, timed out %v: %.300q", step, res.ExitCode, res.TimedOut, res.Stderr)
		}
		return strings.TrimSpace(res.Stdout), nil
	}
	cell := func(step string, lang Language, code string) (CellResult, error) {
		res, err := s.RunCell(ctx, CellRequest{Language: lang, Code: code, Timeout: 30 * time.Second})
		if err != nil {
			return res, fmt.Errorf("session smoke: %s: %w", step, err)
		}
		if res.ExitCode != 0 || res.TimedOut {
			return res, fmt.Errorf("session smoke: %s: exit %d, timed out %v: %.300q", step, res.ExitCode, res.TimedOut, res.Stderr)
		}
		return res, nil
	}

	out, err := js("a call that leaves a process", `const { spawn } = require("child_process");
const c = spawn("sleep", ["600"], { detached: true, stdio: "ignore" });
c.unref();
require("fs").writeFileSync("plimsoll-session-smoke.txt", "kept");
console.log(c.pid);`)
	if err != nil {
		return err
	}
	pid, perr := strconv.Atoi(out)
	if perr != nil || pid <= 1 {
		return fmt.Errorf("session smoke: the first call printed %.80q, not the PID of the process it left", out)
	}
	// A process is gone when /proc has no entry for it, or only a zombie's (it was
	// killed and its parent has not reaped it yet).
	out, err = js("the next call", fmt.Sprintf(`const fs = require("fs");
let state = "gone";
try { const st = fs.readFileSync("/proc/%d/stat", "utf8"); const s = st.slice(st.lastIndexOf(")") + 2, st.lastIndexOf(")") + 3); if (s !== "Z" && s !== "X") state = "alive"; } catch {}
console.log(state + " " + fs.readFileSync("plimsoll-session-smoke.txt", "utf8"));`, pid))
	if err != nil {
		return err
	}
	if out != "gone kept" {
		return fmt.Errorf("session smoke: after the sweep the next call saw %.80q, want the process gone and the file kept", out)
	}

	langs := sp.SessionEnvironments().Project.Languages
	if len(langs) == 0 {
		langs = []Language{LanguageJavaScript}
	}
	for _, lang := range langs {
		check, ok := cellChecks[lang]
		if !ok {
			return fmt.Errorf("session smoke: the provider states cell language %q, which has no startup check", lang)
		}
		if _, err := cell("a "+string(lang)+" cell that defines", lang, check.define); err != nil {
			return err
		}
		res, err := cell("the next "+string(lang)+" cell", lang, check.read)
		if err != nil {
			return err
		}
		if res.InterpreterStarted || strings.TrimSpace(res.Stdout) != "42" {
			return fmt.Errorf("session smoke: the next %s cell got %.80q (fresh interpreter %v), want 42 from the same interpreter", lang, res.Stdout, res.InterpreterStarted)
		}
	}

	out, err = js("a call that reaches for the relays", relayReachCode)
	if err != nil {
		return err
	}
	if found, opened, _ := strings.Cut(out, " "); found == "0" || opened != "" {
		return fmt.Errorf("session smoke: a call of the session found %s relays and opened %q of their pipes; want relays found and none opened", found, opened)
	}

	if _, err := s.Suspend(ctx); err != nil {
		return fmt.Errorf("session smoke: suspend: %w", err)
	}
	if out, err = js("the call that resumes", `console.log(require("fs").readFileSync("plimsoll-session-smoke.txt", "utf8"))`); err != nil {
		return err
	}
	if out != "kept" {
		return fmt.Errorf("session smoke: after the suspend the file reads %.80q, want it kept", out)
	}
	res, err := cell("a cell after the resume", LanguageJavaScript, "typeof plimsollSmoke")
	if err != nil {
		return err
	}
	if got, want := strings.TrimSpace(res.Stdout), map[bool]string{true: "'undefined'", false: "'number'"}[res.InterpreterStarted]; got != want {
		return fmt.Errorf("session smoke: after the resume a cell saw %.80q while saying its interpreter is fresh: %v", got, res.InterpreterStarted)
	}

	failed, err := s.RunJavaScript(ctx, Request{Code: `console.error("plimsoll smoke: a failing call"); process.exitCode = 3`, Timeout: 30 * time.Second})
	if err != nil {
		return fmt.Errorf("session smoke: a call whose code exits 3 came back as an error, not a result: %w", err)
	}
	if failed.ExitCode != 3 || failed.TimedOut {
		return fmt.Errorf("session smoke: a call whose code exits 3 came back with exit %d, timed out %v", failed.ExitCode, failed.TimedOut)
	}

	if err := s.Close(ctx); err != nil {
		return fmt.Errorf("session smoke: close: %w", err)
	}
	select {
	case <-s.Done():
	case <-ctx.Done():
		return fmt.Errorf("session smoke: the session did not end after Close: %w", ctx.Err())
	}
	var end *SessionEndedError
	if !errors.As(s.Err(), &end) || end.Reason != SessionClosed {
		return fmt.Errorf("session smoke: a closed session reports %v, want closed", s.Err())
	}
	return nil
}

// relayReachCode counts the session's relays and tries to open each one's input and
// output, closing at once whatever opens (nothing is read or written). It prints the
// count and the pipes it opened: "2 " is the answer a sound provider gives.
const relayReachCode = `const fs = require("fs");
let found = 0; const opened = [];
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d)) continue;
  let c = ""; try { c = fs.readFileSync("/proc/" + d + "/cmdline", "latin1"); } catch { continue; }
  if (!c.includes("A session interpreter's relay")) continue;
  found++;
  for (const [n, mode] of [["0", "r"], ["1", "w"]]) {
    try { fs.closeSync(fs.openSync("/proc/" + d + "/fd/" + n, mode)); opened.push(d + "/" + n); } catch {}
  }
}
console.log(found + " " + opened.join(","));`

// cellChecks are the two cells SessionSmokeTest runs in each cell language: one that
// defines a value and one that reads it back, printing 42, from the same interpreter.
var cellChecks = map[Language]struct{ define, read string }{
	LanguageJavaScript: {"globalThis.plimsollSmoke = 41", "plimsollSmoke + 1"},
	LanguagePython:     {"plimsoll_smoke = 41", "plimsoll_smoke + 1"},
}
