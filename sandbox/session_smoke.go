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
//   - a cell's interpreter keeps what the cell before it defined;
//   - after a suspend, the call that resumes the session finds the file, and a cell's
//     interpreter is either the one that holds the definition or one that says it is
//     new;
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
	cell := func(step, code string) (CellResult, error) {
		res, err := s.RunCell(ctx, CellRequest{Language: LanguageJavaScript, Code: code, Timeout: 30 * time.Second})
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

	if _, err := cell("a cell that defines", "globalThis.plimsollSmoke = 41"); err != nil {
		return err
	}
	res, err := cell("the next cell", "plimsollSmoke + 1")
	if err != nil {
		return err
	}
	if res.InterpreterStarted || strings.TrimSpace(res.Stdout) != "42" {
		return fmt.Errorf("session smoke: the next cell got %.80q (fresh interpreter %v), want 42 from the same interpreter", res.Stdout, res.InterpreterStarted)
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
	res, err = cell("a cell after the resume", "typeof plimsollSmoke")
	if err != nil {
		return err
	}
	if got, want := strings.TrimSpace(res.Stdout), map[bool]string{true: "'undefined'", false: "'number'"}[res.InterpreterStarted]; got != want {
		return fmt.Errorf("session smoke: after the resume a cell saw %.80q while saying its interpreter is fresh: %v", got, res.InterpreterStarted)
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
