package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDockerGuestGuardRefusesASessionsMainProcess (finding guest-guard-16): the guard refuses to
// start a session's main process, and the open's refusal names the step and errno of the
// guard's own line, which the open reads from the attached docker run, not the exit code alone
// (which names no errno). guardFirstSeam hands the main process's command a program no image
// has, so the real guard, in the real container, fails at its exec step. The refusal is marked
// not dispatched, no container is left behind, and the next open works.
func TestDockerGuestGuardRefusesASessionsMainProcess(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	var fired atomic.Bool
	seam := func(argv []string) string {
		if slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "plimsoll-session-main:") }) && fired.CompareAndSwap(false, true) {
			return "/.plimsoll-test-no-such-program"
		}
		return ""
	}
	guardFirstSeam.Store(&seam)
	s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
	guardFirstSeam.Store(nil)
	if err == nil {
		s.Close(ctx)
		t.Fatal("the open behind the failing guard opened a session")
	}
	if !fired.Load() {
		t.Fatal("no command carried the main process's marker, so the guard was never handed the failing program")
	}
	if reason, marked := NotDispatchedReason(err); !marked || reason != RefusalEnvironment {
		t.Fatalf("the open: %v (reason %v, marked %v); want not dispatched, environment", err, reason, marked)
	}
	if !strings.Contains(err.Error(), "main process") || !strings.Contains(err.Error(), "step exec, errno 2 (exit 124)") {
		t.Fatalf("the open: %v; want the main process named and the guard's own line read: step exec, errno 2 (exit 124)", err)
	}
	if strings.Contains(err.Error(), "plimsoll guest guard:") {
		t.Fatalf("the open: %q carries the guard's line itself; want plimsoll's own words", err)
	}
	out, lerr := exec.Command("docker", "ps", "-a", "-q", "--filter", "label="+dockerInstanceLabel+"="+d.instance()).Output()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if left := strings.TrimSpace(string(out)); left != "" {
		t.Fatalf("the refused open left containers behind: %s", left)
	}
	s, err = d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
	if err != nil {
		t.Fatalf("an open after it: %v", err)
	}
	defer s.Close(ctx)
	r, err := s.RunJavaScript(ctx, Request{Code: `console.log("ran")`, Timeout: 20 * time.Second})
	if err != nil || strings.TrimSpace(r.Stdout) != "ran" {
		t.Fatalf("a call in the next session: %q, %v", r.Stdout, err)
	}
}

// TestDockerGuestGuardRefusesALaterSessionCall (finding guest-guard-15): the guard refuses in a
// later call of an open session, and the session ends as boundary failed. No real run can make
// the guard refuse once a session is open (its file and /usr/bin/env, the program it starts
// every command with, are on read-only mounts), so the test seam guardFirstSeam hands one call's
// command a program no image has: the real guard, in the real container, then fails at its exec
// step (exit 124, errno 2) and starts nothing. For a snippet's call and for the runner's: the
// session's first call works, the call behind the failing guard ends the session as boundary
// failed with plimsoll's words for the guard's step, and so does every call after it. The call
// behind the failing guard is not marked not dispatched (finding hunt-security-30): code of the
// session can make a call that ran end the same way
// (TestDockerSessionCallThatRanIsNeverMarkedFromItsStderr), so the end's words say whether the
// call ran is not known.
//
// The seam is package-wide, so this test does not run in parallel: Go starts the package's
// parallel tests only after its sequential ones have ended. It changes only the first command
// that carries a call's start marker after it is set.
func TestDockerGuestGuardRefusesALaterSessionCall(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	const missing = "/.plimsoll-test-no-such-program"
	const want = "step exec, errno 2, exit 124"
	ended := func(t *testing.T, what string, err error) {
		t.Helper()
		var end *SessionEndedError
		if !errors.As(err, &end) || end.Reason != SessionBoundaryFailed || !strings.Contains(end.Detail, "as the guest guard ends when it refuses") || !strings.Contains(end.Detail, want) {
			t.Fatalf("%s: %v; want the session ended, boundary failed, naming the guard's %s", what, err, want)
		}
		if strings.Contains(end.Detail, "plimsoll guest guard:") {
			t.Errorf("%s: %q carries the guard's line itself; want plimsoll's own words", what, end.Detail)
		}
	}
	for _, c := range []struct {
		name string
		call func(s Session) (string, error)
	}{
		{"a snippet", func(s Session) (string, error) {
			r, err := s.RunJavaScript(ctx, Request{Code: `console.log("ran")`, Timeout: 20 * time.Second})
			return strings.TrimSpace(r.Stdout), err
		}},
		{"the runner", func(s Session) (string, error) {
			r, err := s.RunProject(ctx, ProjectRequest{Steps: []string{"echo ran"}, Timeout: 20 * time.Second})
			if err != nil || len(r.Steps) != 1 {
				return "", err
			}
			return strings.TrimSpace(r.Steps[0].Stdout), nil
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close(ctx)
			if out, err := c.call(s); err != nil || out != "ran" {
				t.Fatalf("the session's first call: %q, %v", out, err)
			}
			var fired atomic.Bool
			seam := func(argv []string) string {
				if slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "plimsoll-started:") }) && fired.CompareAndSwap(false, true) {
					return missing
				}
				return ""
			}
			guardFirstSeam.Store(&seam)
			_, err = c.call(s)
			guardFirstSeam.Store(nil)
			if !fired.Load() {
				t.Fatal("no command of the call carried a start marker, so the guard was never handed the failing program")
			}
			ended(t, "the call behind the failing guard", err)
			if reason, marked := NotDispatchedReason(err); marked {
				t.Fatalf("the call behind the failing guard: %v is marked not dispatched (reason %v); code of the session can forge this end, so it is never marked", err, reason)
			}
			ended(t, "the session's state after it", s.Err())
			_, err = c.call(s)
			ended(t, "a call after it", err)
		})
	}
}

// TestDockerSessionMarksOnlyItsOwnRefusedCommand (finding guest-guard-24, decision 24 B): in a
// session a caller holds, a call whose own command the refusing point refuses (docker never
// started) is marked not dispatched and the session ends; a refusal that comes after the call's
// code ran leaves the call unmarked, since no mark means the code may have run (the guard's own
// refusal of the call's command is unmarked too: TestDockerGuestGuardRefusesALaterSessionCall).
// For a snippet's call and a project's:
//
//   - the refusing point refuses the call's own command (guardFirstSeam names the guard's own
//     path, which the refusing point refuses before docker starts): marked, reason environment,
//     and the session ended, boundary failed, in plimsoll's words for the refusal;
//   - the call runs and the sweep after it is refused, by the guard (a program no image has) or
//     by the refusing point: the call is a result with no error, and the session's end reaches
//     the next call;
//   - a project whose second step starts the guard itself, in front of a program no image has,
//     after its first step ran: the guard's line and code are the step's own exit in the runner's
//     report, a result with no error and no mark, and the session goes on.
//
// The seam is package-wide, so this test does not run in parallel.
func TestDockerSessionMarksOnlyItsOwnRefusedCommand(t *testing.T) {
	d := testDocker()
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	const missing = "/.plimsoll-test-no-such-program"
	hasMarker := func(argv []string) bool {
		return slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "plimsoll-started:") })
	}
	calls := []struct {
		name string
		call func(s Session) (string, error)
	}{
		{"a snippet", func(s Session) (string, error) {
			r, err := s.RunJavaScript(ctx, Request{Code: `console.log("ran")`, Timeout: 20 * time.Second})
			return strings.TrimSpace(r.Stdout), err
		}},
		{"a project", func(s Session) (string, error) {
			r, err := s.RunProject(ctx, ProjectRequest{Steps: []string{"echo ran"}, Timeout: 20 * time.Second})
			if err != nil || len(r.Steps) != 1 {
				return "", err
			}
			return strings.TrimSpace(r.Steps[0].Stdout), nil
		}},
	}
	open := func(t *testing.T) Session {
		t.Helper()
		s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 2 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close(ctx) })
		return s
	}
	unmarked := func(t *testing.T, what string, err error) {
		t.Helper()
		if _, marked := NotDispatchedReason(err); marked {
			t.Fatalf("%s: %v is marked not dispatched; the call ran", what, err)
		}
	}
	for _, c := range calls {
		t.Run("the refusing point refuses "+c.name+"'s own command", func(t *testing.T) {
			s := open(t)
			var fired atomic.Bool
			seam := func(argv []string) string {
				if hasMarker(argv) && fired.CompareAndSwap(false, true) {
					return guestGuardTarget
				}
				return ""
			}
			guardFirstSeam.Store(&seam)
			_, err := c.call(s)
			guardFirstSeam.Store(nil)
			if !fired.Load() {
				t.Fatal("no command of the call carried a start marker")
			}
			if reason, marked := NotDispatchedReason(err); !marked || reason != RefusalEnvironment {
				t.Fatalf("the refused call: %v (reason %v, marked %v); want not dispatched, environment", err, reason, marked)
			}
			var end *SessionEndedError
			if !errors.As(err, &end) || end.Reason != SessionBoundaryFailed || end.Detail != errDockerRefused {
				t.Fatalf("the refused call: %v; want the session ended, boundary failed, in plimsoll's words for the refusal", err)
			}
			if s.Err() == nil {
				t.Fatal("the session is still open")
			}
			if strings.Contains(err.Error(), guestGuardTarget) {
				t.Fatalf("the refusal quotes the refused command: %v", err)
			}
		})
		for _, refuser := range []struct{ name, program string }{{"the guard", missing}, {"the refusing point", guestGuardTarget}} {
			t.Run(refuser.name+" refuses the sweep after "+c.name+" that ran", func(t *testing.T) {
				s := open(t)
				var phase atomic.Int32 // 0: before the call's own command; 1: the next command is refused; 2: refused
				seam := func(argv []string) string {
					switch {
					case phase.Load() == 0 && hasMarker(argv):
						phase.Store(1)
					case phase.Load() == 1 && !hasMarker(argv):
						phase.Store(2)
						return refuser.program
					}
					return ""
				}
				guardFirstSeam.Store(&seam)
				out, err := c.call(s)
				// The sweep runs after the answer; the seam stays until it has been refused.
				for wait := time.Now().Add(time.Minute); phase.Load() != 2 && time.Now().Before(wait); {
					time.Sleep(20 * time.Millisecond)
				}
				guardFirstSeam.Store(nil)
				if phase.Load() != 2 {
					t.Fatal("no command after the call's own was built, so the sweep was never refused")
				}
				unmarked(t, "the call that ran", err)
				if err != nil || out != "ran" {
					t.Fatalf("the call that ran: %q, %v; want its result", out, err)
				}
				_, err = c.call(s)
				var end *SessionEndedError
				if !errors.As(err, &end) || end.Reason != SessionBoundaryFailed {
					t.Fatalf("the next call: %v; want the session's end, boundary failed, from the refused sweep", err)
				}
			})
		}
	}
	t.Run("a project whose second step the guard refuses", func(t *testing.T) {
		s := open(t)
		r, err := s.RunProject(ctx, ProjectRequest{Steps: []string{"echo one", guestGuardTarget + " -- " + missing}, Timeout: 20 * time.Second})
		unmarked(t, "the project", err)
		if err != nil {
			t.Fatalf("the project: %v; want the runner's report", err)
		}
		if len(r.Steps) != 2 || strings.TrimSpace(r.Steps[0].Stdout) != "one" || r.Steps[0].ExitCode != 0 {
			t.Fatalf("the project's steps: %+v; want the first step's output", r.Steps)
		}
		if code := r.Steps[1].ExitCode; code < 120 || code > 124 || !strings.Contains(r.Steps[1].Stderr, "plimsoll guest guard:") {
			t.Fatalf("the second step: exit %d, stderr %q; want the guard's own refusal as the step's exit", code, r.Steps[1].Stderr)
		}
		if s.Err() != nil {
			t.Fatalf("the session ended: %v; the guard's refusal inside a step is the step's own exit", s.Err())
		}
		if out, err := calls[0].call(s); err != nil || out != "ran" {
			t.Fatalf("a call after it: %q, %v", out, err)
		}
	})
}
