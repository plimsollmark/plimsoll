package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A Docker Cloud project runs every step in one microVM, as root, with no sweep between
// steps: each step is a script uploaded before the first runs, and each runs under
// dcExecWrapper, whose exit status goes through a file in /tmp. So an earlier step, or a
// process it leaves running, can decide what a later step of the same run reports. These
// cases measure it on the local stand-in: the fake service, with every exec but a mkdir run
// on this machine's shell, wrapper and all, in a directory of the test's own (dcHostVM),
// so the provider's RunProject, the wrapper and the host's reading of its answer are the
// shipped ones. The guest's user here is the test's, not root; nothing below needs more
// than the same user. docs/dockercloud.md says what a later step may trust, and why a
// grader runs as a run of its own.
func TestDockerCloudStepLeftoverReachesALaterStep(t *testing.T) {
	t.Parallel()
	for _, tool := range []string{"sh", "timeout", "grep", "tr", "sleep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc")
	}
	run := func(t *testing.T, timeout time.Duration, steps ...string) ProjectResult {
		t.Helper()
		f := newDCFake(t)
		d := f.provider()
		d.ProjectDir = dcHostVM(t, f) + "/project"
		res, err := d.RunProject(context.Background(), ProjectRequest{Steps: steps, Timeout: timeout})
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		if len(res.Steps) != len(steps) || res.Steps[0].ExitCode != 0 || res.Steps[0].Stdout != "graded\n" {
			t.Fatalf("%s %q, steps %+v; want every step, the first done", res.Outcome, res.Detail, res.Steps)
		}
		return res
	}
	t.Run("an earlier step rewrites a later step's script", func(t *testing.T) {
		t.Parallel()
		res := run(t, 20*time.Second, `printf 'echo forged; exit 0\n' >"${0%-0.sh}-1.sh"; echo graded`, "echo genuine; exit 3")
		if s := res.Steps[1]; s.Stdout != "forged\n" || s.ExitCode != 0 {
			t.Fatalf("the later step: stdout %q, exit %d; want the earlier step's script, forged and 0", s.Stdout, s.ExitCode)
		}
	})
	// The leftover holds the later step's output open, so the wrapper cannot read the exit
	// status file before the leftover has replaced it, and writes 0 there.
	// The status file is named after the wrapper's own shell, one of $W (the rest are its
	// subshells, which carry the same command line), so the first of theirs to appear is it.
	setsZero := `exec 9>"/proc/$C/fd/1" || exit 1
rc=; j=0
while [ -z "$rc" ] && [ $j -lt 2000 ]; do
  for w in $W; do [ -s /tmp/.plimsoll-rc.$w ] && rc=/tmp/.plimsoll-rc.$w; done
  j=$((j+1)); [ -n "$rc" ] || sleep 0.01
done
[ -n "$rc" ] && echo 0 >"$rc"; exec 9>&-`
	t.Run("a leftover sets a later step's exit status", func(t *testing.T) {
		t.Parallel()
		res := run(t, 20*time.Second, dcLeftoverStep(setsZero), "sleep 1; exit 3")
		if s := res.Steps[1]; s.ExitCode != 0 || s.TimedOut || res.Outcome != ProjectOutcomeCompleted {
			t.Fatalf("the later step: exit %d, timed out %v, outcome %s; want 0, not timed out, completed", s.ExitCode, s.TimedOut, res.Outcome)
		}
	})
	t.Run("a leftover clears a later step's time-out", func(t *testing.T) {
		t.Parallel()
		// The run's 6 s leave the later step an in-guest limit of 3 s (dcGuestMargin), which
		// its sleep passes; its kill's status, 137, is replaced by 0.
		res := run(t, 6*time.Second, dcLeftoverStep(setsZero), "sleep 30")
		if s := res.Steps[1]; s.ExitCode != 0 || s.TimedOut || res.Outcome != ProjectOutcomeCompleted || s.Duration < 2*time.Second {
			t.Fatalf("the later step: exit %d, timed out %v, outcome %s after %v; want 0, not timed out, completed, after its limit",
				s.ExitCode, s.TimedOut, res.Outcome, s.Duration)
		}
	})
	t.Run("a leftover makes a later step time out", func(t *testing.T) {
		t.Parallel()
		res := run(t, 6*time.Second, dcLeftoverStep(`kill -STOP $C`), "sleep 0.5; echo genuine")
		if s := res.Steps[1]; s.ExitCode != 124 || !s.TimedOut || res.Outcome != ProjectOutcomeTimedOut {
			t.Fatalf("the later step: exit %d, timed out %v, outcome %s; want 124, timed out", s.ExitCode, s.TimedOut, res.Outcome)
		}
	})
}

// dcLeftoverStep is a first step that leaves a process behind, holding none of its
// streams, which waits (at most about 30 s) for the second step's wrapper ($W, the shells
// whose command line carries plimsoll-exec: the wrapper and its subshells) and its command
// ($C, the outer shell stepArgv starts), found by the second step's script path on their command lines, then
// does act.
func dcLeftoverStep(act string) string {
	return `s1="${0%-0.sh}-1.sh"
( exec </dev/null >/dev/null 2>&1; i=0; W=; C=
  while [ $i -lt 1500 ] && { [ -z "$W" ] || [ -z "$C" ]; }; do
    for f in $(grep -l -F -e "$s1" /proc/[0-9]*/cmdline 2>/dev/null); do
      c=$(tr '\0' ' ' <"$f" 2>/dev/null) || continue
      p=${f#/proc/}; p=${p%/cmdline}
      case "$c" in "sh -c sh "*) C=$p;; *plimsoll-exec*) case " $W " in *" $p "*) ;; *) W="$W $p";; esac;; esac
    done
    i=$((i+1)); sleep 0.02
  done
  [ -n "$W" ] && [ -n "$C" ] || exit 1
  ` + act + `
) &
echo graded`
}

// dcHostVM makes f run every exec but a mkdir on this machine's shell, in a directory of
// the test's own, and returns it: the files of every upload so far are written there first
// (a step script's /tmp/plimsoll-step- path is moved into it, with every argument and the
// working directory that names one), and the command runs whole, wrapper included.
func dcHostVM(t *testing.T, f *dcFake) string {
	t.Helper()
	root := t.TempDir()
	move := func(s string) string { return strings.ReplaceAll(s, "/tmp/plimsoll-step-", root+"/plimsoll-step-") }
	var mu sync.Mutex
	written := 0
	f.execRun = func(cmd []string, cwd string) (int, string, string) {
		mu.Lock()
		f.mu.Lock()
		batches := f.uploads[written:]
		written = len(f.uploads)
		f.mu.Unlock()
		for _, batch := range batches {
			for _, file := range batch {
				p := move(file.path)
				if !strings.HasPrefix(p, root+"/") {
					t.Errorf("an upload outside the stand-in's directory: %s", file.path)
					continue
				}
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Error(err)
				}
				if err := os.WriteFile(p, file.content, 0o644); err != nil {
					t.Error(err)
				}
			}
		}
		mu.Unlock()
		args := make([]string, len(cmd))
		for i, a := range cmd {
			args[i] = move(a)
		}
		c := exec.Command(args[0], args[1:]...)
		c.Dir = move(cwd)
		if err := os.MkdirAll(c.Dir, 0o755); err != nil {
			t.Error(err)
		}
		var out, errb bytes.Buffer
		c.Stdout, c.Stderr = &out, &errb
		err := c.Run()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return 0, out.String(), errb.String()
		case errors.As(err, &exitErr):
			return exitErr.ExitCode(), out.String(), errb.String()
		default:
			t.Errorf("the stand-in's exec: %v", err)
			return 1, "", ""
		}
	}
	return root
}
