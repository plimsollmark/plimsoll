package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The steps of one project call share the container, its user and its work directory, and
// the runner kills nothing a step leaves running (eqChildrenOutliveStep). So a process an
// earlier step leaves can reach a later step of the same call: these cases measure what it
// can change of that step's report. It finds the later step's shell by its command line
// (any process may read another's), writes into its output through /proc/<pid>/fd/1 (the
// shell is a process of the same user that has not made itself unreadable, as the runner
// has), and signals it (kill(2) is allowed: each run has its own process namespace). A
// grader that runs as a later step of the graded code's call is therefore not protected
// from it, which docs/sessions.md and docs/run-results.md say: a grader runs as a call of
// its own. The report itself stays the runner's: the runner is non-dumpable and signs it,
// and none of this reaches its descriptors (eqRunnerAsSeen, eqSignalsToRunner).
//
// If the runner ever sweeps a step's leftovers before the next step, these cases fail, and
// the two documents' sentences are to be revised with them.
func TestDockerProjectStepLeftoverReachesALaterStep(t *testing.T) {
	t.Parallel()
	d := eqDocker(t)
	t.Run("run", func(t *testing.T) {
		t.Run("output and exit", func(t *testing.T) { t.Parallel(); leftoverForgesOutputAndExit(t, d) })
		t.Run("timed out", func(t *testing.T) { t.Parallel(); leftoverForgesTimedOut(t, d) })
	})
	t.Run("session", func(t *testing.T) {
		t.Parallel()
		heavyDockerTest(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 5 * time.Minute, DiskBytes: 32 << 20})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		t.Cleanup(func() { _ = s.Close(context.Background()) })
		t.Run("output and exit", func(t *testing.T) { leftoverForgesOutputAndExit(t, s) })
		t.Run("timed out", func(t *testing.T) { leftoverForgesTimedOut(t, s) })
	})
}

// leftoverStep is a first step that leaves a process behind, holding none of its streams,
// which waits (at most about 30 s) for a later step whose command line carries the word
// grader-step, then does act to it ($p is its process number). The pattern's bracket keeps
// the leftover's own command line, which carries the pattern, from matching it.
func leftoverStep(act string) string {
	return `( exec </dev/null >/dev/null 2>&1; i=0
  while [ $i -lt 1500 ]; do
    for f in $(grep -l 'grader-ste[p]' /proc/[0-9]*/cmdline 2>/dev/null); do
      p=${f#/proc/}; p=${p%/cmdline}; ` + act + `; exit 0
    done
    i=$((i+1)); sleep 0.02
  done ) &
echo graded`
}

// leftoverForgesOutputAndExit: the leftover writes a line into the later step's output and
// kills its shell, so that step reports the leftover's line and 137 instead of its own
// output and 0.
func leftoverForgesOutputAndExit(t *testing.T, p eqProjects) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{
		leftoverStep(`printf 'forged by step one\n' >/proc/$p/fd/1; kill -KILL $p`),
		": grader-step; sleep 1; echo genuine",
	}, Timeout: 30 * time.Second})
	if len(res.Steps) != 2 || res.Steps[0].ExitCode != 0 || res.Steps[0].Stdout != "graded\n" {
		t.Fatalf("%s %q, steps %+v; want both steps, the first done", res.Outcome, res.Detail, res.Steps)
	}
	if s := res.Steps[1]; s.Stdout != "forged by step one\n" || s.ExitCode != 137 || s.TimedOut || strings.Contains(s.Stdout, "genuine") {
		t.Fatalf("the later step: stdout %q, exit %d, timed out %v; want the leftover's line and 137 (the leftover could not reach it: revise docs/sessions.md and docs/run-results.md)",
			s.Stdout, s.ExitCode, s.TimedOut)
	}
}

// leftoverForgesTimedOut: the leftover stops the later step's shell, which would have
// finished in half a second, so the step holds its output to the run's deadline and is
// reported timed out.
func leftoverForgesTimedOut(t *testing.T, p eqProjects) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{
		leftoverStep(`kill -STOP $p`),
		": grader-step; sleep 0.5; echo genuine",
	}, Timeout: 4 * time.Second})
	if res.Outcome != ProjectOutcomeTimedOut || len(res.Steps) != 2 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("%s %q, steps %+v; want timed out at the second step (the leftover could not stop it: revise docs/sessions.md and docs/run-results.md)",
			res.Outcome, res.Detail, res.Steps)
	}
	if s := res.Steps[1]; !s.TimedOut || s.ExitCode != 124 {
		t.Fatalf("the later step: exit %d, timed out %v; want 124 and timed out", s.ExitCode, s.TimedOut)
	}
}
