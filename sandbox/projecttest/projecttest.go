// Package projecttest is the one-shot project conformance suite: what every provider's
// RunProject promises, whatever carries its steps (the in-sandbox runner on docker,
// OpenShell and agentsandbox; each step through the platform's own exec on E2B and
// Docker Cloud). Those paths once disagreed on artifacts after a timeout, an artifact
// over the size cap, links among the artifacts, the per-step output cap and a step that
// killed its own shell (review D2, 2026-10-23). The suite is the counterpart of
// sessiontest and needs a provider whose image runs sh, head, tr, yes, ln and mkfifo. It reads
// no device file: OpenShell's filesystem policy denies /dev/zero.
package projecttest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// StepOutputCap is the per-stream output a project step keeps: the bytes past it are
// dropped and the stream marked cut, and the step runs on.
const StepOutputCap = sandbox.ProjectStepOutputCap

// FloodExit is the exit a step reports when its output passed
// sandbox.ProjectStepTransferBudget: 128 plus SIGXFSZ, both streams cut.
const FloodExit = 153

// Projects is what the suite runs against: a provider, or a session, whose calls share
// one sandbox (the cases write distinct files, so they may).
type Projects interface {
	RunProject(ctx context.Context, req sandbox.ProjectRequest) (sandbox.ProjectResult, error)
}

// Run runs every case against sb, each in a call of its own. timeout is the budget of
// the cases that hang a step; it must leave room for the provider to start a sandbox
// and run a quick step (8 s on docker, more on a microVM provider that boots one).
func Run(t *testing.T, sb Projects, timeout time.Duration) {
	t.Helper()
	run := func(t *testing.T, req sandbox.ProjectRequest) sandbox.ProjectResult {
		t.Helper()
		if req.Timeout == 0 {
			req.Timeout = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), req.Timeout+2*time.Minute)
		defer cancel()
		res, err := sb.RunProject(ctx, req)
		if err != nil {
			t.Fatalf("RunProject: %v", err)
		}
		return res
	}
	artifact := func(res sandbox.ProjectResult, path string) (string, bool) {
		for _, a := range res.Artifacts {
			if a.Path == path {
				return string(a.Content), true
			}
		}
		return "", false
	}

	t.Run("files are written and steps run in the work directory", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Files: []sandbox.File{{Path: "dir/a.txt", Content: "hi"}}, Steps: []string{"cat dir/a.txt"}})
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].Stdout != "hi" || res.Steps[0].ExitCode != 0 {
			t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
		}
	})
	t.Run("steps stop at the first failure", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"echo a; exit 3", "echo never"}})
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 3 || res.Steps[0].Stdout != "a\n" {
			t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
		}
	})
	t.Run("a step that hangs late keeps the earlier steps, its own output and the artifacts", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"echo one; echo kept > b.txt", "echo two; sleep 600"}, Artifacts: []string{"b.txt"}, Timeout: timeout})
		if res.Outcome != sandbox.ProjectOutcomeTimedOut || len(res.Steps) != 2 || res.Steps[0].Stdout != "one\n" {
			t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
		}
		if s := res.Steps[1]; !s.TimedOut || s.ExitCode != 124 || s.Stdout != "two\n" {
			t.Fatalf("the hung step: exit %d, timed out %v, stdout %q (what it wrote before the deadline is kept)", s.ExitCode, s.TimedOut, s.Stdout)
		}
		if got, ok := artifact(res, "b.txt"); !ok || got != "kept\n" {
			t.Fatalf("the artifact written before the hang: %q, %v", got, ok)
		}
	})
	t.Run("artifacts come back after a failed step", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"echo x > a.txt; exit 1"}, Artifacts: []string{"a.txt", "missing.txt"}})
		if got, ok := artifact(res, "a.txt"); !ok || got != "x\n" || len(res.Artifacts) != 1 || res.ArtifactsTruncated {
			t.Fatalf("artifacts %+v, truncated %v", res.Artifacts, res.ArtifactsTruncated)
		}
	})
	t.Run("artifacts past the total cap are marked cut, not an error", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"echo s > small.txt; yes x | tr -d '\\n' | head -c 9437184 > big.bin"}, Artifacts: []string{"small.txt", "big.bin"}})
		if got, ok := artifact(res, "small.txt"); !ok || got != "s\n" || !res.ArtifactsTruncated {
			t.Fatalf("artifacts %d, truncated %v", len(res.Artifacts), res.ArtifactsTruncated)
		}
		if _, ok := artifact(res, "big.bin"); ok {
			t.Fatal("an artifact past the cap came back")
		}
	})
	t.Run("a link out of the work directory is skipped, one inside is followed", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"ln -s /etc/hostname out.txt; echo inner > in.txt; ln -s in.txt rel.txt"}, Artifacts: []string{"out.txt", "rel.txt"}})
		if _, ok := artifact(res, "out.txt"); ok {
			t.Fatal("a link out of the work directory was followed")
		}
		if got, ok := artifact(res, "rel.txt"); !ok || got != "inner\n" {
			t.Fatalf("a link inside the work directory: %q, %v", got, ok)
		}
	})
	t.Run("a link to a name ending in a newline reads that file, not its sibling", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{`printf 'sibling\n' > a; f=$(printf 'a\nx'); f=${f%x}; printf 'newline\n' > "$f"; ln -s "$f" nl.txt`}, Artifacts: []string{"nl.txt"}})
		if got, ok := artifact(res, "nl.txt"); !ok || got != "newline\n" {
			t.Fatalf("the link's target: %q, %v", got, ok)
		}
	})
	t.Run("output past the cap is cut and the step runs on to its own exit", func(t *testing.T) {
		for _, c := range []struct{ step, other string }{
			{"yes x | tr -d '\\n' | head -c 2097152; echo other >&2; exit 7", "stdout"},
			{"yes x | tr -d '\\n' | head -c 2097152 >&2; echo other; exit 7", "stderr"},
		} {
			res := run(t, sandbox.ProjectRequest{Steps: []string{c.step}})
			if len(res.Steps) != 1 {
				t.Fatalf("steps %+v", res.Steps)
			}
			s := res.Steps[0]
			cut, cutFlag, other, otherFlag := s.Stdout, s.StdoutTruncated, s.Stderr, s.StderrTruncated
			if c.other == "stderr" {
				cut, cutFlag, other, otherFlag = s.Stderr, s.StderrTruncated, s.Stdout, s.StdoutTruncated
			}
			if !cutFlag || len(cut) != StepOutputCap || strings.Trim(cut, "x") != "" {
				t.Fatalf("%s: kept %d bytes, cut %v; want %d bytes of x, cut", c.other, len(cut), cutFlag, StepOutputCap)
			}
			if other != "other\n" || otherFlag || s.ExitCode != 7 || s.TimedOut || res.Outcome != sandbox.ProjectOutcomeCompleted {
				t.Fatalf("%s past the cap: the other stream %q (cut %v), exit %d, outcome %s; want it whole, the step's own exit 7 and a completed run", c.other, other, otherFlag, s.ExitCode, res.Outcome)
			}
		}
	})
	t.Run("a flood past the transfer budget ends the step as flooded", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"yes x | tr -d '\\n' | head -c 41943040; echo after"}})
		if len(res.Steps) != 1 {
			t.Fatalf("steps %+v", res.Steps)
		}
		if s := res.Steps[0]; s.ExitCode != FloodExit || !s.StdoutTruncated || !s.StderrTruncated || s.TimedOut || res.Outcome != sandbox.ProjectOutcomeCompleted {
			t.Fatalf("40 MiB of output: exit %d, cut %v and %v, outcome %s; want %d with both streams cut and a completed run", s.ExitCode, s.StdoutTruncated, s.StderrTruncated, res.Outcome, FloodExit)
		}
	})
	t.Run("a step that kills its own shell reports 128 plus the signal", func(t *testing.T) {
		res := run(t, sandbox.ProjectRequest{Steps: []string{"kill -9 $$"}})
		if len(res.Steps) != 1 || res.Steps[0].ExitCode != 137 || res.Steps[0].TimedOut || res.Outcome != sandbox.ProjectOutcomeCompleted {
			t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
		}
	})
	t.Run("an artifact at a fifo is skipped and the run completes at once", func(t *testing.T) {
		// sessiontest holds sessions to this; one-shot runs read their artifacts through a
		// different path on the exec-based providers (review, 2026-10-26).
		start := time.Now()
		res := run(t, sandbox.ProjectRequest{Steps: []string{"mkfifo out.txt"}, Artifacts: []string{"out.txt"}})
		if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Artifacts) != 0 || time.Since(start) > 40*time.Second {
			t.Fatalf("an artifact at a fifo: %s %q, %d artifacts after %v; want a completed run without it, at once", res.Outcome, res.Detail, len(res.Artifacts), time.Since(start))
		}
	})
}
