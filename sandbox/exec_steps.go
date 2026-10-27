package sandbox

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
)

// The project contract of the providers that run each step through their platform's own
// exec (E2B one-shot, E2B sessions, Docker Cloud), written once. The in-sandbox runner
// (docker, OpenShell, agentsandbox) keeps the same contract in docker/runner.mjs, and
// projecttest holds every provider to it: the three exec paths once kept a loop each,
// and they and the runner disagreed on artifacts after a timeout, an artifact over the
// cap, links among the artifacts, the per-step output cap and a step that killed its own
// shell (review D2, 2026-10-23).

// projectArtifactGrace is how long after a run's deadline an exec-based provider still
// reads the run's artifacts, so a run whose last step timed out returns what it wrote,
// as the runner does within the five seconds docker leaves it. The billing reservation
// counts it (meteredBillingTail).
const projectArtifactGrace = 5 * time.Second

// stepArgv is how an exec-based provider starts a staged step script: under an outer
// shell, so a step that kills its own shell is reported as 128 plus the signal, as the
// runner reports it, instead of whatever the platform says of a process killed by one.
// The trailing exit keeps a shell from replacing itself with the step's.
func stepArgv(script string) []string {
	return []string{"sh", "-c", `sh "$0"; exit $?`, script}
}

// stepOutput is one step's result as an exec-based provider's transport reports it.
type stepOutput struct {
	stdout, stderr                   string
	stdoutTruncated, stderrTruncated bool
	exitCode                         int
	timedOut                         bool // the step's own time limit killed it
}

// runExecSteps runs steps in order through run, all inside ctx's deadline: it stops at
// the first step that fails or times out, and a step ended by the deadline is reported
// timed out (exit 124) with what it wrote before, as the runner reports one, and makes
// the run timed out, the steps before it kept. An error that is not the deadline is the
// transport's, returned with the steps that ran. run returns what the transport had
// captured with its error, so the deadline path keeps it (review, 2026-10-26).
func runExecSteps(ctx context.Context, steps []string, run func(ctx context.Context, i int, step string) (stepOutput, error)) ([]StepResult, ProjectOutcome, string, error) {
	var out []StepResult
	for i, step := range steps {
		start := time.Now()
		o, err := run(ctx, i, step)
		if err != nil {
			if deadline.Expired(ctx) == context.DeadlineExceeded {
				out = append(out, StepResult{
					Command: step, Stdout: o.stdout, Stderr: o.stderr,
					StdoutTruncated: o.stdoutTruncated, StderrTruncated: o.stderrTruncated,
					ExitCode: 124, TimedOut: true, Duration: time.Since(start),
				})
				return out, ProjectOutcomeTimedOut, "run exceeded the time budget", nil
			}
			return out, ProjectOutcomeUnspecified, "", err
		}
		out = append(out, StepResult{
			Command: step, Stdout: o.stdout, Stderr: o.stderr,
			StdoutTruncated: o.stdoutTruncated, StderrTruncated: o.stderrTruncated,
			ExitCode: o.exitCode, TimedOut: o.timedOut, Duration: time.Since(start),
		})
		if o.timedOut {
			return out, ProjectOutcomeTimedOut, "step exceeded the time budget", nil
		}
		if o.exitCode != 0 {
			break
		}
	}
	return out, ProjectOutcomeCompleted, "", nil
}

// artifactScript prints, for each artifact path among its arguments after the work
// directory ($1) that names a regular file whose real path lies inside the work
// directory, the path and that real path, each ended by a NUL: a link out of the work
// directory is skipped, one within it followed, as the runner does. The provider then
// reads the real path, since a platform's file API may not follow a link (Docker Cloud's
// download does not, measured 2026-10-24). A process the run left behind could swap a
// file after this check; what it could then return is a file of the run's own
// disposable sandbox, never one of the host's.
//
// A command substitution strips every trailing newline, so each realpath's answer is
// followed by an x that is then cut off with the one newline realpath adds: a name
// ending in a newline keeps it, and is not read as its sibling without one (review,
// 2026-10-24).
const artifactScript = `d=$(realpath "$1" && printf x) || exit 0; d=${d%x}; d=${d%?}; shift
for p; do r=$(realpath "$d/$p" 2>/dev/null && printf x) || continue; r=${r%x}; r=${r%?}; case "$r" in "$d"/*) [ -f "$r" ] && printf '%s\000%s\000' "$p" "$r";; esac; done
exit 0`

// artifactFile is one artifact artifactScript selected: the path requested and the
// absolute real path to read.
type artifactFile struct{ path, real string }

// selectorAnswer believes artifactScript's answer only if the script finished: it
// always exits 0 and prints well under its output cap, so another exit or a cut answer
// means it did not, and pairs past the cut would be missing with nothing to say so
// (review, 2026-10-24). The error makes the run runner_failed (setArtifacts).
func selectorAnswer(stdout string, exitCode int, cut bool, requested []string) ([]artifactFile, error) {
	if exitCode != 0 || cut {
		return nil, fmt.Errorf("the artifact selection did not finish (exit %d, output cut %v)", exitCode, cut)
	}
	return selectedArtifacts(stdout, requested), nil
}

// selectedArtifacts reads artifactScript's answer, keeping only whole pairs (a cut
// answer's last is not) whose path was requested and whose real path is absolute; NUL
// ends each field, and no path holds one.
func selectedArtifacts(stdout string, requested []string) []artifactFile {
	fields := strings.Split(stdout, "\x00")
	var out []artifactFile
	for i := 0; i+2 < len(fields); i += 2 {
		if slices.Contains(requested, fields[i]) && strings.HasPrefix(fields[i+1], "/") {
			out = append(out, artifactFile{path: fields[i], real: fields[i+1]})
		}
	}
	return out
}

// setArtifacts puts what reading a run's artifacts gave into res. A read that failed
// after the steps began is the runner's failure, as the runner reports it: runner_failed,
// the steps kept, since the caller's code ran. A run that already timed out stays timed
// out, its artifacts missing, which that outcome allows. The error is logged, never
// returned to the caller, whose answer names a fixed detail.
func setArtifacts(res *ProjectResult, arts []Artifact, truncated bool, err error) {
	if err != nil {
		slog.Error(res.Sandbox+": could not read a project's artifacts", "error", err)
		if res.Outcome != ProjectOutcomeTimedOut {
			res.Outcome, res.Detail = ProjectOutcomeRunnerFailed, "could not read the artifacts"
		}
		return
	}
	res.Artifacts, res.ArtifactsTruncated = arts, truncated
}

// collectArtifacts returns the selected artifacts, read with read, in the order
// requested, at most maxArtifactBytesTotal in all: the first that would pass the total
// stops the collection and marks it truncated, as the runner does. read returns at
// most limit+1 bytes, so a file past the total is known without reading all of it.
func collectArtifacts(ctx context.Context, files []artifactFile,
	read func(ctx context.Context, path string, limit int64) ([]byte, bool, error)) ([]Artifact, bool, error) {
	var out []Artifact
	var total int64
	for _, f := range files {
		data, found, err := read(ctx, f.real, maxArtifactBytesTotal-total)
		if err != nil {
			return out, false, err
		}
		if !found {
			continue
		}
		if total+int64(len(data)) > maxArtifactBytesTotal {
			return out, true, nil
		}
		total += int64(len(data))
		out = append(out, Artifact{Path: f.path, Content: data})
	}
	return out, false, nil
}

// artifactDeadline is when reading a run's artifacts must end: projectArtifactGrace after
// the later of the run's deadline and now. A run's steps end by its deadline, but what
// comes between them and the artifacts (ending a session's grant can wait on a network
// update) must not eat the artifacts' time (review, 2026-10-24).
func artifactDeadline(runDeadline time.Time) time.Time {
	if now := time.Now(); now.After(runDeadline) {
		runDeadline = now
	}
	return runDeadline.Add(projectArtifactGrace)
}
