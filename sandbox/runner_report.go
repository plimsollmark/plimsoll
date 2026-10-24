package sandbox

import (
	"errors"

	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// RunnerReport reads the project runner's authenticated report out of its stdout and
// returns the project result it states: what every provider that runs /runner.mjs with a
// runnerwire plan does once the runner has exited. reported is false when stdout holds no
// report at all: the runner never reported, and only the provider can say why (the docker
// provider reads its start marker), in its own words and never the runner's stderr. A
// report that does not authenticate under key, or does not parse, is a protocol error and
// never a result, since every process in the sandbox can write the runner's stdout.
func RunnerReport(provider string, isolation IsolationClass, stdout string, key []byte) (res ProjectResult, reported bool) {
	res = ProjectResult{Sandbox: provider, Isolation: isolation}
	report, found, err := runnerwire.Parse(stdout, key)
	switch {
	case !found:
		return res, false
	case errors.Is(err, runnerwire.ErrUnauthenticated):
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "no authenticated runner report"
		return res, true
	case err != nil:
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "could not parse sandbox result"
		return res, true
	}
	for _, s := range report.Steps {
		res.Steps = append(res.Steps, StepResult(s))
	}
	for _, a := range report.Artifacts {
		res.Artifacts = append(res.Artifacts, Artifact(a))
	}
	res.ArtifactsTruncated = report.ArtifactsTruncated
	// A runner-reported failure before any step (illegal file path, unwritable file)
	// is request-attributable: setup_failed. One after a step began is runner_failed:
	// the caller's code ran. A step killed by the run's time budget is a timed-out run,
	// not a completed one; RunModule classifies the same event as timed_out, and the two
	// operations must not disagree.
	outcome, detail := report.Outcome()
	res.Outcome, res.Detail = ProjectOutcomeCompleted, detail
	switch outcome {
	case runnerwire.SetupFailed:
		res.Outcome = ProjectOutcomeSetupFailed
	case runnerwire.RunnerFailed:
		res.Outcome = ProjectOutcomeRunnerFailed
	case runnerwire.TimedOut:
		res.Outcome = ProjectOutcomeTimedOut
	}
	return res, true
}
