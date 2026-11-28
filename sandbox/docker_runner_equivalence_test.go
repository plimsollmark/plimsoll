package sandbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// The runner equivalence suite: everything a caller or a step can observe of the
// project runner. It was written against the Node runner (docker/runner.mjs) and held the
// native helper (sandbox/internal/nativehelper, plimsoll-helper run-project) to the same
// results, case by case, under runc and gVisor, before the helper replaced it in every
// image (2026-11-21); the Node runner is gone, and the suite now holds the runner the
// images ship to those results. Where the helper differs from the Node runner on purpose,
// the case says so with "DIFFERS ON PURPOSE" in its log, naming what the Node runner did
// (the accepted differences, listed on the status page).
//
// It drives the runner through one seam, dockerProjectRunner, the command plimsoll starts
// as the runner (nativehelper.RunProject), in a run, a granted run and a session call
// alike. One test-only setting, read here (init, before any test runs) and nowhere in the
// daemon, changes it for every docker test in this package's test binary, so the whole
// docker suite, not only this file, can run against another build of the helper:
//
//	PLIMSOLL_TEST_NATIVE_HELPER_FILE=/abs/path  that file, bind-mounted read-only over the
//	                                            image's runner in every container, and its
//	                                            SHA-256 the one the startup test requires
//	                                            (a broken build shows a case catches it)
//
// Two levels. The provider cases go through RunProject, so they see what a caller sees
// (the outcome, its detail, every step's fields, the artifacts), in a fresh run and in a
// session. The plan cases (eqRunPlan) start the runner exactly as a run does but feed it
// a plan the host would never send (no key, a path that climbs out, a command past its
// cut, a report past its budget), and read its stdout byte for byte.
//
// Cases that exist elsewhere are not repeated here; the status page's table cites them
// (projecttest, sessiontest, runner_integrity_test.go, docker_guard_test.go).

// The build under test: the image's own runner, or the file PLIMSOLL_TEST_NATIVE_HELPER_FILE
// names, handed to every container in its place.
func init() {
	f := os.Getenv("PLIMSOLL_TEST_NATIVE_HELPER_FILE")
	if f == "" {
		return
	}
	abs, err := filepath.Abs(f)
	var b []byte
	if err == nil {
		b, err = os.ReadFile(abs)
	}
	if err != nil {
		panic(fmt.Sprintf("PLIMSOLL_TEST_NATIVE_HELPER_FILE: %v", err))
	}
	sum := sha256.Sum256(b)
	// The build's own identity line, which the startup check requires in place of the pin's:
	// the helper is a static x86-64 program, so it runs here as it runs in a container.
	id, err := exec.Command(abs, "identity").Output()
	if err != nil {
		panic(fmt.Sprintf("PLIMSOLL_TEST_NATIVE_HELPER_FILE: its identity command: %v (a build from before the command cannot be handed in)", err))
	}
	dockerNativeHelperFile = abs
	dockerNativeHelperWant = nativehelper.Want{SHA256: hex.EncodeToString(sum[:]), Identity: strings.TrimSuffix(string(id), "\n")}
}

// eqDocker is the docker provider the suite runs, with its runner's command wrapped in
// wrap when wrap is not empty (a shell that changes what the runner starts with, then
// execs it): the one use of the per-instance seam, DockerSandbox.projectRunner.
func eqDocker(t *testing.T, wrap ...string) *DockerSandbox {
	t.Helper()
	d := testDocker()
	requireProjectImage(t, d)
	if len(wrap) > 0 {
		d.projectRunner = append(slices.Clone(wrap), d.runnerCommand()...)
	}
	return d
}

// eqState is the execution state a run of d gets (the verified image, its environment,
// the runtime), from the same admission a run passes.
func eqState(t *testing.T, d *DockerSandbox) dockerExecutionState {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	state, _, err := d.admit(ctx, dockerProject, IsolationUnknown, SoftwareRule{})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	return state
}

// eqDiffers logs a case's intended difference: what the Node runner did and what the
// native runner does instead, so the difference is a decision on the page.
func eqDiffers(t *testing.T, node, native string) {
	t.Helper()
	t.Logf("DIFFERS ON PURPOSE: the Node runner %s; the native runner %s", node, native)
}

// eqProjects is what a provider case runs against: a fresh run or a session's calls.
type eqProjects interface {
	RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error)
}

func eqRun(t *testing.T, p eqProjects, req ProjectRequest) ProjectResult {
	t.Helper()
	if req.Timeout == 0 {
		req.Timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout+2*time.Minute)
	defer cancel()
	res, err := p.RunProject(ctx, req)
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	return res
}

func eqArtifact(res ProjectResult, path string) ([]byte, bool) {
	for _, a := range res.Artifacts {
		if a.Path == path {
			return a.Content, true
		}
	}
	return nil, false
}

// eqFill is a step fragment that writes n bytes of the letter c to stdout.
func eqFill(c byte, n int) string {
	return fmt.Sprintf("yes %c | tr -d '\\n' | head -c %d", c, n)
}

// TestDockerRunnerEquivalence runs every provider case in a fresh run each, then the
// ones that mean something in a session in one session's calls, then the plan cases.
func TestDockerRunnerEquivalence(t *testing.T) {
	t.Parallel()
	d := eqDocker(t)
	t.Run("run", func(t *testing.T) {
		for _, c := range eqProviderCases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				c.run(t, d, d, false)
			})
		}
	})
	t.Run("session", func(t *testing.T) {
		t.Parallel()
		heavyDockerTest(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		s, err := d.OpenSession(ctx, SessionOptions{Lifetime: 10 * time.Minute, DiskBytes: 96 << 20})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		t.Cleanup(func() { _ = s.Close(context.Background()) })
		for _, c := range eqProviderCases {
			if !c.session {
				continue
			}
			t.Run(c.name, func(t *testing.T) { c.run(t, d, s, true) })
		}
		t.Run("a file written over a link or a fifo an earlier call left is refused", func(t *testing.T) {
			eqFileOverLink(t, s)
		})
	})
	t.Run("plan", func(t *testing.T) {
		for _, c := range eqPlanCases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				c.run(t, d)
			})
		}
	})
}

type eqProviderCase struct {
	name    string
	session bool // also run in a session's calls
	run     func(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool)
}

var eqProviderCases = []eqProviderCase{
	{"every field of a plain run", true, eqPlainRun},
	{"output at the per-stream cap and one byte either side", false, eqStreamCapEdges},
	{"the encoded budget across steps cuts a later step's output", false, eqStepsBudget},
	{"a flood shared across both streams ends the step as flooded", false, eqSharedFlood},
	{"a flood from a background program after its shell exits 0 ends the plan", true, eqBackgroundFloodStops},
	{"one deadline is shared by every step", true, eqSharedDeadline},
	{"a background program holding the output is timed out at the deadline", true, eqHeldOutputTimesOut},
	{"a background program holding the output is waited for until it ends", true, eqHeldOutputWaited},
	{"a step that closes its output and runs on is waited for until it exits", true, eqClosedOutputWaited},
	{"a step's children outlive the step and are not killed by the runner", true, eqChildrenOutliveStep},
	{"what a step's standard descriptors are", true, eqStepDescriptors},
	{"the environment a step starts with, in order", true, eqStepEnvironment},
	{"the signals a step starts with", true, eqStepSignals},
	{"signals ignored above the runner, as a step sees them", false, eqStepSignalsInherited},
	{"signals blocked above the runner are not blocked in a step", false, eqStepMaskInherited},
	{"a setup failure reports the error's own text", true, eqSetupFailureText},
	{"artifacts at the 8 MiB edge", false, eqArtifactEdges},
	{"a directory at an artifact path is skipped", true, eqArtifactDirectory},
	{"a parent directory swapped for a link while artifacts are read", false, eqArtifactParentSwap},
	{"an artifact that grows while it is read", false, eqArtifactGrows},
	{"the files the runner writes and the folder a step runs in", true, eqWrittenFiles},
	{"the same, with the runner started elsewhere and under umask 0", false, eqWrittenFilesOtherStart},
	{"signals a step sends the runner do not end it", true, eqSignalsToRunner},
	{"a step whose shell a signal ends reports 128 plus the signal", true, eqStepEndedBySignal},
	{"the runner as a step sees it", true, eqRunnerAsSeen},
	{"the runner refuses to run where a step could open its descriptors", false, eqRunnerRefusesDumpable},
}

func eqPlainRun(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{
		Files:     []File{{Path: "plain/a.txt", Content: "hi"}, {Path: "plain/b.txt", Content: "bee\n"}},
		Steps:     []string{"cat plain/a.txt; printf err >&2", "cat plain/b.txt"},
		Artifacts: []string{"plain/b.txt", "plain/missing", "plain/a.txt"},
	})
	if res.Outcome != ProjectOutcomeCompleted || res.Detail != "" || len(res.Steps) != 2 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	want := []StepResult{
		{Command: "cat plain/a.txt; printf err >&2", Stdout: "hi", Stderr: "err"},
		{Command: "cat plain/b.txt", Stdout: "bee\n"},
	}
	for i, s := range res.Steps {
		s.Duration = 0
		if s != want[i] {
			t.Fatalf("step %d: %+v, want %+v", i+1, s, want[i])
		}
	}
	// In the request's order, a missing one left out, nothing cut.
	if len(res.Artifacts) != 2 || res.Artifacts[0].Path != "plain/b.txt" || string(res.Artifacts[0].Content) != "bee\n" ||
		res.Artifacts[1].Path != "plain/a.txt" || string(res.Artifacts[1].Content) != "hi" || res.ArtifactsTruncated {
		t.Fatalf("artifacts %+v, truncated %v", res.Artifacts, res.ArtifactsTruncated)
	}
}

func eqStreamCapEdges(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	const cap = ProjectStepOutputCap
	for _, n := range []int{cap - 1, cap, cap + 1} {
		res := eqRun(t, p, ProjectRequest{Steps: []string{eqFill('o', n) + "; " + eqFill('e', n) + " >&2"}})
		if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
			t.Fatalf("%d bytes: %s %q, steps %d", n, res.Outcome, res.Detail, len(res.Steps))
		}
		s := res.Steps[0]
		kept := min(n, cap)
		if len(s.Stdout) != kept || strings.Trim(s.Stdout, "o") != "" || s.StdoutTruncated != (n > cap) ||
			len(s.Stderr) != kept || strings.Trim(s.Stderr, "e") != "" || s.StderrTruncated != (n > cap) ||
			s.ExitCode != 0 || s.TimedOut {
			t.Fatalf("%d bytes on each stream: kept %d and %d, cut %v and %v, exit %d; want %d kept each, cut %v", n,
				len(s.Stdout), len(s.Stderr), s.StdoutTruncated, s.StderrTruncated, s.ExitCode, kept, n > cap)
		}
	}
}

// eqStepJSON is one step as the runner encodes it, field for field in its order.
type eqStepJSON struct {
	Command         string `json:"command"`
	StdoutBase64    string `json:"stdoutBase64"`
	StderrBase64    string `json:"stderrBase64"`
	StdoutTruncated bool   `json:"stdoutTruncated"`
	StderrTruncated bool   `json:"stderrTruncated"`
	ExitCode        int    `json:"exitCode"`
	TimedOut        bool   `json:"timedOut"`
	DurationMs      int64  `json:"durationMs"`
}

// eqEncodedSteps is len(JSON.stringify({steps})) for ASCII commands.
func eqEncodedSteps(t *testing.T, steps []eqStepJSON) int {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		Steps []eqStepJSON `json:"steps"`
	}{steps}); err != nil {
		t.Fatal(err)
	}
	return b.Len() - 1 // the encoder's newline
}

// eqStepsBudget: the runner keeps every step's encoded output within 3 MiB together
// (MAX_STEPS_JSON), counted on its own JSON encoding, and fits a step that would pass
// it by keeping as many whole base64 groups of its stdout, then its stderr, as fit.
// Two steps of 1 MiB per stream already pass it (review finding rust-native-helper-5). The expected cut
// is computed here the way the runner computes it, from the durations it reported.
func eqStepsBudget(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	// The cut keeps whole groups of 3 bytes: the room left is a number of base64
	// characters, and the case pads the second step's command by 0 to 3 characters so
	// that room comes in every remainder of 4 across the four runs (a cut that kept a
	// part of a group differs only when the remainder is 2 or 3).
	for pad := range 4 {
		eqStepsBudgetOnce(t, p, strings.Repeat(" ", pad))
	}
}

func eqStepsBudgetOnce(t *testing.T, p eqProjects, pad string) {
	t.Helper()
	const mib = 1 << 20
	const budget = 3 << 20
	type spec struct {
		cmd      string
		out, err int // bytes written to each stream, of 'o' and 'e'
	}
	specs := []spec{
		{eqFill('o', mib) + "; " + eqFill('e', mib) + " >&2", mib, mib},
		{eqFill('o', mib) + "; " + eqFill('e', mib) + " >&2; true" + pad, mib, mib},
		{"echo three; echo three >&2", 6, 6},
	}
	req := ProjectRequest{}
	for _, s := range specs {
		req.Steps = append(req.Steps, s.cmd)
	}
	res := eqRun(t, p, req)
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != len(specs) {
		t.Fatalf("%s %q, %d steps", res.Outcome, res.Detail, len(res.Steps))
	}
	var done []eqStepJSON
	for i, sp := range specs {
		rawOut := strings.Repeat("o", sp.out)
		rawErr := strings.Repeat("e", sp.err)
		if i == 2 {
			rawOut, rawErr = "three\n", "three\n"
		}
		got := res.Steps[i]
		step := eqStepJSON{Command: sp.cmd, StdoutBase64: base64.StdEncoding.EncodeToString([]byte(rawOut)),
			StderrBase64: base64.StdEncoding.EncodeToString([]byte(rawErr)), DurationMs: got.Duration.Milliseconds()}
		wantOut, wantErr, cutOut, cutErr := rawOut, rawErr, false, false
		if eqEncodedSteps(t, append(slices.Clone(done), step)) > budget {
			step.StdoutBase64, step.StderrBase64 = "", ""
			size := eqEncodedSteps(t, append(slices.Clone(done), step))
			keep := func(raw string) (string, bool) {
				n := min(len(raw), max(0, budget-size)/4*3)
				size += len(base64.StdEncoding.EncodeToString([]byte(raw[:n])))
				return raw[:n], n < len(raw)
			}
			wantOut, cutOut = keep(rawOut)
			wantErr, cutErr = keep(rawErr)
		}
		if got.Stdout != wantOut || got.Stderr != wantErr || got.StdoutTruncated != cutOut || got.StderrTruncated != cutErr || got.ExitCode != 0 {
			t.Fatalf("step %d: kept %d and %d bytes, cut %v and %v, exit %d; the runner's budget gives %d and %d, cut %v and %v",
				i+1, len(got.Stdout), len(got.Stderr), got.StdoutTruncated, got.StderrTruncated, got.ExitCode, len(wantOut), len(wantErr), cutOut, cutErr)
		}
		t.Logf("pad %d, step %d: kept %d and %d bytes (cut %v, %v)", len(pad), i+1, len(got.Stdout), len(got.Stderr), cutOut, cutErr)
		step.StdoutBase64 = base64.StdEncoding.EncodeToString([]byte(got.Stdout))
		step.StderrBase64 = base64.StdEncoding.EncodeToString([]byte(got.Stderr))
		step.StdoutTruncated, step.StderrTruncated = cutOut, cutErr
		done = append(done, step)
	}
	if !res.Steps[1].StdoutTruncated {
		t.Fatal("the second step of 1 MiB per stream was not cut: the case did not reach the budget")
	}
}

// eqSharedFlood: the 32 MiB transfer budget is one budget for both streams (Node's
// spawnSync maxBuffer), so 17 MiB on each passes it although neither stream does.
func eqSharedFlood(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	const n = 17 << 20
	res := eqRun(t, p, ProjectRequest{Steps: []string{eqFill('o', n) + "; " + eqFill('e', n) + " >&2; echo after"}})
	if len(res.Steps) != 1 {
		t.Fatalf("steps %+v", res.Steps)
	}
	s := res.Steps[0]
	if s.ExitCode != 153 || !s.StdoutTruncated || !s.StderrTruncated || s.TimedOut || res.Outcome != ProjectOutcomeCompleted ||
		len(s.Stdout) != ProjectStepOutputCap || strings.Trim(s.Stdout, "o") != "" || len(s.Stderr) != ProjectStepOutputCap || strings.Trim(s.Stderr, "e") != "" {
		t.Fatalf("17 MiB on each stream: exit %d, cut %v and %v, kept %d and %d, outcome %s; want 153, both cut at 1 MiB, completed",
			s.ExitCode, s.StdoutTruncated, s.StderrTruncated, len(s.Stdout), len(s.Stderr), res.Outcome)
	}
}

// eqBackgroundFloodStops: a step whose shell exits 0 while a program it left in the
// background floods the output is reported flooded (153, both streams cut) and ends the
// plan, as any step whose exit is not 0 does on every exec-based provider. The runner once
// read the reaped shell's 0 and ran the next step (finding release-97, 2026-11-21).
func eqBackgroundFloodStops(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	marker := "release97-run"
	if inSession {
		marker = "release97-session"
	}
	res := eqRun(t, p, ProjectRequest{
		Steps:     []string{"(sleep 0.3; head -c 40000000 /dev/zero) & exit 0", "echo second > " + marker},
		Artifacts: []string{marker},
	})
	if len(res.Steps) == 0 {
		t.Fatalf("%s %q, no steps", res.Outcome, res.Detail)
	}
	if s := res.Steps[0]; s.ExitCode != 153 || !s.StdoutTruncated || !s.StderrTruncated || s.TimedOut {
		t.Fatalf("the first step: exit %d, cut %v and %v, timed out %v; want 153, both cut", s.ExitCode, s.StdoutTruncated, s.StderrTruncated, s.TimedOut)
	}
	if _, ran := eqArtifact(res, marker); len(res.Steps) != 1 || ran {
		t.Fatalf("%d steps, marker written %v: the step after the flooded one ran", len(res.Steps), ran)
	}
	if res.Outcome != ProjectOutcomeCompleted || res.Detail != "" {
		t.Fatalf("%s %q, want completed", res.Outcome, res.Detail)
	}
}

func eqSharedDeadline(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{"sleep 1.5; echo one", "echo two; sleep 1.5; echo never", "echo three"}, Timeout: 2500 * time.Millisecond})
	if res.Outcome != ProjectOutcomeTimedOut || res.Detail != "step 2 exceeded the run's time budget" || len(res.Steps) != 2 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	one, two := res.Steps[0], res.Steps[1]
	if one.Stdout != "one\n" || one.ExitCode != 0 || one.TimedOut {
		t.Fatalf("the first step: %+v", one)
	}
	// Two gets what is left of the run's 2.5 s, about 1 s, not a budget of its own.
	if two.Stdout != "two\n" || two.ExitCode != 124 || !two.TimedOut || two.StdoutTruncated || two.Duration >= 1400*time.Millisecond {
		t.Fatalf("the second step: %+v; want exit 124, timed out, its output kept, after what was left of the budget", two)
	}
}

// eqHeldOutputTimesOut: the runner waits for a step's output to close, not only for its
// shell to exit, so a background program holding it makes the step time out at the
// deadline and the plan stop there (review finding rust-native-helper-3).
func eqHeldOutputTimesOut(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{"sleep 4 & echo bg", "echo second"}, Timeout: 1500 * time.Millisecond})
	if res.Outcome != ProjectOutcomeTimedOut || len(res.Steps) != 1 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	if s := res.Steps[0]; s.ExitCode != 124 || !s.TimedOut || s.Stdout != "bg\n" || s.Duration < 1400*time.Millisecond {
		t.Fatalf("the step whose background program held its output: %+v; want exit 124, timed out at the deadline, its output kept", s)
	}
}

func eqHeldOutputWaited(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{"sleep 1 & echo bg", "echo second"}, Timeout: 8 * time.Second})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 2 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	if s := res.Steps[0]; s.ExitCode != 0 || s.TimedOut || s.Stdout != "bg\n" || s.Duration < 950*time.Millisecond {
		t.Fatalf("the first step: %+v; want exit 0 after its background program closed the output (about 1 s)", s)
	}
	if res.Steps[1].Stdout != "second\n" {
		t.Fatalf("the second step: %+v", res.Steps[1])
	}
}

// eqClosedOutputWaited: a step whose shell closes its output and error and then runs on
// is waited for until the shell exits, not ended when the output closes: the runner waits
// for the exit and for both streams, and the deadline still holds once both are closed (the
// native runner's deletion run found no case that reached either: no-sigchld-handler and
// end-at-output-close).
func eqClosedOutputWaited(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{"echo before; exec >&- 2>&-; sleep 1; exit 3", "echo never"}, Timeout: 10 * time.Second})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	if s := res.Steps[0]; s.Stdout != "before\n" || s.ExitCode != 3 || s.TimedOut || s.Duration < 900*time.Millisecond || s.Duration > 8*time.Second {
		t.Fatalf("the step that closed its output and ran on: %+v; want its own exit 3 after about a second", s)
	}
	// And the deadline still holds once the output is closed: the shell is killed there.
	start := time.Now()
	res = eqRun(t, p, ProjectRequest{Steps: []string{"exec >&- 2>&-; sleep 20", "echo never"}, Timeout: 1500 * time.Millisecond})
	if res.Outcome != ProjectOutcomeTimedOut || len(res.Steps) != 1 || time.Since(start) > 15*time.Second {
		t.Fatalf("%s %q, steps %+v after %v", res.Outcome, res.Detail, res.Steps, time.Since(start))
	}
	if s := res.Steps[0]; s.ExitCode != 124 || !s.TimedOut || s.Duration > 5*time.Second {
		t.Fatalf("the step that closed its output and ran past the deadline: %+v; want exit 124, timed out at the deadline", s)
	}
}

func eqChildrenOutliveStep(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	count := `for p in /proc/[0-9]*; do tr '\0' ' ' < $p/cmdline 2>/dev/null; echo; done | grep -c '^sleep 7 $'`
	res := eqRun(t, p, ProjectRequest{Steps: []string{"(sleep 7 >/dev/null 2>&1 </dev/null &); echo started", count}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 2 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	if s := res.Steps[0]; s.ExitCode != 0 || s.Stdout != "started\n" || s.Duration > 900*time.Millisecond {
		t.Fatalf("the step that left a child holding nothing: %+v; want it done at once", s)
	}
	if got := res.Steps[1].Stdout; got != "1\n" {
		t.Fatalf("the next step counted %q children of the first still running, want 1", got)
	}
}

// eqStepDescriptors: under the Node runner a step's standard input, output and error were Unix sockets
// (Node's spawnSync default), so a step that opened /dev/stdout failed (review finding rust-native-helper-2,
// a shipped defect). The native runner gives pipes and an empty input, and that step works.
func eqStepDescriptors(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	kinds := `for n in 0 1 2; do readlink /proc/$$/fd/$n | sed 's/:.*//'; done | tr '\n' ' '; echo`
	res := eqRun(t, p, ProjectRequest{Steps: []string{
		kinds,
		`cat; echo "stdin rc=$?"`,
		`echo hi > /dev/stdout; echo "rc=$?"`,
	}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 3 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	if got := res.Steps[1]; got.Stdout != "stdin rc=0\n" || got.Stderr != "" {
		t.Fatalf("reading the step's input: %+v; want end of input at once", got)
	}
	got, dev := res.Steps[0].Stdout, res.Steps[2]
	eqDiffers(t, "gave socket socket socket, and > /dev/stdout failed", "gives /dev/null for input and pipes for output, and > /dev/stdout works")
	if got != "/dev/null pipe pipe \n" || dev.Stdout != "hi\nrc=0\n" || dev.Stderr != "" {
		t.Fatalf("descriptors %q, /dev/stdout step %+v", got, dev)
	}
}

// eqStepEnvironment: a step starts with the runner's own environment in its order
// (PATH, HOME, HOSTNAME from the start script; the guard's LD_PRELOAD removed), the
// plan's entries over it (a name already there keeps its place, a new one goes last),
// then PLIMSOLL_RUNNER_PID (review finding rust-native-helper-4: a native runner must keep this order, not
// sort it).
func eqStepEnvironment(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	state := eqState(t, d)
	res := eqRun(t, p, ProjectRequest{Steps: []string{`tr '\0' '\n' < /proc/$$/environ; echo ---; cat /etc/hostname`}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	env, host, ok := strings.Cut(res.Steps[0].Stdout, "---\n")
	if !ok {
		t.Fatalf("stdout %q", res.Steps[0].Stdout)
	}
	type kv struct{ k, v string }
	want := []kv{{"PATH", sessionkit.ControlPath}, {"HOME", "/"}, {"HOSTNAME", strings.TrimSpace(host)}}
	for _, e := range state.guestEnv(state.projectImageID) {
		k, v, _ := strings.Cut(e, "=")
		if i := slices.IndexFunc(want, func(w kv) bool { return w.k == k }); i >= 0 {
			want[i].v = v
		} else {
			want = append(want, kv{k, v})
		}
	}
	lines := strings.Split(strings.TrimSuffix(env, "\n"), "\n")
	var got []kv
	for _, l := range lines {
		k, v, _ := strings.Cut(l, "=")
		got = append(got, kv{k, v})
	}
	if len(got) != len(want)+1 || got[len(got)-1].k != "PLIMSOLL_RUNNER_PID" {
		t.Fatalf("the step's environment, in order: %q; want %v then PLIMSOLL_RUNNER_PID", lines, want)
	}
	if pid, err := strconv.Atoi(got[len(got)-1].v); err != nil || pid <= 0 || (!inSession && pid != 1) {
		t.Fatalf("PLIMSOLL_RUNNER_PID=%q", got[len(got)-1].v)
	}
	if !slices.Equal(got[:len(want)], want) {
		t.Fatalf("the step's environment, in order: %q; want %v then PLIMSOLL_RUNNER_PID", lines, want)
	}
}

// eqSignalsStep reports, from inside a step, whether HUP, INT and QUIT are ignored there
// (a shell that sends one to itself and survives), and the step's blocked and ignored
// masks where the kernel lists them (gVisor's status file has neither line).
const eqSignalsStep = `for s in HUP INT QUIT TERM; do sh -c "kill -$s \$\$; echo $s ignored"; echo "$s=$?"; done; grep -E '^Sig(Blk|Ign):' /proc/$$/status || echo nomask`

func eqSignalReport(t *testing.T, p eqProjects) (string, string) {
	t.Helper()
	res := eqRun(t, p, ProjectRequest{Steps: []string{eqSignalsStep}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	out := res.Steps[0].Stdout
	behaved, masks, _ := strings.Cut(out, "TERM=143\n")
	return behaved + "TERM=143\n", masks
}

// eqStepSignalsWant is what a step's shell sees: HUP, INT and TERM end it, and QUIT is
// ignored, by the image's shell itself (busybox ash ignores SIGQUIT in every shell it
// starts, measured 2026-11-19 in a shell docker started directly), so the same under any
// runner.
const eqStepSignalsWant = "HUP=129\nINT=130\nQUIT ignored\nQUIT=0\nTERM=143\n"

func eqStepSignals(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	behaved, masks := eqSignalReport(t, p)
	if behaved != eqStepSignalsWant {
		t.Fatalf("a step's shell sending itself HUP, INT, QUIT and TERM: %q; want %q", behaved, eqStepSignalsWant)
	}
	// Nothing blocked, and only the shell's own QUIT ignored, where the kernel lists them.
	if masks != "nomask\n" && masks != "SigBlk:\t0000000000000000\nSigIgn:\t0000000000000004\n" {
		t.Fatalf("the step's signal masks: %q; want none blocked, only QUIT ignored", masks)
	}
	t.Logf("masks: %q", masks)
}

// eqStepSignalsInherited: the runner started with HUP, INT and QUIT ignored (whether
// any provider does is not known: OpenShell's and WSL's exec were not checked). Node's
// library resets every signal in a step to its default; Rust's standard library resets
// only SIGPIPE (review finding rust-native-helper-4), so a native runner must reset them itself.
func eqStepSignalsInherited(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	ignoring := eqDocker(t, "/bin/sh", "-c", `trap "" HUP INT QUIT; exec "$@"`, "sh")
	behaved, masks := eqSignalReport(t, ignoring)
	t.Logf("with HUP, INT and QUIT ignored above the runner: %q, masks %q", behaved, masks)
	if behaved != eqStepSignalsWant {
		t.Fatalf("a step's shell sending itself HUP, INT, QUIT and TERM: %q; want %q, as with nothing ignored above the runner: the runner resets what it inherited", behaved, eqStepSignalsWant)
	}
}

// eqMaskBlocker is a program that blocks HUP, USR1 and TERM and then becomes its arguments,
// which keep the mask: the runner started with those signals blocked. Python's, so the case
// runs in the Python image; the Node image has nothing that sets a mask.
const eqMaskBlocker = `import os, signal, sys
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP, signal.SIGUSR1, signal.SIGTERM})
os.execv(sys.argv[1], sys.argv[1:])`

// eqMaskStep reports the runner's mask, then whether HUP, USR1 and TERM each still end a
// shell the step starts (a blocked signal stays pending and the shell goes on), then the
// step's own mask, where the kernel lists masks.
const eqMaskStep = `grep -E '^SigBlk:' /proc/$PLIMSOLL_RUNNER_PID/status || echo 'runner nomask'; for s in HUP USR1 TERM; do sh -c "kill -$s \$\$; echo $s blocked"; echo "$s=$?"; done; grep -E '^SigBlk:' /proc/$$/status || echo nomask`

// eqStepMaskInherited: the runner started with HUP, USR1 and TERM blocked (finding
// rust-native-helper-25). A blocked signal is inherited through fork and exec, so a step
// would start with them blocked unless the runner clears its mask in each step; the runner
// does (sys::reset_signals_in_child), and so does Rust's standard library before it, so
// only a runner that cleared neither fails here. The runner's own mask is read first, to
// show the case blocked something: where the kernel lists it, it must be those three.
func eqStepMaskInherited(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	blocking := eqDocker(t, "python3", "-c", eqMaskBlocker)
	blocking.ProjectImage = pythonProjectImage
	requireProjectImage(t, blocking)
	res := eqRun(t, blocking, ProjectRequest{Steps: []string{eqMaskStep}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	out := res.Steps[0].Stdout
	t.Logf("with HUP, USR1 and TERM blocked above the runner: %q", out)
	runner, rest, _ := strings.Cut(out, "\n")
	// HUP is 1, USR1 10 and TERM 15: bits 0, 9 and 14.
	if runner != "runner nomask" && runner != "SigBlk:\t0000000000004201" {
		t.Fatalf("the runner's own mask is %q; want HUP, USR1 and TERM blocked (0000000000004201), or the case blocked nothing", runner)
	}
	const behaved = "HUP=129\nUSR1=138\nTERM=143\n"
	if !strings.HasPrefix(rest, behaved) {
		t.Fatalf("a step's shell sending itself HUP, USR1 and TERM: %q; want %q, as with nothing blocked above the runner: the runner clears the mask it inherited", rest, behaved)
	}
	if mask := strings.TrimPrefix(rest, behaved); mask != "nomask\n" && mask != "SigBlk:\t0000000000000000\n" {
		t.Fatalf("the step's mask: %q; want nothing blocked", mask)
	}
}

// eqSetupFailureText: a failure while writing the plan's files is reported with the
// error's own text as the outcome's detail, which a caller and the audit line see
// (review finding rust-native-helper-5): the error's code first, where the Node runner gave Node's message.
func eqSetupFailureText(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Files: []File{{Path: "isdir/b", Content: "x"}, {Path: "isdir", Content: "y"}}, Steps: []string{"echo never"}})
	if res.Outcome != ProjectOutcomeSetupFailed || len(res.Steps) != 0 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	const node = "EISDIR: illegal operation on a directory, open '/work/isdir'"
	eqDiffers(t, "gave Node's message "+strconv.Quote(node), "gives the same outcome, a detail that starts with the same error code (EISDIR)")
	if !strings.HasPrefix(res.Detail, "EISDIR") {
		t.Fatalf("detail %q", res.Detail)
	}
}

// eqFileOverLink: in a session the work directory holds what earlier calls left, so a
// file the runner writes may already be a link; it is refused, never followed.
func eqFileOverLink(t *testing.T, s eqProjects) {
	if r := eqRun(t, s, ProjectRequest{Steps: []string{"ln -sf /tmp/eq-outside linked.txt"}}); r.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("planting the link: %s %q", r.Outcome, r.Detail)
	}
	res := eqRun(t, s, ProjectRequest{Files: []File{{Path: "linked.txt", Content: "x"}}, Steps: []string{"echo never"}})
	if res.Outcome != ProjectOutcomeSetupFailed || len(res.Steps) != 0 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	const node = "ELOOP: too many symbolic links encountered, open '/work/linked.txt'"
	eqDiffers(t, "gave Node's message "+strconv.Quote(node), "gives the same outcome, a detail that starts with ELOOP")
	if !strings.HasPrefix(res.Detail, "ELOOP") {
		t.Fatalf("detail %q", res.Detail)
	}
	if r := eqRun(t, s, ProjectRequest{Steps: []string{"test ! -e /tmp/eq-outside && echo absent"}}); len(r.Steps) != 1 || r.Steps[0].Stdout != "absent\n" {
		t.Fatalf("the link's target: %+v", r.Steps)
	}
	// A fifo there is refused at once, not waited on: opened without waiting for a
	// reader, which fails (ENXIO) before the runner's own regular-file check is reached.
	if r := eqRun(t, s, ProjectRequest{Steps: []string{"mkfifo eqfifo.txt"}}); r.Outcome != ProjectOutcomeCompleted {
		t.Fatalf("planting the fifo: %s %q", r.Outcome, r.Detail)
	}
	start := time.Now()
	res = eqRun(t, s, ProjectRequest{Files: []File{{Path: "eqfifo.txt", Content: "x"}}, Steps: []string{"echo never"}, Timeout: 20 * time.Second})
	if res.Outcome != ProjectOutcomeSetupFailed || len(res.Steps) != 0 || time.Since(start) > 15*time.Second {
		t.Fatalf("a file over a fifo: %s %q after %v; want refused at once", res.Outcome, res.Detail, time.Since(start))
	}
	const fifo = "ENXIO: no such device or address, open '/work/eqfifo.txt'"
	eqDiffers(t, "gave Node's message "+strconv.Quote(fifo), "gives the same outcome, a detail that starts with ENXIO")
	if !strings.HasPrefix(res.Detail, "ENXIO") {
		t.Fatalf("detail %q", res.Detail)
	}
}

// eqArtifactEdges: 8 MiB across all artifacts, counted on each file's size when it is
// opened; the first one that would pass it ends the reading, so a later one that would
// still fit is not read either.
func eqArtifactEdges(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	const total = 8 << 20
	for _, c := range []struct {
		name  string
		sizes []int
		want  []int // the sizes that come back
		cut   bool
	}{
		{"one at the budget", []int{total}, []int{total}, false},
		{"one past it", []int{total + 1}, nil, true},
		{"two that fill it", []int{total / 2, total / 2}, []int{total / 2, total / 2}, false},
		{"the second passes it, the third would fit", []int{total / 2, total/2 + 1, 1}, []int{total / 2}, true},
	} {
		req := ProjectRequest{}
		var step []string
		for i, n := range c.sizes {
			name := fmt.Sprintf("edge%d.bin", i)
			step = append(step, eqFill('a', n)+" > "+name)
			req.Artifacts = append(req.Artifacts, name)
		}
		req.Steps = []string{strings.Join(step, "; ")}
		res := eqRun(t, p, req)
		var got []int
		for _, a := range res.Artifacts {
			got = append(got, len(a.Content))
		}
		if res.Outcome != ProjectOutcomeCompleted || !slices.Equal(got, c.want) || res.ArtifactsTruncated != c.cut {
			t.Fatalf("%s: %s, artifacts of %v bytes, cut %v; want %v, cut %v", c.name, res.Outcome, got, res.ArtifactsTruncated, c.want, c.cut)
		}
	}
}

func eqArtifactDirectory(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{"mkdir -p adir/inner; echo f > afile"}, Artifacts: []string{"adir", "afile"}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Artifacts) != 1 || res.Artifacts[0].Path != "afile" || res.ArtifactsTruncated {
		t.Fatalf("%s, artifacts %+v, cut %v; want the file alone", res.Outcome, res.Artifacts, res.ArtifactsTruncated)
	}
}

// eqArtifactParentSwap: a step leaves a program that swaps the directory d for a link
// to /etc as fast as it can, and asks for d/hostname by a hundred names that go through
// d (links inside the work directory). Between the runner resolving a name and opening
// it, d can turn into the link; the runner asks the kernel what it opened and keeps
// only a file inside the work directory, so /etc/hostname never comes back. The race is
// the point, so the run is repeated.
func eqArtifactParentSwap(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	swap := `const fs=require("node:fs");
for(;;){try{fs.renameSync("d","d.real");fs.symlinkSync("/etc","d");fs.unlinkSync("d");fs.renameSync("d.real","d")}catch{}}`
	req := ProjectRequest{
		Files: []File{{Path: "swap.js", Content: swap}},
		Steps: []string{`mkdir d; echo inner > d/hostname; for i in $(seq 0 99); do ln -s d a$i; done; node swap.js >/dev/null 2>&1 </dev/null & sleep 0.3`},
	}
	for i := range 100 {
		req.Artifacts = append(req.Artifacts, fmt.Sprintf("a%d/hostname", i))
	}
	read := 0
	for run := range 4 {
		res := eqRun(t, p, req)
		if res.Outcome != ProjectOutcomeCompleted {
			t.Fatalf("run %d: %s %q", run, res.Outcome, res.Detail)
		}
		for _, a := range res.Artifacts {
			if string(a.Content) != "inner\n" {
				t.Fatalf("run %d: %s came back as %q: a file outside the work directory was read", run, a.Path, a.Content)
			}
		}
		read += len(res.Artifacts)
	}
	t.Logf("%d of 400 reads came back, every one the file inside", read)
}

// eqArtifactGrows: a program a step leaves keeps appending to an artifact while it is
// read, starting when the runner opens the fifo asked for before it. The run still
// reports, and the artifact comes back as a prefix of the file. The Node runner checked
// the budget against its own measure of the file and then read with readFileSync,
// which measured the file again and read to that second size, so an artifact that grew
// between the two came back past the 8 MiB budget (measured under gVisor, 2026-11-19:
// 8,650,752 bytes; review finding rust-native-helper-6 said the read was bounded by the
// size at the open). The native runner reads at most the size it checked.
func eqArtifactGrows(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	grow := `const fs=require("node:fs");fs.closeSync(fs.openSync("gate","w"));
const fd=fs.openSync("grow.txt","a");const b=Buffer.alloc(1<<18,0x79);
for(let i=0;i<256;i++){try{fs.writeSync(fd,b)}catch{break}}`
	req := ProjectRequest{
		Files:     []File{{Path: "grow.js", Content: grow}},
		Steps:     []string{eqFill('x', 6<<20) + ` > grow.txt; mkfifo gate; node grow.js >/dev/null 2>&1 </dev/null & sleep 0.3`},
		Artifacts: []string{"gate", "grow.txt"},
	}
	for run := range 3 {
		res := eqRun(t, p, req)
		if res.Outcome != ProjectOutcomeCompleted {
			t.Fatalf("run %d: %s %q", run, res.Outcome, res.Detail)
		}
		got, ok := eqArtifact(res, "grow.txt")
		if ok && (len(got) < 6<<20 || strings.Trim(string(got[:6<<20]), "x") != "" || strings.Trim(string(got[6<<20:]), "y") != "") {
			t.Fatalf("run %d: grow.txt came back with %d bytes; want its first 6 MiB and what was appended", run, len(got))
		}
		t.Logf("run %d: grow.txt %v, %d bytes, cut %v", run, ok, len(got), res.ArtifactsTruncated)
		if len(got) > 8<<20 {
			t.Fatalf("run %d: grow.txt came back with %d bytes, past the 8 MiB budget", run, len(got))
		}
	}
}

func eqWrittenFiles(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{
		Files: []File{{Path: "w/x/y.txt", Content: "c"}},
		Steps: []string{`pwd; umask; stat -c '%a %u %F' w w/x w/x/y.txt`},
	})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	uid := d.guestUID()
	want := fmt.Sprintf("/work\n0022\n755 %d directory\n755 %d directory\n644 %d regular file\n", uid, uid, uid)
	if res.Steps[0].Stdout != want {
		t.Fatalf("the step saw %q, want %q", res.Steps[0].Stdout, want)
	}
}

// eqWrittenFilesOtherStart: the runner started in / under umask 0 (a wrapper), where docker
// would otherwise hide both behind its own settings (it starts the runner in /work under
// umask 0022): a step still runs in the work directory, and a written file still gets mode
// 0644, which the runner asks for, while the folders it makes get what the umask leaves of
// 0777, as Node's mkdirSync gives them (finding rust-native-helper-24; OpenShell,
// agent-sandbox and WSL containers start the runner their own way).
func eqWrittenFilesOtherStart(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	elsewhere := eqDocker(t, "/bin/sh", "-c", `umask 0; cd /; exec "$@"`, "sh")
	res := eqRun(t, elsewhere, ProjectRequest{
		Files: []File{{Path: "o/x/y.txt", Content: "c"}},
		Steps: []string{`pwd; umask; stat -c '%a %u %F' o o/x o/x/y.txt`},
	})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	uid := elsewhere.guestUID()
	want := fmt.Sprintf("/work\n0000\n777 %d directory\n777 %d directory\n644 %d regular file\n", uid, uid, uid)
	if res.Steps[0].Stdout != want {
		t.Fatalf("with the runner started in / under umask 0, the step saw %q, want %q", res.Steps[0].Stdout, want)
	}
}

// eqSignalsToRunnerStep sends the runner every signal a step's shell can name that ends a
// process by default (and two of the real-time ones: 34, the first, which musl keeps for
// itself, and 64, the last), then reports that it is still there.
const eqSignalsToRunnerStep = `for s in TERM USR1 USR2 HUP INT QUIT ALRM PIPE VTALRM PROF XCPU XFSZ SYS TRAP ABRT 34 64; do kill -$s "$PLIMSOLL_RUNNER_PID" || echo "kill -$s failed"; done; sleep 0.3; echo sent`

// eqSignalsToRunner: a step runs as the runner's user and knows its process number
// (PLIMSOLL_RUNNER_PID), so it may signal it. The native runner ignores every catchable
// signal but SIGCHLD (finding rust-native-helper-28, decided with the landing of the review's
// fixes), so the call comes back completed with the next step run. The Node
// runner was ended by the first of them wherever it was not the container's first process
// (a session; every gVisor run), and the call read protocol_error.
func eqSignalsToRunner(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Steps: []string{eqSignalsToRunnerStep, "echo second"}, Timeout: 30 * time.Second})
	eqDiffers(t, "was ended by the signal outside a runc run's first process (protocol_error)",
		"ignores it and the call completes")
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 2 || res.Steps[0].Stdout != "sent\n" || res.Steps[0].ExitCode != 0 ||
		res.Steps[1].Stdout != "second\n" {
		t.Fatalf("the native runner signalled by a step: %s %q, steps %+v; want completed, the step's sent and the next step run", res.Outcome, res.Detail, res.Steps)
	}
}

// eqStepEndedBySignal: a step whose own shell is ended by a signal has no exit status; the
// runner reports 128 plus the signal's number (KILL 137, TERM 143, USR1 138, and the
// real-time signals 35 and 64 as 163 and 192), and, as for any step that fails, the plan
// stops there. No other case looked at such a step's code: a helper built to report the
// signal's bare number passed the whole suite until this case was added (2026-11-21). The
// real-time signals are where the Node runner differed: Node names no real-time signal, so
// runner.mjs reported -1 for them (review finding rust-native-helper-42); the new value is
// what the exec-based providers report.
func eqStepEndedBySignal(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	eqDiffers(t, "reported -1 for a step a real-time signal (34 to 64) ended", "reports 128 plus the signal, as for every other signal")
	for sig, want := range map[string]int{"KILL": 137, "TERM": 143, "USR1": 138, "35": 163, "64": 192} {
		res := eqRun(t, p, ProjectRequest{Steps: []string{"kill -" + sig + " $$", "echo never"}})
		if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 {
			t.Fatalf("SIG%s: %s %q, steps %+v; want completed with the one step", sig, res.Outcome, res.Detail, res.Steps)
		}
		if s := res.Steps[0]; s.ExitCode != want || s.TimedOut || s.Stdout != "" {
			t.Fatalf("a step its shell's SIG%s ended: exit %d, timed out %v; want %d", sig, s.ExitCode, s.TimedOut, want)
		}
	}
}

// eqRunnerLook, run as a step, reports the runner as the step sees it: its process
// number from PLIMSOLL_RUNNER_PID, its command line, whether it is the step's parent,
// and what opening its descriptors, reading its maps and the owner of its environ give
// (review findings rust-native-helper-10 and 11: tests and the smoke tests find the runner this way).
const eqRunnerLook = `const fs=require("node:fs");const pid=process.env.PLIMSOLL_RUNNER_PID;
const open=(p,f)=>{try{fs.closeSync(fs.openSync(p,f));return "open"}catch(e){return e.code}};
const r={pid:+pid,argv:fs.readFileSync("/proc/"+pid+"/cmdline","latin1").split("\0").slice(0,-1),
 parent:process.ppid,fd0:open("/proc/"+pid+"/fd/0",fs.constants.O_RDONLY),
 fd1:open("/proc/"+pid+"/fd/1",fs.constants.O_WRONLY),owner:fs.statSync("/proc/"+pid+"/environ").uid,uid:process.getuid()};
try{fs.readFileSync("/proc/"+pid+"/maps");r.maps="read"}catch(e){r.maps=e.code}
process.stdout.write(JSON.stringify(r));`

func eqRunnerAsSeen(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	res := eqRun(t, p, ProjectRequest{Files: []File{{Path: "look.js", Content: eqRunnerLook}}, Steps: []string{"node look.js"}})
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		t.Fatalf("%s %q, steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	var r struct {
		PID        int      `json:"pid"`
		Argv       []string `json:"argv"`
		Parent     int      `json:"parent"`
		FD0, FD1   string
		Maps       string `json:"maps"`
		Owner, UID int
	}
	if err := json.Unmarshal([]byte(res.Steps[0].Stdout), &r); err != nil {
		t.Fatalf("%v: %q", err, res.Steps[0].Stdout)
	}
	denied := func(s string) bool { return s == "EACCES" || s == "EPERM" }
	// The step's sh -c replaced itself with node, so node's parent is the runner.
	if !slices.Equal(r.Argv, d.runnerCommand()) || r.Parent != r.PID || (!inSession && r.PID != 1) {
		t.Fatalf("the runner is pid %d with command line %q, the step's parent %d; want the runner under test's command line, the step's parent", r.PID, r.Argv, r.Parent)
	}
	if !denied(r.FD0) || !denied(r.FD1) || !denied(r.Maps) || r.Owner == r.UID {
		t.Fatalf("a step reached the runner: descriptor 0 %s, descriptor 1 %s, maps %s, environ owner %d (the step's uid %d); want each refused and the owner not the step's", r.FD0, r.FD1, r.Maps, r.Owner, r.UID)
	}
}

// eqRunnerRefusesDumpable: the runner proves, every run and before it reads the plan,
// that a process of its uid cannot open its descriptors (review finding rust-native-helper-11). It
// makes itself non-dumpable with one call and no library, so it is started with its
// test-only argument that skips that call (nothing a daemon starts passes it:
// nativehelper's tests hold that); it then proves nothing and reports that, unsigned, so
// the run is a protocol error and no step runs.
func eqRunnerRefusesDumpable(t *testing.T, d *DockerSandbox, p eqProjects, inSession bool) {
	unguarded := eqDocker(t, "/bin/sh", "-c", `exec "$@" `+nativehelper.TestOnlyStayDumpable, "sh")
	res := eqRun(t, unguarded, ProjectRequest{Steps: []string{"echo ran > ran.txt"}, Artifacts: []string{"ran.txt"}})
	if res.Outcome != ProjectOutcomeProtocolError || res.Detail != "no authenticated runner report" || len(res.Steps) != 0 || len(res.Artifacts) != 0 {
		t.Fatalf("the runner started dumpable: %s %q, steps %+v; want a protocol error and nothing run", res.Outcome, res.Detail, res.Steps)
	}
	plan, key := eqPlan(t, map[string]any{"steps": []string{"echo ran"}})
	raw := eqRunPlan(t, unguarded, plan, key)
	if body := eqUnsignedFrame(t, raw.stdout); body != `{"error":"runner descriptor and memory isolation could not be proven"}` {
		t.Fatalf("its report %q", body)
	}
}

// --- The plan cases: the runner fed a plan directly, its stdout read byte for byte.

type eqPlanCase struct {
	name string
	run  func(t *testing.T, d *DockerSandbox)
}

var eqPlanCases = []eqPlanCase{
	{"the report frame's bytes", eqFrameBytes},
	{"a plan with no key or a short one", eqNoKey},
	{"a plan path that climbs out of the work directory", eqPlanPathOut},
	{"an empty file path", eqPlanEmptyPath},
	{"a plan environment entry that is not NAME=value", eqPlanBadEnv},
	{"a command is cut at 16,384 UTF-16 units", eqCommandCut},
	{"a report past its budget keeps whether steps began", eqReportOverBudget},
	{"a report past its budget drops artifacts from the end", eqReportDropsArtifacts},
	{"the report key reaches no step", eqKeyReachesNoStep},
	{"the host client module and NODE_OPTIONS", eqHostSDK},
	{"a plan with no budget sets no deadline", eqNoBudget},
	{"a step the runner cannot start", eqStepCannotStart},
}

type eqRaw struct {
	stdout string // the runner's whole stdout
	stderr string // its stderr after the start marker
	exit   int    // the container's exit
	key    []byte
}

// eqPlan encodes a plan as the runner reads it, with a fresh key unless the plan
// states its own reportKey (or null for none).
func eqPlan(t *testing.T, plan map[string]any) ([]byte, []byte) {
	t.Helper()
	var key []byte
	if _, set := plan["reportKey"]; !set {
		k, err := runnerwire.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		key = k
		plan["reportKey"] = hex.EncodeToString(k)
	} else if s, ok := plan["reportKey"].(string); ok {
		key, _ = hex.DecodeString(s)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return b, key
}

// eqRunPlan starts the runner under test exactly as RunProject does (the same lockdown,
// image, start script, guard and seam) with plan on its stdin.
func eqRunPlan(t *testing.T, d *DockerSandbox, plan, key []byte) eqRaw {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	state := eqState(t, d)
	seccomp, _, err := state.seccomp.seccompFor(nil, state.runtime)
	if err != nil {
		t.Fatal(err)
	}
	started := startMarker()
	runner, err := d.runnerArgv(started)
	if err != nil {
		t.Fatal(err)
	}
	name := "crsbx-" + providerkit.RandHex(8)
	args := d.lockdownArgs(name, d.containerExpiry(ctx), true, state.runtime, seccomp)
	if state.platform != "" {
		args = append(args, "--platform", state.platform)
	}
	tail, err := launch(state.guard, state.projectImageID, runner)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, tail...)
	args, err = dockerArgs(state.host, args...)
	if err != nil {
		t.Fatal(err)
	}
	cmd := dockerCommand(ctx, args...)
	cmd.Stdin = bytes.NewReader(plan)
	var stdout, stderr providerkit.Capture
	stdout.Limit = runnerwire.StdoutCap
	stderr.Limit = 1 << 20
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	out := eqRaw{key: key}
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			d.removeOrHold(ctx, state.host, name)
			t.Fatalf("docker run: %v: %s", err, stderr.String())
		}
		out.exit = exitErr.ExitCode()
	}
	after, ran := afterMarker(stderr.String(), started)
	if !ran {
		t.Fatalf("the runner never started: %q", stderr.String())
	}
	out.stdout, out.stderr = stdout.String(), after
	return out
}

var eqFrameHeader = regexp.MustCompile(`\A\n` + regexp.QuoteMeta(runnerwire.Marker) + ` ([0-9]+) ([0-9a-f]{64})\n`)

// eqSignedFrame checks that stdout is one frame and nothing else, its length right
// and its MAC the HMAC-SHA256 of its body under key, and returns the body.
func eqSignedFrame(t *testing.T, r eqRaw) string {
	t.Helper()
	m := eqFrameHeader.FindStringSubmatch(r.stdout)
	if m == nil {
		t.Fatalf("stdout does not open with the report frame: %.300q", r.stdout)
	}
	body := r.stdout[len(m[0]):]
	if n, _ := strconv.Atoi(m[1]); n != len(body) {
		t.Fatalf("the frame states %s bytes and %d follow", m[1], len(body))
	}
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(body))
	if hex.EncodeToString(mac.Sum(nil)) != m[2] {
		t.Fatalf("the frame's MAC %s is not the body's under the key", m[2])
	}
	if r.exit != 0 || r.stderr != "" {
		t.Fatalf("the runner exited %d with stderr %q", r.exit, r.stderr)
	}
	return body
}

// eqUnsignedFrame checks a frame written without a key: the MAC is 64 zeros.
func eqUnsignedFrame(t *testing.T, stdout string) string {
	t.Helper()
	m := eqFrameHeader.FindStringSubmatch(stdout)
	if m == nil || m[2] != strings.Repeat("0", 64) {
		t.Fatalf("stdout is not one unsigned frame: %.300q", stdout)
	}
	body := stdout[len(m[0]):]
	if n, _ := strconv.Atoi(m[1]); n != len(body) {
		t.Fatalf("the frame states %s bytes and %d follow", m[1], len(body))
	}
	return body
}

var eqDuration = regexp.MustCompile(`"durationMs":[0-9]+`)

func eqFrameBytes(t *testing.T, d *DockerSandbox) {
	plan, key := eqPlan(t, map[string]any{
		"files": []map[string]string{{"path": "a.txt", "content": "hi"}}, "steps": []string{"cat a.txt", "printf 'e\\377' >&2; exit 3", "echo never"},
		"budgetMs": 30000, "artifacts": []string{"a.txt", "none"},
	})
	body := eqSignedFrame(t, eqRunPlan(t, d, plan, key))
	const want = `{"steps":[{"command":"cat a.txt","stdoutBase64":"aGk=","stderrBase64":"","stdoutTruncated":false,"stderrTruncated":false,"exitCode":0,"timedOut":false,"durationMs":N},` +
		`{"command":"printf 'e\\377' >&2; exit 3","stdoutBase64":"","stderrBase64":"Zf8=","stdoutTruncated":false,"stderrTruncated":false,"exitCode":3,"timedOut":false,"durationMs":N}],` +
		`"artifacts":[{"path":"a.txt","content":"aGk="}],"artifactsTruncated":false}`
	if got := eqDuration.ReplaceAllString(body, `"durationMs":N`); got != want {
		t.Fatalf("the report body\n got %s\nwant %s", got, want)
	}
}

func eqNoKey(t *testing.T, d *DockerSandbox) {
	for _, key := range []any{nil, strings.Repeat("ab", 31)} {
		plan, _ := eqPlan(t, map[string]any{"steps": []string{"echo ran > /tmp/ran"}, "reportKey": key})
		r := eqRunPlan(t, d, plan, nil)
		if body := eqUnsignedFrame(t, r.stdout); body != `{"error":"plan carries no report key"}` || r.exit != 0 {
			t.Fatalf("key %v: report %q, exit %d", key, body, r.exit)
		}
	}
}

func eqPlanPathOut(t *testing.T, d *DockerSandbox) {
	plan, key := eqPlan(t, map[string]any{"files": []map[string]string{{"path": "ok.txt", "content": "a"}, {"path": "../x", "content": "b"}}, "steps": []string{"echo never"}})
	if body := eqSignedFrame(t, eqRunPlan(t, d, plan, key)); body != `{"error":"illegal file path: ../x"}` {
		t.Fatalf("report %s", body)
	}
	plan, key = eqPlan(t, map[string]any{"steps": []string{"echo in > in.txt"}, "artifacts": []string{"../etc/hostname", "/etc/hostname", "in.txt", "."}})
	body := eqSignedFrame(t, eqRunPlan(t, d, plan, key))
	if !strings.HasSuffix(body, `"artifacts":[{"path":"in.txt","content":"aW4K"}],"artifactsTruncated":false}`) {
		t.Fatalf("report %s; want only the artifact inside the work directory", body)
	}
}

func eqPlanEmptyPath(t *testing.T, d *DockerSandbox) {
	plan, key := eqPlan(t, map[string]any{"files": []map[string]string{{"path": "", "content": "a"}}, "steps": []string{"echo never"}})
	body := eqSignedFrame(t, eqRunPlan(t, d, plan, key))
	eqDiffers(t, `gave Node's message {"error":"EISDIR: illegal operation on a directory, open '/work'"}`, "gives an error that starts with EISDIR")
	if !strings.HasPrefix(body, `{"error":"EISDIR`) {
		t.Fatalf("report %s", body)
	}
}

func eqPlanBadEnv(t *testing.T, d *DockerSandbox) {
	for _, entry := range []string{"NOEQUALS", "=value"} {
		plan, key := eqPlan(t, map[string]any{"steps": []string{"echo never"}, "env": []string{"A=1", entry}})
		if body := eqSignedFrame(t, eqRunPlan(t, d, plan, key)); body != `{"error":"plan env entry is not NAME=value"}` {
			t.Fatalf("entry %q: report %s", entry, body)
		}
	}
}

// eqCommandCut: the reported command is cut at 16,384 bytes on a character boundary. The
// Node runner cut at 16,384 JavaScript characters (UTF-16 units), which could split a
// character outside the basic set and leave a lone surrogate in the report, which Go read
// as U+FFFD (review finding rust-native-helper-5). No provider can send such a command (a
// step is at most 16 KiB of UTF-8, which is never more units).
func eqCommandCut(t *testing.T, d *DockerSandbox) {
	cmd := ": " + strings.Repeat("a", 16381) + "\U0001F600"
	if n := len(utf16.Encode([]rune(cmd))); n != 16385 {
		t.Fatalf("the command is %d units", n)
	}
	plan, key := eqPlan(t, map[string]any{"steps": []string{cmd}})
	r := eqRunPlan(t, d, plan, key)
	eqSignedFrame(t, r)
	rep, _, err := runnerwire.Parse(r.stdout, key)
	if err != nil || len(rep.Steps) != 1 {
		t.Fatalf("parse: %v", err)
	}
	eqDiffers(t, "cut at 16,384 UTF-16 units, splitting the emoji", "cuts on a character boundary at 16,384 bytes at most")
	if got := rep.Steps[0].Command; len(got) > 16384 || !strings.HasPrefix(cmd, got) || got != ": "+strings.Repeat("a", 16381) {
		t.Fatalf("command of %d bytes", len(got))
	}
}

// eqLongSteps is n steps that each do nothing and whose commands JSON-escape to about
// 96 KB each (16,000 control characters, six bytes apiece).
func eqLongSteps(n int) []string {
	steps := make([]string, n)
	for i := range steps {
		steps[i] = ": " + strings.Repeat("\x01", 16000)
	}
	return steps
}

func eqReportOverBudget(t *testing.T, d *DockerSandbox) {
	plan, key := eqPlan(t, map[string]any{"steps": eqLongSteps(200)})
	r := eqRunPlan(t, d, plan, key)
	if body := eqSignedFrame(t, r); body != `{"error":"sandbox result exceeds the encoded response budget","stepsBegan":true}` {
		t.Fatalf("report %.300s", body)
	}
	res, _ := RunnerReport(ProjectResult{}, r.stdout, key)
	if res.Outcome != ProjectOutcomeRunnerFailed || res.Detail != "sandbox result exceeds the encoded response budget" {
		t.Fatalf("a caller reads %s %q", res.Outcome, res.Detail)
	}
}

func eqReportDropsArtifacts(t *testing.T, d *DockerSandbox) {
	steps := eqLongSteps(100)
	steps[99] = eqFill('a', 3<<20) + " > one.bin; " + eqFill('b', 3<<20) + " > two.bin"
	plan, key := eqPlan(t, map[string]any{"steps": steps, "artifacts": []string{"one.bin", "two.bin"}})
	r := eqRunPlan(t, d, plan, key)
	eqSignedFrame(t, r)
	rep, _, err := runnerwire.Parse(r.stdout, key)
	if err != nil || len(rep.Steps) != 100 || len(rep.Artifacts) != 1 || rep.Artifacts[0].Path != "one.bin" || len(rep.Artifacts[0].Content) != 3<<20 || !rep.ArtifactsTruncated || rep.Err != "" {
		t.Fatalf("parse %v: %d steps, %d artifacts, cut %v, error %q; want every step, the first artifact alone and cut", err, len(rep.Steps), len(rep.Artifacts), rep.ArtifactsTruncated, rep.Err)
	}
	if n := len(r.stdout); n > 15<<20 {
		t.Fatalf("the report is %d bytes, past its 15 MiB budget", n)
	}
}

// eqKeyReachesNoStep: the key is in the plan alone; a step finds it in no process's
// command line or environment and in no file under /work or /tmp.
func eqKeyReachesNoStep(t *testing.T, d *DockerSandbox) {
	key, err := runnerwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(key)
	find := fmt.Sprintf(`const fs=require("node:fs");const k=%q+%q;let hits=[];
const look=(p)=>{try{if(fs.readFileSync(p,"latin1").includes(k))hits.push(p)}catch{}};
for(const d of fs.readdirSync("/proc")){if(/^[0-9]+$/.test(d)){look("/proc/"+d+"/cmdline");look("/proc/"+d+"/environ")}}
const walk=(dir)=>{let es=[];try{es=fs.readdirSync(dir,{withFileTypes:true})}catch{return}
for(const e of es){const p=dir+"/"+e.name;if(e.isDirectory())walk(p);else if(e.isFile())look(p)}};walk("/work");walk("/tmp");
process.stdout.write(JSON.stringify(hits));`, h[:32], h[32:])
	plan, _ := eqPlan(t, map[string]any{"files": []map[string]string{{"path": "find.js", "content": find}}, "steps": []string{"node find.js"}, "reportKey": h})
	r := eqRunPlan(t, d, plan, key)
	eqSignedFrame(t, r)
	rep, _, err := runnerwire.Parse(r.stdout, key)
	if err != nil || len(rep.Steps) != 1 || rep.Steps[0].Stdout != "[]" {
		t.Fatalf("parse %v, steps %+v; want the key found nowhere", err, rep.Steps)
	}
}

func eqHostSDK(t *testing.T, d *DockerSandbox) {
	plan, key := eqPlan(t, map[string]any{"steps": []string{`echo "$NODE_OPTIONS"; node -e 'console.log(globalThis.plimsollEq)'; stat -c '%a %F' /tmp/plimsoll-host.mjs`},
		"hostSDK": "globalThis.plimsollEq = 7;", "env": []string{"NODE_OPTIONS=--no-warnings"}})
	r := eqRunPlan(t, d, plan, key)
	eqSignedFrame(t, r)
	rep, _, err := runnerwire.Parse(r.stdout, key)
	if err != nil || len(rep.Steps) != 1 || rep.Steps[0].Stdout != "--no-warnings --import=file:///tmp/plimsoll-host.mjs\n7\n644 regular file\n" {
		t.Fatalf("parse %v, steps %+v", err, rep.Steps)
	}
}

func eqNoBudget(t *testing.T, d *DockerSandbox) {
	for _, budget := range []any{nil, 0, -5} {
		p := map[string]any{"steps": []string{"sleep 1.2; echo done"}}
		if budget != nil {
			p["budgetMs"] = budget
		}
		plan, key := eqPlan(t, p)
		r := eqRunPlan(t, d, plan, key)
		eqSignedFrame(t, r)
		rep, _, err := runnerwire.Parse(r.stdout, key)
		if err != nil || len(rep.Steps) != 1 || rep.Steps[0].Stdout != "done\n" || rep.Steps[0].TimedOut {
			t.Fatalf("budget %v: parse %v, steps %+v", budget, err, rep.Steps)
		}
	}
}

// eqStepCannotStart: a step the runner cannot start (its command past the kernel's
// limit on one argument, 128 KiB, which only a plan can carry: a provider refuses a step
// over 16 KiB) is reported with exit -1 and the start error as its stderr, and the plan
// stops there. The command is reported cut at 16,384 characters, as any other.
func eqStepCannotStart(t *testing.T, d *DockerSandbox) {
	plan, key := eqPlan(t, map[string]any{"steps": []string{"echo first", ": " + strings.Repeat("a", 200<<10), "echo never"}})
	r := eqRunPlan(t, d, plan, key)
	eqSignedFrame(t, r)
	rep, _, err := runnerwire.Parse(r.stdout, key)
	if err != nil || len(rep.Steps) != 2 || rep.Steps[0].Stdout != "first\n" {
		t.Fatalf("parse %v, %d steps", err, len(rep.Steps))
	}
	s := rep.Steps[1]
	if s.ExitCode != -1 || s.TimedOut || s.Stdout != "" || s.StdoutTruncated || s.StderrTruncated || len(s.Command) != 16384 {
		t.Fatalf("the step that could not start: exit %d, timed out %v, stdout %q, command of %d bytes; want exit -1", s.ExitCode, s.TimedOut, s.Stdout, len(s.Command))
	}
	// The kernel's error: Linux says E2BIG. gVisor said ENAMETOOLONG on 2026-11-19 and says
	// E2BIG since release-20261116.0 (measured 2026-11-21, under both runners alike), so
	// under gVisor either is its answer; the runner only reports it (outside fact
	// eq-gvisor-exec-long-argument-errno).
	codes := []string{"E2BIG"}
	if d.Runtime == "runsc" {
		codes = append(codes, "ENAMETOOLONG")
	}
	eqDiffers(t, "gave stderr \"spawnSync sh <the kernel's code>\"", "gives exit -1 and a stderr that names the kernel's code")
	if !slices.ContainsFunc(codes, func(c string) bool { return strings.Contains(s.Stderr, c) }) {
		t.Fatalf("stderr %q, want one naming %v", s.Stderr, codes)
	}
}
