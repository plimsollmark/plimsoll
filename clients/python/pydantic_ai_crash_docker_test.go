package python

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPydanticAICrashDocker runs examples/pydantic_ai_crash.py, "kill the worker, keep the sandbox", as a reader
// would run it, in the pydantic_ai framework environment, against a daemon served here on the docker provider,
// sessions on, plimsoll/sandbox-python as the project image, behind a token (a takeover needs an authenticated
// caller). The model is the example's scripted one, so nothing calls a model service. make docker-suite runs it
// (DOCKER_PY_TESTS in the Makefile; frameworkDocker says when it skips).
//
// It runs the example twice and holds each run to the lines the example's page shows, in order, and exit 0:
//
//   - crash mode: worker A is killed by SIGKILL 1.5 s into its command; worker B resumes the call that was in flight,
//     takes the session over across it, and the lost call's record states no answer (canceled); plimsoll does not
//     send the repeat and the model is told so; the model reads the file the cut command wrote, its first answer is
//     refused by the output check and its second is the typed answer; the sandbox's runs.log says the script began
//     once; and the receipt says the two workers' record logs form one chain the daemon's count at close matches.
//   - freeze mode: worker A is stopped between calls; worker B takes the session over with no call lost and answers;
//     worker A, woken, is refused with nothing sent; report.md is not in the sandbox; and the receipt matches.
//
// The crash run pins the timing it claims: a kill that landed before the request was sent prints no refusal line,
// and the test fails.
func TestPydanticAICrashDocker(t *testing.T) {
	t.Parallel()
	const token = "pydantic-ai-crash-docker-token-0123456789"
	python, url, floor := frameworkDockerAs(t, "pydantic_ai", "plimsoll/sandbox-python:latest", token)

	runs := []struct {
		name string
		args []string
		want []string // regular expressions, each matched on a line after the line the one before matched
	}{
		{name: "crash", want: []string{
			`^supervisor : ticket-42 \(user ana\) goes to worker A$`,
			`^worker A   : put access\.log \(600 lines\) in a plimsoll sandbox, (container|kernel) tier$`,
			`^worker A   : the model wrote triage\.py and is running it: python3 triage\.py$`,
			`^supervisor : killed worker A \(SIGKILL\) 1\.5 s into that command, `,
			`^supervisor : ticket-42 now belongs to worker B$`,
			`^worker B   : StepPersistence's ledger: plimsoll_shell \(call-1\) is 'started' with no end; `,
			`^worker B   : the checkpoint store holds call ([0-9]+) as pending \(request [0-9a-f]{12}\.\.\.\), worker A's call that never settled; the kit gives it up to 30 s to settle, then takes the sandbox over across it$`,
			`^worker B   : PydanticAI resumes the call that was in flight \(call-1\): python3 triage\.py$`,
			`^worker B   : took the sandbox over \(ref plimsoll/[0-9a-f]+\.\.\., ownership generation 2\) across that call; plimsoll's record of it, call [0-9]+: the call ended without an answer \(canceled\), after 1\.[0-9] s$`,
			`^worker B   : plimsoll did not send call-1 again, and told the model: "plimsoll: this exact command was already sent once in this sandbox, and the call ended without an answer after 1\.[0-9] s: .*It was not run again\.`,
			`^worker B   : the model read by_route\.json, which the cut command had written$`,
			`^worker B   : first answer refused by the output check: by_route\.json says /checkout has error_rate 0\.[0-9]+ `,
			`^worker B   : typed answer: Incident\(route='/checkout', first_bad_minute='12:04', errors=57, requests=184, error_rate=0\.31, evidence='by_route\.json'\)$`,
			`^worker B   : runs\.log in the sandbox has 1 line: triage\.py began once in this sandbox$`,
			`^worker B   : closed the sandbox: the daemon counts [0-9]+ calls`,
			`^receipt    : one session, [0-9]+ calls: 1 to [0-9]+ by worker A; [0-9]+ the lost call \(no answer: canceled, after 1\.[0-9] s; its record reached worker B at the takeover\); [0-9]+ to [0-9]+ by worker B; the daemon's own count at close \([0-9]+, last [0-9a-f]{12}\) matches$`,
		}},
		{name: "freeze", args: []string{"--freeze"}, want: []string{
			`^supervisor : ticket-42 \(user ana\) goes to worker A$`,
			`^worker A   : the model wrote triage\.py and is running it: python3 triage\.py$`,
			`^worker A   : triage\.py ran, and its answer came back: `,
			`^worker A   : stops here, between two calls `,
			`^supervisor : worker A stopped answering$`,
			`^supervisor : ticket-42 now belongs to worker B$`,
			`^worker B   : StepPersistence's ledger: every tool call of worker A's run has an end$`,
			`^worker B   : the checkpoint store is ready after call [0-9]+: no call was in flight$`,
			`^worker B   : took the sandbox over \(ref plimsoll/[0-9a-f]+\.\.\., ownership generation 2\); no call was lost$`,
			`^worker B   : the model read by_route\.json, which worker A's triage\.py wrote$`,
			`^worker B   : first answer refused by the output check: `,
			`^worker B   : typed answer: Incident\(route='/checkout', first_bad_minute='12:04', errors=57, requests=184, error_rate=0\.31, evidence='by_route\.json'\)$`,
			`^worker B   : runs\.log in the sandbox has 1 line: triage\.py began once in this sandbox$`,
			`^worker B   : ready: waiting for the supervisor$`,
			`^supervisor : waking worker A$`,
			`^worker A   : tried to write report\.md: refused, nothing was sent \(ticket-42 belongs to worker B\)$`,
			`^worker B   : report\.md is not in the sandbox; closing it$`,
			`^receipt    : one session, [0-9]+ calls: 1 to ([0-9]+) by worker A, [0-9]+ to [0-9]+ by worker B; call [0-9]+ names call [0-9]+; the daemon's own count at close \([0-9]+, last [0-9a-f]{12}\) matches$`,
		}},
	}
	for _, r := range runs {
		t.Run(r.name, func(t *testing.T) {
			cmd := exec.Command(python, append([]string{"-B", filepath.Join("examples", "pydantic_ai_crash.py")}, r.args...)...)
			cmd.Env = append(withoutTracing(os.Environ()),
				"PLIMSOLL_URL="+url,
				"PLIMSOLL_TOKEN="+token,
				"PLIMSOLL_MIN_ISOLATION="+floor,
				"PYTHONPATH=src",
				"PYTHONDONTWRITEBYTECODE=1",
				"TMPDIR="+t.TempDir(), // the supervisor's state directory, records included
			)
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			if err != nil {
				t.Fatalf("python examples/pydantic_ai_crash.py %s: %v", strings.Join(r.args, " "), err)
			}
			linesInOrder(t, string(out), r.want)
		})
	}
}

// linesInOrder fails unless each of want, a regular expression, matches a line of out after the line the one before
// it matched.
func linesInOrder(t *testing.T, out string, want []string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	at := 0
	for _, w := range want {
		re := regexp.MustCompile(w)
		found := false
		for at < len(lines) {
			line := lines[at]
			at++
			if re.MatchString(line) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no line matching %q after the lines before it matched", w)
			return
		}
	}
}
