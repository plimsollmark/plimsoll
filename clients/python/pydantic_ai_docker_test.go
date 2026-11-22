package python

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestPydanticAIDocker runs frameworks/pydantic_ai/docker_pydantic_ai_check.py with the pydantic_ai framework
// environment against a daemon served here on the docker provider, sessions on, with plimsoll/sandbox as the
// project image: PydanticAI's own conformance suite for workspace backends on real sessions, then agents of the
// installed PydanticAI with plimsoll's capability, driven by a scripted model. make docker-suite runs it
// (frameworkDocker says when it skips).
//
// The conformance suite skips a rule its backend gives it no means to check, and "a skipped rule is not a passed
// rule" (PydanticAI's guide), so every skip is compared with pydanticAISkips: the rules the package does not
// promise, each with the reason the suite gives. A skip not in that list, a listed skip that ran, a failure, or any
// other count of passed cases fails this test.
func TestPydanticAIDocker(t *testing.T) {
	t.Parallel()
	// Behind a token: a session taken over from another process needs an authenticated caller.
	const token = "pydantic-ai-docker-token"
	python, url, floor := frameworkDockerAs(t, "pydantic_ai", "plimsoll/sandbox:latest", token)

	report := filepath.Join(t.TempDir(), "report.xml")
	cmd := exec.Command(python, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-v", "-rs", "--junitxml="+report,
		filepath.Join("frameworks", "pydantic_ai", "docker_pydantic_ai_check.py"))
	cmd.Env = append(frameworkDockerEnv(url, floor), "PLIMSOLL_DOCKER_TOKEN="+token)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python -m pytest docker_pydantic_ai_check.py: %v", err)
	}
	passed, skipped, other := pytestOutcomes(t, report)
	if len(other) > 0 {
		t.Errorf("cases that neither passed nor skipped: %v", other)
	}
	for name, reason := range skipped {
		want, ok := pydanticAISkips[name]
		switch {
		case !ok:
			t.Errorf("%s skipped (%q), which the package promises to pass", name, reason)
		case reason != want:
			t.Errorf("%s skipped for %q, not the listed %q", name, reason, want)
		}
	}
	for name := range pydanticAISkips {
		if _, ok := skipped[name]; !ok {
			t.Errorf("%s is listed as a skip and did not skip: update pydanticAISkips and what the README promises", name)
		}
	}
	if len(passed) != pydanticAIPasses {
		sort.Strings(passed)
		t.Errorf("%d cases passed, want %d: %v", len(passed), pydanticAIPasses, passed)
	}
}

// pydanticAIPasses is how many cases of the docker check pass: the 20 conformance rules the package promises and the
// check's 10 agent and backend cases.
const pydanticAIPasses = 20 + 10

const noCommands = "backend does not implement SupportsCommands"

// pydanticAISkips is every rule of pydantic-ai-slim 2.70.0's WorkspaceBackendSuite that pydantic-ai-plimsoll
// does not promise, with the reason the suite skips it. The backend
// implements no SupportsCommands: the command rules skip, and so do the file rules that make their case with a
// command (a symlink, a FIFO, a chmod); the docker check makes those cases through plimsoll's shell tool and holds
// the backend to the same rules' expectations (the links, the loop in a listing, a FIFO, permission denied). The
// three attach rules need attach_backend, a backend reaching the session from another process, which the package
// does not offer. Of the three attach rules, which run with attach_backend (a backend of another capability, standing
// for another process, taking the session over from a shared checkpoint store), the one about a detached process
// skips as the command rules do: it starts its process with a command.
var pydanticAISkips = map[string]string{
	"test_command_form_must_match_shell":                            noCommands,
	"test_stdin_is_at_eof":                                          noCommands,
	"test_undecodable_command_bytes_are_replaced":                   noCommands,
	"test_command_output_is_complete":                               noCommands,
	"test_background_child_does_not_hold_up_completed_command":      noCommands,
	"test_result_reports_exit_code_stdout_and_stderr":               noCommands,
	"test_a_missing_program_exits_127":                              noCommands,
	"test_argv_items_are_literal":                                   noCommands,
	"test_run_starts_in_cwd":                                        noCommands,
	"test_timeout_raises_workspace_timeout_error":                   noCommands,
	"test_cancellation_stops_foreground_work":                       noCommands,
	"test_env_is_added":                                             noCommands,
	"test_commands_and_files_share_one_environment":                 noCommands,
	"test_symlink_loop_does_not_break_listing":                      noCommands,
	"test_fifo_read_does_not_wait_for_writer":                       noCommands,
	"test_permission_denied_uses_builtin_error":                     noCommands,
	"test_realpath_and_entries_follow_symlinks":                     noCommands,
	"test_writes_go_through_a_symlink":                              noCommands,
	"test_destroying_environment_during_command_raises_unavailable": noCommands,
	"test_a_backend_attached_by_ref_reaches_a_detached_process":     noCommands,
}

// junitReport is the part of pytest's --junitxml report this test reads: each case's name, and a skip's message,
// a failure or an error when the case had one. pytest's -v lines do not carry a skip's reason, and its -rs
// summary folds skips by the line that raised them, so the report is the one place each case's reason is.
type junitReport struct {
	Cases []struct {
		Name    string `xml:"name,attr"`
		Skipped *struct {
			Message string `xml:"message,attr"`
		} `xml:"skipped"`
		Failure *struct{} `xml:"failure"`
		Error   *struct{} `xml:"error"`
	} `xml:"testsuite>testcase"`
}

// pytestOutcomes reads a pytest --junitxml report: the cases that passed, those skipped with their reasons, and
// every case that failed or errored, as "name failed" or "name error".
func pytestOutcomes(t *testing.T, path string) (passed []string, skipped map[string]string, other []string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pytest wrote no report: %v", err)
	}
	var r junitReport
	if err := xml.Unmarshal(b, &r); err != nil {
		t.Fatalf("pytest's report: %v", err)
	}
	skipped = map[string]string{}
	for _, c := range r.Cases {
		switch {
		case c.Failure != nil:
			other = append(other, c.Name+" failed")
		case c.Error != nil:
			other = append(other, c.Name+" error")
		case c.Skipped != nil:
			skipped[c.Name] = strings.TrimSpace(c.Skipped.Message)
		default:
			passed = append(passed, c.Name)
		}
	}
	return passed, skipped, other
}
