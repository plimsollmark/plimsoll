package python

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// TestDeepAgentsDocker runs frameworks/deepagents/docker_deepagents_check.py with the
// deepagents framework environment against a daemon served here on the docker provider,
// sessions on, with plimsoll/sandbox-python as the project image (Deep Agents' file tools
// run python3 in the sandbox): LangChain's standard sandbox tests and a scripted Deep
// Agents agent on a real session, and a thread resumed on another worker (PlimsollSandbox
// attach, which needs an authenticated caller, so the daemon takes a token). make
// docker-suite runs it (frameworkDocker says when it skips).
func TestDeepAgentsDocker(t *testing.T) {
	t.Parallel()
	const token = "deepagents-docker-token"
	python, url, floor := frameworkDockerAs(t, "deepagents", "plimsoll/sandbox-python:latest", token)

	cmd := exec.Command(python, "-B", "-m", "pytest", "-p", "no:cacheprovider", "-o", "asyncio_mode=auto", "-v", "-rsxX",
		filepath.Join("frameworks", "deepagents", "docker_deepagents_check.py"))
	cmd.Env = append(os.Environ(),
		"PLIMSOLL_DOCKER_SESSIONS_URL="+url,
		"PLIMSOLL_DOCKER_TOKEN="+token,
		"PLIMSOLL_DOCKER_FLOOR="+floor,
		"PYTHONPATH=src",
		"PYTHONDONTWRITEBYTECODE=1",
	)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("python -m pytest docker_deepagents_check.py: %v", err)
	}
	if dockerCheckSkip.Match(out) {
		t.Fatal("the Deep Agents docker check skipped a case, or one expected to fail passed; under this test every case must run")
	}
	// The cases langchain-tests and deepagents disagree on, and only they, fail as expected
	// (UPSTREAM_DISAGREEMENTS in the check, each strict, so a case that starts passing
	// fails the run).
	if !upstreamDisagreements.Match(out) {
		t.Fatal("expected exactly the check's 7 upstream disagreements to fail as expected (`7 xfailed`)")
	}
}

var (
	dockerCheckSkip       = regexp.MustCompile(`(?m)\b(SKIPPED|XPASS)\b|\b[0-9]+ (skipped|xpassed)\b`)
	upstreamDisagreements = regexp.MustCompile(`\b7 xfailed\b`)
)
