package python

import "testing"

// TestSmolagentsDocker runs frameworks/smolagents/docker_smolagents_check.py on
// plimsoll/sandbox-python: a scripted CodeAgent's three steps in one session's Python
// interpreter, a variable kept from the first step to the second and the third's
// final_answer ending the run; and a step that prints past the sandbox's output limit and a
// terminal control sequence, whose result is lost while the run goes on. make docker-suite runs
// it (DOCKER_PY_TESTS in the Makefile); clients-suite excludes it, as it does every check on a
// real docker session.
func TestSmolagentsDocker(t *testing.T) {
	t.Parallel()
	python, url, floor := frameworkDocker(t, "smolagents", "plimsoll/sandbox-python:latest")
	frameworkDockerCheck(t, python, url, floor, "frameworks.smolagents.docker_smolagents_check", 2)
}
