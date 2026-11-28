package python

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/clientsuite"
)

// TestPythonFrameworks runs each framework adapter's suite, frameworks/<name>/, with
// that framework installed: a virtual environment per framework at
// tmp/py-frameworks/<name> (make clients-suite builds it from the directory's
// requirements.txt), since the client itself has no dependencies and the frameworks'
// own conflict. A framework is a directory, so adding one needs no change here.
//
// The suites call each tool through the framework's own tool-call path, with no model,
// against the daemons of internal/clientsuite's table, the ones every client driver
// serves (P7b of the refactor plan of 2026-11-18; until then this driver served three of
// its own, one under the name the table gives another daemon). The suites read three:
// tool-echo, a container-tier provider that runs nothing and answers each project with
// what it was asked to run, or with the failure a marker in the code names, whose handler
// can hold a Describe or a Run until a test releases it; wasm, the real wasm provider,
// which runs no projects; and sessions, the in-memory session provider.
// frameworksDeclined says why they use no other.
func TestPythonFrameworks(t *testing.T) {
	dirs, err := filepath.Glob("frameworks/*/requirements.txt")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no framework suites under frameworks/: %v", err)
	}
	env := append(withoutTracing(os.Environ()), clientsuite.Env(t)...)
	env = append(env,
		"PLIMSOLL_INTEGRATION_REQUIRED=1",
		// plimsoll-client, and every framework package (<name>-plimsoll/src) a suite imports.
		"PYTHONPATH="+strings.Join(append([]string{"src"}, frameworkPackages(t)...), string(os.PathListSeparator)),
		"PYTHONDONTWRITEBYTECODE=1",
	)
	for _, req := range dirs {
		dir := filepath.Dir(req)
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			python, err := filepath.Abs(filepath.Join("..", "..", "tmp", "py-frameworks", name, "bin", "python"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(python); err != nil {
				clientSkipOrFail(t, "no environment for %s at %s: run make clients-suite", name, python)
			}
			// A suite whose directory has a pytest.ini runs under pytest (LangChain's
			// standard tests are pytest classes); every other under unittest.
			args, runner, skipped := []string{"-B", "-m", "unittest", "discover", "-s", dir, "-t", ".", "-v"}, "unittest", pythonSkip
			if _, err := os.Stat(filepath.Join(dir, "pytest.ini")); err == nil {
				args, runner, skipped = []string{"-B", "-m", "pytest", "-p", "no:cacheprovider", "-v", "-rsxX", dir}, "pytest", pytestSkip
			}
			cmd := exec.Command(python, args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			t.Logf("%s", out)
			if err != nil {
				t.Fatalf("%s: python -m %s: %v", name, runner, err)
			}
			if skipped.Match(out) {
				t.Fatalf("the %s suite skipped a case; under this test every case must run", name)
			}
			// The environment holds no LangSmith key (withoutTracing), so an upload a suite
			// set off fails, and LangSmith's client logs the failure with its URL.
			if bytes.Contains(out, []byte("api.smith.langchain.com")) {
				t.Fatalf("the %s suite tried to send runs to LangSmith; no test may", name)
			}
		})
	}
}

// frameworkPackages is the src directory of every framework package beside plimsoll-client
// (clients/python/<name>-plimsoll, each a thin package over a module of plimsoll-client), so a
// suite imports the package it tests, and a package is added by adding its directory. It
// fails when it finds none: crewai-plimsoll and langchain-plimsoll are always there.
func frameworkPackages(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join("*-plimsoll", "src"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no framework package under clients/python/*-plimsoll/src (%v)", err)
	}
	return dirs
}

// TestAdaptersPinTheVersionTheirLockInstalls: every framework package beside plimsoll-client
// (clients/python/<name>-plimsoll, found by listing them) requires exactly the version of
// each framework package that its suite's lock file installs
// (frameworks/<name>/requirements.txt), and each of its extras exactly what the extra's own
// suite installs (frameworks/<extra>/requirements.txt). So what pip installs beside an
// adapter is what the adapter was tested with: a range, a different version, or a
// requirement its lock does not install fails here. Each adapter is pinned to the exact
// version it is tested at since 2026-11-20 (finding hunt-quality-65: four of the five
// declared a range of framework versions and were tested at one). plimsoll-client's own
// extras (clients/python/pyproject.toml, one per framework adapter it carries) are held
// the same way, each to its extra's suite, since the same day (hunt-quality-74: they still
// declared ranges, and five adapters are installed only through them). It reads the files
// as text and needs no Python.
func TestAdaptersPinTheVersionTheirLockInstalls(t *testing.T) {
	dirs, err := filepath.Glob("*-plimsoll")
	if err != nil || len(dirs) < 5 {
		t.Fatalf("found %d framework packages under clients/python/*-plimsoll, fewer than the five there were (%v)", len(dirs), err)
	}
	// "." is plimsoll-client itself: no dependencies, and an extra per framework adapter.
	for _, dir := range append(dirs, ".") {
		pkg := dir
		deps, extras := pyprojectRequirements(t, filepath.Join(dir, "pyproject.toml"))
		switch {
		case dir == ".":
			pkg = "plimsoll-client"
			if len(deps) != 0 {
				t.Errorf("plimsoll-client declares the dependencies %q; it has none, and each framework comes through its extra", deps)
			}
			if len(extras) < 8 {
				t.Errorf("plimsoll-client declares %d extras, fewer than the eight there were: is the scan reading clients/python/pyproject.toml?", len(extras))
			}
		case len(deps) == 0:
			t.Errorf("%s declares no dependencies: is the scan reading its pyproject.toml?", dir)
		}
		pinned := 0
		check := func(what, suite string, reqs []string) {
			lockFile := filepath.Join("frameworks", strings.ReplaceAll(suite, "-", "_"), "requirements.txt")
			lock := lockedVersions(t, lockFile)
			for _, req := range reqs {
				m := pyRequirement.FindStringSubmatch(req)
				if m == nil {
					t.Errorf("%s: %s: cannot read the requirement %q", pkg, what, req)
					continue
				}
				name, spec := pyName(m[1]), strings.ReplaceAll(m[2], " ", "")
				if name == "plimsoll-client" {
					continue // the client itself, pinned to the package's own version (each suite checks it)
				}
				locked, ok := lock[name]
				switch {
				case !ok:
					t.Errorf("%s: %s requires %s, which its suite's lock file %s does not install", pkg, what, name, lockFile)
				case spec != "=="+locked:
					t.Errorf("%s: %s declares %q; want %s==%s, exactly the version its suite's lock file %s installs", pkg, what, req, m[1], locked, lockFile)
				default:
					pinned++
				}
			}
		}
		if len(deps) > 0 {
			check("its dependencies", strings.TrimSuffix(dir, "-plimsoll"), deps)
		}
		for extra, reqs := range extras {
			check("its extra "+extra, extra, reqs)
		}
		if pinned == 0 && !t.Failed() {
			t.Errorf("%s pins no framework: is the scan reading its pyproject.toml?", pkg)
		}
	}
}

// pyRequirement is a requirement as these packages write one: a name, extras or none, and
// the version rule (no environment marker).
var pyRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*([^;]*)$`)

// pyName is a package name as pip compares names: lowercase, with each run of "-", "_"
// and "." one "-".
func pyName(name string) string {
	return regexp.MustCompile(`[-_.]+`).ReplaceAllString(strings.ToLower(name), "-")
}

// pyprojectRequirements reads a pyproject.toml's [project] dependencies (an empty list
// included) and each list of its [project.optional-dependencies], as these packages
// write them: one quoted requirement per line, or a list on one line.
func pyprojectRequirements(t *testing.T, path string) (deps []string, extras map[string][]string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	quoted := regexp.MustCompile(`"([^"]+)"`)
	extras = map[string][]string{}
	section, inDeps, sawDeps := "", false, false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		code, _, _ := strings.Cut(trimmed, "#")
		switch {
		case strings.HasPrefix(trimmed, "[") && !inDeps:
			section = trimmed
		case section == "[project]" && strings.HasPrefix(code, "dependencies"):
			inDeps, sawDeps = !strings.Contains(code, "]"), true
			for _, m := range quoted.FindAllStringSubmatch(code, -1) {
				deps = append(deps, m[1])
			}
		case inDeps:
			for _, m := range quoted.FindAllStringSubmatch(code, -1) {
				deps = append(deps, m[1])
			}
			inDeps = !strings.Contains(code, "]")
		case section == "[project.optional-dependencies]" && strings.Contains(code, "="):
			key, list, _ := strings.Cut(code, "=")
			if !strings.Contains(list, "]") {
				t.Fatalf("%s: the extra %s is not a list on one line, which this reader takes", path, strings.TrimSpace(key))
			}
			for _, m := range quoted.FindAllStringSubmatch(list, -1) {
				extras[strings.TrimSpace(key)] = append(extras[strings.TrimSpace(key)], m[1])
			}
		}
	}
	// An empty list is read (plimsoll-client's own is empty); a missing one is not.
	if !sawDeps {
		t.Fatalf("%s: found no [project] dependencies", path)
	}
	return deps, extras
}

// lockedVersions reads a pip-compile lock file: each package it installs, by pip's form of
// its name, with the one version it is locked to.
func lockedVersions(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no lock file for the suite: %v", err)
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)`).FindAllStringSubmatch(string(raw), -1) {
		out[pyName(m[1])] = m[2]
	}
	if len(out) == 0 {
		t.Fatalf("%s locks no package", path)
	}
	return out
}

// withoutTracing drops LangSmith's and LangChain's settings from the environment the
// suites run in: with LANGSMITH_TRACING set, LangChain would upload every traced test
// call, the model-free tool calls of these suites included, to LangSmith. The LangSmith
// cases (frameworks/langchain/test_langsmith.py) keep their tracer's runs in memory.
// OpenAI's settings go too: the OpenAI Agents SDK exports its traces to OpenAI whenever
// OPENAI_API_KEY is set, and its suites keep their spans in memory.
func withoutTracing(environ []string) []string {
	out := environ[:0:0]
	for _, kv := range environ {
		if !strings.HasPrefix(kv, "LANGSMITH_") && !strings.HasPrefix(kv, "LANGCHAIN_") && !strings.HasPrefix(kv, "OPENAI_") {
			out = append(out, kv)
		}
	}
	return out
}

// pytestSkip finds a skipped, expected-to-fail or unexpectedly passing case in a pytest
// run's report: under this test every case must run and pass.
var pytestSkip = regexp.MustCompile(`(?m)\b(SKIPPED|XFAIL|XPASS)\b|\b[0-9]+ (skipped|xfailed|xpassed)\b`)

// The reasons the framework suites decline a daemon of the table: an adapter calls
// plimsoll through the client, so what the client checks of an answer, a session or a
// connection is the client suite's (tests/), and an adapter's suite tests what the adapter
// does with what the client returned or raised.
const (
	declinedClientsCheck = "a check the client makes of a hostile or broken answer, tested in the client's suite (tests/); an adapter gets what the client raised, which the tool-echo daemon's markers produce"
	declinedSessionEdge  = "a session edge case the client handles (tests/); the adapters' unanswered and ended-session paths are tested against fakes and the tool-echo daemon"
	declinedPool         = "no adapter sends a Run cell that prefers a pool member (prefer_warm is the client's alone)"
)

// frameworksDeclined names the daemons of internal/clientsuite's table the framework
// suites do not use, and why; TestPythonFrameworksUseOrDeclineEveryDaemon fails a daemon
// they neither read nor name here.
var frameworksDeclined = map[string]string{
	"PLIMSOLL_AUTH_URL":           "authentication is the client's (tests/); no adapter takes a token of its own",
	"PLIMSOLL_AUTH_TOKEN":         "authentication is the client's (tests/); no adapter takes a token of its own",
	"PLIMSOLL_TAMPER_URL":         declinedClientsCheck,
	"PLIMSOLL_SCRIPTED_URL":       "values a JSON client is likely to get wrong are the client's to read (tests/); no adapter parses an answer",
	"PLIMSOLL_SCRIPTED_SOFTWARE":  "values a JSON client is likely to get wrong are the client's to read (tests/); no adapter parses an answer",
	"PLIMSOLL_LIAR_URL":           declinedClientsCheck,
	"PLIMSOLL_OWNER_CAP_URL":      declinedSessionEdge,
	"PLIMSOLL_BREAKING_URL":       declinedSessionEdge,
	"PLIMSOLL_LOSSY_URL":          declinedSessionEdge,
	"PLIMSOLL_QUICK_IDLE_URL":     declinedSessionEdge,
	"PLIMSOLL_POOLED_URL":         declinedPool,
	"PLIMSOLL_DRAINED_URL":        declinedPool,
	"PLIMSOLL_ONE_CALL_URL":       declinedPool,
	"PLIMSOLL_NO_POOL_URL":        declinedPool,
	"PLIMSOLL_CLAIM_MISS_URL":     declinedPool,
	"PLIMSOLL_ECHO_URL":           "the plan echo of an executeCode call, for the TypeScript tools; a framework tool is checked against tool-echo, whose answer carries the files' contents and the budget",
	"PLIMSOLL_REPLAY_REFUSAL_URL": declinedClientsCheck,
	"PLIMSOLL_REPLAY_SUCCESS_URL": declinedClientsCheck,
	"PLIMSOLL_REPLAY_RUNS_URL":    declinedClientsCheck,
	"PLIMSOLL_UNBOUND_URL":        declinedClientsCheck,
	"PLIMSOLL_EARLY_REFUSAL_URL":  declinedClientsCheck,
	"PLIMSOLL_NO_PROCEDURE_URL":   declinedClientsCheck,
	"PLIMSOLL_TLS_URL":            "TLS is the client's transport (tests/); no adapter opens a connection of its own",
	"PLIMSOLL_TLS_CA":             "TLS is the client's transport (tests/); no adapter opens a connection of its own",
	"PLIMSOLL_REATTACH_URL":       declinedAttach,
	"PLIMSOLL_REATTACH_TOKEN":     declinedAttach,
	"PLIMSOLL_ATTACH_LIAR_URL":    declinedAttach,
	"PLIMSOLL_FILES_URL":          "the shared file-call cases run through the client's Session.run_files (tests/), the one call every adapter's file operations end in",
}

// declinedAttach: the one adapter that attaches, the Deep Agents backend, is checked over a
// fake client here and on a real docker session (TestDeepAgentsDocker); the client's attach
// against these daemons is checked in tests/.
const declinedAttach = "the Deep Agents attach is checked over a fake client here and on docker; the client's attach in tests/"

func TestPythonFrameworksUseOrDeclineEveryDaemon(t *testing.T) {
	clientsuite.CheckDeclined(t, frameworksDeclined, filepath.Join("frameworks", "*.py"), filepath.Join("frameworks", "*", "*.py"))
}
