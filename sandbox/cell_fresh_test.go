package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// freshFake records the run RunCellFresh makes and answers it as told.
type freshFake struct {
	projects bool
	env      Environments
	proj     ProjectResult
	js       Result
	gotProj  []ProjectRequest
	gotJS    []Request
}

func (*freshFake) Name() string                   { return "fresh-fake" }
func (*freshFake) IsolationClass() IsolationClass { return IsolationContainer }
func (f *freshFake) SupportsProjects() bool       { return f.projects }
func (f *freshFake) Environments() Environments   { return f.env }
func (f *freshFake) RunJavaScript(_ context.Context, req Request) (Result, error) {
	f.gotJS = append(f.gotJS, req)
	return f.js, nil
}
func (f *freshFake) RunProject(_ context.Context, req ProjectRequest) (ProjectResult, error) {
	f.gotProj = append(f.gotProj, req)
	return f.proj, nil
}
func (*freshFake) RunModule(context.Context, ModuleRequest) (ModuleResult, error) {
	return ModuleResult{}, NotDispatched(RefusalUnsupported, ErrUnsupported)
}

// Every language plimsoll keeps an interpreter for has a fresh runner.
func TestEveryLanguageHasAFreshRunner(t *testing.T) {
	for _, l := range Languages {
		if r, ok := cellRunners[l]; !ok || r.source == "" || !strings.HasPrefix(r.code, CellRunnerDir+"/") || !strings.HasPrefix(r.runner, CellRunnerDir+"/") {
			t.Errorf("%s has no fresh runner under %s/", l, CellRunnerDir)
		}
	}
}

// A cell runs fresh as one project: its files, then its code and its runner under
// .plimsoll/, one step, the request's limits; the step's answer is the cell's, and the
// cell keeps nothing.
func TestRunCellFreshRunsOneProject(t *testing.T) {
	f := &freshFake{projects: true, env: Environments{Project: PayloadEnvironment{Languages: []Language{LanguagePython, LanguageJavaScript}}},
		proj: ProjectResult{Sandbox: "fresh-fake", Isolation: IsolationContainer, SoftwareIdentity: "sw", EnvironmentIdentity: "env", Instance: "docker-container:abc",
			Outcome: ProjectOutcomeCompleted, Steps: []StepResult{{Stdout: "42\n", Stderr: "warn\n", ExitCode: 1, StdoutTruncated: true}}}}
	req := CellRequest{Language: LanguagePython, Code: "6 * 7", Files: []File{{Path: "a.csv", Content: "a"}}, Timeout: 3e9, MinimumIsolation: IsolationContainer,
		Software: SoftwareRule{Mode: SoftwareExact, Identities: []string{"sw"}}}
	res, err := RunCellFresh(context.Background(), f, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.gotProj) != 1 {
		t.Fatalf("%d projects; want one", len(f.gotProj))
	}
	p := f.gotProj[0]
	paths := []string{}
	for _, file := range p.Files {
		paths = append(paths, file.Path)
	}
	if !slices.Equal(paths, []string{"a.csv", ".plimsoll/cell.py", ".plimsoll/run.py"}) || p.Files[1].Content != "6 * 7" || p.Files[2].Content != cellRunnerPython {
		t.Fatalf("files %v; want the cell's, then its code and the python runner", paths)
	}
	if !slices.Equal(p.Steps, []string{"python3 -I .plimsoll/run.py"}) || p.Timeout != req.Timeout || p.MinimumIsolation != req.MinimumIsolation || p.Software.ID() != req.Software.ID() {
		t.Fatalf("project %+v; want one runner step under the cell's limits", p)
	}
	want := CellResult{Stdout: "42\n", Stderr: "warn\n", ExitCode: 1, StdoutTruncated: true, InterpreterStarted: true, InterpreterEnded: true,
		Sandbox: "fresh-fake", Isolation: IsolationContainer, SoftwareIdentity: "sw", EnvironmentIdentity: "env", Instance: "docker-container:abc"}
	res.Duration = 0
	if res != want {
		t.Fatalf("result %+v; want %+v", res, want)
	}
}

// How a project's end without a usable step becomes the cell's answer: a timeout is exit
// 124, a setup that failed before any step began ran nothing (not dispatched, request),
// and any other end without a step report may have run (unmarked).
func TestRunCellFreshEnds(t *testing.T) {
	cell := CellRequest{Language: LanguageJavaScript, Code: "1"}
	for _, tc := range []struct {
		name   string
		proj   ProjectResult
		exit   int
		timed  bool
		marked bool
		reason Refusal
		fails  bool
	}{
		{"timed out step", ProjectResult{Outcome: ProjectOutcomeTimedOut, Steps: []StepResult{{ExitCode: -1, TimedOut: true}}}, 124, true, false, 0, false},
		{"timed out, no step", ProjectResult{Outcome: ProjectOutcomeTimedOut}, 124, true, false, 0, false},
		{"setup failed", ProjectResult{Outcome: ProjectOutcomeSetupFailed, Detail: "illegal file path"}, 0, false, true, RefusalRequest, true},
		{"protocol error", ProjectResult{Outcome: ProjectOutcomeProtocolError}, 0, false, false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &freshFake{projects: true, proj: tc.proj}
			res, err := RunCellFresh(context.Background(), f, cell)
			if (err != nil) != tc.fails {
				t.Fatalf("err %v; want failure %v", err, tc.fails)
			}
			reason, marked := NotDispatchedReason(err)
			if marked != tc.marked || (marked && reason != tc.reason) {
				t.Fatalf("err %v marked %v (%v); want marked %v (%v)", err, marked, reason, tc.marked, tc.reason)
			}
			if !tc.fails && (res.ExitCode != tc.exit || res.TimedOut != tc.timed) {
				t.Fatalf("exit %d timed out %v; want %d %v", res.ExitCode, res.TimedOut, tc.exit, tc.timed)
			}
		})
	}
}

// A provider that runs no projects runs a JavaScript cell without files as a snippet
// that prints its value, and refuses anything else, not dispatched, before running.
func TestRunCellFreshOnASnippetProvider(t *testing.T) {
	f := &freshFake{js: Result{Stdout: "2\n", Sandbox: "fresh-fake", Isolation: IsolationProcess, TimedOut: true}}
	res, err := RunCellFresh(context.Background(), f, CellRequest{Language: LanguageJavaScript, Code: "1 + 1"})
	if err != nil || len(f.gotJS) != 1 || f.gotJS[0].Code != SnippetCell("1 + 1") || res.ExitCode != 124 || !res.InterpreterEnded {
		t.Fatalf("snippet path: %+v, %v, %d snippets; want the snippet runner's answer", res, err, len(f.gotJS))
	}
	for _, req := range []CellRequest{
		{Language: LanguagePython, Code: "1"},
		{Language: LanguageJavaScript, Code: "1", Files: []File{{Path: "a", Content: "a"}}},
	} {
		_, err := RunCellFresh(context.Background(), &freshFake{}, req)
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalUnsupported || !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%v on a snippet provider: %v; want refused, unsupported", req, err)
		}
	}
}

// Refused before anything runs: a file where the runner goes, and a language the
// project image does not state.
func TestCheckRunCellRefusals(t *testing.T) {
	f := &freshFake{projects: true, env: Environments{Project: PayloadEnvironment{Languages: []Language{LanguageJavaScript}}}}
	for _, path := range []string{".plimsoll", ".plimsoll/run.py", ".plimsoll/x/y"} {
		err := CheckRunCell(f, CellRequest{Language: LanguageJavaScript, Code: "1", Files: []File{{Path: path, Content: "x"}}})
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalRequest {
			t.Errorf("a file at %s: %v; want refused, request", path, err)
		}
	}
	if err := CheckRunCell(f, CellRequest{Language: LanguageJavaScript, Code: "1", Files: []File{{Path: ".plimsollx", Content: "x"}}}); err != nil {
		t.Errorf("a file beside the runner's directory: %v; want it allowed", err)
	}
	err := CheckRunCell(f, CellRequest{Language: LanguagePython, Code: "1"})
	if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalUnsupported {
		t.Errorf("python on a JavaScript-only image: %v; want refused, unsupported", err)
	}
	if len(f.gotProj) != 0 {
		t.Fatal("a refused cell ran")
	}
}

// The runners, run here on this machine's interpreters as a sandbox runs them: the code
// in .plimsoll/, the runner beside it, the work directory the current directory.
func runRunner(t *testing.T, l Language, code string, extra map[string]string, args ...string) string {
	t.Helper()
	r := cellRunners[l]
	bin := "python3"
	if l == LanguageJavaScript {
		bin = "node"
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s is not installed", bin)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, CellRunnerDir), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{r.code: code, r.runner: r.source}
	for p, c := range extra {
		files[p] = c
	}
	for p, c := range files {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	argv := strings.Fields(r.step)
	cmd := exec.Command(argv[0], append(args, argv[1:]...)...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s runner: %v (%s)", l, err, out)
	}
	return string(out)
}

// A fresh cell prints its last expression and takes what a session cell takes: imports
// from the work directory (Python's own imports first, in isolated mode), top-level
// await, Python's asyncio.run, Node's CommonJS names. These are the checks the
// TypeScript client ran on the runners while they were its own.
func TestFreshRunnersRunWhatACellRuns(t *testing.T) {
	for _, tc := range []struct {
		lang  Language
		code  string
		extra map[string]string
		want  string
	}{
		{LanguagePython, "rows = [1, 2, 3]\nprint('printed')\nsum(rows)", nil, "printed\n6\n"},
		{LanguageJavaScript, "const rows = [1, 2, 3];\nconsole.log('printed');\nrows.reduce((a, b) => a + b, 0)", nil, "printed\n6\n"},
		{LanguagePython, "import asyncio, helper\nawait asyncio.sleep(0)\nhelper.x + 1",
			map[string]string{"helper.py": "x = 5\n", "json.py": "raise SystemExit('a work-directory json.py ran')\n"}, "6\n"},
		{LanguageJavaScript, "const helper = require('./helper.js');\nawait new Promise((r) => setTimeout(r, 1));\nhelper.x + 1",
			map[string]string{"helper.js": "module.exports = { x: 5 };\n"}, "6\n"},
		{LanguagePython, "import asyncio\nasync def f():\n    return 41\nif __name__ == '__main__':\n    x = asyncio.run(f())\nx + 1", nil, "42\n"},
		{LanguageJavaScript, "[typeof module, typeof exports, typeof require, __dirname, __filename].join(' ')", nil, "'object object function . [eval]'\n"},
	} {
		if got := runRunner(t, tc.lang, tc.code, tc.extra); got != tc.want {
			t.Errorf("%s %q printed %q; want %q", tc.lang, tc.code, got, tc.want)
		}
	}
}

// A guest gets the image's environment, so the Python runner reads the cell as the
// UTF-8 the client wrote whatever the locale: LC_ALL=C with UTF-8 mode off stands in
// for an image whose locale's encoding is ASCII.
func TestFreshPythonRunnerReadsUTF8UnderAnotherLocale(t *testing.T) {
	t.Setenv("LC_ALL", "C")
	if got := runRunner(t, LanguagePython, "s = \"h\xc3\xa9llo\"\nlen(s)", nil, "-X", "utf8=0"); got != "5\n" {
		t.Fatalf("printed %q; want 5", got)
	}
}

// The snippet form prints the last value on Node as on QuickJS.
func TestSnippetCellPrintsTheLastValue(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command("node", "-e", SnippetCell("const rows = [1, 2, 3];\nconsole.log('printed');\nrows.reduce((a, b) => a + b, 0)")).Output()
	if err != nil || string(out) != "printed\n6\n" {
		t.Fatalf("node printed %q, %v; want the line and 6", out, err)
	}
}
