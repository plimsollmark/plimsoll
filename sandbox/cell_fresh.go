package sandbox

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// A cell run by itself (RunCellFresh) runs in a sandbox made for it, as one project of
// one step: the cell's files, its code in CellRunnerDir and a runner beside it that runs
// the code as a session's interpreter runs a cell (its statements, top-level await,
// imports from the work directory first, the value of a final expression printed),
// in one process that ends with the call. These were the TypeScript client's and the
// MCP server's fresh-call runners, byte for byte, until the daemon took the path over.
//
// The Python runner reads the cell as UTF-8 whatever the image's locale, and runs it at
// module level with an event loop only for code that awaits at the top level, so the
// cell's own asyncio.run works. The JavaScript runner's top-level await comes from
// Node's private module internal/repl/await (the REPL's own rewrite of a cell), which
// only --expose-internals makes loadable; it is not a public API. Its test runs it on
// the node that runs the suite (22.18.0 in CI, the line of the project image's node:22
// base; it also passed on 26.3.1 on 2026-10-07). If a Node release moves or removes it,
// the runner runs the cell without the rewrite: a cell that awaits at the top level
// then fails visibly (a SyntaxError on stderr, exit code 1), and so does
// TestFreshRunnersRunWhatACellRuns; a cell without top-level await runs as before.
var (
	//go:embed cellrunner/run.py
	cellRunnerPython string
	//go:embed cellrunner/run.cjs
	cellRunnerJavaScript string
)

// CellRunnerDir is the directory of a fresh cell's work directory that holds its code
// and its runner, so a cell run by itself may not send a file there (CheckRunCell).
const CellRunnerDir = ".plimsoll"

// cellRunner is one language's fresh form: where the code goes, where the runner goes,
// the one step that runs it, and the runner's source.
type cellRunner struct{ code, runner, step, source string }

var cellRunners = map[Language]cellRunner{
	LanguagePython:     {code: ".plimsoll/cell.py", runner: ".plimsoll/run.py", step: "python3 -I .plimsoll/run.py", source: cellRunnerPython},
	LanguageJavaScript: {code: ".plimsoll/cell.js", runner: ".plimsoll/run.cjs", step: "node --expose-internals .plimsoll/run.cjs", source: cellRunnerJavaScript},
}

// SnippetCell is a JavaScript cell's code as a snippet that prints its final value, for
// a provider that runs snippets only (wasm): Node's inspection where require exists,
// else JSON, else String, on Node and QuickJS alike. A snippet takes no files.
func SnippetCell(code string) string {
	quoted, _ := json.Marshal(code)
	return strings.Join([]string{
		"(() => {",
		"  const show = (v) => {",
		`    if (typeof require === "function") { try { return require("node:util").inspect(v, { depth: 4 }); } catch (_) {} }`,
		"    try { const s = JSON.stringify(v); if (s !== undefined) return s; } catch (_) {}",
		"    return String(v);",
		"  };",
		"  const v = (0, eval)(" + string(quoted) + ");",
		"  Promise.resolve(v).then((v) => { if (v !== undefined) console.log(show(v)); });",
		"})();",
		"",
	}, "\n")
}

// runsProjects reports whether sb runs projects, and the project environment it states.
func runsProjects(sb Sandbox) (bool, PayloadEnvironment) {
	pc, ok := sb.(ProjectCapable)
	if !ok || !pc.SupportsProjects() {
		return false, PayloadEnvironment{}
	}
	if d, ok := sb.(Describer); ok {
		return true, d.Environments().Project
	}
	return true, PayloadEnvironment{}
}

// CheckRunCell refuses, marked not dispatched, a cell that cannot run by itself on sb: a
// malformed one (ValidateCellRequest), one that sends a file under CellRunnerDir, where
// its code and runner go (reason request), and one sb has no way to run in a sandbox
// made for it (reason unsupported): a provider that runs projects runs every language
// its project environment states (all, when it states none), and one that runs no
// projects runs only a JavaScript cell without files, as a snippet. It does not depend
// on whether a pool member is waiting, so a call that asks for one is refused for the
// same reasons, and only those, as one that does not.
func CheckRunCell(sb Sandbox, req CellRequest) error {
	if err := ValidateCellRequest(req); err != nil {
		return err
	}
	for _, f := range req.Files {
		if f.Path == CellRunnerDir || strings.HasPrefix(f.Path, CellRunnerDir+"/") {
			return NotDispatched(RefusalRequest, fmt.Errorf("%w: %q is under %s/, where a cell run by itself keeps its code and runner", ErrInvalidRequest, f.Path, CellRunnerDir))
		}
	}
	projects, env := runsProjects(sb)
	switch {
	case projects && (len(env.Languages) == 0 || env.SupportsLanguage(req.Language)):
		return nil
	case projects:
		return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: the project image runs no %s interpreter (it runs %s)", ErrUnsupported, req.Language, languageList(env.Languages)))
	case req.Language != LanguageJavaScript:
		return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: provider %s runs JavaScript snippets only, not %s", ErrUnsupported, sb.Name(), req.Language))
	case len(req.Files) > 0:
		return NotDispatched(RefusalUnsupported, fmt.Errorf("%w: provider %s runs JavaScript snippets only, which take no files", ErrUnsupported, sb.Name()))
	}
	return nil
}

func languageList(langs []Language) string {
	if len(langs) == 0 {
		return "none"
	}
	names := make([]string, len(langs))
	for i, l := range langs {
		names[i] = string(l)
	}
	return strings.Join(names, ", ")
}

// cellTimedOut is a cell's exit code when the call's deadline ended it.
const cellTimedOut = 124

// RunCellFresh runs req by itself in a sandbox made for it on sb, after CheckRunCell:
// as one project of one step (the cell's files, its code and its runner under
// CellRunnerDir), or, on a provider that runs no projects, as a snippet (SnippetCell).
// The cell keeps nothing, so the result states InterpreterStarted and InterpreterEnded.
// Its streams and exit code are the step's (or the snippet's), a timed-out one exit 124;
// the runner exits 1 when the code raised, as a session cell reports, and passes on an
// exit code the code itself chose (a session cell reports 1). A project that ended
// setup_failed with no step report ran none of the cell (its files could not be
// written), refused not dispatched, reason request; any other end without a step report
// is an unmarked error, since the code may have run.
func RunCellFresh(ctx context.Context, sb Sandbox, req CellRequest) (CellResult, error) {
	if err := CheckRunCell(sb, req); err != nil {
		return CellResult{Sandbox: sb.Name()}, err
	}
	started := time.Now()
	if projects, _ := runsProjects(sb); !projects {
		res, err := sb.RunJavaScript(ctx, Request{Code: SnippetCell(req.Code), Timeout: req.Timeout, MinimumIsolation: req.MinimumIsolation, Software: req.Software})
		out := CellResult{
			Stdout: res.Stdout, Stderr: res.Stderr, StdoutTruncated: res.StdoutTruncated, StderrTruncated: res.StderrTruncated,
			ExitCode: res.ExitCode, TimedOut: res.TimedOut, InterpreterStarted: true, InterpreterEnded: true, Duration: res.Duration,
			Sandbox: res.Sandbox, Isolation: res.Isolation, SoftwareIdentity: res.SoftwareIdentity, EnvironmentIdentity: res.EnvironmentIdentity, Instance: res.Instance,
			Policy: res.Policy,
		}
		if out.TimedOut {
			out.ExitCode = cellTimedOut
		}
		return out, err
	}
	r := cellRunners[req.Language]
	files := append(slices.Clone(req.Files), File{Path: r.code, Content: req.Code}, File{Path: r.runner, Content: r.source})
	res, err := sb.RunProject(ctx, ProjectRequest{Files: files, Steps: []string{r.step}, Timeout: req.Timeout, MinimumIsolation: req.MinimumIsolation, Software: req.Software})
	out := CellResult{
		InterpreterStarted: true, InterpreterEnded: true, Duration: time.Since(started),
		Sandbox: res.Sandbox, Isolation: res.Isolation, SoftwareIdentity: res.SoftwareIdentity, EnvironmentIdentity: res.EnvironmentIdentity, Instance: res.Instance,
		Policy: res.Policy,
	}
	if err != nil {
		return out, err
	}
	if len(res.Steps) == 0 {
		switch res.Outcome {
		case ProjectOutcomeTimedOut:
			out.ExitCode, out.TimedOut = cellTimedOut, true
			return out, nil
		case ProjectOutcomeSetupFailed:
			return out, NotDispatched(RefusalRequest, fmt.Errorf("%w: the cell's files could not be set up, so none of it ran: %s", ErrInvalidRequest, res.Detail))
		}
		return out, fmt.Errorf("sandbox: the cell's run ended %s without a step report (%s); the code may have run", res.Outcome, res.Detail)
	}
	st := res.Steps[0]
	out.Stdout, out.Stderr, out.StdoutTruncated, out.StderrTruncated = st.Stdout, st.Stderr, st.StdoutTruncated, st.StderrTruncated
	out.ExitCode, out.TimedOut = st.ExitCode, st.TimedOut || res.Outcome == ProjectOutcomeTimedOut
	if out.TimedOut {
		out.ExitCode = cellTimedOut
	}
	return out, nil
}
