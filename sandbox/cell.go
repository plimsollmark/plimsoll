package sandbox

import (
	"context"
	"slices"
	"strings"
	"time"
)

// Language is an interpreter's language: a cell's, and one an environment states.
type Language string

const (
	LanguageJavaScript Language = "javascript"
	LanguagePython     Language = "python"
)

// LanguageSpec is what plimsoll knows about one interpreter language, in one place:
// the shell command that proves an image runs it, and the two cells that prove a kept
// interpreter keeps state. How a session starts the interpreter is sessionkit's (a
// test in this package requires one for every language here). Adding a language was
// six coordinated edits across the providers' probes, the session smoke test and the
// name list, and missing one left it silently unoffered (review, 2026-10-23).
type LanguageSpec struct {
	Language Language
	// Probe prints the language's name, alone on a line, when the image runs it, and
	// nothing when it does not; it exits 0 either way, except for JavaScript, which the
	// runner itself needs and whose probe fails when node is missing.
	Probe string
	// Define and Read are cells: Read prints 42 when it runs in the interpreter that
	// ran Define.
	Define, Read string
}

// LanguageSpecs are the languages plimsoll keeps an interpreter for, JavaScript first.
var LanguageSpecs = []LanguageSpec{
	{LanguageJavaScript, `node -e 'console.log("javascript")'`, "globalThis.plimsollSmoke = 41", "plimsollSmoke + 1"},
	{LanguagePython, `{ python3 -I -c 'print("python")' 2>/dev/null || true; }`, "plimsoll_smoke = 41", "plimsoll_smoke + 1"},
}

// Languages are LanguageSpecs' languages. The Python and TypeScript clients' copies are
// generated from this list (internal/wiretables).
var Languages = func() []Language {
	out := make([]Language, len(LanguageSpecs))
	for i, s := range LanguageSpecs {
		out[i] = s.Language
	}
	return out
}()

// Known reports whether l is a language plimsoll keeps an interpreter for.
func (l Language) Known() bool { return slices.Contains(Languages, l) }

// LanguageProbe is one shell command that prints every known language an image runs,
// one per line, and fails when node is missing: every provider's startup check runs it.
func LanguageProbe() string {
	probes := make([]string, len(LanguageSpecs))
	for i, s := range LanguageSpecs {
		probes[i] = s.Probe
	}
	return strings.Join(probes, " && ")
}

// ProbedLanguages reads LanguageProbe's output: the known languages it names, in order,
// each once.
func ProbedLanguages(stdout string) []Language {
	var langs []Language
	for _, line := range strings.Fields(stdout) {
		if l := Language(line); l.Known() && !slices.Contains(langs, l) {
			langs = append(langs, l)
		}
	}
	return langs
}

// SupportsLanguage reports whether the environment states l.
func (e PayloadEnvironment) SupportsLanguage(l Language) bool { return slices.Contains(e.Languages, l) }

// CellRequest is one call to a session's interpreter (Session.RunCell). A session
// keeps one interpreter per language alive between its calls, so what a cell
// defines is there for the next cell, as in a notebook. A cell carries no grant:
// its interpreter outlives the call, and a grant lives for one call.
type CellRequest struct {
	Language Language
	Code     string
	// Files are written into the session's work directory, the interpreter's working
	// directory, before the code runs: how a caller hands a cell data, for example
	// the output of another tool.
	Files            []File
	Timeout          time.Duration
	MinimumIsolation IsolationClass
	Software         SoftwareRule
}

// CellResult is a cell's outcome.
type CellResult struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	// ExitCode is 0 when the code ran without raising, 1 when it raised (the error
	// is on Stderr), as a notebook reports a cell, and 124 when the call's deadline
	// ended it. A final expression's value is printed to Stdout.
	ExitCode int
	TimedOut bool
	// InterpreterStarted: this call started a fresh interpreter, so nothing an
	// earlier cell defined exists.
	InterpreterStarted bool
	// InterpreterEnded: the interpreter ended during this call (the code exited it,
	// it was killed, or the deadline passed); the next cell starts a fresh one.
	InterpreterEnded    bool
	Duration            time.Duration
	Sandbox             string
	Isolation           IsolationClass
	SoftwareIdentity    string
	EnvironmentIdentity string
	// Instance is the sandbox instance that ran it, as a typed reference ("k8s-pod-uid:" and
	// the pod's UID), or "" when the provider names none (sandbox.ValidInstance).
	Instance string
	// Record is the run record the daemon returned, filled in by the client.
	Record *RunRecord
}

// CellRunner is the cell half of a Session, named so a caller can hold just it.
type CellRunner interface {
	RunCell(ctx context.Context, req CellRequest) (CellResult, error)
}
