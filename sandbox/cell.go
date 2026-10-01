package sandbox

import (
	"context"
	"slices"
	"time"
)

// Language is an interpreter's language: a cell's, and one an environment states.
type Language string

const (
	LanguageJavaScript Language = "javascript"
	LanguagePython     Language = "python"
)

// Known reports whether l is a language plimsoll keeps an interpreter for.
func (l Language) Known() bool { return l == LanguageJavaScript || l == LanguagePython }

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
	// Record is the run record the daemon returned, filled in by the client.
	Record *RunRecord
}

// CellRunner is the cell half of a Session, named so a caller can hold just it.
type CellRunner interface {
	RunCell(ctx context.Context, req CellRequest) (CellResult, error)
}
