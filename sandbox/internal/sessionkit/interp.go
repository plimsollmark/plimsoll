package sessionkit

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"sync"
)

// A session may keep one interpreter per language alive between its calls, so what
// a cell defines is there for the next cell. The four programs below run in the
// sandbox:
//
//   - launch.sh starts an interpreter in its own process session, with its stdout and
//     stderr on two FIFOs it holds open, and prints the identity the sweep keeps it
//     by. It runs right after a clean sweep, so the only code that can have run since
//     is another interpreter of the same session.
//   - kernel.js and kernel.py are the interpreters: one cell per connection to a Unix
//     socket, in one global namespace, the final expression's value printed.
//   - relay.js (relay.go) runs beside each interpreter, attached to the provider: for
//     each cell it writes the cell's files, hands the code to the interpreter, and
//     streams back what the interpreter writes between the cell's markers. Output an
//     interpreter writes between cells is dropped.
//
// The interpreter is the one process the sweep keeps besides the sandbox's own; its
// children die with the call like any other process. While it lives, code can run
// between calls (a timer, a thread), inside the session's own limits.

var (
	//go:embed interp/kernel.js
	kernelJS string
	//go:embed interp/kernel.py
	kernelPy string
	//go:embed interp/launch.sh
	launchScript string
)

// A cell's statuses, as the relay reports them.
const (
	cellRan           = 0
	cellRaised        = 1
	cellFilesFailed   = 3
	cellNoInterpreter = 75
	cellEnded         = 76
)

// ErrLaunch is an interpreter that could not start: its language is not in the
// image, or it exited at once. No code of the cell ran.
var ErrLaunch = errors.New("the interpreter could not start")

// interpRoot holds one directory per language: the control socket and the FIFOs.
const interpRoot = "/tmp/.plimsoll-interp/"

// command is how each language's interpreter starts.
var command = map[string][]string{
	"javascript": {"node", "--expose-internals", "-e", kernelJS},
	"python":     {"python3", "-c", kernelPy},
}

// ExecResult is one command's outcome in the sandbox, as the provider's exec reports it.
type ExecResult struct {
	Stdout, Stderr                   string
	StdoutTruncated, StderrTruncated bool
	ExitCode                         int
	Exited                           bool // the command exited by itself, with ExitCode
}

// ExecFunc runs argv in the session's sandbox, in its work directory, with env and
// stdin, keeping at most outCap and errCap bytes of output.
type ExecFunc func(ctx context.Context, argv []string, env map[string]string, stdin []byte, outCap, errCap int) (ExecResult, error)

// File is one file a cell writes into the work directory.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Cell is one cell's request.
type Cell struct {
	Language string
	Code     string
	Files    []File
	// Work is the session's work directory: where the files go and where the
	// interpreter starts.
	Work           string
	OutCap, ErrCap int
}

// CellOutcome is what one cell produced.
type CellOutcome struct {
	ExecResult
	// Raised: the code raised, or the interpreter ended under it.
	Raised   bool
	TimedOut bool
	Started  bool // a fresh interpreter was started for this call
	Ended    bool // the interpreter ended during this call
}

// Interpreters is a session's live interpreters, by language, with the identity
// the sweep keeps each by.
type Interpreters struct {
	mu     sync.Mutex
	live   map[string]string
	relays map[string]*relay // only for a provider that relays (RunRelayed)
}

// Keep is baseline plus every live interpreter and relay: what the sweep spares.
func (in *Interpreters) Keep(baseline []string) []string {
	in.mu.Lock()
	defer in.mu.Unlock()
	keep := append([]string(nil), baseline...)
	for _, id := range in.live {
		keep = append(keep, id)
	}
	for _, r := range in.relays {
		keep = append(keep, r.id)
	}
	return keep
}

// Clear forgets every interpreter and relay: the sandbox was stopped or restarted,
// which killed them.
func (in *Interpreters) Clear() { in.Close() }

func (in *Interpreters) drop(lang string) {
	in.mu.Lock()
	delete(in.live, lang)
	in.mu.Unlock()
}

func (in *Interpreters) set(lang, id string) {
	in.mu.Lock()
	if in.live == nil {
		in.live = map[string]string{}
	}
	in.live[lang] = id
	in.mu.Unlock()
}

func (in *Interpreters) alive(lang string) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	_, ok := in.live[lang]
	return ok
}

// identityPattern is the launcher's output: pid:starttime:cmdline-hex. The start
// time can be negative: gVisor reported -146 for a process started just after its
// sandbox booted (measured 2026-10-01), and the sweep compares it as text, as read.
var identityPattern = regexp.MustCompile(`^[0-9]+:-?[0-9]+:[0-9a-f]+$`)

// launch starts lang's interpreter and records it. It runs where the sweep has just
// run, so nothing of a call is left that could have written the launcher's output
// but another live interpreter of the same session, whose code is the session's own.
func (in *Interpreters) launch(ctx context.Context, exec ExecFunc, lang, work string) error {
	argv := append([]string{"sh", "-c", launchScript, "sh"}, command[lang]...)
	env := map[string]string{"PLIMSOLL_INTERP_DIR": interpRoot + lang, "PLIMSOLL_WORK": work}
	out, err := exec(ctx, argv, env, nil, 1<<20, 4096)
	if err != nil {
		return err
	}
	if !out.Exited || out.ExitCode != 0 {
		return fmt.Errorf("%w (%s, exit %d)", ErrLaunch, lang, out.ExitCode)
	}
	if !identityPattern.MatchString(out.Stdout) {
		return fmt.Errorf("%w: the launcher printed no identity", ErrLaunch)
	}
	in.set(lang, out.Stdout)
	return nil
}
