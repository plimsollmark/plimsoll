package sessionkit

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// A session may keep one interpreter per language alive between its calls, so what
// a cell defines is there for the next cell. The four programs below run in the
// sandbox:
//
//   - launch.sh starts an interpreter in its own process session, with its stdout and
//     stderr on two FIFOs it holds open, and prints the identity the sweep keeps it
//     by. It runs before any of the cell's code is sent, but not always right after a
//     sweep (a cell that finds its interpreter gone starts it again in the same call),
//     so code of the session's other interpreters, and anything they started since
//     the last sweep, can have run and can write anything in the sandbox.
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

// ErrFiles is a cell whose files could not all be written into the work directory
// (a directory in the way, a full disk). Its code did not run and its interpreter is
// as the previous cell left it; files written before the failing one stay.
var ErrFiles = errors.New("the cell's files could not be written")

// ErrUnsent is a cell whose deadline passed before its code was sent: while its
// interpreter or relay was starting, or its files were being written. None of its
// code ran, so it is a refusal, not a timed-out cell.
var ErrUnsent = errors.New("the deadline passed before the cell's code was sent")

// filesError states which file failed and why, from the relay's done frame. The
// relay is the session's on OpenShell, so it states only an index into the request
// and a name shaped like an errno, never text of its own.
func filesError(f frame, n int) error {
	which := "a file"
	if f.File != nil && *f.File >= 0 && *f.File < n {
		which = fmt.Sprintf("file %d of %d", *f.File+1, n)
	}
	why := "an unnamed error"
	if errnoShaped(f.Errno) {
		why = f.Errno
	}
	return fmt.Errorf("%w: %s: %s; the code did not run", ErrFiles, which, why)
}

func errnoShaped(s string) bool {
	if len(s) < 2 || len(s) > 16 || s[0] != 'E' {
		return false
	}
	for _, c := range s[1:] {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// interpRoot holds one directory per language: the control socket and the FIFOs.
const interpRoot = "/tmp/.plimsoll-interp/"

// command is how each language's interpreter starts.
var command = map[string][]string{
	"javascript": {"node", "--expose-internals", "-e", kernelJS},
	"python":     {"python3", "-I", "-c", kernelPy},
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
	// Checker, where the provider has one, runs a command as a user the session's
	// code is not; identities reported from inside the sandbox are kept only once
	// CheckScript confirms them through it. Docker has one (a second uid). OpenShell
	// has none: its exec takes no user, and it walls each exec's processes off from
	// the others' (a cell could not open its relay's stdout, measured 2026-10-01;
	// sandbox.SessionSmokeTest refuses sessions where a call can).
	Checker ExecFunc
	// Start, when set, is put before an interpreter's command: how the provider starts
	// a guest-facing process with the guest's environment, while the launcher, one of
	// plimsoll's own programs, starts with none of it. It must exec the command
	// without forking, so the process the launcher started is the interpreter.
	Start []string

	mu     sync.Mutex
	live   map[string]string
	relays map[string]*relay // only for a provider that relays (RunRelayed)
	// unreported: languages whose interpreter was started for a cell that answered
	// with an error (its files failed), so no result has said it is new.
	unreported map[string]bool
}

func (in *Interpreters) markUnreported(lang string) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.unreported == nil {
		in.unreported = map[string]bool{}
	}
	in.unreported[lang] = true
}

func (in *Interpreters) takeUnreported(lang string) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	was := in.unreported[lang]
	delete(in.unreported, lang)
	return was
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
// run, but another live interpreter of the same session can still write anything in
// the sandbox, so the launcher takes the identity from the process it started and
// trusts no file for it: a PID read from a writable file let a cell make the sweep
// keep a process of its choosing.
func (in *Interpreters) launch(ctx context.Context, exec ExecFunc, lang, work string) error {
	argv := append(append([]string{"sh", "-c", launchScript, "sh"}, in.Start...), command[lang]...)
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
	if reportedCmd(out.Stdout) != argvHex(interpArgv(lang)) {
		return fmt.Errorf("%w: the launcher reported a process that is not the %s interpreter", ErrLaunch, lang)
	}
	if err := in.check(ctx, "interp:"+out.Stdout); err != nil {
		return err
	}
	in.set(lang, out.Stdout)
	return nil
}

// interpArgv is lang's interpreter as the launcher starts it: its command, then its
// directory.
func interpArgv(lang string) []string {
	return append(append([]string(nil), command[lang]...), interpRoot+lang)
}

// argvHex is a command line as /proc/<pid>/cmdline holds it, in hex: each argument
// followed by a zero byte. A reported identity's command line must be the one
// plimsoll started, so an identity naming another live process (the container's
// init, which also has parent 0; the other language's relay; a decoy with a unique
// command line) is refused before the check that it is live.
func argvHex(argv []string) string {
	var b []byte
	for _, a := range argv {
		b = append(append(b, a...), 0)
	}
	return hex.EncodeToString(b)
}

// reportedCmd is the command-line part of an identity (pid:starttime:cmdline-hex).
func reportedCmd(id string) string {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}

// check confirms identities a launcher or relay reported (kind:identity, see
// CheckScript) through the provider's Checker; with none, the reports stand. A
// failed check is ErrLaunch: it runs before any of the cell's code is sent.
func (in *Interpreters) check(ctx context.Context, ids ...string) error {
	if in.Checker == nil {
		return nil
	}
	out, err := in.Checker(ctx, CheckArgv(ids), nil, nil, 4096, 4096)
	if err != nil {
		return fmt.Errorf("%w: the identity check could not run: %v", ErrLaunch, err)
	}
	if !out.Exited || out.ExitCode != 0 {
		return fmt.Errorf("%w: a reported identity is not the process plimsoll started (check exit %d)", ErrLaunch, out.ExitCode)
	}
	return nil
}
