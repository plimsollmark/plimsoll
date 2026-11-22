package wslc

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// How one call of a kept session reaches its container (2026-11-21).
//
// Every call is one `wslc container exec` whose command is the call's own, as real
// arguments: `/usr/bin/env -i -- NAME=value ... COMMAND ARG...`, started as the call's
// user by runc, which switches the user before execve. Standard input carries the call's
// payload and nothing else. A first design sent the command line and environment as a
// header on standard input, read by a helper (docker/guard/session-exec.c); a process an
// earlier call left behind, running as the same uid, opened that input through /proc
// and wrote into it (1 exec in 60 under runc, measured on WSL containers 3.0.5), so it
// could have chosen the command. An exec's arguments are fixed before anything in the
// container runs, so nothing there can change them, and they were measured to cross
// interop byte for byte, so the helper left this path.
//
// Why the environment is in the arguments and not in wslc.exe's environment (WSLENV and
// `-e NAME`): Windows variable names ignore case (A and a become one variable), wslc.exe
// reads some of its own (PATH, TEMP, USERPROFILE: a guest PATH named in WSLENV arrived as
// plimsolld's own), a name WSLENV lists but nothing sets leaks the Windows user's own
// value, and an empty value erases the variable (all measured 2026-11-21). `env -i` also
// drops the image's variables, so the command gets exactly the call's strings.
//
// What crossing costs: the whole command line, the environment's values included, is
// wslc.exe's Windows command line, which any process of the same Windows user can read
// and which Windows can record (process-creation auditing, endpoint tools). It holds
// nothing the call did not send; a caller who puts a secret in a session call's
// environment puts it there.

const (
	// maxCommandLine is CreateProcess's 32,767 characters less the terminating NUL it
	// counts: measured 2026-11-21, a line of 32,766 started and one of 32,767 did not.
	maxCommandLine = 32766
	// sessionEnvPath is the image's env, the program each call starts as: the same one
	// sessionkit.ControlArgv starts plimsoll's own programs under.
	sessionEnvPath = "/usr/bin/env"
)

// The users a session's calls run as (measured on WSL containers 3.0.5 under runc,
// 2026-11-21). The guest's code runs as sessionGuestUser. plimsoll's own programs in the
// container run as a user the guest is not, for their whole life, so no process the
// guest leaves behind can open their standard input, output or error under /proc, stop
// them or attach to them (each was tried, and refused, by a leftover of the guest's): the
// lister and the identity check as sessionCheckerUser, which holds no capability and
// still reads every process's stat and command line; the sweep as sessionSweepUser,
// root, which in a container started with sessionCapFlags holds CAP_KILL and nothing
// else (without it root cannot signal the guest's processes). The guest holds no
// capability (CapPrm 0), but KILL is in its bounding set and WSL containers have no
// no-new-privileges option, so a set-user-ID program in the image would hand the guest
// uid 0 and CAP_KILL: a session's image must hold none.
var (
	sessionGuestUser   = strconv.Itoa(GuestUID) + ":" + strconv.Itoa(GuestUID)
	sessionCheckerUser = strconv.Itoa(GuestUID+1) + ":" + strconv.Itoa(GuestUID+1)
	sessionSweepUser   = "0:0"
	sessionCapFlags    = []string{"--cap-drop", "ALL", "--cap-add", "KILL"}
)

var (
	errUnsafeForwarded    = errors.New("wslc: a session call's argument or environment string is not valid UTF-8 or holds a NUL byte")
	errCommandLineTooLong = errors.New("wslc: a session call's command line is past Windows' limit")
)

// checkForwarded refuses what interop would not deliver byte for byte: invalid UTF-8
// (MultiByteToWideChar makes it U+FFFD) and NUL (a Linux argument cannot hold one).
func checkForwarded(a string) error {
	if !utf8.ValidString(a) || strings.IndexByte(a, 0) >= 0 {
		return errUnsafeForwarded
	}
	return nil
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// windowsCommandLineLen is the length, in UTF-16 units, of the command line WSL's
// FormatCommandLine (src/windows/common/interop.cpp) builds for path's program and args:
// the program's base name (interop uses it when argv[0] is the path, as exec.Command
// sets it), then each argument after one space, quoted when it is empty or holds a space,
// tab, CR, LF or quote, with a backslash doubled when a quote or the closing quote
// follows it and every quote escaped.
func windowsCommandLineLen(path string, args []string) int {
	n := quotedLen(filepath.Base(path))
	for _, a := range args {
		n += 1 + quotedLen(a)
	}
	return n
}

func quotedLen(a string) int {
	if a != "" && !strings.ContainsAny(a, " \t\r\n\"") {
		return utf16Len(a)
	}
	n, slashes := 2, 0 // the two quotes
	for _, r := range a {
		switch r {
		case '\\':
			slashes++
		case '"':
			n += slashes*2 + 2 // the backslashes doubled, then \"
			slashes = 0
		default:
			n += slashes + utf16.RuneLen(r)
			slashes = 0
		}
	}
	return n + slashes*2 // backslashes before the closing quote, doubled
}

// sessionExecCall is the call that runs argv (an absolute command and its arguments)
// with exactly env (NAME=value strings) as user (uid:gid) in /work of container in the
// WSLC session named session. A call that cannot cross exactly is refused, marked not
// dispatched for the request.
func sessionExecCall(session, container, user string, argv, env []string) (hostCall, error) {
	refuse := func(err error) (hostCall, error) {
		return hostCall{}, sandbox.NotDispatched(sandbox.RefusalRequest, err)
	}
	// env reads every argument holding '=' as an assignment until the first that does
	// not, so the command's path must hold none.
	if len(argv) == 0 || !strings.HasPrefix(argv[0], "/") || strings.Contains(argv[0], "=") {
		return refuse(errors.New("wslc: a session call's command is not an absolute path without '='"))
	}
	for i, e := range env {
		if name, _, ok := strings.Cut(e, "="); !ok || name == "" {
			return refuse(fmt.Errorf("wslc: environment string %d is not NAME=value", i))
		}
	}
	forwarded := append(append([]string{sessionEnvPath, "-i", "--"}, env...), argv...)
	for i, a := range forwarded {
		if err := checkForwarded(a); err != nil {
			return refuse(fmt.Errorf("%w (forwarded argument %d)", err, i))
		}
	}
	args := []string{"--session", session, "container", "exec", "--interactive", "--user", user, "--workdir", workDir, container}
	if err := checkArgs(args); err != nil {
		return refuse(err)
	}
	return hostCall{args: args, forwarded: forwarded}, nil
}

// sessionExec is sessionExecCall's command for this provider's wslc.exe, checked against
// Windows' command-line limit: every refusal comes before any process exists and is
// marked not dispatched.
func (p *Provider) sessionExec(ctx context.Context, session, container, user string, argv, env []string) (*exec.Cmd, error) {
	c, err := sessionExecCall(session, container, user, argv, env)
	if err != nil {
		return nil, err
	}
	if err := c.check(p.cfg.Path); err != nil {
		return nil, sandbox.NotDispatched(sandbox.RefusalRequest, err)
	}
	return startHost(ctx, p.cfg.Path, c), nil
}
