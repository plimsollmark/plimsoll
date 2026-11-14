package wslc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// WARNING: read this before changing how this provider starts a process.
//
// plimsolld runs inside a WSL distribution and starts the Windows program wslc.exe
// through WSL interop (WSL's ability to start a Windows program from a Linux process);
// in the per-run mode it also starts powershell.exe (to copy the template disk, Windows
// side to Windows side) and, on the Linux side, mkfs.ext4 (to format the template).
// Two channels cross the interop boundary, and each is closed here, in this one function,
// for every one of the three:
//
//  1. The environment. Every child process inherits its parent's environment unless
//     told otherwise, and plimsolld's holds caller tokens and provider keys. Interop
//     translates into the Windows process only the variables WSLENV lists (the Windows
//     side builds the new process's environment from the Windows user's own plus those:
//     BuildEnvironment in WSL's src/windows/common/interop.cpp). hostCommand gives the
//     process PATH and nothing else, so WSLENV is unset and no variable of plimsolld's
//     is translated. Interop still finds its server without WSL_INTEROP: init walks up
//     the parent processes for an interop socket (UtilConnectToInteropServer in
//     src/linux/init/util.cpp).
//  2. The command line. Interop sends each argument separately and the Windows side
//     joins them into one command line with the C runtime's quoting rules
//     (FormatCommandLine, same file), which wslc.exe splits again. The rules round-trip
//     on paper, but a space, a quote, a backslash or a byte that is not ASCII is where a
//     mismatch between two parsers would change what runs. So every argument is checked
//     against safeArg before anything starts: only fixed flags, checked IDs, checked
//     paths and a base64 PowerShell script built from fixed text and checked paths ever
//     go in argv. Everything a caller controls (files, steps, the environment the steps
//     get) travels in the runner's plan over stdin.
//
// TestProcessesStartOnlyThroughHostCommand fails the build if this package starts a
// process any other way, and TestRunArgvIsInteropSafe and TestPerRunArgvIsInteropSafe
// hold every argument the run paths build to safeArg.

// safeArg is every byte an argument to wslc.exe may hold: letters, digits and . _ : /
// = , @ + -. No space, quote, backslash, percent sign, shell or command-line
// metacharacter, control byte or byte past ASCII, and never empty.
var safeArg = regexp.MustCompile(`^[A-Za-z0-9._:/=,@+-]+$`)

// errUnsafeArg is returned, before anything starts, for an argument outside safeArg.
var errUnsafeArg = errors.New("wslc: an argument holds a character the interop command line could re-quote")

// checkArgs refuses any argument safeArg does not match.
func checkArgs(args []string) error {
	for i, a := range args {
		if !safeArg.MatchString(a) {
			return fmt.Errorf("%w (argument %d, %d bytes)", errUnsafeArg, i, len(a))
		}
	}
	return nil
}

// hostEnv is the whole environment every process is started with: PATH, so the interop
// loader resolves as it would from a shell. Not WSLENV, WSL_INTEROP or anything else.
func hostEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH")}
}

// hostCommand is the one way this package starts a process (wslc.exe, powershell.exe or
// mkfs.ext4 at path) with args, PATH as its whole environment. An argument outside
// safeArg makes the command fail at Start, Run or Output with errUnsafeArg, before any
// process exists.
func hostCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = hostEnv()
	if err := checkArgs(args); err != nil {
		cmd.Err = err
	}
	// A Windows process started through interop is not in this process's group, so a
	// cancelled context kills only the Linux side of interop; the caller removes the
	// container by name afterwards (Provider.forceRemove).
	return cmd
}

// outputCap bounds the answer of any wslc command whose output this package parses
// (a version, an image inspect, a session read). The largest, an image inspect, is a
// few kilobytes; 1 MiB leaves room without letting an answer grow without bound.
const outputCap = 1 << 20

// errorCap bounds the stderr kept for an error from a command that ran no guest code.
const errorCap = 16 << 10

// cappedBuffer keeps the first limit bytes written to it and drops the rest,
// remembering that it did.
type cappedBuffer struct {
	buf     bytes.Buffer
	limit   int
	dropped bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room <= 0 {
		c.dropped = c.dropped || len(p) > 0
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.dropped = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

func (c *cappedBuffer) String() string  { return c.buf.String() }
func (c *cappedBuffer) Bytes() []byte   { return c.buf.Bytes() }
func (c *cappedBuffer) Truncated() bool { return c.dropped }

// output runs a wslc command that starts no guest code and returns its stdout,
// refusing an answer past outputCap rather than parsing part of one. A failure carries
// wslc's own stderr, bounded: nothing of a guest's can be in it.
func (p *Provider) output(ctx context.Context, args ...string) ([]byte, error) {
	return p.outputWithStdin(ctx, nil, args...)
}

// outputWithStdin is output with stdin as the command's input (nil is none): how a fixed
// script or an archive reaches a session VM, never as an argument (the argument rules above).
func (p *Provider) outputWithStdin(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := hostCommand(ctx, p.cfg.Path, args...)
	cmd.Stdin = stdin
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = outputCap, errorCap
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("wslc %s: %w: %s", strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Truncated() {
		return nil, fmt.Errorf("wslc %s answered more than %d bytes", strings.Join(args[:min(2, len(args))], " "), outputCap)
	}
	return stdout.Bytes(), nil
}
