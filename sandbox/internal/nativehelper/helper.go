// Package nativehelper holds the native in-sandbox helper, plimsoll-helper: one static Rust
// program (program/, a crate with no outside package) with a mode per job plimsoll runs inside
// a sandbox. Its first mode is the project runner (run-project, with its self-check), which
// replaced the Node runner (docker/runner.mjs, deleted 2026-11-21) after the runner
// equivalence suite (sandbox/docker_runner_equivalence_test.go) held the two to the same
// results, case by case, under runc and gVisor. Its second is the file commands (files,
// program/src/files.rs): one generic interface to a sandbox's work folder, run as the guest's
// own user, whose contract is docs/session-files.md (FilesVersion, Files).
//
// The committed file program/plimsoll-helper_<goarch> is built by program/build.sh statically
// against musl, inside a container image pinned by digest with the toolchain pinned exactly, to
// the same bytes from two folders (and from this machine's own toolchain, HOST=1); the pin,
// program/plimsoll-helper.sha256, names every input of the build and the file. The package's
// tests fail when the two disagree; the gate cannot rebuild, so that is as far as it checks.
//
// Every project image plimsoll builds carries this committed file at InContainer
// (docker/Dockerfile and docker/sim.Dockerfile copy it from the named build context
// nativehelper), and every provider that starts it as the runner refuses at startup an image
// whose file there is missing, is not these bytes (SHA256, where the check can read them) or
// does not print this build's identity line (Identity, on every provider), as it refuses an
// image without the guard library the node programs beside it still load.
package nativehelper

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

//go:embed program/plimsoll-helper_* program/plimsoll-helper.sha256
var programFiles embed.FS

// InContainer is where the helper is inside a sandbox.
const InContainer = "/usr/local/libexec/plimsoll-helper"

// RunProject is the helper's command line as the project runner.
var RunProject = []string{InContainer, "run-project"}

// RunProjectShell is RunProject for a command line a shell reads ("exec " + RunProjectShell).
const RunProjectShell = InContainer + " run-project"

// Files is the helper's command line for its file commands, before the command and its
// arguments (docs/session-files.md).
var Files = []string{InContainer, "files"}

// FilesVersion is the version of the file commands' contract (docs/session-files.md: the
// commands, their arguments, the framing and the exit codes) in the committed build. Wherever
// the startup check verified this build at InContainer, the commands are this version. Raise
// it with any change a caller of the commands would see.
const FilesVersion = 8

// SHA256 is the hex SHA-256 of the committed helper for goarch: what a provider requires of
// the file at InContainer before it starts it as the runner.
func SHA256(goarch string) (string, error) {
	b, err := Program(goarch)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// TestOnlyStayDumpable is the one argument that makes the runner dumpable in place of its own
// non-dumpable call (a helper installed readable by root alone is non-dumpable from its exec,
// so skipping the call would not do), so a test can reach its refusal to run where a step
// could open its descriptors (it then reports that and runs nothing). Nothing a daemon starts
// may pass it.
const TestOnlyStayDumpable = "--test-only-stay-dumpable"

// ProgramFile is the built helper's file name for goarch.
func ProgramFile(goarch string) string { return "program/plimsoll-helper_" + goarch }

// Program is the committed bytes of the helper for goarch (amd64 alone: no plimsoll image is
// built for another machine yet).
func Program(goarch string) ([]byte, error) {
	b, err := programFiles.ReadFile(ProgramFile(goarch))
	if err != nil {
		return nil, fmt.Errorf("no native helper is built for %s (build.sh installs amd64 only until an image is built for another machine): %w", goarch, err)
	}
	return b, nil
}

// IdentityCommand is the helper's command line that reports which build it is: one line,
// "inputs " and the SHA-256 of the build's inputs, which build.sh compiles in (Identity).
var IdentityCommand = []string{InContainer, "identity"}

// Identity is the line the committed build's identity command prints, less its newline:
// "inputs " and the SHA-256 of the pin's lines for the build's inputs (every line of
// program/plimsoll-helper.sha256 but the built files', in its order, each with its newline),
// which build.sh computes the same way before it builds and compiles in. The pin's own test
// holds each of those lines to its file, so the reported identity of the pinned build is fixed
// by the pin. It tells one build of plimsoll's from another (a stale image's helper, another
// release's); a program built to lie can print any line, so it proves nothing against a hostile
// image, which the operator's own image is not taken to be.
func Identity() (string, error) {
	pin, err := programFiles.ReadFile("program/plimsoll-helper.sha256")
	if err != nil {
		return "", err
	}
	var inputs []byte
	for _, line := range strings.SplitAfter(string(pin), "\n") {
		if line == "" {
			continue
		}
		_, name, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "  ")
		if !ok || !strings.HasSuffix(line, "\n") {
			return "", fmt.Errorf("the helper's pin has a line %q that is not sha256sum's", line)
		}
		if strings.HasPrefix(name, "plimsoll-helper_") {
			continue
		}
		inputs = append(inputs, line...)
	}
	if len(inputs) == 0 {
		return "", errors.New("the helper's pin names no input")
	}
	sum := sha256.Sum256(inputs)
	return "inputs " + hex.EncodeToString(sum[:]), nil
}

// Want is what a startup check requires of the file at InContainer: the build's SHA-256 (when
// the check can read the bytes) and the line its identity command prints.
type Want struct {
	SHA256   string
	Identity string
}

// Pinned is Want for the committed build for goarch.
func Pinned(goarch string) (Want, error) {
	sum, err := SHA256(goarch)
	if err != nil {
		return Want{}, err
	}
	id, err := Identity()
	if err != nil {
		return Want{}, err
	}
	return Want{SHA256: sum, Identity: id}, nil
}
