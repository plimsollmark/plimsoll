// Package nativehelper holds the native in-sandbox helper, plimsoll-helper: one static Rust
// program (program/, a crate with no outside package) with a mode per job plimsoll runs inside
// a sandbox. Its first mode is the project runner (run-project, with its self-check), which
// replaced the Node runner (docker/runner.mjs, deleted 2026-11-21) after the runner
// equivalence suite (sandbox/docker_runner_equivalence_test.go) held the two to the same
// results, case by case, under runc and gVisor.
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
// whose file there is missing or is not these bytes (SHA256), as it refuses an image without
// the guard library the node programs beside it still load.
package nativehelper

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
)

//go:embed program/plimsoll-helper_* program/plimsoll-helper.sha256
var programFiles embed.FS

// InContainer is where the helper is inside a sandbox.
const InContainer = "/usr/local/libexec/plimsoll-helper"

// RunProject is the helper's command line as the project runner.
var RunProject = []string{InContainer, "run-project"}

// RunProjectShell is RunProject for a command line a shell reads ("exec " + RunProjectShell).
const RunProjectShell = InContainer + " run-project"

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

// TestOnlyStayDumpable is the one argument that makes the runner skip its own non-dumpable
// call, so a test can reach its refusal to run where a step could open its descriptors (it
// then reports that and runs nothing). Nothing a daemon starts may pass it.
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
