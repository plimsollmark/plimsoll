package sessionkit

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

// These two tests hold what this package believes about node to a real node: the one on this
// machine's PATH. The tests in node_test.go check plimsoll's reading of words and versions
// that were written into the tests by hand, which pass whatever node does.

// realNode runs the machine's node with args and returns its exit code, standard output and
// standard error. The test is skipped on a machine with no node.
func realNode(t *testing.T, args ...string) (exit int, stdout, stderr string) {
	t.Helper()
	path, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on this machine's PATH: node's own words and exit code cannot be read here")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	var outb, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outb, &errb
	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, outb.String(), errb.String()
	case errors.As(err, &exitErr) && exitErr.Exited():
		return exitErr.ExitCode(), outb.String(), errb.String()
	}
	t.Fatalf("node %q could not be run: %v", args, err)
	return 0, "", ""
}

// A real node refuses an option it does not know with exit 9 and the words nodeRefusedOption
// reads. The option is one no node has, so the test reads node's wording on any version.
func TestRealNodeRefusesAnUnknownOptionInTheseWords(t *testing.T) {
	t.Parallel()
	const option = "--plimsoll-no-such-option"
	exit, _, stderr := realNode(t, option, "-e", "0")
	if exit != 9 {
		t.Errorf("node exited %d for an option it does not know; the providers read 9 as the refusal of %s (stderr %q)", exit, NodeSignalFlag, stderr)
	}
	if !nodeRefusedOption(stderr, option) {
		t.Errorf("node's words for an unknown option are %q, which NodeFlagRefused does not read: an image with an old node would be refused without the words that name the version needed", stderr)
	}
	if nodeRefusedOption(stderr, NodeSignalFlag) {
		t.Errorf("node's refusal of %s was read as its refusal of %s", option, NodeSignalFlag)
	}
}

// The version rule and the real node agree: a node CheckNodeVersion accepts takes
// NodeSignalFlag and runs, and one it refuses exits 9 with the words NodeFlagRefused reads.
func TestRealNodeAgreesWithTheVersionRule(t *testing.T) {
	t.Parallel()
	exit, stdout, stderr := realNode(t, "--version")
	if exit != 0 {
		t.Fatalf("node --version exited %d: %q", exit, stderr)
	}
	version := string(bytes.TrimSpace([]byte(stdout)))
	if !nodeVersion.MatchString(version) {
		t.Fatalf("node states its version as %q, which CheckNodeVersion cannot read", version)
	}
	accepted := CheckNodeVersion(version) == nil
	exit, _, stderr = realNode(t, NodeSignalFlag, "-e", "0")
	switch {
	case accepted && exit != 0:
		t.Errorf("CheckNodeVersion accepts node %s, but it exited %d given %s: %q", version, exit, NodeSignalFlag, stderr)
	case !accepted && (exit != 9 || !NodeFlagRefused(stderr)):
		t.Errorf("CheckNodeVersion refuses node %s, but it exited %d given %s and said %q, which is not the refusal the providers read", version, exit, NodeSignalFlag, stderr)
	}
}
