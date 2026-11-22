package sessionkit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Every node command line plimsoll writes is built here, by one of three functions that
// say whose program it is (finding rust-native-helper-26, 2026-11-20). A test of package
// sandbox (TestNodeIsStartedOnlyThroughSessionkit) fails the build on a node command line
// written anywhere else in the Go code under sandbox/, cmd/ and internal/, or in an
// in-sandbox script under sandbox/ and docker/.
//
// Node opens its debugger when it receives SIGUSR1 (process._debugProcess sends the same
// signal), on 127.0.0.1:9229, which a sandbox's own loopback reaches. Any process of the
// same user may send it, so a step, a cell or a process a call left behind could open the
// debugger of a node program of plimsoll's own running beside it (the project runner until
// the native helper replaced it on 2026-11-21, the forwarder, a session's sweep or relay)
// and run code inside it: measured on
// 2026-11-20, a step replaced its own output in the runner's report and read the key the
// report is signed with. --disable-sigusr1 starts node without that signal handler.

// NodeSignalFlag is the option that keeps a node program's debugger shut to every other
// process: node then registers no SIGUSR1 handler (Node's src/env-inl.h,
// should_start_debug_signal_handler, and src/inspector_agent.cc), and the signal then does
// nothing (measured 2026-11-20: the runner went on and reported every later step; Node's
// src/node.cc blocks SIGUSR1 on its main thread at start, read, not traced). It is a command-line
// argument, never NODE_OPTIONS:
// a variable would reach the guest's own node through the environment, and every
// control program starts with an empty one (ControlArgv).
const NodeSignalFlag = "--disable-sigusr1"

// NodeArgv is the command line of a node program of plimsoll's own that runs where guest
// code can reach it (the loopback forwarder, the lister, the
// sweep, the quiesce, the identity check, a relay, a provider's session helper, a smoke
// test's control program): node with NodeSignalFlag, then args.
func NodeArgv(args ...string) []string {
	return append([]string{"node", NodeSignalFlag}, args...)
}

// GuestNode is the program name of the guest's own node: a snippet's, a project step's
// (and a startup test's step, which stands for one), a session cell interpreter's (the
// kernel that runs a cell's code in its own process). The guest's code
// runs inside that process, so opening its debugger gains the guest nothing it does not
// already have, and the guest keeps node's ordinary behavior there, the signal included.
const GuestNode = "node"

// GuestNodeArgv is GuestNode with args.
func GuestNodeArgv(args ...string) []string {
	return append([]string{GuestNode}, args...)
}

// StartupNodeArgv is the node of a startup check: a program of plimsoll's own that runs
// alone in a sandbox started for the startup smoke test, with no guest code beside it, and whose
// report includes node's version (process.version), so that CheckNodeVersion can refuse
// a node too old for NodeSignalFlag with words that name the version needed. With the
// flag such a node would only exit 9 ("bad option") before reporting anything.
func StartupNodeArgv(args ...string) []string {
	return append([]string{"node"}, args...)
}

// The first releases whose node accepts NodeSignalFlag: v22.14.0 and v23.7.0 (Node's
// documentation, cli.html, "--disable-sigusr1": "Added in: v23.7.0, v22.14.0"; no longer
// experimental from v24.8.0 and v22.20.0). Every release line from 24 has it.
const (
	nodeFlagMin22 = 14 // v22.14.0
	nodeFlagMin23 = 7  // v23.7.0
)

// NodeVersionNeeded is the version wording every refusal of an old node uses.
const NodeVersionNeeded = "node v22.14.0 or later in the 22 line, v23.7.0 or later in the 23 line, or any v24 or later"

// nodeVersion reads a release's version and nothing else. A build before a release
// ("v24.0.0-rc.1", "v25.0.0-nightly2026...") is refused as a version plimsoll cannot read,
// on purpose: its number says which release it leads to, not whether that build already
// has the flag (a v22.14.0 release candidate cut before the flag landed would carry the
// same number), and an image or template for serving runs is built on a release. The edges
// of each line are held by TestCheckNodeVersionEdges (hunt-quality-66).
var nodeVersion = regexp.MustCompile(`^v([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})$`)

// NodeVersionRead reports whether v is a release's version as CheckNodeVersion reads one,
// so that a caller can tell a node it read as too old from an answer it could not read.
func NodeVersionRead(v string) bool {
	return nodeVersion.MatchString(strings.TrimSpace(v))
}

// CheckNodeVersion refuses a node version (process.version, "v22.23.4") that would not
// accept NodeSignalFlag, and a version it cannot read: plimsoll never starts its own node
// programs without the flag, so an image or template whose node is older cannot serve.
func CheckNodeVersion(v string) error {
	m := nodeVersion.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return fmt.Errorf("node reported the version %q, which plimsoll cannot read; it needs %s, which accepts %s", truncate(v), NodeVersionNeeded, NodeSignalFlag)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	ok := major >= 24 || (major == 23 && minor >= nodeFlagMin23) || (major == 22 && minor >= nodeFlagMin22)
	if !ok {
		return fmt.Errorf("node %s is too old: plimsoll starts its own node programs with %s, which keeps their debugger shut to guest code, and needs %s", m[0], NodeSignalFlag, NodeVersionNeeded)
	}
	return nil
}

// NodeFlagRefused reports whether a node program's stderr says its node does not know
// NodeSignalFlag: such a node prints "node: bad option: --disable-sigusr1" and exits 9.
func NodeFlagRefused(stderr string) bool {
	return nodeRefusedOption(stderr, NodeSignalFlag)
}

// nodeRefusedOption is NodeFlagRefused for any option: node's words for one it does not know.
// It is apart from NodeFlagRefused so a test can hold the words to a real node, with an option
// no node knows (node_real_test.go).
func nodeRefusedOption(stderr, option string) bool {
	return strings.Contains(stderr, "bad option: "+option)
}

// ErrNodeFlagRefused is the refusal, in plimsoll's own words, for an image whose node
// refused NodeSignalFlag (NodeFlagRefused).
var ErrNodeFlagRefused = fmt.Errorf("the image's node does not accept %s, so plimsoll cannot start its own node programs with their debugger shut to guest code; it needs %s", NodeSignalFlag, NodeVersionNeeded)

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
