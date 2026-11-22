package sessionkit

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Every program of plimsoll's own that this package starts carries the flag that keeps
// node's debugger shut to guest code (finding rust-native-helper-26); the interpreter that
// runs a session's cells is the guest's and keeps node's ordinary behavior.
func TestOwnProgramsStartWithTheSignalFlag(t *testing.T) {
	t.Parallel()
	for name, argv := range map[string][]string{
		"check":   CheckArgv([]string{"interp:1:2:00"}),
		"list":    ListArgv(),
		"sweep":   SweepArgv(1, MeasureStatfs, []string{"/work"}, []string{"main:1:2:00"}),
		"quiesce": QuiesceArgv([]string{"main:1:2:00"}),
		"relay":   RelayArgv("javascript", "/work"),
	} {
		if len(argv) < 3 || argv[0] != "node" || argv[1] != NodeSignalFlag || argv[2] != "-e" {
			t.Errorf("%s starts %q; want node %s -e first", name, argv[:min(3, len(argv))], NodeSignalFlag)
		}
	}
	if slices.Contains(command["javascript"], NodeSignalFlag) {
		t.Errorf("the javascript interpreter %q carries %s; it is the guest's node", command["javascript"][:2], NodeSignalFlag)
	}
	if slices.Contains(GuestNodeArgv("-"), NodeSignalFlag) || slices.Contains(StartupNodeArgv("-"), NodeSignalFlag) {
		t.Error("a guest or startup node carries the flag")
	}
}

func TestCheckNodeVersion(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"v22.14.0", "v22.23.4", "v23.7.0", "v23.11.1", "v24.0.0", "v26.3.1", "v22.23.4\n"} {
		if err := CheckNodeVersion(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"v22.13.1", "v22.0.0", "v23.6.1", "v20.19.0", "v18.20.8", "", "22.23.4", "v22", "vx.y.z"} {
		err := CheckNodeVersion(v)
		if err == nil {
			t.Errorf("%q accepted", v)
			continue
		}
		if !strings.Contains(err.Error(), "v22.14.0") || !strings.Contains(err.Error(), "v23.7.0") || !strings.Contains(err.Error(), NodeSignalFlag) {
			t.Errorf("%q: the refusal %q does not name the versions needed and the flag", v, err)
		}
	}
}

// Each line of the version table at its edge: the last version it refuses and the first it
// accepts, written here from Node's documentation ("--disable-sigusr1": "Added in: v23.7.0,
// v22.14.0"), never computed from the table's own constants, so a constant that moves fails
// here. The readable range's edges and a build before a release are held too
// (hunt-quality-66).
func TestCheckNodeVersionEdges(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ line, lastRefused, firstAccepted string }{
		{"before the 22 line", "v21.9999.9999", ""},
		{"the 22 line", "v22.13.9999", "v22.14.0"},
		{"the 22 line's last readable release", "", "v22.9999.9999"},
		{"the 23 line", "v23.6.9999", "v23.7.0"},
		{"the 23 line's first release", "v23.0.0", ""},
		{"24 and later", "", "v24.0.0"},
		{"the largest version it reads", "", "v9999.9999.9999"},
	} {
		if v := tc.lastRefused; v != "" {
			if err := CheckNodeVersion(v); err == nil || !strings.Contains(err.Error(), "too old") {
				t.Errorf("%s: %s must be refused as too old, got %v", tc.line, v, err)
			}
		}
		if v := tc.firstAccepted; v != "" {
			if err := CheckNodeVersion(v); err != nil {
				t.Errorf("%s: %s must be accepted: %v", tc.line, v, err)
			}
			if (strings.HasPrefix(v, "v22.14.") || strings.HasPrefix(v, "v23.7.")) && !strings.Contains(NodeVersionNeeded, v) {
				t.Errorf("%s: the refusal's wording %q does not name %s", tc.line, NodeVersionNeeded, v)
			}
		}
	}
	// Not a release's version: refused as unreadable, with the versions needed, never
	// guessed at. A build before a release is one of these on purpose (node.go says why).
	for _, v := range []string{"v24.0.0-rc.1", "v25.0.0-nightly20261120abcdef0123", "v22.14.0-pre", "v10000.0.0", "v24.10000.0", "v24.0.10000", "v24.0", "v24.0.0.1", "V24.0.0", "v 24.0.0", "v24.0.0 extra"} {
		err := CheckNodeVersion(v)
		if err == nil || !strings.Contains(err.Error(), "cannot read") || !strings.Contains(err.Error(), NodeVersionNeeded) {
			t.Errorf("%q must be refused as a version plimsoll cannot read, naming the versions needed; got %v", v, err)
		}
	}
}

func TestNodeFlagRefused(t *testing.T) {
	t.Parallel()
	// What a node that does not know the option prints (measured with another unknown
	// option on node v26.3.1: "node: bad option: --nonexistent-xyz", exit 9).
	if !NodeFlagRefused("node: bad option: " + NodeSignalFlag + "\n") {
		t.Error("an old node's refusal was not recognized")
	}
	if NodeFlagRefused("node: bad option: --other\n") || NodeFlagRefused("") {
		t.Error("another failure read as an old node")
	}
	if !strings.Contains(ErrNodeFlagRefused.Error(), "v22.14.0") || errors.Unwrap(ErrNodeFlagRefused) != nil {
		t.Errorf("ErrNodeFlagRefused is %q", ErrNodeFlagRefused)
	}
}
