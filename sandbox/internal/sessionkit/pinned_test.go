package sessionkit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// mustInterpArgv is lang's interpreter as an Interpreters without Bins starts it.
func mustInterpArgv(lang string) []string {
	argv, err := (&Interpreters{}).interpArgv(lang)
	if err != nil {
		panic(err)
	}
	return argv
}

// With Bins set, the launcher is handed the interpreter by its full path, the identity
// it must report is that command line, and the relay starts as the full path too: no
// search path chooses either program (E2B pins them at open).
func TestInterpretersBinsNameTheInterpreterAndTheRelayByPath(t *testing.T) {
	bins := map[string]string{"node": "/opt/root/bin/node", "python3": "/opt/root/bin/python3"}
	in := Interpreters{Bins: bins, Start: []string{"/usr/bin/env", "-i", "HOME=/work"}}
	var launchedArgv, relayArgv []string
	launch := func(_ context.Context, argv []string, env map[string]string, _ []byte, _, _ int) (ExecResult, error) {
		launchedArgv = argv
		// The launcher appends the interpreter's directory and reports what it started.
		started := append(append([]string(nil), argv[4+len(in.Start):]...), env["PLIMSOLL_INTERP_DIR"])
		return ExecResult{Stdout: "7:1:" + argvHex(started), Exited: true}, nil
	}
	honestRelay := scriptedRelay(nil, honest)
	attach := func(argv []string, env map[string]string) (Attached, error) {
		relayArgv = argv
		return honestRelay(argv, env)
	}
	if _, err := in.RunRelayed(context.Background(), launch, attach, plainCell); err != nil {
		t.Fatal(err)
	}
	interp := launchedArgv[4+len(in.Start):]
	if interp[0] != bins["python3"] || !slices.Equal(interp[1:], command["python"][1:]) {
		t.Fatalf("the launcher was handed the interpreter %q; want %s by its full path", interp, bins["python3"])
	}
	if !slices.Equal(launchedArgv[4:4+len(in.Start)], in.Start) {
		t.Fatalf("the launcher's argv %q lost Start", launchedArgv)
	}
	if relayArgv[0] != bins["node"] || !slices.Equal(relayArgv[1:], RelayArgv("python", "/work")[1:]) {
		t.Fatalf("the relay started as %q; want %s by its full path", relayArgv, bins["node"])
	}

	// A launcher that reports the interpreter by name, as a search path would have
	// found it, reports a process that is not the one plimsoll started.
	byName := func(_ context.Context, argv []string, env map[string]string, _ []byte, _, _ int) (ExecResult, error) {
		return ExecResult{Stdout: "7:1:" + argvHex(append(append([]string(nil), command["python"]...), env["PLIMSOLL_INTERP_DIR"])), Exited: true}, nil
	}
	fresh := Interpreters{Bins: bins}
	if _, err := fresh.RunRelayed(context.Background(), byName, attach, plainCell); !errors.Is(err, ErrLaunch) {
		t.Fatalf("an interpreter found by name was kept: err %v", err)
	}
}

// A language whose program Bins lacks does not start, and nothing is launched for it.
func TestInterpretersBinsWithoutTheProgramRefuse(t *testing.T) {
	in := Interpreters{Bins: map[string]string{"node": "/usr/bin/node"}}
	called := false
	launch := func(context.Context, []string, map[string]string, []byte, int, int) (ExecResult, error) {
		called = true
		return ExecResult{}, nil
	}
	_, err := in.RunRelayed(context.Background(), launch, scriptedRelay(nil, honest), plainCell)
	if !errors.Is(err, ErrNoInterpreter) || !strings.Contains(err.Error(), "python3") || called {
		t.Fatalf("err %v, launcher called %v; want ErrNoInterpreter naming python3 before any launch", err, called)
	}
}

// Without Bins nothing changes: the interpreter and the relay are named as command and
// RelayArgv have them (docker, OpenShell).
func TestInterpretersWithoutBinsKeepTheirNames(t *testing.T) {
	var in Interpreters
	argv, err := in.interpArgv("javascript")
	if err != nil || argv[0] != "node" {
		t.Fatalf("interpArgv = %q, %v", argv, err)
	}
	if relay, err := in.pinned(RelayArgv("javascript", "/work")); err != nil || relay[0] != "node" {
		t.Fatalf("relay argv = %q, %v", relay, err)
	}
}

// ControlArgvClosed is ControlArgv with the empty OpenSSL settings file and with
// ControlPathClosed, which names no folder under /usr/local (E2B's template build
// leaves that folder writable by every user in the machine), and refuses a program
// named for a search path to find. ControlArgvClosedByName is the same for the one
// start by name, a session's open.
func TestControlArgvClosed(t *testing.T) {
	for _, d := range strings.Split(ControlPathClosed, ":") {
		if d == "/usr/local" || strings.HasPrefix(d, "/usr/local/") || !strings.HasPrefix(d, "/") {
			t.Errorf("ControlPathClosed %q names %q; want absolute folders outside /usr/local only", ControlPathClosed, d)
		}
		if !slices.Contains(strings.Split(ControlPath, ":"), d) {
			t.Errorf("ControlPathClosed names %q, which ControlPath %q does not", d, ControlPath)
		}
	}
	open, err := ControlArgvClosedByName(nil, "node", "-e", "1")
	if wantOpen := []string{"/usr/bin/env", "-i", "PATH=" + ControlPathClosed, ControlOpenSSL, "node", "-e", "1"}; err != nil || !slices.Equal(open, wantOpen) {
		t.Fatalf("ControlArgvClosedByName = %q, %v; want %q", open, err, wantOpen)
	}
	if _, err := ControlArgvClosedByName(nil); err == nil {
		t.Error("ControlArgvClosedByName accepted no program")
	}
	argv, err := ControlArgvClosed(map[string]string{"PLIMSOLL_RELAY_UID": "61000"}, "/usr/bin/node", "-e", "1")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/env", "-i", "PATH=" + ControlPathClosed, ControlOpenSSL, "PLIMSOLL_RELAY_UID=61000", "/usr/bin/node", "-e", "1"}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for _, name := range []string{"node", "bin/node", ""} {
		if _, err := ControlArgvClosed(nil, name, "-e", "1"); err == nil {
			t.Errorf("ControlArgvClosed accepted the program %q, which a search path would choose", name)
		}
	}
	if _, err := ControlArgvClosed(nil); err == nil {
		t.Error("ControlArgvClosed accepted no program")
	}
	for _, name := range []string{"OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES"} {
		if _, err := ControlArgvClosed(map[string]string{name: "/work/x"}, "/usr/bin/node"); err == nil {
			t.Errorf("ControlArgvClosed accepted %s, which would undo the empty OpenSSL settings file", name)
		}
	}
}
