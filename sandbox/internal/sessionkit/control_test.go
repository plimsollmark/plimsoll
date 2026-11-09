package sessionkit

import (
	"slices"
	"strings"
	"testing"
)

// ControlArgv is the one place every control program's environment is built, so it
// is where the invariant holds or does not: an empty environment plus ControlPath and
// the caller's variables. A caller's variable must not be able to undo that. env
// applies assignments left to right, so a PATH among them replaces ControlPath, and
// the loader and C library read LD_* and the names checkLoaderEnv refuses on an image
// before any program runs; NODE_OPTIONS and NODE_PATH make node load code. Every
// caller today passes only PLIMSOLL_* names; this keeps a later one from passing a
// name that would turn a control program into a guest-facing one by accident.
func TestControlArgvRefusesNamesThatChooseCode(t *testing.T) {
	for _, name := range []string{"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "GCONV_PATH", "NODE_OPTIONS", "NODE_PATH"} {
		if _, err := ControlArgv(map[string]string{name: "/work/x"}, "node", "-e", "1"); err == nil {
			t.Errorf("ControlArgv accepted %s, which would choose what the control program loads or runs", name)
		}
	}
	for _, name := range []string{"", "1X", "A-B", "a b", "A=B"} {
		if _, err := ControlArgv(map[string]string{name: "x"}, "node"); err == nil {
			t.Errorf("ControlArgv accepted %q as a variable name", name)
		}
	}
}

func TestControlArgvStartsCleanWithTheCallersVariables(t *testing.T) {
	argv, err := ControlArgv(map[string]string{"PLIMSOLL_WORK": "/work", "PLIMSOLL_INTERP_DIR": interpRoot + "python"}, "sh", "-c", "echo")
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "/usr/bin/env" || argv[1] != "-i" || argv[2] != "PATH="+ControlPath {
		t.Fatalf("argv starts %q; want /usr/bin/env -i PATH=%s", argv[:3], ControlPath)
	}
	vars, cmd := argv[3:5], argv[5:]
	slices.Sort(vars)
	if !slices.Equal(vars, []string{"PLIMSOLL_INTERP_DIR=" + interpRoot + "python", "PLIMSOLL_WORK=/work"}) || !slices.Equal(cmd, []string{"sh", "-c", "echo"}) {
		t.Fatalf("argv = %q", argv)
	}
	if strings.Contains(ControlPath, "/work") || strings.Contains(ControlPath, "/tmp") {
		t.Fatalf("ControlPath %q names a writable directory", ControlPath)
	}
}
