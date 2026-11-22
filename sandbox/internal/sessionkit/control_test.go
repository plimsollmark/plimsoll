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
// before any program runs; NODE_OPTIONS and NODE_PATH make node load code.
func TestControlArgvRefusesNamesThatChooseCode(t *testing.T) {
	for _, name := range []string{"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "GCONV_PATH", "NODE_OPTIONS", "NODE_PATH", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES"} {
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

// The rule is an allow list: a control program takes only names plimsoll itself reads.
// The names above are other people's lists (the loader's, node's, OpenSSL's), and a
// list of things to refuse passes whatever its owner adds next. These names choose code
// for some program and were on no list here: each was accepted until 2026-11-20.
func TestControlArgvTakesOnlyPlimsollsOwnNames(t *testing.T) {
	for _, name := range []string{
		"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", // python: where modules and a startup file come from
		"BASH_ENV", "ENV", // a shell: a file it runs at start
		"PERL5LIB", "RUBYOPT", "JAVA_TOOL_OPTIONS", // other interpreters' own
		"SSL_CERT_FILE", "TMPDIR", "HOME", // where a program finds certificates, scratch files, settings
		"MUSL_LOCPATH",                     // musl's own locale path, which the glibc list never had
		"A_VARIABLE_A_LATER_RELEASE_READS", // and whatever comes next
		"plimsoll_work", "PLIMSOLL_", "XPLIMSOLL_WORK", "PLIMSOLL_work",
	} {
		if _, err := ControlArgv(map[string]string{name: "/work/x"}, "node", "-e", "1"); err == nil {
			t.Errorf("ControlArgv accepted %s, which is not a name of plimsoll's own", name)
		}
		if _, err := ControlArgvClosed(map[string]string{name: "/work/x"}, "/usr/bin/node", "-e", "1"); err == nil {
			t.Errorf("ControlArgvClosed accepted %s, which is not a name of plimsoll's own", name)
		}
	}
	for _, name := range []string{"PLIMSOLL_WORK", "PLIMSOLL_INTERP_DIR", "PLIMSOLL_RELAY_UID", "PLIMSOLL_X9"} {
		if _, err := ControlArgv(map[string]string{name: "x"}, "node"); err != nil {
			t.Errorf("ControlArgv refused %s: %v", name, err)
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
