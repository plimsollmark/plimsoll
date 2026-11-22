package sessionkit

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ControlPath is the PATH plimsoll's own programs in a sandbox run with: the standard
// system directories of every image plimsoll ships, all on the image's read-only
// root. It is also docker's default PATH for an image that declares none.
const ControlPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// ControlPathClosed is the PATH plimsoll's own programs run with on a provider whose
// machine image the platform's own build changes after the operator's recipe: it is
// ControlPath without /usr/local. E2B's template build leaves /usr/local and
// everything in it writable by every user in the machine (mode 777; measured
// 2026-11-20 on E2B's base template and on one built from plimsoll's recipe), so a
// program found there could be one the session's code put there.
const ControlPathClosed = "/usr/sbin:/usr/bin:/sbin:/bin"

// libcStartupEnv are the variables the C library and dynamic loader of a program read
// while it starts, before its main runs, to find files to load: glibc's own list of
// variables unsafe in an environment someone else controls (UNSECURE_ENVVARS), cut to
// those GNU or busybox env reads at startup.
var libcStartupEnv = map[string]bool{"GLIBC_TUNABLES": true, "LOCPATH": true, "NLSPATH": true, "GCONV_PATH": true}

// LoaderStartupVariable reports whether name is a variable the C library or dynamic loader
// reads before a program's main: a libcStartupEnv name, or any LD_ name (musl reads
// LD_PRELOAD and LD_LIBRARY_PATH). It is the one copy of that list: the providers whose
// first process in a container starts with the image's environment (docker, wslc) refuse an
// image that sets one. It is a list of things to refuse, and so passes whatever a loader
// learns to read next (finding hunt-quality-67); it stands only where the names are an
// image's own and no list of names plimsoll writes can replace it.
func LoaderStartupVariable(name string) bool {
	return strings.HasPrefix(name, "LD_") || libcStartupEnv[name]
}

// controlEnvName is the shape of a variable a control program may be handed: one of
// plimsoll's own, PLIMSOLL_ and capitals, digits or underscores.
var controlEnvName = regexp.MustCompile(`^PLIMSOLL_[A-Z0-9_]+$`)

// controlEnvAllowed reports whether name may be a control program's variable: only a
// name plimsoll itself reads (PLIMSOLL_WORK, PLIMSOLL_INTERP_DIR, PLIMSOLL_RELAY_UID).
// It is an allow list on purpose. The names that choose what a program loads or runs are
// other people's lists, and they grow: PATH (env applies its assignments left to right,
// so one among env's would replace ControlPath), what the dynamic loader and the C
// library read before any program's main runs (every LD_ name, GLIBC_TUNABLES, LOCPATH,
// NLSPATH, GCONV_PATH), what node reads code from (NODE_OPTIONS, NODE_PATH, the rest of
// NODE_*), what OpenSSL reads a settings file or a module folder from (OPENSSL_CONF,
// OPENSSL_MODULES, OPENSSL_ENGINES). Until 2026-11-20 this was that list, refused; a
// name a later loader, node or library learned to read would have passed. No program of
// plimsoll's, and nothing it loads, reads a PLIMSOLL_ name as code or as a place to find
// code.
func controlEnvAllowed(name string) bool {
	return controlEnvName.MatchString(name)
}

// ControlArgv starts argv, one of plimsoll's own programs in a sandbox (the sweep, the
// process lister, the identity check, a relay, the runner, a smoke probe), with an
// empty environment plus ControlPath and env: nothing the image or the platform's exec
// declares reaches it, so no variable can load code into it (NODE_OPTIONS, a search
// path into a writable directory). env is named by its absolute path, so a PATH cannot
// choose it either, and it reads no variable itself; a variable in env that is not one
// of plimsoll's own names is refused (controlEnvAllowed). What docker
// hands the first process before env clears anything is docker_cli.go's concern.
func ControlArgv(env map[string]string, argv ...string) ([]string, error) {
	return controlArgv(ControlPath, env, argv...)
}

func controlArgv(searchPath string, env map[string]string, argv ...string) ([]string, error) {
	out := []string{"/usr/bin/env", "-i", "PATH=" + searchPath}
	for k, v := range env {
		if !controlEnvAllowed(k) {
			return nil, fmt.Errorf("%q is not a variable a control program takes: only PLIMSOLL_ names, which plimsoll itself reads, are handed on, so no variable can choose what the program loads or runs", k)
		}
		out = append(out, k+"="+v)
	}
	return append(out, argv...), nil
}

// ControlOpenSSL is the variable ControlArgvClosed adds: an empty OpenSSL settings
// file, so OpenSSL in a control program (node's cryptography) reads no settings file of
// the machine's, and with it no module a settings file names by path.
const ControlOpenSSL = "OPENSSL_CONF=/dev/null"

// ControlArgvClosed is ControlArgv for a provider whose sandbox root is an operator's
// machine image rather than plimsoll's own (E2B's templates): the same empty
// environment with ControlPathClosed in place of ControlPath, plus ControlOpenSSL, and
// argv's program must be named by its full path, never found through a search path.
// Where the program starts (its working folder) is the provider's to set; it must be
// one the session cannot write.
func ControlArgvClosed(env map[string]string, argv ...string) ([]string, error) {
	if len(argv) == 0 || !strings.HasPrefix(argv[0], "/") {
		return nil, fmt.Errorf("a control program must be named by its full path, not %q", strings.Join(argv[:min(len(argv), 1)], ""))
	}
	return ControlArgvClosedByName(env, argv...)
}

// ControlArgvClosedByName is ControlArgvClosed for the one program such a provider
// starts by name: a session's open, which runs before any of the session's code and
// pins every program later starts name by path. Its program is found through
// ControlPathClosed alone.
func ControlArgvClosedByName(env map[string]string, argv ...string) ([]string, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("a control program must be named")
	}
	out, err := controlArgv(ControlPathClosed, env, argv...)
	if err != nil {
		return nil, err
	}
	// After PATH, before the caller's variables and the program.
	return slices.Insert(out, 3, ControlOpenSSL), nil
}
