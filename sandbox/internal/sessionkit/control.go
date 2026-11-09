package sessionkit

import (
	"fmt"
	"regexp"
	"strings"
)

// ControlPath is the PATH plimsoll's own programs in a sandbox run with: the standard
// system directories of every image plimsoll ships, all on the image's read-only
// root. It is also docker's default PATH for an image that declares none.
const ControlPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// controlEnvRefused reports whether name may not be a control program's variable,
// because it chooses what the program loads or runs: PATH (env applies its assignments
// left to right, so one among env's would replace ControlPath, and the program is then
// looked up where the caller said), the names the dynamic loader and the C library read
// before any program's main runs (every LD_ name, and the libcStartupEnv set the docker
// provider refuses on an image), and the names node reads code from (NODE_OPTIONS,
// NODE_PATH, the rest of NODE_*). Every caller passes PLIMSOLL_* names; this keeps a
// later one from handing a control program a variable that would make it guest-facing.
func controlEnvRefused(name string) bool {
	switch name {
	case "PATH", "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "GCONV_PATH":
		return true
	}
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "NODE_")
}

// ControlArgv starts argv, one of plimsoll's own programs in a sandbox (the sweep, the
// process lister, the identity check, a relay, the runner, a smoke probe), with an
// empty environment plus ControlPath and env: nothing the image or the platform's exec
// declares reaches it, so no variable can load code into it (NODE_OPTIONS, a search
// path into a writable directory). env is named by its absolute path, so a PATH cannot
// choose it either, and it reads no variable itself; a variable in env that would
// choose what the program loads or runs is refused (controlEnvRefused). What docker
// hands the first process before env clears anything is docker_cli.go's concern.
func ControlArgv(env map[string]string, argv ...string) ([]string, error) {
	out := []string{"/usr/bin/env", "-i", "PATH=" + ControlPath}
	for k, v := range env {
		if !envName.MatchString(k) {
			return nil, fmt.Errorf("%q is not an environment variable name", k)
		}
		if controlEnvRefused(k) {
			return nil, fmt.Errorf("%s is not a variable a control program takes: it would choose what the program loads or runs", k)
		}
		out = append(out, k+"="+v)
	}
	return append(out, argv...), nil
}
