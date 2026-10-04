package sessionkit

import (
	"fmt"
	"regexp"
)

// ControlPath is the PATH plimsoll's own programs in a sandbox run with: the standard
// system directories of every image plimsoll ships, all on the image's read-only
// root. It is also docker's default PATH for an image that declares none.
const ControlPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ControlArgv starts argv, one of plimsoll's own programs in a sandbox (the sweep, the
// process lister, the identity check, a relay, the runner, a smoke probe), with an
// empty environment plus ControlPath and env: nothing the image or the platform's exec
// declares reaches it, so no variable can load code into it (NODE_OPTIONS, a search
// path into a writable directory). env is named by its absolute path, so a PATH cannot
// choose it either, and it reads no variable itself. What docker hands the first
// process before env clears anything is docker_cli.go's concern.
func ControlArgv(env map[string]string, argv ...string) ([]string, error) {
	out := []string{"/usr/bin/env", "-i", "PATH=" + ControlPath}
	for k, v := range env {
		if !envName.MatchString(k) {
			return nil, fmt.Errorf("%q is not an environment variable name", k)
		}
		out = append(out, k+"="+v)
	}
	return append(out, argv...), nil
}
