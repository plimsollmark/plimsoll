package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// WARNING: read this before changing how the docker provider starts the docker CLI,
// what environment a process in a sandbox starts with, or which images it accepts.
// Environment variables are a channel into the sandbox that no wall of the container
// closes, and two leaks through it were reproduced on 2026-10-02:
//
//  1. The host's docker client config. Its `proxies` setting makes `docker run` put
//     HTTP_PROXY, HTTPS_PROXY and NO_PROXY, credentials included, into every
//     container it starts, where guest code reads them. dockerCommand points the CLI
//     at an empty config directory this process owns (--config), so no client setting
//     of the host applies: no proxies, credential helpers, plugins or contexts.
//  2. The image's environment. Every `docker exec` starts with the image's ENV. An
//     image setting NODE_OPTIONS="--require /work/hook.js" ran a file guest code had
//     written inside the next node process plimsoll started, which in a session is
//     the sweep (whose exit status is the session's boundary) and the relay (whose
//     frames carry results). noexec does not stop it: node reads the file. So
//     plimsoll's own programs in the sandbox start under controlArgv (`env -i`, a fixed
//     PATH), and checkImageEnv refuses an image whose ENV can load code from a place
//     guest code can write.
//
// And one near miss: every child process inherits its parent's environment unless
// told otherwise, and plimsolld's holds caller tokens and provider keys. The CLI
// copies one of its own variables into a container for `-e NAME` written without a
// value, so a single such flag would have handed a secret to guest code.
// dockerCommand gives the CLI PATH and nothing else, and dockerEnvFlag is the one
// place an -e flag is built.
//
// Tests hold these in place: TestDockerCLIIsStartedOnlyThroughDockerCommand fails the
// build if this package starts docker any other way or builds an -e flag by hand,
// and the docker suite proves a proxy in the client config and a hook in the image
// never reach guest code.

// dockerClientConfig is an empty directory this process owns, given to every docker
// command as its client config. Made once; a failure fails every docker command. It
// must be a fresh private directory: a fixed path in a shared temp directory could be
// made first by another user, with a `proxies` setting in it. Nothing removes it when
// the process exits, so it holds dockerAliveSocket, which the process listens on for
// its life, and reapDeadHostDirs removes a config directory whose socket refuses
// (docker_hostdirs.go). The docker CLI reads only its own files there.
var dockerClientConfig = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "plimsoll-docker-config-")
	if err != nil {
		return "", err
	}
	l, err := net.Listen("unix", filepath.Join(dir, dockerAliveSocket))
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("docker client config: liveness socket: %w", err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			_ = c.Close()
		}
	}()
	return dir, nil
})

// dockerAliveSocket is the liveness socket in the docker client config directory.
const dockerAliveSocket = "alive.sock"

// dockerCLIEnv is the whole environment the docker CLI gets: PATH, so it can find
// its own helpers. Not HOME, DOCKER_CONFIG, DOCKER_HOST, DOCKER_CONTEXT or anything
// else: every command names its daemon with --host and its config with --config.
func dockerCLIEnv() []string {
	return []string{"PATH=" + os.Getenv("PATH")}
}

// dockerCommand is the one way the docker provider starts the docker CLI (see the
// warning above). A failure to make the config directory is returned by the
// command's Start, Run or Output.
func dockerCommand(ctx context.Context, args ...string) *exec.Cmd {
	dir, err := dockerClientConfig()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--config", dir}, args...)...)
	cmd.Env = dockerCLIEnv()
	if err != nil {
		cmd.Err = fmt.Errorf("docker: no private client config directory: %w", err)
	}
	return cmd
}

// dockerOutputCap bounds the answer of any docker command whose output plimsoll
// parses: an inspect, a listing, a version. The largest it reads (an image inspect
// or a long listing of session containers) is tens of kilobytes; 4 MiB leaves room
// without letting a daemon's answer grow without bound in plimsolld's memory.
const dockerOutputCap = 4 << 20

// dockerOutput runs a docker command (through dockerCommand) and returns its stdout,
// refusing an answer past dockerOutputCap rather than parsing part of one. A failure
// carries docker's stderr, bounded.
func dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = dockerOutputCap, 64<<10
	cmd := dockerCommand(ctx, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Truncated() {
		return nil, fmt.Errorf("docker answered more than %d bytes", dockerOutputCap)
	}
	return []byte(stdout.String()), nil
}

// dockerResolveCommand starts the docker CLI for the one command that must read the
// operator's client setup: resolving which daemon DOCKER_HOST, DOCKER_CONTEXT and
// the saved context name. It starts no container, so the config's proxies cannot
// reach one; it gets only the variables that resolution reads, never a secret.
func dockerResolveCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", args...)
	env := dockerCLIEnv()
	for _, k := range []string{"HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = env
	return cmd
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// dockerEnvFlag is the one place a docker -e flag is built: always NAME=value, so the
// CLI never copies a variable from its own environment, and the name a valid one.
func dockerEnvFlag(name, value string) ([]string, error) {
	if !envName.MatchString(name) {
		return nil, fmt.Errorf("docker: %q is not an environment variable name", name)
	}
	return []string{"-e", name + "=" + value}, nil
}

// dockerEnvFlagPair is dockerEnvFlag for a NAME=value string.
func dockerEnvFlagPair(pair string) ([]string, error) {
	name, value, ok := strings.Cut(pair, "=")
	if !ok {
		return nil, fmt.Errorf("docker: environment entry %q has no value; the CLI would copy its own", pair)
	}
	return dockerEnvFlag(name, value)
}

// controlPath is the PATH plimsoll's own programs in a sandbox run with: the standard
// system directories of every image plimsoll ships, all on the read-only root.
const controlPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// controlArgv starts argv, one of plimsoll's own programs in the sandbox (the sweep,
// the process lister, the identity check, a relay), with an empty environment plus
// controlPath and env: nothing the image declares reaches it (see the warning
// above). Guest-facing processes (snippets, project steps, interpreters) keep the
// image's environment, which checkImageEnv has vetted.
func controlArgv(env map[string]string, argv ...string) ([]string, error) {
	out := []string{"env", "-i", "PATH=" + controlPath}
	for k, v := range env {
		if !envName.MatchString(k) {
			return nil, fmt.Errorf("docker: %q is not an environment variable name", k)
		}
		out = append(out, k+"="+v)
	}
	return append(out, argv...), nil
}

// imageEnvLoaders make a program load code or a library, or change what it trusts,
// whatever their value; an image declaring one is refused. A toolchain can bake such
// a setting into its own files instead.
var imageEnvLoaders = map[string]bool{
	"NODE_OPTIONS": true, "NODE_REPL_EXTERNAL_MODULE": true, "NODE_EXTRA_CA_CERTS": true,
	"NODE_TLS_REJECT_UNAUTHORIZED": true, "NODE_V8_COVERAGE": true, "NODE_ICU_DATA": true,
	"BASH_ENV": true, "ENV": true, "GLIBC_TUNABLES": true, "GCONV_PATH": true, "LOCPATH": true,
	"HOSTALIASES": true, "PERL5OPT": true, "RUBYOPT": true, "JAVA_TOOL_OPTIONS": true,
	"_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "PYTHONSTARTUP": true, "PYTHONHOME": true,
	"PYTHONUSERBASE": true, "PYTHONBREAKPOINT": true, "PYTHONINSPECT": true, "PYTHONEXECUTABLE": true,
	"PYTHONPYCACHEPREFIX": true, "NODE_COMPILE_CACHE": true,
}

// imageEnvPathLists are searched for code, one directory per entry; an image may set
// them only to absolute directories on its read-only root.
var imageEnvPathLists = map[string]bool{
	"PATH": true, "NODE_PATH": true, "PYTHONPATH": true, "PERL5LIB": true, "PERLLIB": true, "RUBYLIB": true,
}

// guestWritable are the places guest code can write in any provider's sandbox: the
// docker provider's tmpfs mounts and OpenShell's work directory, and the kernel's
// virtual trees, whose paths name descriptors and processes rather than files.
var guestWritable = []string{"/tmp", "/work", "/dev", "/proc", "/sys", "/run", "/var/tmp"}

// checkImageEnv refuses an image environment that could load code guest code wrote:
// a loader variable (imageEnvLoaders, or any LD_ or DYLD_ variable), or a search path
// with an entry that is relative or inside a place guest code can write.
func checkImageEnv(env []string) error {
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if imageEnvLoaders[name] || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
			return fmt.Errorf("the image sets %s, which makes a program load code or change what it trusts before plimsoll's checks run; refused (bake the setting into the toolchain's own files instead)", name)
		}
		if !imageEnvPathLists[name] {
			continue
		}
		for _, dir := range strings.Split(value, ":") {
			if !strings.HasPrefix(dir, "/") {
				return fmt.Errorf("the image's %s has the entry %q, which is not an absolute directory; a relative entry resolves inside the work directory guest code writes; refused", name, dir)
			}
			// Compared as the place it names: //tmp, /usr/../tmp and /./tmp are /tmp. A
			// link on the image's root is the image author's own statement and is not
			// followed here.
			clean := path.Clean(dir)
			for _, w := range guestWritable {
				if clean == w || strings.HasPrefix(clean, w+"/") {
					return fmt.Errorf("the image's %s has the entry %q, inside %s, which guest code can write; refused", name, dir, w)
				}
			}
		}
	}
	return nil
}
