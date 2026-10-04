package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"

	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
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
//  2. The image's environment. Every process docker starts in a container begins
//     with the image's ENV. An image setting NODE_OPTIONS="--require /work/hook.js"
//     ran a file guest code had written inside the next node process plimsoll
//     started, which in a session is the sweep (whose exit status is the session's
//     boundary) and the relay (whose frames carry results). noexec does not stop it:
//     node reads the file. A denylist of such variables guarded it until review F5;
//     now no program of plimsoll's starts with the image's environment at all. Each
//     starts under sessionkit.ControlArgv (/usr/bin/env -i, a fixed PATH), and guest-facing
//     processes get the image's environment handed to them explicitly (guestArgv, and
//     the runner's plan), read from the verified image's config. Whatever the image
//     declares then reaches guest processes alone, where it can load only the guest's
//     own code.
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

// dockerErrorCap bounds the stderr kept for an error: docker's own complaint is one
// line, and 64 KiB keeps a long one whole without holding a runaway stream.
const dockerErrorCap = 64 << 10

// dockerOutput runs a docker command (through dockerCommand) and returns its stdout,
// refusing an answer past dockerOutputCap rather than parsing part of one. A failure
// carries docker's stderr, bounded. Only stdout is parsed: a warning docker prints on
// stderr never lands inside the answer.
func dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	return cappedOutput(dockerCommand(ctx, args...))
}

// dockerResolveOutput is dockerOutput for dockerResolveCommand.
func dockerResolveOutput(ctx context.Context, args ...string) ([]byte, error) {
	return cappedOutput(dockerResolveCommand(ctx, args...))
}

// cappedOutput runs cmd with both streams bounded. Every docker answer the provider
// reads whole goes through it; TestDockerCLIOutputIsAlwaysCapped fails the build on a
// read that does not.
func cappedOutput(cmd *exec.Cmd) ([]byte, error) {
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = dockerOutputCap, dockerErrorCap
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

// defaultGuestUID is the user every sandbox process runs as unless SANDBOX_GUEST_UID
// says otherwise, with a group of the same number: a uid no host account uses.
// Under runc without user-namespace
// remapping a container's uid is the host's, and uid 1000, the old default, is the first
// account most machines make, often its operator's; an escape, or any kernel check keyed
// on uid, would land as that account. 61000 is below 65,536, since docker's userns-remap
// and rootless docker map 65,536 container uids by default (docs.docker.com), so it
// still starts under them; and it is in the band systemd leaves unused (60706 to 61183,
// systemd.io/UIDS-GIDS): above the 60000 ceiling regular accounts get by default, below
// the dynamic service users (61184 and up). The identity check runs as the next uid.
const defaultGuestUID = 61000

// maxGuestUID is the highest uid SANDBOX_GUEST_UID may name: 65532, so the guest and its
// identity check (uid + 1) stay below nobody (65534) and inside a default user-namespace
// mapping of 65,536 uids.
const maxGuestUID = 65532

// Every program of plimsoll's in a docker sandbox starts through
// sessionkit.ControlArgv. Its first process, /usr/bin/env, is the one docker starts
// with the image's environment: its dynamic loader and C library read that before -i
// clears anything, so Preflight refuses an image that sets a variable they read at
// startup (checkLoaderEnv), and the loader variables it could inherit load only from
// the read-only root, since every writable mount is noexec.

// startScript starts a guest-facing process (a snippet's node, the runner whose steps
// are the guest's) with the environment docker gives a process it starts: HOME from
// the passwd entry of the uid it runs as, read from /proc/self/status ("/" without one,
// which a guest uid no account uses gets), HOSTNAME from /etc/hostname, then
// the variables in its arguments, which override them as an image's own HOME would.
// It runs under sessionkit.ControlArgv, so the image's environment cannot change what this shell
// does; with a marker, it writes the marker to stderr first, before any process the
// image's environment reaches exists. Arguments: the marker ("" for none), then
// NAME=value entries, then the command.
const startScript = `m=$1; shift
[ -z "$m" ] || printf %s "$m" >&2
u=
{ while read -r k v _; do if [ "$k" = Uid: ]; then u=$v; break; fi; done < /proc/self/status; } 2>/dev/null
h=/
{ [ -n "$u" ] && while IFS=: read -r _ _ i _ _ d _ || [ -n "$i" ]; do if [ "$i" = "$u" ]; then h=$d; break; fi; done < /etc/passwd; } 2>/dev/null
n=
{ read -r n < /etc/hostname; } 2>/dev/null
exec /usr/bin/env -i PATH=` + sessionkit.ControlPath + ` HOME="$h" HOSTNAME="$n" "$@"`

// guestArgv starts argv as a guest-facing process through startScript, with env (the
// image's environment, then the run's own variables) as its environment and marker,
// when not empty, written to stderr before it starts.
func guestArgv(marker string, env []string, argv ...string) ([]string, error) {
	if err := checkEnvEntries(env); err != nil {
		return nil, err
	}
	out, err := sessionkit.ControlArgv(nil, "/bin/sh", "-c", startScript, "sh", marker)
	if err != nil {
		return nil, err
	}
	out = append(out, env...)
	return append(out, argv...), nil
}

// startMarker is a fresh marker for one call: startScript writes it to stderr before
// the call's command starts, so it is never guest output.
func startMarker() string { return "plimsoll-started:" + randID() + "\n" }

// afterMarker reports whether stderr holds marker, which proves the call's start
// script ran in the container, and returns what followed it: the call's own stderr.
// Anything before it is not the guest's (a warning the docker CLI printed before the
// container's output, or bytes another process of a session wrote into the new
// process's stderr before the script did). Its absence, whatever the exit code, is never
// the guest's result: almost always docker never started plimsoll's command, and no list
// of docker's error wording decides it (review F6); since a broken attach stream can lose
// the marker of a call that did start, it is an error never marked not dispatched.
func afterMarker(stderr, marker string) (string, bool) {
	i := strings.Index(stderr, marker)
	if i < 0 {
		return stderr, false
	}
	return stderr[i+len(marker):], true
}

// checkEnvEntries refuses an environment entry guestArgv could not hand on exactly:
// one without "=" or with an empty name. Any other name is passed on as docker passes
// it (spring.profiles.active, my-var): every entry follows a PATH= operand, after
// which both GNU and busybox env read NAME=value as an assignment whatever NAME is
// (checked 2026-10-03, "-x=1" included).
func checkEnvEntries(env []string) error {
	for _, kv := range env {
		if name, _, ok := strings.Cut(kv, "="); !ok || name == "" {
			return fmt.Errorf("the environment entry %q is not NAME=value; plimsoll hands the image's environment to guest processes explicitly and cannot pass this one on", kv)
		}
	}
	return nil
}

// libcStartupEnv are the variables the C library and dynamic loader of a program read
// while it starts, before its main runs, to find files to load: glibc's own list of
// variables unsafe in an environment someone else controls (UNSECURE_ENVVARS), cut to
// those GNU or busybox env reads at startup; plus any LD_ name (musl reads
// LD_PRELOAD and LD_LIBRARY_PATH).
var libcStartupEnv = map[string]bool{"GLIBC_TUNABLES": true, "LOCPATH": true, "NLSPATH": true, "GCONV_PATH": true}

// checkLoaderEnv refuses an image environment that sets a libcStartupEnv variable.
// Docker gives the image's environment to the first process of every container
// command, and that process is plimsoll's /usr/bin/env: its loader and C library read
// these before env -i can clear anything. LD_DEBUG writes to stderr ahead of a call's
// start marker, LD_TRACE_LOADED_OBJECTS makes every program exit 0 without running (0
// is a clean sweep), LD_PRELOAD loads a library, and GNU env's setlocale reads locale
// files from LOCPATH, which in a session could be files guest code wrote. It is the one
// part of the image's environment no program of plimsoll's can start ahead of; every
// other variable reaches guest processes alone (guestArgv). A toolchain that needs a
// library or locale path can bake it into the image (ld.so.conf, an rpath) instead.
func checkLoaderEnv(env []string) error {
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "LD_") || libcStartupEnv[name] {
			return fmt.Errorf("the image sets %s, which the C library or dynamic loader reads before any program in the container runs, plimsoll's own included; refused (bake the setting into the image: ld.so.conf, an rpath)", name)
		}
	}
	return nil
}
