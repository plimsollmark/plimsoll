package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// Docker sessions keep one locked-down container for many calls
// (SessionProvider). The container is a run's container (the same lockdown flags,
// the project image, its Preflight-verified content ID) kept alive by a main
// process that does nothing; every call is a `docker exec` into it, and after every
// call the shared sweep (sandbox/internal/sessionkit) kills every process the call
// left behind. What is particular to docker:
//
//   - PID 1 is the guest guard in its process-1 mode (launchPID1; finding guest-guard-10,
//     decision 10 B), in place of docker's --init, so it runs behind the guard's filter like
//     every other process of the container. It collects: a killed process whose parent has
//     gone is reparented to PID 1, and a PID 1 that never collected (sleep) would keep its
//     zombie, which counts against the process limit, for the session's life. It starts
//     the main process as its child, exits with it, and exits on a signal recorded as from
//     outside the container (docker stop's is one), so the kernel ends the rest; it passes no
//     signal on. Code of the session can still end or stall its own session through process 1,
//     as it always could by ending the main process: it can cause a signal recorded as from
//     outside (finding guest-guard-34), stop or end process 1 under gVisor (35), and keep a
//     SIGTERM pending so an outside docker stop waits its timeout (36). Close does not use
//     docker stop: removeContainer is docker rm -f, which does not wait.
//   - The sweep runs non-dumpable under the runner guard, so once the guard has loaded
//     no process of a call can attach to it and forge its exit status. From its exec
//     until then (env, sh, then node's loader) it is dumpable, and what refuses an
//     attach in that moment is Yama: docker exec starts it outside the ancestry of
//     every process of the session's, and the baseline refuses a host whose
//     ptrace_scope reads 0 (gVisor's own reads 1 whatever the host's). What code of the
//     session can still open then is the exec's own pipes, which the verdict, an exit
//     status, does not travel on (docker_guard_window_test.go measures both).
//   - Every writable mount is a sized tmpfs, which a stopped container loses. So a
//     suspend is `docker pause` (the cgroup freezer): CPU stops, memory, files and
//     live interpreters stay, and Suspend reports that the memory is still held. And
//     a sweep that does not prove the boundary ends the session: the only recovery
//     that kills every process, a restart, would lose the files.
//   - Anyone who can reach the docker daemon can change a running container (`docker
//     update`, `docker network connect`), so the security-relevant parts of
//     `docker inspect` are read back before every call and compared with what they
//     were at open.
//   - The broker socket is mounted at open, because a running container cannot gain
//     a mount. It serves a call's grant only during that call; between calls, and in
//     a call without a grant, it answers 503.

var (
	// dockerSessionCommand is a session container's main process (under the guard as
	// PID 1): 2^31-1 seconds, which every sleep accepts, and far beyond any lifetime.
	dockerSessionCommand = []string{"sleep", "2147483647"}
	// dockerSessionDirs are a session's writable mounts, which the sweep measures
	// against its disk budget.
	dockerSessionDirs = []string{"/tmp", "/work", "/dev/shm"}
)

const (
	// dockerSessionLabel marks a session container. dockerExpiresLabel is when a
	// container's lifetime ends (Unix seconds): every container this provider starts
	// declares it (a run's, the smoke test's, a session's, a pool member's), and
	// ReconcileOrphans reads it (review F2).
	dockerSessionLabel = "io.plimsoll.session"
	dockerExpiresLabel = "io.plimsoll.expires"
	// dockerInstanceLabel names the DockerSandbox that started a container, a random id
	// per value, so the containers of several daemons (or test runs) on one docker host
	// can be told apart: docker ps --filter label=io.plimsoll.instance=ID. Nothing reads
	// it to decide anything; ReconcileOrphans still reaps by lifetime alone.
	dockerInstanceLabel = "io.plimsoll.instance"
	// dockerReapMargin is how long past its declared lifetime a container must be
	// before ReconcileOrphans removes it, so a clock difference between two daemons
	// sharing a docker host never removes a live one, nor a run's container while its
	// removal after a deadline (forceRemove, up to dockerRemoveBudget) is under way.
	dockerReapMargin = 5 * time.Minute
	// dockerSessionWork is the working directory of every call.
	dockerSessionWork = "/work"
	// dockerRunnerGuard is the library plimsoll loads into each node program of its own
	// beside guest code (a session's sweep, quiesce and relays, the granted-run
	// forwarder) to make it non-dumpable. The project runner, the native helper, makes
	// itself non-dumpable with one call and loads nothing.
	dockerRunnerGuard = "/usr/local/lib/plimsoll-runner-guard.so"
	// dockerControlBudget bounds a create, inspect, pause, unpause or listing.
	dockerControlBudget = 60 * time.Second
)

// A pause's budget is held under SuspendBound, which a session layer's suspend budget is
// derived from: a larger number here does not compile.
const _ = uint64(SuspendBound - dockerControlBudget)

// dockerProjectRunner is the project runner's own command line: what plimsoll starts,
// after the start script, for every project call (a run, a granted run behind the
// forwarder, a session's project call): the native helper in the project image
// (nativehelper.RunProject), which SmokeTest holds to its pin (smokeNativeHelper) before
// any run. A variable only so that a test can wrap it; nothing a daemon reads sets it.
var dockerProjectRunner = slices.Clone(nativehelper.RunProject)

// runnerCommand is the project runner's command line this provider starts:
// dockerProjectRunner, or the one a test set (projectRunner).
func (d *DockerSandbox) runnerCommand() []string {
	if len(d.projectRunner) > 0 {
		return slices.Clone(d.projectRunner)
	}
	return slices.Clone(dockerProjectRunner)
}

// runnerArgv starts the project image's runner with the environment startScript gives a
// process, and none of the image's: the steps get that through the plan
// (runnerwire.Plan.Env), the runner never does. marker is the call's start marker
// (afterMarker). No guard library: the runner is a static program that makes itself
// non-dumpable before it reads its plan, and no loader reads LD_PRELOAD for it.
func (d *DockerSandbox) runnerArgv(marker string) ([]string, error) {
	return guestArgv(marker, nil, d.runnerCommand()...)
}

// forwardingRunnerArgv starts the runner for a granted project run: behind
// plimsoll's loopback forwarder (hostForwarderWrapperJS), which listens on hostAPIListen,
// passes each connection to the broker's socket, and runs the runner as its child with
// the same stdin and stdout. The guard loads into the forwarder, a node program that
// holds the same descriptors the runner does; the runner inherits LD_PRELOAD, which
// nothing in a static program reads, and drops it from every step's environment.
func (d *DockerSandbox) forwardingRunnerArgv(marker, listen string) ([]string, error) {
	argv := append(sessionkit.NodeArgv("--eval", hostForwarderWrapperJS, listen, containerSocketPath, "--", "--"), d.runnerCommand()...)
	return guestArgv(marker, []string{"LD_PRELOAD=" + dockerRunnerGuard}, argv...)
}

// dockerForwardingSnippetArgv starts a snippet with sdk_env behind the forwarder: the
// wrapper runs under the control environment, listens, and then starts `node -` with
// env, the guest's environment (the image's and the grant's), which never reaches the
// wrapper itself.
func dockerForwardingSnippetArgv(marker, listen string, env []string) ([]string, error) {
	if err := checkEnvEntries(env); err != nil {
		return nil, err
	}
	argv := append(sessionkit.NodeArgv("--eval", hostForwarderWrapperJS, listen, containerSocketPath, "--"), env...)
	argv = append(append(argv, "--"), sessionkit.GuestNodeArgv("-")...)
	return guestArgv(marker, nil, argv...)
}

// guarded runs argv non-dumpable: the guard is loaded into the process that execs
// argv, never into sh, and only into that one program.
func guarded(argv []string) []string {
	return append([]string{"sh", "-c", `export LD_PRELOAD=` + dockerRunnerGuard + `; exec "$@"`, "sh"}, argv...)
}

// sessionControlArgv is how a session starts each of its control programs (the sweep,
// the quiesce, every cell relay): under sessionkit.ControlArgv, with env as its only
// variables (docker_cli.go), and non-dumpable under the runner guard. SmokeTest starts
// its guard check the same way (smokeGuard), so an image that lacks the library, which
// a loader skips without a word, is refused at startup.
func sessionControlArgv(env map[string]string, argv []string) ([]string, error) {
	return sessionkit.ControlArgv(env, guarded(argv)...)
}

// SupportsSessions reports whether a project image is configured: a session runs
// every call in it.
func (d *DockerSandbox) SupportsSessions() bool { return d.ProjectImage != "" }

// SessionEnvironments is the project image's environment for every payload kind:
// a session's snippets run in the project image too, not the snippet image.
func (d *DockerSandbox) SessionEnvironments() Environments {
	env := d.Environments()
	project := env.Project
	project.FileScopes = d.sessionFileScopes()
	return Environments{
		JavaScript: PayloadEnvironment{Identity: project.Identity, SoftwareIdentity: project.SoftwareIdentity, MaxTimeout: d.snippetCeiling(), Languages: project.Languages, FileScopes: d.sessionFileScopes()},
		Project:    project,
	}
}

// sessionFileScopes are the scopes a session takes file calls in. The project image's helper,
// which carries them out, is the build this plimsolld carries, checked at startup (RunFiles),
// and the work folder is a tmpfs of its own, so the work scope holds wherever the kernel has
// what it needs, which the last SmokeTest saw (smokeRunner); where it does not (before Linux
// 5.8), or before a SmokeTest has seen it, the sandbox scope alone, so no session states a
// scope whose every call the helper refuses.
func (d *DockerSandbox) sessionFileScopes() []FilesScope {
	d.stateMu.RLock()
	work := d.workScope
	d.stateMu.RUnlock()
	if work {
		return FilesScopesBoth()
	}
	return FilesScopesSandboxOnly()
}

// errDraining is an open refused because Drain has begun.
var errDraining = fmt.Errorf("%w: the docker provider is shutting down", ErrAtCapacity)

// dockerSession is one open session.
type dockerSession struct {
	d        *DockerSandbox
	routes   *RouteBudget // route caps span the session's granted calls
	host     string
	name     string
	id       string // the full container ID docker run printed
	imageID  string
	manifest string
	env      []string // the image's environment: what the session's guest processes start with
	tier     IsolationClass
	// policy is the seccomp profile the container applies for its life, as a run's record
	// names it (the default's identity, or skipped under runsc): a session never gets the
	// sdk_env variant (CheckSessionGrant), so every call in it ran under this one.
	policy   string
	snapshot string // the security-relevant read-back at open
	broker   *dockerSessionBroker
	// life is the lifecycle every provider's sessions share: the turn, the lifetime,
	// suspend and the sweep after every call (sessionkit.Life), with the session's
	// interpreters, which a pause keeps.
	life *sessionkit.Life
	// held is set once a caller holds the session (activate): from then on a command the
	// refusing point refuses ends the session (refused); before, it fails the open or the
	// pool member, marked not dispatched.
	held atomic.Bool
}

var _ Session = (*dockerSession)(nil)

// OpenSession hands over a ready member of the session pool (docker_pool.go) when one
// matches, preferring one warming the hinted languages (every stated one without a
// hint), and otherwise creates a session container; either way the session's
// lifetime runs from now.
func (d *DockerSandbox) OpenSession(ctx context.Context, opts SessionOptions) (Session, error) {
	if opts.Lifetime <= 0 {
		return nil, NotDispatched(RefusalRequest, fmt.Errorf("%w: a session needs a positive lifetime", ErrInvalidRequest))
	}
	if !d.SupportsSessions() {
		return nil, NotDispatched(RefusalUnsupported, fmt.Errorf("%w: docker sessions need a project image", ErrUnsupported))
	}
	if err := validateDockerImage(d.ProjectImage); err != nil {
		return nil, notReady(ctx, err)
	}
	leave, ok := d.sessions.Enter()
	if !ok {
		return nil, AtCapacity(CapacityProvider, errDraining)
	}
	defer leave()
	d.stateMu.RLock()
	stated := slices.Clone(d.projectLanguages)
	d.stateMu.RUnlock()
	want, err := SessionLanguages(opts.Languages, stated)
	if err != nil {
		return nil, err
	}
	if len(want) == 0 {
		want = stated
	}
	expires := time.Now().Add(opts.Lifetime)
	// A pool member was verified when the pool made it and is read back before every
	// call, as any session is for its whole life, so a claim needs no new Preflight
	// (which re-runs once its result is 5 seconds old): it must match the execution
	// state the last Preflight verified, which a failed Preflight withdraws. An open
	// counts toward the pool's demand once it passes the floor, where opens are
	// refused, so a caller whose opens are refused cannot move the pool toward its
	// languages; and before the claim, so the refill the claim asks for sees it. A
	// warm-only open is refused when no member may be handed over, so it counts only
	// after a claim that found one: refused warm-only opens cost the caller nothing,
	// and counted they would steer the pool to whatever such a caller names (found in
	// review, 2026-10-28).
	pool := d.pool.Load()
	observed := false
	observe := func() {
		if pool != nil && !observed {
			pool.Observe(languageNames(want))
			observed = true
		}
	}
	if pool != nil {
		if state, err := d.executionState(); err == nil {
			if err := CheckMinimumIsolation(state.isolation, opts.MinimumIsolation); err != nil {
				return nil, err
			}
			if !opts.WarmOnly {
				observe()
			}
			if s, ok := pool.Claim(dockerPoolKey(state), expires, languageNames(want)); ok {
				observe()
				if err := d.activate(s, expires, opts.DiskBytes); err != nil {
					s.abandon(ctx)
					return nil, err
				}
				return s, nil
			}
		}
	}
	// Nothing is made for a warm-only open: no pool, no state a member could be claimed
	// under, or no member that may be handed over.
	if opts.WarmOnly {
		return nil, RefuseNoWarmSandbox()
	}
	if err := d.ensurePreflight(ctx); err != nil {
		return nil, notReady(ctx, err)
	}
	state, err := d.executionState()
	if err != nil {
		return nil, notReady(ctx, err)
	}
	if err := CheckMinimumIsolation(state.isolation, opts.MinimumIsolation); err != nil {
		return nil, err
	}
	observe()
	s, err := d.newSessionContainer(ctx, state, expires)
	if err != nil {
		return nil, err
	}
	if err := d.activate(s, expires, opts.DiskBytes); err != nil {
		s.abandon(ctx)
		return nil, err
	}
	return s, nil
}

// newSessionContainer creates a session container from the Preflight-verified project
// image under the run lockdown, with the guard as PID 1 (launchPID1), sleep as its main process
// and label as the end of its declared lifetime (which ReconcileOrphans reads); reads
// it back; and records its own processes, which every sweep spares. No caller holds it
// until activate.
func (d *DockerSandbox) newSessionContainer(ctx context.Context, state dockerExecutionState, label time.Time) (*dockerSession, error) {
	broker, err := startDockerSessionBroker()
	if err != nil {
		return nil, err
	}
	s := &dockerSession{
		d: d, host: state.host, name: "plsm-session-" + providerkit.RandHex(8),
		imageID: state.projectImageID, manifest: state.projectManifest, env: state.guestEnv(state.projectImageID), tier: state.isolation, policy: state.sessionPolicy(),
		broker: broker, routes: NewRouteBudget(),
	}
	s.life = sessionkit.NewLife(s.name, s.hooks())
	s.life.Interps.Checker = s.checkFunc
	// A cell's interpreter is guest-facing: it starts with the image's environment,
	// handed to it as a snippet's node gets it, while its launcher starts clean
	// (execFunc). startScript execs without forking, so the launcher's child is the
	// interpreter itself.
	start, err := guestArgv("", s.env)
	if err != nil {
		broker.Close()
		return nil, err
	}
	s.life.Interps.Start = start
	marker := dockerMainMarker()
	main, err := dockerSessionMain(marker)
	if err != nil {
		broker.Close()
		return nil, err
	}
	// Attached, not -d: the open reads the main process's standard error until its marker
	// (startMain), then lets the CLI go. Docker keeps nothing of it (--log-driver none).
	// No --init: process 1 is the guard itself (launchPID1), which collects as docker's init did.
	args := []string{"run", "--name", s.name, "--log-driver", "none",
		"--label", dockerSessionLabel + "=1"}
	args = append(args, d.labelArgs(label)...)
	// A session's container applies the default profile for its life: a grant with
	// sdk_env is refused in a session (CheckSessionGrant), since a later call could not
	// change the profile of processes already running.
	args = append(args, d.lockdownFlags(true, state.runtime, state.seccomp.defaultPath)...)
	args = append(args, "--mount", bindMount(broker.sock, containerSocketPath, false))
	if state.platform != "" {
		args = append(args, "--platform", state.platform)
	}
	tail, err := launchPID1(state.guard, state.projectImageID, main)
	if err != nil {
		broker.Close()
		return nil, err
	}
	args = append(args, tail...)
	opened, err := s.startMain(ctx, marker, args...)
	if err != nil {
		if refused := refusalIn(err); refused != nil {
			// The refusing point refused the session's docker run: docker never started, so
			// no container exists to remove and nothing ran (finding guest-guard-24).
			s.life.Abandon()
			broker.Close()
			return nil, NotDispatched(RefusalEnvironment, refused)
		}
		s.abandon(ctx)
		return nil, err
	}
	if err := guardLineAtOpen(opened); err != nil {
		s.abandon(ctx)
		return nil, err
	}
	insp, err := s.inspect(ctx)
	if err != nil {
		s.abandon(ctx)
		if !opened.started {
			// docker run ended before the main process started and left no container to read:
			// docker's own failure, as a failed docker run -d was.
			return nil, fmt.Errorf("docker run exited %d before the session's main process started: %s", opened.exit, truncateForError(strings.TrimSpace(opened.stderr)))
		}
		return nil, err
	}
	if err := insp.verifyAtOpen(state.projectImageID); err != nil {
		s.abandon(ctx)
		if refusal := guardCodeAtOpen(opened.started, insp); refusal != nil {
			return nil, refusal
		}
		return nil, err
	}
	if s.id = insp.ID; !dockerContainerID.MatchString(s.id) {
		s.abandon(ctx)
		return nil, fmt.Errorf("docker inspect: unreadable container ID %q", truncateForError(s.id))
	}
	s.snapshot = insp.securitySnapshot()
	if err := s.recordBaseline(ctx, guardedPID1(main), dockerSessionShell(marker)); err != nil {
		s.abandon(ctx)
		return nil, err
	}
	return s, nil
}

// The open reads the guest guard's own line (finding guest-guard-16, decision 16 B). A session's
// container keeps no output (--log-driver none), so the line the guard writes when it refuses
// the main process was lost, and the open read the main process's exit code alone. Now the
// open runs docker run attached, reads the CLI's standard error, and lets the CLI go once the
// main process has written its marker: plimsoll's shell, which the guard starts in place of the
// sleep, writes a fresh marker and then becomes the sleep (dockerSessionMain). The marker
// before anything else shows the guard started the main process. Without it, the CLI exited with
// the container, and its standard error ends with the guard's line when the guard refused.
//
// Guest code cannot forge either. Nothing of a caller's has run at that point: the container
// was created from the verified image a moment before, no call has been made in it, and every
// process in it is the guard, as process 1, and the plimsoll programs it starts. So what
// reaches that standard error is the docker CLI's and plimsoll's own, and only the guard
// writes a line in its form with its exit code. Docker still keeps nothing (attaching is
// not logging), and nothing reads the container's output after the open.

// dockerMainMarker is a fresh marker for a session's main process (dockerSessionMain); its
// prefix is not a call's (startMarker).
func dockerMainMarker() string { return "plimsoll-session-main:" + providerkit.RandHex(8) + "\n" }

// dockerSessionMain is a session container's main process, for the guard to start: plimsoll's
// shell under sessionkit.ControlArgv writes marker to standard error and becomes the sleep
// (dockerSessionCommand), so the process the session keeps is the sleep, with the environment
// it had before.
func dockerSessionMain(marker string) ([]string, error) {
	return sessionkit.ControlArgv(nil, dockerSessionShell(marker)...)
}

// dockerSessionShell is the shell's own command line in the main process, as the process
// list shows it between the marker and the exec (sessionkit.BaselineSettled): env -i has
// already become it, and it has not yet become the sleep.
func dockerSessionShell(marker string) []string {
	return append([]string{"/bin/sh", "-c", `printf %s "$1" >&2; shift; exec "$@"`, "sh", marker}, dockerSessionCommand...)
}

// mainStderrCap bounds what the open keeps of the attached docker run's standard error: the
// docker CLI's warnings, the guard's one line, the marker.
const mainStderrCap = 64 << 10

// mainStart is how a session's attached docker run went (startMain).
type mainStart struct {
	started bool   // the main process wrote its marker: the guard started it
	exit    int    // without the marker, the CLI's exit code: the container's, or docker's own (125)
	stderr  string // the CLI's standard error up to the marker or its exit, at most mainStderrCap bytes
}

// startMain runs the session's docker run (args) attached, reading its standard error until
// the main process writes marker or the CLI exits. On the marker the CLI is killed: the
// container runs on without it, as a docker run -d leaves it (measured 2026-11-20 under runc
// and gVisor: running, and docker exec into it works), and nothing reads its output again.
// An error means the docker run could not be started or did not end within the budget.
func (s *dockerSession) startMain(ctx context.Context, marker string, args ...string) (mainStart, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerControlBudget)
	defer cancel()
	full, err := dockerArgs(s.host, args...)
	if err != nil {
		return mainStart{}, err
	}
	cmd := dockerCommand(ctx, full...)
	if cmd.Err != nil {
		return mainStart{}, fmt.Errorf("docker run: %w", cmd.Err)
	}
	pipe, err := cmd.StderrPipe()
	if err != nil {
		return mainStart{}, err
	}
	if err := cmd.Start(); err != nil {
		return mainStart{}, fmt.Errorf("docker run: %w", err)
	}
	var got []byte
	chunk := make([]byte, 4096)
	started := false
	for len(got) < mainStderrCap {
		n, rerr := pipe.Read(chunk)
		got = append(got, chunk[:min(n, mainStderrCap-len(got))]...)
		if started = bytes.Contains(got, []byte(marker)); started || rerr != nil {
			break
		}
	}
	if started || len(got) >= mainStderrCap {
		_ = cmd.Process.Kill()
	}
	werr := cmd.Wait()
	if started {
		return mainStart{started: true, stderr: string(got)}, nil
	}
	if ctx.Err() != nil {
		return mainStart{}, fmt.Errorf("docker run: %w", ctx.Err())
	}
	if len(got) >= mainStderrCap {
		return mainStart{}, fmt.Errorf("docker run wrote more than %d bytes before the session's main process started", mainStderrCap)
	}
	return mainStart{exit: exitCodeOf(werr), stderr: string(got)}, nil
}

// guardLineAtOpen is the open's reading of the guard's own line: when the main process never
// wrote its marker and the CLI's standard error ends with the guard's line for its exit code,
// the guard refused to start it, marked not dispatched, in plimsoll's words for the step and
// errno the line names. nil otherwise, and then the exit code is still read (guardCodeAtOpen).
func guardLineAtOpen(start mainStart) error {
	if start.started {
		return nil
	}
	refusal, ok := guestGuardRefusal(start.exit, start.stderr)
	if !ok {
		return nil
	}
	return NotDispatched(RefusalEnvironment, errors.New("docker session: the main process: "+refusal))
}

// guardCodeAtOpen is the reading the open made before it read the guard's line, kept for when
// that line cannot be read, so the open is never weaker than it was: a main process that is
// not running at open and exited with a code of the guard's is refused, marked not dispatched,
// since no code of a caller's exists at open whatever ended it. Without the marker the code
// names the step; with it, the guard had started the main process, and the words say so.
func guardCodeAtOpen(started bool, insp dockerInspect) error {
	if insp.State.Running {
		return nil
	}
	for step, code := range guestGuardExit {
		if insp.State.ExitCode != code {
			continue
		}
		if started {
			return NotDispatched(RefusalEnvironment, fmt.Errorf("the session's main process ended at open with exit %d after the guest guard had started it; no code of a caller's had run", code))
		}
		return NotDispatched(RefusalEnvironment, fmt.Errorf("the guest guard refused to start the session's main process, so nothing was started: exit %d, its code for step %s", code, step))
	}
	return nil
}

// instance is d's id for dockerInstanceLabel.
func (d *DockerSandbox) instance() string {
	d.instanceOnce.Do(func() { d.instanceID = providerkit.RandHex(8) })
	return d.instanceID
}

// labelArgs labels a container d starts: its lifetime and d's instance.
func (d *DockerSandbox) labelArgs(expires time.Time) []string {
	return append(expiresLabelArgs(expires), "--label", dockerInstanceLabel+"="+d.instance())
}

// expiresLabelArgs declares t, rounded up to the second, as a container's lifetime
// (dockerExpiresLabel).
func expiresLabelArgs(t time.Time) []string {
	sec := t.Unix()
	if t.Nanosecond() > 0 {
		sec++
	}
	return []string{"--label", dockerExpiresLabel + "=" + strconv.FormatInt(sec, 10)}
}

// activate gives s to a caller: its lifetime ends at expires and its disk budget is
// disk, and Drain and ReconcileOrphans count it as open. Once Drain has begun it
// refuses, and the caller removes s.
func (d *DockerSandbox) activate(s *dockerSession, expires time.Time, disk int64) error {
	if !s.life.Activate(&d.sessions, expires, disk) {
		return AtCapacity(CapacityProvider, errDraining)
	}
	s.held.Store(true)
	return nil
}

// refused is what a session command the refusing point refused becomes (refusedCommand, finding
// guest-guard-24). Before a caller holds the session (an open, a pool member) it is marked not
// dispatched: no code of a caller's exists yet. Once held, the sandbox no longer starts
// plimsoll's programs as opened, so the session ends, as when the boundary is not proven, and
// the call gets that end; when the refused command was the call's own, callRefusal marks the
// call not dispatched as well.
func (s *dockerSession) refused(r *refusedCommandError) error {
	if !s.held.Load() {
		return NotDispatched(RefusalEnvironment, r)
	}
	s.life.FinishWith(&SessionEndedError{Reason: SessionBoundaryFailed, Detail: errDockerRefused})
	return s.Err()
}

// callRefusal is the one place that decides whether a call of a session a caller holds is
// marked not dispatched because its own command was refused (finding guest-guard-24, decision
// 24 B, narrowed by finding hunt-security-30). It is asked once per call, about the call's own
// command only, as soon as that command's exec has returned (out and err are what execAs
// returned; started is the call's start marker). It answers nil when it has nothing to say, and
// the call's other branches then decide.
//
// The call's own command is the one exec that starts the caller's code:
//
//   - a snippet: the exec of guestArgv(started, ..., node -), the start script and node behind
//     the guard. Before it a snippet makes no exec (the read-back is a docker inspect).
//   - a project: the exec of the runner (runnerArgv). Every step runs inside that one exec,
//     started by the runner, not by plimsoll and not behind a guard of their own, so no refusal of
//     plimsoll's can fall between two steps. A project whose second step fails after its first
//     ran, the guard's own line and code included (a step that starts the guard itself), is the
//     runner's authenticated report: the call ran, and it is a result, never marked. The quiesce
//     before the runner is not the call's own command; a refused quiesce refuses the call
//     through the session's lifecycle (sessionkit.Life.Quiesce), as one that never ran does.
//   - a cell: none. Its code travels over a relay to an interpreter, and its execs (the launcher,
//     the identity check, the relay's attach) are the interpreter driver's (sessionkit); a refusal
//     of one ends the session and leaves the cell unmarked, as before.
//   - a module: none. A session runs no modules; a module run is a fresh run, and docker_run.go
//     marks its refused command.
//
// One refusal of the call's own command is marked, reason environment: the refusing point
// refused it (out.refused), so docker was never started and no byte of the call exists. The
// session ends (boundary failed), as before.
//
// The guard's refusal is not marked, though nothing of the call ran when it is real. What shows
// it is the exec's standard error and exit code: the guard's line and code, and no start
// marker. Code of the session can shape all three. It writes the line and picks the code once
// its own call runs, and it can take the marker out: under runc the exec's standard error is a
// pipe the guest's uid owns, so a thread left in a kept interpreter (or the call's own code)
// reopens it through /proc/<pid>/fd/2 and reads the marker off it before docker does
// (TestDockerSessionCallThatRanIsNeverMarkedFromItsStderr does it on the first try). A mark
// there would tell the caller that a call that ran did not, and invite a retry that runs it
// again. So such an end is the session's end, boundary failed, unmarked, in words that say
// whether the call ran is not known; a real refusal of the guard's loses only its mark (no
// mark means execution may have occurred, which then forbids a blind retry and nothing more).
// The mark stays where no byte of a caller's can reach: the refusing point's refusal here, and
// the guard's line at open (guardLineAtOpen), before any code of a caller's exists.
//
// Everything else stays unmarked too, because no mark means execution may have occurred and
// that must stay true: a refusal of the sweep after the call (it runs after the answer has
// gone back, and the session's end reaches the next call), of the process list, the identity
// check, or of any command after the call's own command started.
func (s *dockerSession) callRefusal(out dockerExecResult, err error, started string) error {
	if out.refused {
		return NotDispatched(RefusalEnvironment, s.Err())
	}
	if err != nil || !out.exited {
		return nil
	}
	if _, ran := afterMarker(out.stderr, started); ran {
		return nil
	}
	step, errno, ok := guestGuardShape(out.exitCode, out.stderr)
	if !ok {
		return nil
	}
	s.life.FinishWith(&SessionEndedError{Reason: SessionBoundaryFailed, Detail: fmt.Sprintf(
		"the call's command ended as the guest guard ends when it refuses (step %s, errno %d, exit %d) and its start marker was not read; code of the session can write that line and take the marker, so whether the call's code ran is not known", step, errno, out.exitCode)})
	return s.Err()
}

// abandon removes a session container no caller ever held (one that failed to open,
// or a pool member), its relays and its broker. A container whose removal cannot be
// confirmed keeps the capacity admitted for the call ctx belongs to (removeOrHold): a
// failed open's, and nothing for a pool member, which no call admitted.
func (s *dockerSession) abandon(ctx context.Context) {
	s.life.Abandon()
	s.broker.Close()
	s.d.removeOrHold(ctx, s.host, s.name)
}

// hooks are what the session's lifecycle does to its container.
func (s *dockerSession) hooks() sessionkit.Hooks {
	return sessionkit.Hooks{
		Provider: "docker", Unit: "container",
		Refuse: sessionRefusals(),
		// A pause keeps the container's processes and memory, and its files in their
		// tmpfs mounts.
		Suspend: func(ctx context.Context) error {
			if err := s.control(ctx, "pause", s.name); err != nil {
				return fmt.Errorf("the container could not be paused: %w", err)
			}
			return nil
		},
		SuspendHoldsMemory: true,
		Resume: func(ctx context.Context) error {
			if err := s.control(ctx, "unpause", s.name); err != nil {
				return fmt.Errorf("the container could not be unpaused: %w", err)
			}
			return nil
		},
		ReadBack: s.readBack,
		// The sweep's exit status is the session's boundary: it starts under
		// sessionkit.ControlArgv, so no variable of the image can load code into it
		// (docker_cli.go), and non-dumpable under the runner guard, so no process of the
		// session can attach to it; before the guard has loaded, Yama refuses the attach
		// (the baseline requires ptrace_scope 1 or more; TestDockerGuardWindowSweep).
		Sweep: func(ctx context.Context, argv []string) (sessionkit.ExecResult, error) {
			argv, err := sessionControlArgv(nil, argv)
			if err != nil {
				return sessionkit.ExecResult{}, err
			}
			out, err := s.exec(ctx, argv, nil, nil, 4096, 4096)
			return sessionkit.ExecResult{ExitCode: out.exitCode, Exited: out.exited}, err
		},
		// The quiesce before a project call: every program of plimsoll's starts in this
		// container as the uid the session's code runs as, so nothing of the session's
		// may run while one starts (QuiesceScript). It starts the same way the sweep
		// does, and its exit status is as trustworthy.
		Quiesce: func(ctx context.Context, argv []string) (sessionkit.ExecResult, error) {
			argv, err := sessionControlArgv(nil, argv)
			if err != nil {
				return sessionkit.ExecResult{}, err
			}
			out, err := s.exec(ctx, argv, nil, nil, 4096, 4096)
			return sessionkit.ExecResult{ExitCode: out.exitCode, Exited: out.exited}, err
		},
		Measure: sessionkit.MeasureStatfs,
		Dirs:    dockerSessionDirs,
		// No restart: a restart would lose the files, which live in tmpfs mounts.
		Unproven: func(_ context.Context, sweep string) *sessionkit.EndedError {
			if end := s.containerEnd(); end != nil {
				return end
			}
			return &SessionEndedError{Reason: SessionBoundaryFailed, Detail: sweep}
		},
		// The broker closes first, so a container that outlives its removal can no
		// longer reach it. The teardown returns, and the session's Done closes and its
		// capacity comes back, only once the container is confirmed gone: a removal that
		// fails is quarantined, and ReconcileOrphans retries it until then.
		Teardown: func() {
			s.broker.Close()
			s.d.quarantine.DestroyAndWait(s.name, func() error { return s.d.forceRemove(s.host, s.name) })
		},
	}
}

// control runs one docker CLI command against the pinned daemon, bounded.
func (s *dockerSession) control(ctx context.Context, args ...string) error {
	_, err := s.controlOutput(ctx, args...)
	return err
}

func (s *dockerSession) controlOutput(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerControlBudget)
	defer cancel()
	full, err := dockerArgs(s.host, args...)
	if err != nil {
		return nil, err
	}
	out, err := dockerOutput(ctx, full...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("docker %s: %w", args[0], ctx.Err())
		}
		return nil, fmt.Errorf("docker %s: %w", args[0], err)
	}
	return out, nil
}

// dockerExecResult is one docker exec's outcome.
type dockerExecResult struct {
	stdout, stderr                   string
	stdoutTruncated, stderrTruncated bool
	exitCode                         int
	exited                           bool // the CLI exited by itself, with exitCode
	// refused: the refusing point refused the command, so docker was never started and nothing
	// of it ran (the error is the refusal's, s.refused). Only callRefusal reads it.
	refused bool
}

// exec runs argv in the session's container with stdin, in the work directory.
// Killing the docker CLI at ctx's end does not kill the command inside the
// container; the sweep after the call does.
func (s *dockerSession) exec(ctx context.Context, argv, env []string, stdin []byte, outCap, errCap int) (dockerExecResult, error) {
	return s.execAs(ctx, "", argv, env, stdin, outCap, errCap)
}

// execAs is exec as user ("" for the container's own), behind the guest guard
// (guardFirst, docker_guestguard.go).
func (s *dockerSession) execAs(ctx context.Context, user string, argv, env []string, stdin []byte, outCap, errCap int) (dockerExecResult, error) {
	argv, err := guardFirst(argv)
	if err != nil {
		return dockerExecResult{}, err
	}
	args := []string{"exec", "-i", "-w", dockerSessionWork}
	if user != "" {
		args = append(args, "--user", user)
	}
	for _, e := range env {
		flag, err := dockerEnvFlagPair(e)
		if err != nil {
			return dockerExecResult{}, err
		}
		args = append(args, flag...)
	}
	args = append(args, s.name)
	args = append(args, argv...)
	full, err := dockerArgs(s.host, args...)
	if err != nil {
		return dockerExecResult{}, err
	}
	var stdout, stderr providerkit.Capture
	stdout.Limit, stderr.Limit = outCap, errCap
	cmd := dockerCommand(ctx, full...)
	if refused := refusedCommand(cmd); refused != nil {
		return dockerExecResult{refused: true}, s.refused(refused)
	}
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	res := dockerExecResult{
		stdout: stdout.String(), stderr: stderr.String(),
		stdoutTruncated: stdout.Truncated(), stderrTruncated: stderr.Truncated(),
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	if runErr == nil {
		res.exited = true
		return res, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() >= 0 {
		res.exited, res.exitCode = true, exitErr.ExitCode()
		return res, nil
	}
	return res, runErr
}

// dockerInspect is the part of `docker inspect` a session reads back.
type dockerInspect struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		Status    string `json:"Status"`
		Running   bool   `json:"Running"`
		Paused    bool   `json:"Paused"`
		OOMKilled bool   `json:"OOMKilled"`
		ExitCode  int    `json:"ExitCode"`
	} `json:"State"`
	Config struct {
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig      json.RawMessage `json:"HostConfig"`
	Mounts          json.RawMessage `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
	hostConfig dockerHostConfig
}

// dockerHostConfig is the HostConfig fields the open-time check reads.
type dockerHostConfig struct {
	NetworkMode    string   `json:"NetworkMode"`
	ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
	Privileged     bool     `json:"Privileged"`
	CapAdd         []string `json:"CapAdd"`
	Init           *bool    `json:"Init"`
}

// errContainerGone is inspect's answer for a container that no longer exists.
var errContainerGone = errors.New("the session container no longer exists")

// dockerContainerID is the full ID docker run -d prints.
var dockerContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// inspect reads the container back. When docker cannot, the container is gone only
// if a listing filtered by its ID answers empty: docker's wording for a missing
// container is not a contract, and a daemon that did not answer is not a removal. At
// open, before the first inspect has named the ID, there is no listing to make.
func (s *dockerSession) inspect(ctx context.Context) (dockerInspect, error) {
	out, err := s.controlOutput(ctx, "inspect", "--type", "container", s.name)
	if err != nil {
		if s.id == "" {
			return dockerInspect{}, err
		}
		if listed, lerr := s.controlOutput(ctx, "ps", "-a", "-q", "--no-trunc", "--filter", "id="+s.id); lerr == nil && strings.TrimSpace(string(listed)) == "" {
			return dockerInspect{}, errContainerGone
		}
		return dockerInspect{}, err
	}
	var list []dockerInspect
	if err := json.Unmarshal(out, &list); err != nil || len(list) != 1 {
		return dockerInspect{}, fmt.Errorf("docker inspect: unreadable answer (%v)", err)
	}
	insp := list[0]
	if err := json.Unmarshal(insp.HostConfig, &insp.hostConfig); err != nil {
		return dockerInspect{}, fmt.Errorf("docker inspect: unreadable HostConfig: %w", err)
	}
	return insp, nil
}

// verifyAtOpen checks what the session's walls depend on, right after create:
// the verified image, running, no network but none, a read-only root, not
// privileged, no added capability, and not docker's init, whose place the guard
// takes as process 1 (recordBaseline reads that it does).
func (i dockerInspect) verifyAtOpen(imageID string) error {
	var problems []string
	if i.Image != imageID {
		problems = append(problems, fmt.Sprintf("image %q, want %q", i.Image, imageID))
	}
	if !i.State.Running || i.State.Paused {
		problems = append(problems, "not running: "+i.State.Status)
	}
	if i.hostConfig.NetworkMode != "none" {
		problems = append(problems, "network mode "+i.hostConfig.NetworkMode)
	}
	for name := range i.NetworkSettings.Networks {
		if name != "none" {
			problems = append(problems, "attached to network "+name)
		}
	}
	if !i.hostConfig.ReadonlyRootfs {
		problems = append(problems, "writable root")
	}
	if i.hostConfig.Privileged {
		problems = append(problems, "privileged")
	}
	if len(i.hostConfig.CapAdd) > 0 {
		problems = append(problems, "added capabilities "+strings.Join(i.hostConfig.CapAdd, ","))
	}
	if i.hostConfig.Init != nil && *i.hostConfig.Init {
		problems = append(problems, "docker's init, outside the guest guard, as process 1")
	}
	if len(problems) > 0 {
		return fmt.Errorf("docker session: the created container is not as requested: %s", strings.Join(problems, "; "))
	}
	return nil
}

// securitySnapshot is the read-back compared before every call: the image, the
// whole HostConfig (resources, runtime, mounts, capabilities, security options),
// the mounts, the networks and the user. Run state is compared on its own.
//
// It compares values, not docker's bytes: HostConfig and each mount are decoded and
// written back with their keys sorted and every empty or zero value left out
// (canonicalJSON), so a docker daemon upgraded under a live session that orders the
// fields otherwise, or adds one at its zero value, does not end every session as
// changed, while a value that appears, disappears or changes still does (review,
// 2026-10-23: the raw bytes were compared). Docker lists a container's mounts in no
// fixed order (a container with two bind mounts had them listed in both orders across
// 40 inspects, 2026-10-14), so the mounts and the networks are sorted. Anything that
// does not decode is kept as its bytes.
func (i dockerInspect) securitySnapshot() string {
	networks := make([]string, 0, len(i.NetworkSettings.Networks))
	for name := range i.NetworkSettings.Networks {
		networks = append(networks, name)
	}
	slices.Sort(networks)
	mounts := string(i.Mounts)
	var list []json.RawMessage
	if json.Unmarshal(i.Mounts, &list) == nil {
		each := make([]string, len(list))
		for n, m := range list {
			each[n] = canonicalJSON(m)
		}
		slices.Sort(each)
		mounts = strings.Join(each, "\n")
	}
	b, _ := json.Marshal(struct {
		Image      string
		User       string
		HostConfig string
		Mounts     string
		Networks   []string
	}{i.Image, i.Config.User, canonicalJSON(i.HostConfig), mounts, networks})
	return string(b)
}

// canonicalJSON is raw's value with object keys sorted and every empty or zero member
// left out (null, false, 0, "", an empty array, and an object empty once its own zero
// members are gone), or raw itself when it does not decode. Array elements keep their
// places.
func canonicalJSON(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(raw)
	}
	b, err := json.Marshal(pruneZero(v))
	if err != nil {
		return string(raw)
	}
	return string(b)
}

// pruneZero drops the zero values canonicalJSON leaves out; nil means v is one.
func pruneZero(v any) any {
	switch t := v.(type) {
	case nil, bool:
		if t == nil || t == false {
			return nil
		}
		return t
	case string:
		if t == "" {
			return nil
		}
		return t
	case json.Number:
		if f, err := t.Float64(); err == nil && f == 0 {
			return nil
		}
		return t
	case []any:
		// An element keeps its place, a zero one as null: only an empty array is left out.
		if len(t) == 0 {
			return nil
		}
		out := make([]any, len(t))
		for n, e := range t {
			out[n] = pruneZero(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if p := pruneZero(e); p != nil {
				out[k] = p
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return v
}

// recordBaseline lists the processes of a container no call has touched and keeps
// them as its own: process 1 and the main process. Process 1 must be pid1, the guard in
// its process-1 mode as launchPID1 started it (finding guest-guard-10): its command
// line is compared byte for byte, so a container whose first process is another
// program (docker's init, the image's own) is refused before any call. The open lists
// right after the main process's marker, which its shell writes before it execs the
// sleep, so a list that shows the shell (shell, its command line) is taken again, under
// the open's deadline and at most dockerControlBudget, until the same process runs the
// sleep (sessionkit.BaselineSettled, hunt-quality-102).
func (s *dockerSession) recordBaseline(ctx context.Context, pid1, shell []string) error {
	argv, err := sessionkit.ControlArgv(nil, sessionkit.ListArgv()...)
	if err != nil {
		return err
	}
	var listErr error // the list's own failure, returned as it is worded
	list := func(ctx context.Context) ([]byte, error) {
		out, err := s.exec(ctx, argv, nil, nil, 1<<20, 64<<10)
		switch {
		case err != nil:
			listErr = fmt.Errorf("docker session: list processes: %w", err)
		case !out.exited || out.exitCode != 0:
			// At open no code of the guest exists, so this stderr is the guard's or docker's alone.
			if refusal, ok := guestGuardRefusal(out.exitCode, out.stderr); ok && out.exited {
				listErr = NotDispatched(RefusalEnvironment, errors.New("docker session: the process list: "+refusal))
			} else {
				listErr = fmt.Errorf("docker session: the process list exited %d: %q", out.exitCode, out.stderr)
			}
		default:
			return []byte(out.stdout), nil
		}
		return nil, listErr
	}
	ctx, cancel := context.WithTimeout(ctx, dockerControlBudget)
	defer cancel()
	stdout, keep, err := sessionkit.BaselineSettled(ctx, list, dockerSessionCommand, shell, true)
	if err != nil {
		if listErr != nil && errors.Is(err, listErr) {
			return err
		}
		return fmt.Errorf("docker session: %w", err)
	}
	if err := processOneIs(stdout, pid1); err != nil {
		return fmt.Errorf("docker session: %w", err)
	}
	s.life.SetBaseline(keep)
	return nil
}

func (s *dockerSession) Isolation() IsolationClass { return s.tier }

// Environments is SessionEnvironments for the image this session's container was
// created from, which is what every call of it runs, and the seccomp profile the
// container applies for its life, which every call's result names: never the
// provider's Describe policy, which names the sdk_env variant too when one is
// configured, a profile no session's container applies.
func (s *dockerSession) Environments() Environments {
	s.d.stateMu.RLock()
	langs := slices.Clone(s.d.projectLanguages)
	s.d.stateMu.RUnlock()
	project := PayloadEnvironment{Identity: dockerImageIdentity(s.imageID), SoftwareIdentity: s.manifest,
		MaxTimeout: s.d.projectCeiling(), Languages: langs, FileScopes: s.FileScopes()}
	js := project
	js.Languages = slices.Clone(langs)
	js.FileScopes = s.FileScopes()
	js.MaxTimeout = s.d.snippetCeiling()
	return Environments{JavaScript: js, Project: project, Policy: s.policy}
}
func (s *dockerSession) ExpiresAt() time.Time  { return s.life.ExpiresAt() }
func (s *dockerSession) Done() <-chan struct{} { return s.life.Done() }
func (s *dockerSession) Err() error            { return s.life.Err() }

// Close ends the session and removes its container. It does not wait for a call in
// flight: the call is stopped.
func (s *dockerSession) Close(context.Context) error {
	s.life.Close()
	return nil
}

// Suspend pauses the container: its processes stop and keep their memory, and its
// files stay in their tmpfs mounts. It reports the memory as still held.
func (s *dockerSession) Suspend(ctx context.Context) (bool, error) { return s.life.Suspend(ctx) }

// readBack reads the container back before a call and says how the session ends on
// any difference from open.
func (s *dockerSession) readBack(ctx context.Context) error {
	insp, err := s.inspect(ctx)
	switch {
	case errors.Is(err, errContainerGone):
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: err.Error()}
	case err != nil:
		return fmt.Errorf("the session's container could not be read back: %w", err)
	case insp.State.Paused:
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the container was paused by someone else", Public: true}
	case !insp.State.Running:
		return &SessionEndedError{Reason: SessionMainProcessEnded, Detail: s.exited(insp), Public: true}
	case insp.securitySnapshot() != s.snapshot:
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the container's configuration changed since open", Public: true}
	}
	return nil
}

// containerEnd reads the container back after a call or a sweep whose exit status
// may be docker's, not its command's, and says how the session ends when the
// container no longer runs as opened: gone or stopped; paused, which the session does
// only between calls with its turn held, so someone else did; or unreadable, which
// leaves the call's outcome unknown. It is nil while the container still runs.
func (s *dockerSession) containerEnd() *SessionEndedError {
	ctx, cancel := context.WithTimeout(context.Background(), dockerControlBudget)
	defer cancel()
	return s.containerEndWithin(ctx)
}

// containerEndWithin is containerEnd within ctx: the session's end, nil while the container
// runs as opened. Docker's own error text stays private (it can name the daemon's socket).
func (s *dockerSession) containerEndWithin(ctx context.Context) *SessionEndedError {
	insp, err := s.inspect(ctx)
	switch {
	case errors.Is(err, errContainerGone):
		return &SessionEndedError{Reason: SessionMainProcessEnded, Detail: "the container no longer exists", Public: true}
	case err != nil:
		return &SessionEndedError{Reason: SessionBoundaryFailed, Detail: "the container could not be read back: " + err.Error()}
	case insp.State.Paused:
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the container was paused by someone else", Public: true}
	case !insp.State.Running:
		return &SessionEndedError{Reason: SessionMainProcessEnded, Detail: s.exited(insp), Public: true}
	}
	return nil
}

// exited says how a session's container that no longer runs ended (dockerExitDetail).
func (s *dockerSession) exited(insp dockerInspect) string {
	return dockerExitDetail(s.d.Runtime, insp.State.Status, insp.State.ExitCode, insp.State.OOMKilled, s.d.Memory)
}

// The words a docker session's end uses for the memory limit, in one place: the kill docker
// recorded, and the probable one under gVisor (dockerExitDetail).
const (
	dockerOOMRecorded = "it ran out of memory"
	dockerOOMLikely   = "probably by its memory limit"
)

// dockerExitDetail is the explanation of a session's end when its container no longer runs,
// built from trusted values only (docker's recorded state, the configured runtime and limit),
// never from anything the guest wrote. It names the memory limit when docker records a kill
// by it: under gVisor one process over the limit ends the whole sandbox, so a guest that used
// too much memory sees its session end, and the end should say why. Under gVisor docker can
// also miss that kill altogether (1 container in 40 over its limit, measured 2026-11-21; the
// outside fact docker-oomkilled-under-runsc): the container then reads exit status 137, a
// SIGKILL, with no kill recorded. So under runsc a 137 with none recorded names the limit as
// the probable cause, never as certain, since any forced kill gives 137. Under runc a process
// over the limit is killed alone, so a 137 there says nothing about memory.
func dockerExitDetail(runtime, status string, exitCode int, oomKilled bool, memory string) string {
	switch {
	case oomKilled:
		return fmt.Sprintf("the container is %s: %s (the sandbox's limit is %s)", status, dockerOOMRecorded, memory)
	case runtime == "runsc" && exitCode == 137:
		return fmt.Sprintf("the container is %s with status 137, a forced kill: %s (the sandbox's limit is %s), "+
			"since under gVisor docker can miss a kill by the memory limit; any other forced kill also gives 137",
			status, dockerOOMLikely, memory)
	}
	return "the container is " + status
}

// dockerEndGrace bounds the wait, after a cell's interpreter ended, for docker to report the
// container's end. Under gVisor a process over the memory limit ends the whole sandbox, but
// docker can record the container as stopped after the interpreter's relay has broken: in the
// lab on 16 October 2026 a Python cell over 1024 MB answered a bare exit 1, and docker reported
// the memory kill 80 ms later, to the next call. An interpreter ends on its own rarely (a crash,
// os._exit), so only such calls pay for the wait, and only while the container goes on running.
const dockerEndGrace = 2 * time.Second

// stoppedWithin is stopped, then looked at again every 100 ms while grace lasts. One deadline,
// inside the call's own, bounds the whole watch, every look included, so a slow docker cannot
// hold the session's turn (and the sweep that follows the call) past it. A look that runs out of
// that time ends nothing: the first look, with its own budget, found the container running.
func (s *dockerSession) stoppedWithin(ctx context.Context, grace time.Duration) bool {
	if s.stopped() {
		return true
	}
	watch, cancel := context.WithTimeout(ctx, grace)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-watch.Done():
			return false
		case <-tick.C:
		}
		end := s.containerEndWithin(watch)
		if watch.Err() != nil {
			return false
		}
		if end != nil {
			s.life.FinishWith(end)
			return true
		}
	}
}

// stopped is the check after a call that exited non-zero: when the container no
// longer runs as opened (containerEnd), the exit status is docker's, not the call's,
// and the session has ended.
func (s *dockerSession) stopped() bool {
	end := s.containerEnd()
	if end != nil {
		s.life.FinishWith(end)
	}
	return end != nil
}

// admit is the checks a call makes before it takes its turn: the floor against the
// tier measured at open, and the rule against the image the session runs.
func (s *dockerSession) admit(floor IsolationClass, rule SoftwareRule) error {
	if err := CheckMinimumIsolation(s.tier, floor); err != nil {
		return err
	}
	return rule.Check(s.manifest)
}

// lend gives the call's grant to the session's broker for the call, and returns
// the environment that points the guest's client at it; the returned release ends
// the grant. A call without a grant gets nothing.
func (s *dockerSession) lend(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*brokerSession, []string, func(), error) {
	if grant == nil {
		return nil, nil, func() {}, nil
	}
	core, err := brokerSessionForGrant(ctx, grant, timeout, s.routes)
	if err != nil {
		return nil, nil, nil, err
	}
	return core, []string{"HOST_API_SOCKET=" + containerSocketPath}, s.broker.lend(core), nil
}

// RunJavaScript runs req.Code with `node -` in the session's container.
func (s *dockerSession) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	fail := Result{Sandbox: s.d.Name(), Isolation: s.tier, Policy: s.policy}
	if err := ValidateRequest(req); err != nil {
		return fail, err
	}
	if err := s.admit(req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	if err := CheckSessionGrant(req.Grant); err != nil {
		return fail, err
	}
	timeout := s.d.snippetTimeout(req.Timeout)
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	core, env, unlend, err := s.lend(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer unlend()
	// As in a single run, startScript writes started to stderr before node exists, so
	// a non-zero exit without it can be docker's: unlike docker run's 125, docker
	// exec's own failures (a daemon error, a refused exec) exit 1, and 126 or 127 when
	// the exec never started the script, so here any non-zero exit without it counts.
	// Session code can write into the new process's stderr before the script does, and
	// can read started from the new process's command line once it exists, so it can
	// make its own call read as docker's failure, or a docker failure as a protocol
	// error, and never docker's failure as a result: the consequence stays inside the
	// forger's own session (review, 2026-10-26).
	started := startMarker()
	argv, err := guestArgv(started, append(slices.Clone(s.env), env...), sessionkit.GuestNodeArgv("-")...)
	if err != nil {
		return fail, err
	}
	start := time.Now()
	out, err := s.exec(runCtx, argv, nil, []byte(withHostSDK(req.Code, req.Grant)), s.d.maxOutput(), s.d.maxOutput()+len(started))
	// Read before the grant is ended, which waits for its calls in flight and can
	// outlast the deadline (as the cleanup in runSnippet can).
	ended := deadline.Expired(runCtx)
	unlend()
	stderr, guestStarted := afterMarker(out.stderr, started)
	res := Result{
		Stdout:              out.stdout,
		Stderr:              stderr,
		StdoutTruncated:     out.stdoutTruncated,
		StderrTruncated:     out.stderrTruncated,
		Duration:            time.Since(start),
		Sandbox:             s.d.Name(),
		Isolation:           s.tier,
		SoftwareIdentity:    s.manifest,
		EnvironmentIdentity: dockerImageIdentity(s.imageID),
		CallTrace:           core.traceSnapshot(),
		Policy:              s.policy,
	}
	if refusal := s.callRefusal(out, err, started); refusal != nil {
		fail.CallTrace = res.CallTrace
		return fail, refusal
	}
	if ended == context.DeadlineExceeded && guestStarted && s.Err() == nil {
		// The call's own deadline: the CLI is killed, and the sweep that follows kills
		// the command and anything it started. Without the marker nothing shows the
		// call's code started, so it is not reported as a timeout: the error below.
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	if err != nil || !out.exited {
		fail.CallTrace = res.CallTrace
		return fail, s.life.CallError(runCtx, err)
	}
	if out.exitCode != 0 && s.stopped() {
		fail.CallTrace = res.CallTrace
		return fail, s.Err()
	}
	if !guestStarted {
		// No start marker, and no refusal of the guard's (callRefusal read that above), whatever
		// docker exited with: almost always docker exec never started the call's start script. Unmarked: an attach stream that broke could lose
		// the marker of a call that ran. plimsoll's own words, as for the runner: session
		// code can write into this stderr before the marker (above), and the daemon logs
		// this error, so docker's text cannot be told from the guest's and stays out (the
		// 2026-10-29 public-source scan, finding 2).
		fail.CallTrace = res.CallTrace
		return fail, fmt.Errorf("docker could not run the call in the session's container (exit %d)", out.exitCode)
	}
	res.ExitCode = out.exitCode
	return res, nil
}

// RunProject writes the files and runs the steps through the image's runner in the
// session's container. The work directory is /work, so files persist to the next
// call.
func (s *dockerSession) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	fail := ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, Policy: s.policy}
	if err := ValidateProjectRequest(req); err != nil {
		return fail, err
	}
	if err := s.admit(req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	if err := CheckSessionGrant(req.Grant); err != nil {
		return fail, err
	}
	timeout := s.d.projectTimeout(req.Timeout)
	key, err := runnerwire.NewKey()
	if err != nil {
		return fail, err
	}
	started := startMarker()
	runner, err := s.d.runnerArgv(started)
	if err != nil {
		return fail, err
	}
	// The runner enforces each step's budget; the outer deadline is the backstop.
	runCtx, done, err := s.life.Call(ctx, timeout+5*time.Second)
	if err != nil {
		return fail, err
	}
	defer done()
	// Nothing of the session's runs while the runner starts, so the plan's report key
	// reaches it alone: until the guard has loaded, a process of the same uid could
	// read the runner's stdin and memory (QuiesceScript). This kills the interpreters
	// the session keeps, so a session that mixes cells and project calls loses its cell
	// state here; the next cell reports a fresh interpreter. It comes before the grant
	// is lent, so a call the quiesce refuses never had a grant that code of the session
	// could use (round-7 review, 2026-10-08).
	if err := s.life.Quiesce(runCtx); err != nil {
		return fail, err
	}
	core, env, unlend, err := s.lend(runCtx, req.Grant, timeout+5*time.Second)
	if err != nil {
		return fail, err
	}
	defer unlend()
	// The steps start with the image's environment and the grant's socket; the runner
	// itself starts with neither (runnerArgv).
	plan := runnerwire.Plan{Steps: req.Steps, Budget: timeout, Artifacts: req.Artifacts, HostSDK: hostSDKModule(req.Grant),
		Env: append(slices.Clone(s.env), env...), ReportKey: key}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		unlend()
		return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: core.traceSnapshot()}, err
	}
	out, err := s.exec(runCtx, runner, nil, planJSON, runnerwire.StdoutCap, s.d.maxOutput()+len(started))
	ended := deadline.Expired(runCtx) // before the grant is ended, as for a snippet
	unlend()
	fail.CallTrace = core.traceSnapshot()
	fail.SoftwareIdentity, fail.EnvironmentIdentity = s.manifest, dockerImageIdentity(s.imageID)
	// An authenticated report is the result whatever the backstop or the exec's own
	// error says: the runner writes it after its steps ended, each step carries its own
	// TimedOut, and here the backstop also covers the quiesce and the grant before the
	// runner starts, so a report already in stdout was thrown away as timed out with no
	// steps (review, 2026-10-26). A session that ended meanwhile says so on its next call.
	res, reported := RunnerReport(fail, out.stdout, key)
	if !reported {
		if refusal := s.callRefusal(out, err, started); refusal != nil {
			return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace}, refusal
		}
		if _, ran := afterMarker(out.stderr, started); ended == context.DeadlineExceeded && ran && s.Err() == nil {
			fail.Outcome, fail.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget"
			return fail, nil
		}
		if err != nil || !out.exited {
			return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace}, s.life.CallError(runCtx, err)
		}
		if s.stopped() {
			return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace}, s.Err()
		}
		if _, ran := afterMarker(out.stderr, started); !ran {
			// docker exec never started the runner's start script. Unmarked, as for a
			// snippet: a broken attach stream could lose the marker of a call that ran.
			return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace},
				fmt.Errorf("docker could not run the runner in the session's container (exit %d)", out.exitCode)
		}
		// plimsoll's own words, never the runner's stderr, which every process in
		// the container can write.
		fail.Outcome, fail.Detail = ProjectOutcomeProtocolError, fmt.Sprintf("the runner did not report (it exited %d)", out.exitCode)
		return fail, nil
	}
	return res, nil
}

// checkFunc runs the interpreter driver's identity check as checkerUser.
func (s *dockerSession) checkFunc(ctx context.Context, argv []string, _ map[string]string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	argv, err := sessionkit.ControlArgv(nil, argv...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	out, err := s.execAs(ctx, s.d.checkerUser(), argv, nil, stdin, outCap, errCap)
	return sessionkit.ExecResult{Stdout: out.stdout, Stderr: out.stderr, ExitCode: out.exitCode, Exited: out.exited}, err
}

// execFunc is exec in the form the shared interpreter driver calls. What it runs is
// plimsoll's own (the interpreter launcher), so it starts under sessionkit.ControlArgv with env as
// its only variables; the interpreter it starts gets the guest's environment through
// Interpreters.Start.
func (s *dockerSession) execFunc(ctx context.Context, argv []string, env map[string]string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	argv, err := sessionkit.ControlArgv(env, argv...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	out, err := s.exec(ctx, argv, nil, stdin, outCap, errCap)
	return out.kit(), err
}

// kit is the exec's outcome in the form the shared session drivers read.
func (out dockerExecResult) kit() sessionkit.ExecResult {
	return sessionkit.ExecResult{
		Stdout: out.stdout, Stderr: out.stderr,
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Exited: out.exited,
	}
}

// dockerAttached is a docker exec kept open for the session: an interpreter's relay.
type dockerAttached struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (a *dockerAttached) Stdin() io.Writer  { return a.stdin }
func (a *dockerAttached) Stdout() io.Reader { return a.stdout }

// Close ends the docker CLI; the relay in the container ends at the next sweep.
func (a *dockerAttached) Close() {
	_ = a.stdin.Close()
	_ = a.cmd.Process.Kill()
	go func() { _ = a.cmd.Wait() }()
}

// attach starts argv in the container, non-dumpable under the runner guard so no
// other process of the session can open its stdin or stdout once it has started (in
// the moment before, one can, which is why nothing a relay says is trusted with
// anything that matters: docs/sessions.md), and keeps its pipes.
//
// A relay is one of plimsoll's own programs: its frames carry every cell's result. It
// starts under sessionkit.ControlArgv, with env as its only variables (docker_cli.go).
func (s *dockerSession) attach(argv []string, env map[string]string) (sessionkit.Attached, error) {
	inner, err := sessionControlArgv(env, argv)
	if err != nil {
		return nil, err
	}
	if inner, err = guardFirst(inner); err != nil {
		return nil, err
	}
	args := append([]string{"exec", "-i", "-w", dockerSessionWork, s.name}, inner...)
	full, err := dockerArgs(s.host, args...)
	if err != nil {
		return nil, err
	}
	cmd := dockerCommand(context.Background(), full...)
	if refused := refusedCommand(cmd); refused != nil {
		return nil, s.refused(refused)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr providerkit.Capture
	stderr.Limit = 4096
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &dockerAttached{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

// RunCell runs code in the session's interpreter for req.Language, starting one
// when none is alive (sandbox/internal/sessionkit), through a relay the session keeps
// attached, so a warm cell starts no process. A cell's budget is a project's.
func (s *dockerSession) RunCell(ctx context.Context, req CellRequest) (CellResult, error) {
	fail := CellResult{Sandbox: s.d.Name(), Isolation: s.tier, Policy: s.policy}
	if err := ValidateCellRequest(req); err != nil {
		return fail, err
	}
	if err := s.admit(req.MinimumIsolation, req.Software); err != nil {
		return fail, err
	}
	timeout := s.d.projectTimeout(req.Timeout)
	runCtx, done, err := s.life.Call(ctx, timeout)
	if err != nil {
		return fail, err
	}
	defer done()
	start := time.Now()
	out, err := s.life.Interps.RunRelayed(runCtx, s.execFunc, s.attach, SessionCell(req, s.Environments().Project, dockerSessionWork, s.d.maxOutput()))
	res, err := SessionCellResult(runCtx, fail, out, err, time.Since(start), s.manifest, dockerImageIdentity(s.imageID), s.Err, func() error {
		if s.stoppedWithin(runCtx, dockerEndGrace) {
			return s.Err()
		}
		return nil
	}, func(err error) error { return s.life.CallError(runCtx, err) })
	if err == nil {
		res.Duration = time.Since(start) // the watch for the container's end included
	}
	return res, err
}

// Drain stops the session pool and removes its members, refuses every open from
// then on (waiting for those already in flight), ends every open session
// (SessionShutdown), and waits, within ctx, for their containers to be removed.
func (d *DockerSandbox) Drain(ctx context.Context) error {
	// From here an open is refused, and one already in flight is waited for: it ends
	// registered, and so ended below, or refused with its container removed.
	d.sessions.Drain()
	opened := d.sessions.Opened()
	poolErr := d.pool.Load().Close(ctx)
	var openErr error
	select {
	case <-opened:
	default:
		select {
		case <-opened:
		case <-ctx.Done():
			openErr = fmt.Errorf("docker: sessions still opening: %w", ctx.Err())
		}
	}
	// The sessions already open end either way; an open still in flight is refused
	// when it finishes, since activate checks draining.
	ended := d.sessions.EndAll(SessionShutdown)
	if err := cmp.Or(openErr, poolErr); err != nil {
		// An open in flight or the pool's filler is still running and will remove the
		// container it was making, a removal counted that must not race a wait; the
		// context has ended anyway.
		return err
	}
	// Each session found open is waited for by its own removal first, since one
	// another goroutine had begun to end may not have counted its removal yet. After
	// that every removal has been counted: opens in flight are done, and the pool's
	// filler stopped.
	if err := ended(ctx); err != nil {
		return fmt.Errorf("docker: session containers still being removed: %w", err)
	}
	if err := d.sessions.WaitRemovals(ctx); err != nil {
		return fmt.Errorf("docker: session containers still being removed: %w", err)
	}
	return nil
}

// ReconcileOrphans removes containers this provider does not hold whose declared
// lifetime ended more than dockerReapMargin ago: what a crashed daemon left behind,
// and a run's container that outlived its CLI and every removal attempt. A
// container's lifetime is its label, so a live run or session of another daemon on
// the same docker host is never touched.
func (d *DockerSandbox) ReconcileOrphans(ctx context.Context) (int, error) {
	if n := reapDeadHostDirs(os.TempDir(), time.Now()); n > 0 {
		slog.Info("docker: removed host directories that stopped processes left", "count", n)
	}
	// The pinned daemon is all reaping needs: an image the smoke test did not prove, or a
	// Preflight that failed since, stops runs, not the cleanup of what earlier ones left.
	// A failed Preflight never changes the pinned daemon, so the pass goes on against it;
	// before one was ever pinned there is no daemon the pass may run docker against, and
	// the pass says so once (hunt-quality-100: it read the whole verified state, so any
	// failed Preflight stopped every removal and quarantine retry, silently).
	host := d.pinnedDaemon()
	d.noteReapSkipped(host == "")
	if host == "" {
		return 0, nil
	}
	quarantined := d.quarantine.Names()
	// The listing is bounded like one removal try, so a daemon that does not answer it
	// leaves the quarantine retries their time.
	lctx, lcancel := context.WithTimeout(ctx, removeAttemptBudget)
	out, listErr := dockerReapListing(lctx, host)
	lcancel()
	held := map[string]bool{}
	for _, l := range d.sessions.Open() {
		held[l.Name] = true
	}
	for _, name := range d.pool.Load().Members() {
		held[name] = true
	}
	for _, name := range quarantined {
		held[name] = true
	}
	var expired []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, exp, ok := strings.Cut(line, "\t")
		if !ok || held[name] {
			continue
		}
		unix, err := strconv.ParseInt(exp, 10, 64)
		if err != nil || time.Since(time.Unix(unix, 0)) < dockerReapMargin {
			continue
		}
		expired = append(expired, name)
	}
	// One rule for every removal of the pass (hunt-quality-101): each name gets an equal
	// share of what the pass has left, at most a removal's own budget, so a removal that
	// hangs costs its share and never another name's try. The quarantined names go first,
	// whatever their age: each still holds the capacity of the call that made it, given
	// back once its removal is confirmed. Before, only the quarantined names had shares,
	// and one expired container whose removal hung took the whole pass, every pass.
	share := reapShares(ctx, len(quarantined)+len(expired))
	var confirmed int
	var stillHeld error
	if len(quarantined) > 0 {
		confirmed, stillHeld = d.quarantine.Retry(func(name string) error {
			rctx, cancel := share()
			defer cancel()
			return removeContainer(rctx, host, name)
		})
		if stillHeld != nil {
			slog.Error("docker: quarantined containers still not confirmed gone; their capacity stays held", "error", stillHeld)
		}
	}
	reaped := 0
	for _, name := range expired {
		// Counted only once confirmed gone; one that is not is tried again next pass.
		rctx, cancel := share()
		if removeContainer(rctx, host, name) == nil {
			reaped++
		}
		cancel()
	}
	if listErr != nil {
		listErr = fmt.Errorf("docker ps: %w", listErr)
	}
	return confirmed + reaped, errors.Join(listErr, stillHeld)
}

// dockerReapListing lists every container carrying the lifetime label, paused ones
// included, with its label: the orphan pass's candidates.
func dockerReapListing(ctx context.Context, host string) ([]byte, error) {
	args, err := dockerArgs(host, "ps", "-a", "--filter", "label="+dockerExpiresLabel,
		"--format", `{{.Names}}	{{.Label "`+dockerExpiresLabel+`"}}`)
	if err != nil {
		return nil, err
	}
	return dockerOutput(ctx, args...)
}

// reapShares hands out the contexts of n removals that share ctx: each call returns one
// bounded by an equal share of what ctx has left for the removals not yet started, and at
// most dockerRemoveBudget, so time a fast removal leaves goes to the ones after it.
func reapShares(ctx context.Context, n int) func() (context.Context, context.CancelFunc) {
	left := n
	return func() (context.Context, context.CancelFunc) {
		slice := dockerRemoveBudget
		if dl, ok := ctx.Deadline(); ok && left > 0 {
			slice = min(slice, time.Until(dl)/time.Duration(left))
		}
		left = max(left-1, 0)
		return context.WithTimeout(ctx, slice)
	}
}

// pinnedDaemon is the daemon address Preflight pinned, "" before one was. A failed
// Preflight leaves it as it was: only a Preflight that succeeds sets it.
func (d *DockerSandbox) pinnedDaemon() string {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return d.daemonHost
}

// noteReapSkipped logs when the orphan pass starts or stops being skipped for want of
// a pinned daemon: once per change, not once a pass. It reports whether it logged.
func (d *DockerSandbox) noteReapSkipped(skipped bool) bool {
	if d.reapSkipped.Swap(skipped) == skipped {
		return false
	}
	if skipped {
		slog.Warn("docker: orphan pass skipped: no docker daemon has been pinned yet (no Preflight has succeeded), so it removes nothing and retries no quarantined removal until one is")
	} else {
		slog.Info("docker: orphan pass running again against the pinned docker daemon")
	}
	return true
}

// dockerSessionBroker is a session's broker socket: mounted at open, it serves the
// grant of the call in progress, if any, and answers 503 otherwise.
type dockerSessionBroker struct {
	*unixBroker
	grantSlot
}

func startDockerSessionBroker() (*dockerSessionBroker, error) {
	b := &dockerSessionBroker{}
	u, err := startUnixBroker("crsbx-session-broker", b.current)
	if err != nil {
		return nil, err
	}
	b.unixBroker = u
	return b, nil
}

// Close stops the broker and removes its socket directory.
func (b *dockerSessionBroker) Close() {
	b.set(nil)
	b.unixBroker.close()
}
