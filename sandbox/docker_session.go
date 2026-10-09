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
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/deadline"
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
//   - PID 1 is docker's init (`--init`), which reaps: a killed process whose parent
//     has gone is reparented to PID 1, and a PID 1 that never reaps (sleep) would
//     keep its zombie, which counts against the process limit, for the session's life.
//   - The sweep runs non-dumpable under the runner guard, so no process of a call
//     can attach to it and forge its exit status, whatever the host's Yama setting;
//     the baseline still refuses a host whose ptrace_scope reads 0.
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
	// dockerSessionCommand is a session container's main process (under docker's
	// init): 2^31-1 seconds, which every sleep accepts, and far beyond any lifetime.
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
	// dockerReapMargin is how long past its declared lifetime a container must be
	// before ReconcileOrphans removes it, so a clock difference between two daemons
	// sharing a docker host never removes a live one, nor a run's container while its
	// removal after a deadline (forceRemove, up to dockerRemoveBudget) is under way.
	dockerReapMargin = 5 * time.Minute
	// dockerSessionWork is the working directory of every call.
	dockerSessionWork = "/work"
	// dockerRunnerGuard is the library the project image's runner loads to make
	// itself non-dumpable; the sweep loads it too.
	dockerRunnerGuard = "/usr/local/lib/plimsoll-runner-guard.so"
	// dockerControlBudget bounds a create, inspect, pause, unpause or listing.
	dockerControlBudget = 60 * time.Second
)

// dockerRunnerArgv starts the project image's runner with its guard loaded and the
// environment startScript gives a process, and none of the image's: the steps get
// that through the plan (runnerwire.Plan.Env), the runner never does. marker is the
// call's start marker (afterMarker).
func dockerRunnerArgv(marker string) ([]string, error) {
	return guestArgv(marker, []string{"LD_PRELOAD=" + dockerRunnerGuard}, "node", "/runner.mjs")
}

// guarded runs argv non-dumpable: the guard is loaded into the process that execs
// argv, never into sh, and only into that one program.
func guarded(argv []string) []string {
	return append([]string{"sh", "-c", `export LD_PRELOAD=` + dockerRunnerGuard + `; exec "$@"`, "sh"}, argv...)
}

// SupportsSessions reports whether a project image is configured: a session runs
// every call in it.
func (d *DockerSandbox) SupportsSessions() bool { return d.ProjectImage != "" }

// SessionEnvironments is the project image's environment for every payload kind:
// a session's snippets run in the project image too, not the snippet image.
func (d *DockerSandbox) SessionEnvironments() Environments {
	env := d.Environments()
	project := env.Project
	return Environments{
		JavaScript: PayloadEnvironment{Identity: project.Identity, SoftwareIdentity: project.SoftwareIdentity, MaxTimeout: d.snippetCeiling(), Languages: project.Languages},
		Project:    project,
	}
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
	snapshot string // the security-relevant read-back at open
	broker   *dockerSessionBroker
	// label is the end of the lifetime the container declares, fixed at creation;
	// key is the execution state it was created under (dockerPoolKey). A pool member
	// is claimed only while both allow it; born and warm are when the pool made it and
	// the languages it started.
	label time.Time
	key   string
	born  time.Time
	warm  []string

	// life is the lifecycle every provider's sessions share: the turn, the lifetime,
	// suspend and the sweep after every call (sessionkit.Life), with the session's
	// interpreters, which a pause keeps.
	life *sessionkit.Life
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
		return nil, NotDispatched(RefusalCapacity, errDraining)
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
	// languages; and before the claim, so the refill the claim asks for sees it.
	pool := d.pool.Load()
	observed := false
	observe := func() {
		if pool != nil && !observed {
			pool.observe(want)
			observed = true
		}
	}
	if pool != nil {
		if state, err := d.executionState(); err == nil {
			if err := CheckMinimumIsolation(state.isolation, opts.MinimumIsolation); err != nil {
				return nil, err
			}
			observe()
			if s := pool.claim(state, expires, want); s != nil {
				if err := d.activate(s, expires, opts.DiskBytes); err != nil {
					s.abandon()
					return nil, err
				}
				return s, nil
			}
		}
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
		s.abandon()
		return nil, err
	}
	return s, nil
}

// newSessionContainer creates a session container from the Preflight-verified project
// image under the run lockdown, with docker's init as PID 1, sleep as its main process
// and label as the end of its declared lifetime (which ReconcileOrphans reads); reads
// it back; and records its own processes, which every sweep spares. No caller holds it
// until activate.
func (d *DockerSandbox) newSessionContainer(ctx context.Context, state dockerExecutionState, label time.Time) (*dockerSession, error) {
	broker, err := startDockerSessionBroker()
	if err != nil {
		return nil, err
	}
	s := &dockerSession{
		d: d, host: state.host, name: "plsm-session-" + randID(),
		imageID: state.projectImageID, manifest: state.projectManifest, env: state.guestEnv(state.projectImageID), tier: state.isolation,
		key: dockerPoolKey(state), label: label, broker: broker, routes: NewRouteBudget(),
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
	main, err := sessionkit.ControlArgv(nil, dockerSessionCommand...)
	if err != nil {
		broker.Close()
		return nil, err
	}
	args := []string{"run", "-d", "--name", s.name, "--log-driver", "none", "--init",
		"--label", dockerSessionLabel + "=1"}
	args = append(args, expiresLabelArgs(label)...)
	args = append(args, d.lockdownFlags(true, state.runtime)...)
	args = append(args, "-v", broker.sock+":"+containerSocketPath)
	if state.platform != "" {
		args = append(args, "--platform", state.platform)
	}
	args = append(args, launch(state.projectImageID, main)...)
	out, err := s.controlOutput(ctx, args...)
	if err != nil {
		s.abandon()
		return nil, err
	}
	if s.id = strings.TrimSpace(string(out)); !dockerContainerID.MatchString(s.id) {
		s.abandon()
		return nil, fmt.Errorf("docker run: unreadable container ID %q", truncateForError(s.id))
	}
	insp, err := s.inspect(ctx)
	if err != nil {
		s.abandon()
		return nil, err
	}
	if err := insp.verifyAtOpen(state.projectImageID); err != nil {
		s.abandon()
		return nil, err
	}
	s.snapshot = insp.securitySnapshot()
	if err := s.recordBaseline(ctx); err != nil {
		s.abandon()
		return nil, err
	}
	return s, nil
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
		return NotDispatched(RefusalCapacity, errDraining)
	}
	return nil
}

// abandon removes a session container no caller ever held (one that failed to open,
// or a pool member), its relays and its broker.
func (s *dockerSession) abandon() {
	s.life.Abandon()
	s.broker.Close()
	s.d.forceRemove(s.host, s.name)
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
		// session can attach to it.
		Sweep: func(ctx context.Context, argv []string) (sessionkit.ExecResult, error) {
			argv, err := sessionkit.ControlArgv(nil, guarded(argv)...)
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
			argv, err := sessionkit.ControlArgv(nil, guarded(argv)...)
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
			if reason, detail, ended := s.containerEnd(); ended {
				return &SessionEndedError{Reason: reason, Detail: detail}
			}
			return &SessionEndedError{Reason: SessionBoundaryFailed, Detail: sweep}
		},
		Teardown: func() {
			s.d.forceRemove(s.host, s.name)
			s.broker.Close()
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
}

// exec runs argv in the session's container with stdin, in the work directory.
// Killing the docker CLI at ctx's end does not kill the command inside the
// container; the sweep after the call does.
func (s *dockerSession) exec(ctx context.Context, argv, env []string, stdin []byte, outCap, errCap int) (dockerExecResult, error) {
	return s.execAs(ctx, "", argv, env, stdin, outCap, errCap)
}

// execAs is exec as user ("" for the container's own).
func (s *dockerSession) execAs(ctx context.Context, user string, argv, env []string, stdin []byte, outCap, errCap int) (dockerExecResult, error) {
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
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = outCap, errCap
	cmd := dockerCommand(ctx, full...)
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
	Image string `json:"Image"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Paused  bool   `json:"Paused"`
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
// container is not a contract, and a daemon that did not answer is not a removal.
func (s *dockerSession) inspect(ctx context.Context) (dockerInspect, error) {
	out, err := s.controlOutput(ctx, "inspect", "--type", "container", s.name)
	if err != nil {
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
// privileged, no added capability, docker's init.
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
	if i.hostConfig.Init == nil || !*i.hostConfig.Init {
		problems = append(problems, "no init")
	}
	if len(problems) > 0 {
		return fmt.Errorf("docker session: the created container is not as requested: %s", strings.Join(problems, "; "))
	}
	return nil
}

// securitySnapshot is the read-back compared before every call: the image, the
// whole HostConfig (resources, runtime, mounts, capabilities, security options),
// the mounts, the networks and the user. Run state is compared on its own.
func (i dockerInspect) securitySnapshot() string {
	networks := make([]string, 0, len(i.NetworkSettings.Networks))
	for name := range i.NetworkSettings.Networks {
		networks = append(networks, name)
	}
	b, _ := json.Marshal(struct {
		Image      string
		User       string
		HostConfig json.RawMessage
		Mounts     json.RawMessage
		Networks   []string
	}{i.Image, i.Config.User, i.HostConfig, i.Mounts, networks})
	return string(b)
}

// recordBaseline lists the processes of a container no call has touched and keeps
// them as its own: docker's init and the main process.
func (s *dockerSession) recordBaseline(ctx context.Context) error {
	argv, err := sessionkit.ControlArgv(nil, sessionkit.ListArgv()...)
	if err != nil {
		return err
	}
	out, err := s.exec(ctx, argv, nil, nil, 1<<20, 64<<10)
	if err != nil {
		return fmt.Errorf("docker session: list processes: %w", err)
	}
	if !out.exited || out.exitCode != 0 {
		return fmt.Errorf("docker session: the process list exited %d: %q", out.exitCode, out.stderr)
	}
	keep, err := sessionkit.Baseline([]byte(out.stdout), dockerSessionCommand, true)
	if err != nil {
		return fmt.Errorf("docker session: %w", err)
	}
	s.life.SetBaseline(keep)
	return nil
}

func (s *dockerSession) Isolation() IsolationClass { return s.tier }

// Environments is SessionEnvironments for the image this session's container was
// created from, which is what every call of it runs.
func (s *dockerSession) Environments() Environments {
	s.d.stateMu.RLock()
	langs := slices.Clone(s.d.projectLanguages)
	s.d.stateMu.RUnlock()
	project := PayloadEnvironment{Identity: dockerImageIdentity(s.imageID), SoftwareIdentity: s.manifest,
		MaxTimeout: s.d.projectCeiling(), Languages: langs}
	js := project
	js.Languages = slices.Clone(langs)
	js.MaxTimeout = s.d.snippetCeiling()
	return Environments{JavaScript: js, Project: project}
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
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the container was paused by someone else"}
	case !insp.State.Running:
		return &SessionEndedError{Reason: SessionMainProcessEnded, Detail: "the container is " + insp.State.Status}
	case insp.securitySnapshot() != s.snapshot:
		return &SessionEndedError{Reason: SessionSandboxChanged, Detail: "the container's configuration changed since open"}
	}
	return nil
}

// containerEnd reads the container back after a call or a sweep whose exit status
// may be docker's, not its command's, and says how the session ends when the
// container no longer runs as opened: gone or stopped; paused, which the session does
// only between calls with its turn held, so someone else did; or unreadable, which
// leaves the call's outcome unknown. ended is false while it still runs.
func (s *dockerSession) containerEnd() (reason SessionEnd, detail string, ended bool) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerControlBudget)
	defer cancel()
	insp, err := s.inspect(ctx)
	switch {
	case errors.Is(err, errContainerGone):
		return SessionMainProcessEnded, "the container no longer exists", true
	case err != nil:
		return SessionBoundaryFailed, "the container could not be read back: " + err.Error(), true
	case insp.State.Paused:
		return SessionSandboxChanged, "the container was paused by someone else", true
	case !insp.State.Running:
		return SessionMainProcessEnded, "the container is " + insp.State.Status, true
	}
	return 0, "", false
}

// stopped is the check after a call that exited non-zero: when the container no
// longer runs as opened (containerEnd), the exit status is docker's, not the call's,
// and the session has ended.
func (s *dockerSession) stopped() bool {
	reason, detail, ended := s.containerEnd()
	if ended {
		s.life.Finish(reason, detail)
	}
	return ended
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
	fail := Result{Sandbox: s.d.Name(), Isolation: s.tier}
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
	// Session code can write into the new process's stderr before the script does, but
	// cannot learn started before the exec exists, so it can make its own call read as
	// docker's failure and never docker's failure as a result.
	started := startMarker()
	argv, err := guestArgv(started, append(slices.Clone(s.env), env...), "node", "-")
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
		// No start marker, whatever docker exited with: almost always docker exec never
		// started the call's start script. Unmarked: an attach stream that broke could lose
		// the marker of a call that ran.
		fail.CallTrace = res.CallTrace
		return fail, fmt.Errorf("docker could not run the call in the session's container (exit %d): %s", out.exitCode, truncateForError(strings.TrimSpace(out.stderr)))
	}
	res.ExitCode = out.exitCode
	return res, nil
}

// RunProject writes the files and runs the steps through the image's runner in the
// session's container. The work directory is /work, so files persist to the next
// call.
func (s *dockerSession) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	fail := ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier}
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
	runner, err := dockerRunnerArgv(started)
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
	// itself starts with neither (dockerRunnerArgv).
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: timeout, Artifacts: req.Artifacts, HostSDK: hostSDKModule(req.Grant),
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
	if _, ran := afterMarker(out.stderr, started); ended == context.DeadlineExceeded && ran && s.Err() == nil {
		fail.Outcome, fail.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget"
		return fail, nil
	}
	if err != nil || !out.exited {
		return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace}, s.life.CallError(runCtx, err)
	}
	report, found, parseErr := runnerwire.Parse(out.stdout, key)
	if !found {
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
	if errors.Is(parseErr, runnerwire.ErrUnauthenticated) {
		fail.Outcome, fail.Detail = ProjectOutcomeProtocolError, "no authenticated runner report"
		return fail, nil
	}
	if parseErr != nil {
		fail.Outcome, fail.Detail = ProjectOutcomeProtocolError, "could not parse sandbox result"
		return fail, nil
	}
	res := projectResultFromReport(s.d.Name(), s.tier, report, fail.CallTrace)
	res.SoftwareIdentity, res.EnvironmentIdentity = s.manifest, dockerImageIdentity(s.imageID)
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
	return sessionkit.ExecResult{
		Stdout: out.stdout, Stderr: out.stderr,
		StdoutTruncated: out.stdoutTruncated, StderrTruncated: out.stderrTruncated,
		ExitCode: out.exitCode, Exited: out.exited,
	}, err
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
// other process of the session can open its stdin or stdout, and keeps its pipes.
//
// A relay is one of plimsoll's own programs: its frames carry every cell's result. It
// starts under sessionkit.ControlArgv, with env as its only variables (docker_cli.go).
func (s *dockerSession) attach(argv []string, env map[string]string) (sessionkit.Attached, error) {
	inner, err := sessionkit.ControlArgv(env, guarded(argv)...)
	if err != nil {
		return nil, err
	}
	args := append([]string{"exec", "-i", "-w", dockerSessionWork, s.name}, inner...)
	full, err := dockerArgs(s.host, args...)
	if err != nil {
		return nil, err
	}
	cmd := dockerCommand(context.Background(), full...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr cappedBuffer
	stderr.limit = 4096
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
	fail := CellResult{Sandbox: s.d.Name(), Isolation: s.tier}
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
	out, err := s.life.Interps.RunRelayed(runCtx, s.execFunc, s.attach, sessionkit.Cell{
		Language: string(req.Language), Code: req.Code, Files: cellFiles(req.Files),
		Work: dockerSessionWork, OutCap: s.d.maxOutput(), ErrCap: s.d.maxOutput(),
	})
	return SessionCellResult(runCtx, fail, out, err, time.Since(start), s.manifest, dockerImageIdentity(s.imageID), s.Err, func() error {
		if s.stopped() {
			return s.Err()
		}
		return nil
	}, func(err error) error { return s.life.CallError(runCtx, err) })
}

// Drain stops the session pool and removes its members, refuses every open from
// then on (waiting for those already in flight), ends every open session
// (SessionShutdown), and waits, within ctx, for their containers to be removed.
func (d *DockerSandbox) Drain(ctx context.Context) error {
	// From here an open is refused, and one already in flight is waited for: it ends
	// registered, and so ended below, or refused with its container removed.
	d.sessions.Drain()
	opened := d.sessions.Opened()
	poolErr := d.pool.Load().close(ctx)
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
	// The pinned daemon is all reaping needs: an image the smoke test did not prove
	// stops runs, not the cleanup of what earlier ones left.
	state, err := d.verifiedState()
	if err != nil || state.host == "" {
		return 0, nil // not preflighted yet: nothing is known to reap
	}
	args, err := dockerArgs(state.host, "ps", "-a", "--filter", "label="+dockerExpiresLabel,
		"--format", `{{.Names}}	{{.Label "`+dockerExpiresLabel+`"}}`)
	if err != nil {
		return 0, err
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("docker ps: %w", err)
	}
	held := map[string]bool{}
	for _, l := range d.sessions.Open() {
		held[l.Name] = true
	}
	for _, name := range d.pool.Load().members() {
		held[name] = true
	}
	reaped := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, exp, ok := strings.Cut(line, "\t")
		if !ok || held[name] {
			continue
		}
		unix, err := strconv.ParseInt(exp, 10, 64)
		if err != nil || time.Since(time.Unix(unix, 0)) < dockerReapMargin {
			continue
		}
		d.forceRemove(state.host, name)
		reaped++
	}
	return reaped, nil
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

// cellFiles is a cell's files in the interpreter driver's form.
func cellFiles(files []File) []sessionkit.File {
	out := make([]sessionkit.File, 0, len(files))
	for _, f := range files {
		out = append(out, sessionkit.File{Path: f.Path, Content: f.Content})
	}
	return out
}
