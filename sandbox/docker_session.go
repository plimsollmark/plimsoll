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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"

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
	// dockerSessionLabel marks a session container; dockerExpiresLabel is when its
	// lifetime ends (Unix seconds), which ReconcileOrphans reads.
	dockerSessionLabel = "io.plimsoll.session"
	dockerExpiresLabel = "io.plimsoll.expires"
	// dockerReapMargin is how long past its declared lifetime a session container
	// must be before ReconcileOrphans removes it, so a clock difference between two
	// daemons sharing a docker host never removes a live session.
	dockerReapMargin = 5 * time.Minute
	// dockerSessionWork is the working directory of every call.
	dockerSessionWork = "/work"
	// dockerRunnerGuard is the library the project image's runner loads to make
	// itself non-dumpable; the sweep loads it too.
	dockerRunnerGuard = "/usr/local/lib/plimsoll-runner-guard.so"
	// dockerSweepBudget bounds one sweep: normally a docker exec, a node start and a
	// walk of the session's files.
	dockerSweepBudget = 20 * time.Second
	// dockerControlBudget bounds a create, inspect, pause, unpause or listing.
	dockerControlBudget = 60 * time.Second
)

// runnerCommand starts the project image's runner as its entrypoint does.
var dockerRunnerCommand = []string{"sh", "-c", "export LD_PRELOAD=" + dockerRunnerGuard + "; exec node /runner.mjs"}

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

// dockerSessions is the provider's registry of open sessions, of the opens and
// container removals still in flight, and whether Drain has begun, for Drain.
type dockerSessions struct {
	mu       sync.Mutex
	open     map[*dockerSession]struct{}
	deletes  sync.WaitGroup
	opening  sync.WaitGroup // added to only under mu while not draining
	draining bool
}

// errDraining is an open refused because Drain has begun.
var errDraining = fmt.Errorf("%w: the docker provider is shutting down", ErrAtCapacity)

// enter counts an open in flight, which Drain waits for; leave ends it. It refuses
// once Drain has begun.
func (r *dockerSessions) enter() (leave func(), err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.draining {
		return nil, NotDispatched(RefusalCapacity, errDraining)
	}
	r.opening.Add(1)
	return r.opening.Done, nil
}

// dockerSession is one open session.
type dockerSession struct {
	d        *DockerSandbox
	host     string
	name     string
	id       string // the full container ID docker run printed
	imageID  string
	manifest string
	tier     IsolationClass
	expires  time.Time
	disk     int64
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

	ctx    context.Context // cancelled when the session ends, which stops a call in flight
	cancel context.CancelFunc
	turn   chan struct{} // one slot: holding it is the right to call, suspend or resume
	done   chan struct{}
	// removed is closed once the container of a session activate registered is removed,
	// whichever goroutine ended it; Drain waits for it.
	removed chan struct{}

	mu       sync.Mutex
	end      *SessionEndedError
	paused   bool
	baseline []string
	life     *time.Timer

	// interps are the session's live interpreters; a pause keeps them.
	interps sessionkit.Interpreters
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
		return nil, err
	}
	leave, err := d.sessions.enter()
	if err != nil {
		return nil, err
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
		return nil, err
	}
	state, err := d.executionState()
	if err != nil {
		return nil, err
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
		imageID: state.projectImageID, manifest: state.projectManifest, tier: state.isolation,
		key: dockerPoolKey(state), label: label, broker: broker,
		turn: make(chan struct{}, 1), done: make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.interps.Checker = s.checkFunc
	args := []string{"run", "-d", "--name", s.name, "--log-driver", "none", "--init",
		"--label", dockerSessionLabel + "=1",
		"--label", dockerExpiresLabel + "=" + strconv.FormatInt(label.Unix(), 10)}
	args = append(args, d.lockdownFlags(true, state.runtime)...)
	args = append(args, "-v", broker.sock+":"+containerSocketPath)
	if state.platform != "" {
		args = append(args, "--platform", state.platform)
	}
	args = append(args, "--entrypoint", dockerSessionCommand[0], state.projectImageID)
	args = append(args, dockerSessionCommand[1:]...)
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

// activate gives s to a caller: its lifetime ends at expires and its disk budget is
// disk, and Drain and ReconcileOrphans count it as open. s is not yet shared, so its
// fields are set without the lock. Once Drain has begun it refuses, and the caller
// removes s.
func (d *DockerSandbox) activate(s *dockerSession, expires time.Time, disk int64) error {
	s.expires, s.disk = expires, disk
	s.removed = make(chan struct{})
	d.sessions.mu.Lock()
	if d.sessions.draining {
		d.sessions.mu.Unlock()
		return NotDispatched(RefusalCapacity, errDraining)
	}
	if d.sessions.open == nil {
		d.sessions.open = map[*dockerSession]struct{}{}
	}
	d.sessions.open[s] = struct{}{}
	d.sessions.mu.Unlock()
	s.mu.Lock()
	s.life = time.AfterFunc(time.Until(expires), func() { s.finish(SessionExpired, "") })
	s.mu.Unlock()
	return nil
}

// abandon removes a session container no caller ever held (one that failed to open,
// or a pool member), its relays and its broker.
func (s *dockerSession) abandon() {
	s.cancel()
	s.interps.Close()
	s.broker.Close()
	s.d.forceRemove(s.host, s.name)
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

// dockerCheckerUser is the user the identity check runs as: not the container's
// (1000), so no process of the session can open the check's stdout or signal it, and
// with no capabilities it can read every process's stat and command line and nothing
// more (measured under runc and gVisor, 2026-10-01).
const dockerCheckerUser = "2000:2000"

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
	argv, err := controlArgv(nil, sessionkit.ListArgv()...)
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
	s.mu.Lock()
	s.baseline = keep
	s.mu.Unlock()
	return nil
}

func (s *dockerSession) Isolation() IsolationClass { return s.tier }
func (s *dockerSession) ExpiresAt() time.Time      { return s.expires }
func (s *dockerSession) Done() <-chan struct{}     { return s.done }

func (s *dockerSession) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.end == nil {
		return nil
	}
	return s.end
}

// finish ends the session once, for the first reason given: it stops a call in
// flight, and removes the container off the caller's path.
func (s *dockerSession) finish(reason SessionEnd, detail string) {
	s.mu.Lock()
	if s.end != nil {
		s.mu.Unlock()
		return
	}
	s.end = &SessionEndedError{Reason: reason, Detail: detail}
	if s.life != nil {
		s.life.Stop()
	}
	s.mu.Unlock()
	s.cancel()
	close(s.done)
	s.d.sessions.mu.Lock()
	delete(s.d.sessions.open, s)
	s.d.sessions.deletes.Add(1)
	s.d.sessions.mu.Unlock()
	if reason != SessionClosed && reason != SessionShutdown {
		slog.Info("docker: session ended", "container", s.name, "reason", reason.String(), "detail", detail)
	}
	go func() {
		defer s.d.sessions.deletes.Done()
		s.interps.Close()
		s.d.forceRemove(s.host, s.name)
		s.broker.Close()
		if s.removed != nil {
			close(s.removed)
		}
	}()
}

// acquire takes the session's turn, bounded by ctx. A session that ended, or ends
// while waiting, refuses: nothing ran.
func (s *dockerSession) acquire(ctx context.Context) error {
	if err := s.Err(); err != nil {
		return RefuseEndedSession(err)
	}
	select {
	case s.turn <- struct{}{}:
	case <-s.done:
		return RefuseEndedSession(s.Err())
	case <-ctx.Done():
		return RefuseGaveUp(ctx)
	}
	if err := s.Err(); err != nil {
		<-s.turn
		return RefuseEndedSession(err)
	}
	return nil
}

func (s *dockerSession) release() { <-s.turn }

// Close ends the session and removes its container. It does not wait for a call in
// flight: the call is stopped.
func (s *dockerSession) Close(context.Context) error {
	s.finish(SessionClosed, "")
	return nil
}

// Suspend pauses the container: its processes stop and keep their memory, and its
// files stay in their tmpfs mounts. It reports the memory as still held.
func (s *dockerSession) Suspend(ctx context.Context) (bool, error) {
	if err := s.acquire(ctx); err != nil {
		return false, err
	}
	defer s.release()
	s.mu.Lock()
	paused := s.paused
	s.mu.Unlock()
	if paused {
		return true, nil
	}
	// The caller cannot cut the pause short, only its budget can: a pause cancelled
	// after docker took it would leave the container paused and this session thinking
	// it runs, and the next call would end the session as paused by someone else.
	if err := s.control(context.WithoutCancel(ctx), "pause", s.name); err != nil {
		s.finish(SessionBoundaryFailed, "the container could not be paused: "+err.Error())
		return false, s.Err()
	}
	s.mu.Lock()
	s.paused = true
	s.mu.Unlock()
	return true, nil
}

// prepare runs with the turn held, before a call: it unpauses a paused container,
// then reads the container back and ends the session on any difference from open.
// Nothing has run when it fails.
func (s *dockerSession) prepare(ctx context.Context) error {
	s.mu.Lock()
	paused := s.paused
	s.mu.Unlock()
	if paused {
		// Not cancellable by the caller either, for the same reason as the pause.
		if err := s.control(context.WithoutCancel(ctx), "unpause", s.name); err != nil {
			s.finish(SessionBoundaryFailed, "the container could not be unpaused: "+err.Error())
			return RefuseEndedSession(s.Err())
		}
		s.mu.Lock()
		s.paused = false
		s.mu.Unlock()
	}
	insp, err := s.inspect(ctx)
	switch {
	case errors.Is(err, errContainerGone):
		s.finish(SessionSandboxChanged, err.Error())
		return RefuseEndedSession(s.Err())
	case err != nil:
		if ctx.Err() != nil {
			return RefuseGaveUp(ctx)
		}
		// Nothing ran, and the container could not be shown to be the one opened.
		// The session goes on: the next call reads it back again.
		return NotDispatched(RefusalEnvironment, fmt.Errorf("the session's container could not be read back: %w", err))
	}
	switch {
	case insp.State.Paused:
		s.finish(SessionSandboxChanged, "the container was paused by someone else")
		return RefuseEndedSession(s.Err())
	case !insp.State.Running:
		s.finish(SessionMainProcessEnded, "the container is "+insp.State.Status)
		return RefuseEndedSession(s.Err())
	case insp.securitySnapshot() != s.snapshot:
		s.finish(SessionSandboxChanged, "the container's configuration changed since open")
		return RefuseEndedSession(s.Err())
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

// keep is what every sweep spares: the container's own processes and the live
// interpreters.
func (s *dockerSession) keep() []string {
	s.mu.Lock()
	baseline := append([]string(nil), s.baseline...)
	s.mu.Unlock()
	return s.interps.Keep(baseline)
}

// boundary runs after every call, with the turn held and whatever happened to the
// caller's context: the sweep, and when it does not prove the boundary, the end of
// the session (a restart would lose the files). A session over its disk budget ends
// here too.
func (s *dockerSession) boundary() {
	if s.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, dockerSweepBudget)
	// The sweep's exit status is the session's boundary: it starts under controlArgv,
	// so no variable of the image can load code into it (docker_cli.go).
	argv, err := controlArgv(nil, guarded(sessionkit.SweepArgv(s.disk, sessionkit.MeasureStatfs, dockerSessionDirs, s.keep()))...)
	if err != nil {
		cancel()
		s.finish(SessionBoundaryFailed, err.Error())
		return
	}
	out, err := s.exec(ctx, argv, nil, nil, 4096, 4096)
	cancel()
	if s.Err() != nil {
		return
	}
	switch {
	case err == nil && out.exited && out.exitCode == sessionkit.SweepClean:
		return
	case err == nil && out.exited && out.exitCode == sessionkit.SweepOverBudget:
		s.finish(SessionDiskExceeded, fmt.Sprintf("the session's writable filesystems hold more than %d bytes", s.disk))
		return
	case err == nil && out.exited && out.exitCode == sessionkit.SweepUnmeasurable:
		s.finish(SessionDiskExceeded, "the session's disk use could not be read")
		return
	}
	if reason, detail, ended := s.containerEnd(); ended {
		s.finish(reason, detail)
		return
	}
	s.finish(SessionBoundaryFailed, fmt.Sprintf("the sweep exited %d (err %v)", out.exitCode, err))
}

// begin takes the session's turn and prepares the container for one call. The
// returned end runs the sweep and gives the turn back off the caller's path: the
// call's answer goes back first, and the next call (or a suspend, or a close)
// waits for the sweep, which an agent's own thinking time between tool calls
// usually hides. A session the sweep ends is therefore reported to the next call.
func (s *dockerSession) begin(ctx context.Context) (end func(), err error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	if err := s.prepare(ctx); err != nil {
		s.release()
		return nil, err
	}
	return func() {
		go func() {
			s.boundary()
			s.release()
		}()
	}, nil
}

// callError is what a call returns when its exec did not deliver an exit status: a
// session that ended during the call is reported as that end. Execution may have
// happened, so it is not marked not-dispatched.
func (s *dockerSession) callError(runCtx context.Context, err error) error {
	if end := s.Err(); end != nil {
		return end
	}
	if ctxErr := deadline.Expired(runCtx); ctxErr != nil {
		return ctxErr
	}
	return err
}

// stopped is the check after a call that exited non-zero: when the container no
// longer runs as opened (containerEnd), the exit status is docker's, not the call's,
// and the session has ended.
func (s *dockerSession) stopped() bool {
	reason, detail, ended := s.containerEnd()
	if ended {
		s.finish(reason, detail)
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
	core, err := brokerSessionForGrant(ctx, grant, timeout)
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
	end, err := s.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer end()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	core, env, unlend, err := s.lend(runCtx, req.Grant, timeout)
	if err != nil {
		return fail, err
	}
	defer unlend()
	// As in a single run, node reads the script from stdin after a preload writes
	// started to stderr, so a non-zero exit without it can be docker's: unlike docker
	// run's 125, docker exec's own failures (a daemon error, a refused exec) exit 1, and
	// 126 or 127 when the exec never started node, so here any non-zero exit without it
	// counts. Session code can write into the new node's stderr before the preload
	// does, but cannot learn started before node exists, so it can make its own call
	// read as docker's failure and never docker's failure as a result.
	started := "plimsoll-started:" + randID() + "\n"
	argv := []string{"node", "--import", "data:text/javascript,process.stderr.write(" + strconv.Quote(started) + ")", "-"}
	start := time.Now()
	out, err := s.exec(runCtx, argv, env, []byte(withHostSDK(req.Code, req.Grant)), s.d.maxOutput(), s.d.maxOutput()+len(started))
	unlend()
	guestStarted := strings.HasPrefix(out.stderr, started)
	res := Result{
		Stdout:              out.stdout,
		Stderr:              strings.TrimPrefix(out.stderr, started),
		StdoutTruncated:     out.stdoutTruncated,
		StderrTruncated:     out.stderrTruncated,
		Duration:            time.Since(start),
		Sandbox:             s.d.Name(),
		Isolation:           s.tier,
		SoftwareIdentity:    s.manifest,
		EnvironmentIdentity: dockerImageIdentity(s.imageID),
		CallTrace:           core.traceSnapshot(),
	}
	if deadline.Expired(runCtx) == context.DeadlineExceeded && s.Err() == nil {
		// The call's own deadline: the CLI is killed, and the sweep that follows kills
		// the command and anything it started.
		res.TimedOut, res.ExitCode = true, 124
		return res, nil
	}
	if err != nil || !out.exited {
		fail.CallTrace = res.CallTrace
		return fail, s.callError(runCtx, err)
	}
	if out.exitCode != 0 && s.stopped() {
		fail.CallTrace = res.CallTrace
		return fail, s.Err()
	}
	if !guestStarted && out.exitCode != 0 {
		// Unmarked: the preload not leading stderr does not prove node never ran.
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
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: timeout, Artifacts: req.Artifacts, HostSDK: hostSDKModule(req.Grant), ReportKey: key}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return fail, err
	}
	end, err := s.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer end()
	// The runner enforces each step's budget; the outer deadline is the backstop.
	runCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	core, env, unlend, err := s.lend(runCtx, req.Grant, timeout+5*time.Second)
	if err != nil {
		return fail, err
	}
	defer unlend()
	out, err := s.exec(runCtx, dockerRunnerCommand, env, planJSON, runnerwire.StdoutCap, s.d.maxOutput())
	unlend()
	fail.CallTrace = core.traceSnapshot()
	fail.SoftwareIdentity, fail.EnvironmentIdentity = s.manifest, dockerImageIdentity(s.imageID)
	if deadline.Expired(runCtx) == context.DeadlineExceeded && s.Err() == nil {
		fail.Outcome, fail.Detail = ProjectOutcomeTimedOut, "run exceeded the time budget"
		return fail, nil
	}
	if err != nil || !out.exited {
		return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace}, s.callError(runCtx, err)
	}
	report, found, parseErr := runnerwire.Parse(out.stdout, key)
	if !found {
		if s.stopped() {
			return ProjectResult{Sandbox: s.d.Name(), Isolation: s.tier, CallTrace: fail.CallTrace}, s.Err()
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

// checkFunc runs the interpreter driver's identity check as dockerCheckerUser.
func (s *dockerSession) checkFunc(ctx context.Context, argv []string, _ map[string]string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	argv, err := controlArgv(nil, argv...)
	if err != nil {
		return sessionkit.ExecResult{}, err
	}
	out, err := s.execAs(ctx, dockerCheckerUser, argv, nil, stdin, outCap, errCap)
	return sessionkit.ExecResult{Stdout: out.stdout, Stderr: out.stderr, ExitCode: out.exitCode, Exited: out.exited}, err
}

// execFunc is exec in the form the shared interpreter driver calls.
func (s *dockerSession) execFunc(ctx context.Context, argv []string, env map[string]string, stdin []byte, outCap, errCap int) (sessionkit.ExecResult, error) {
	var pairs []string
	for k, v := range env {
		pairs = append(pairs, k+"="+v)
	}
	out, err := s.exec(ctx, argv, pairs, stdin, outCap, errCap)
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
// starts under controlArgv, with env as its only variables (docker_cli.go).
func (s *dockerSession) attach(argv []string, env map[string]string) (sessionkit.Attached, error) {
	inner, err := controlArgv(env, guarded(argv)...)
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
	end, err := s.begin(ctx)
	if err != nil {
		return fail, err
	}
	defer end()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	start := time.Now()
	out, err := s.interps.RunRelayed(runCtx, s.execFunc, s.attach, sessionkit.Cell{
		Language: string(req.Language), Code: req.Code, Files: cellFiles(req.Files),
		Work: dockerSessionWork, OutCap: s.d.maxOutput(), ErrCap: s.d.maxOutput(),
	})
	return cellResult(fail, out, err, time.Since(start), s.manifest, dockerImageIdentity(s.imageID), s.Err, func() error {
		if s.stopped() {
			return s.Err()
		}
		return nil
	}, func(err error) error { return s.callError(runCtx, err) })
}

// Drain stops the session pool and removes its members, refuses every open from
// then on (waiting for those already in flight), ends every open session
// (SessionShutdown), and waits, within ctx, for their containers to be removed.
func (d *DockerSandbox) Drain(ctx context.Context) error {
	// From here an open is refused, and one already in flight is waited for: it ends
	// registered, and so ended below, or refused with its container removed.
	d.sessions.mu.Lock()
	d.sessions.draining = true
	d.sessions.mu.Unlock()
	opened := make(chan struct{})
	go func() {
		d.sessions.opening.Wait()
		close(opened)
	}()
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
	d.sessions.mu.Lock()
	open := make([]*dockerSession, 0, len(d.sessions.open))
	for s := range d.sessions.open {
		open = append(open, s)
	}
	d.sessions.mu.Unlock()
	for _, s := range open {
		s.finish(SessionShutdown, "")
	}
	if err := cmp.Or(openErr, poolErr); err != nil {
		// An open in flight or the pool's filler is still running and will remove the
		// container it was making, an Add to deletes that must not race a Wait; the
		// context has ended anyway.
		return err
	}
	// A session another goroutine (its lifetime timer, a client's Close) had begun to
	// end is not finished above, and its removal may not be counted in deletes yet, so
	// each session found open is waited for by its own removal first. After that every
	// Add to deletes has happened: a session ended before the snapshot counted its
	// removal as it left open, opens in flight are done, and the pool's filler stopped.
	for _, s := range open {
		select {
		case <-s.removed:
		case <-ctx.Done():
			return fmt.Errorf("docker: session containers still being removed: %w", ctx.Err())
		}
	}
	done := make(chan struct{})
	go func() {
		d.sessions.deletes.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("docker: session containers still being removed: %w", ctx.Err())
	}
}

// ReconcileOrphans removes session containers this provider does not hold whose
// declared lifetime ended more than dockerReapMargin ago: what a crashed daemon
// left behind. A session container's lifetime is its label, so a live session of
// another daemon on the same docker host is never touched.
func (d *DockerSandbox) ReconcileOrphans(ctx context.Context) (int, error) {
	if n := reapDeadHostDirs(os.TempDir(), time.Now()); n > 0 {
		slog.Info("docker: removed host directories that stopped processes left", "count", n)
	}
	state, err := d.executionState()
	if err != nil || state.host == "" {
		return 0, nil // not preflighted yet: nothing is known to reap
	}
	args, err := dockerArgs(state.host, "ps", "-a", "--filter", "label="+dockerSessionLabel,
		"--format", `{{.Names}}	{{.Label "`+dockerExpiresLabel+`"}}`)
	if err != nil {
		return 0, err
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return 0, fmt.Errorf("docker ps: %w", err)
	}
	d.sessions.mu.Lock()
	held := map[string]bool{}
	for s := range d.sessions.open {
		held[s.name] = true
	}
	d.sessions.mu.Unlock()
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
	dir      string
	sock     string
	listener net.Listener
	srv      *http.Server

	mu   sync.Mutex
	core *brokerSession
}

func startDockerSessionBroker() (*dockerSessionBroker, error) {
	dir, err := os.MkdirTemp("", "crsbx-session-broker")
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "host-api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil { // the container runs as uid 1000
		_ = l.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	b := &dockerSessionBroker{dir: dir, sock: sock}
	b.srv = newBrokerServerFor(b.current)
	b.listener = netutil.LimitListener(l, 32)
	go func() { _ = b.srv.Serve(b.listener) }()
	return b, nil
}

func (b *dockerSessionBroker) current() *brokerSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.core
}

func (b *dockerSessionBroker) set(core *brokerSession) {
	b.mu.Lock()
	b.core = core
	b.mu.Unlock()
}

// lend serves core's grant until the returned release, which stops serving it and
// ends it: a request still in flight is cut off upstream, one still arriving is
// refused, and the release waits for them, so the call's trace is read complete
// after it. Release is idempotent: a call releases before reading its trace and
// again, deferred, on its error paths.
func (b *dockerSessionBroker) lend(core *brokerSession) (release func()) {
	b.set(core)
	var once sync.Once
	return func() {
		once.Do(func() {
			b.set(nil)
			core.Close()
		})
	}
}

// Close stops the broker and removes its socket directory.
func (b *dockerSessionBroker) Close() {
	b.set(nil)
	_ = b.listener.Close()
	_ = b.srv.Close()
	_ = os.RemoveAll(b.dir)
}

// cellFiles is a cell's files in the interpreter driver's form.
func cellFiles(files []File) []sessionkit.File {
	out := make([]sessionkit.File, 0, len(files))
	for _, f := range files {
		out = append(out, sessionkit.File{Path: f.Path, Content: f.Content})
	}
	return out
}

// cellResult turns the driver's outcome into the call's result. An interpreter that
// could not start ran none of the cell's code: that refusal is marked not
// dispatched. A cell whose interpreter ended is checked against the container
// (stopped), since a container that stopped ends the session and its exit status is
// not the cell's.
func cellResult(fail CellResult, out sessionkit.CellOutcome, err error, took time.Duration, software, environment string,
	ended, stopped func() error, callError func(error) error) (CellResult, error) {
	if refusal, ok := RefuseCell(err, ended()); ok {
		return fail, refusal
	}
	if err != nil {
		return fail, callError(err)
	}
	if out.Ended && !out.TimedOut {
		if end := stopped(); end != nil {
			return fail, end
		}
	}
	res := CellResult{
		Stdout:              out.Stdout,
		Stderr:              out.Stderr,
		StdoutTruncated:     out.StdoutTruncated,
		StderrTruncated:     out.StderrTruncated,
		TimedOut:            out.TimedOut,
		InterpreterStarted:  out.Started,
		InterpreterEnded:    out.Ended,
		Duration:            took,
		Sandbox:             fail.Sandbox,
		Isolation:           fail.Isolation,
		SoftwareIdentity:    software,
		EnvironmentIdentity: environment,
	}
	switch {
	case out.TimedOut:
		res.ExitCode = 124
	case out.Raised:
		res.ExitCode = 1
	}
	return res, nil
}
