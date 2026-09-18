package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

// DockerSandbox executes JavaScript in a throwaway, locked-down container. The
// code is piped to `node -` on stdin (no host mounts, no escaping games). The
// container has no network, a read-only root, dropped capabilities, a non-root
// user, and memory/PID/CPU caps — so hostile code is contained and cannot reach
// the host, the bridge, or the network.
//
// For a real host/VM boundary against hostile code, set Runtime to "runsc"
// (gVisor): docker then runs the container under a user-space kernel instead of
// sharing the host kernel via runc. runc alone is NOT a hostile-code boundary;
// gVisor (or the E2B microVM provider) is. See docs/gvisor.md to install runsc.
type DockerSandbox struct {
	Image        string // snippet image (plain node), for RunJavaScript
	ProjectImage string // toolchain image (node + tsc/tsx/eslint), for RunProject
	// ModuleImage is the simulation worker image for RunModule
	// (docker/sim.Dockerfile): the supervised worker plus the AOT-compiled models
	// it may load, under /models. "" = module runs unsupported.
	ModuleImage string
	Runtime     string // OCI runtime, e.g. "runsc" (gVisor). "" = docker default (runc)
	Memory      string // e.g. "256m"
	PidsLimit   string // e.g. "128"
	CPUs        string // e.g. "1"
	WorkDiskMB  int    // size of the writable /work tmpfs for project runs (MiB); 0 = derived from DiskBudgetMB, else 128
	TmpDiskMB   int    // size of the writable /tmp tmpfs (MiB); 0 = 16
	ShmDiskMB   int    // size of the writable /dev/shm tmpfs (MiB); 0 = 16

	// DiskBudgetMB is the AGGREGATE writable-storage budget for one run (MiB).
	// A container's writable surfaces are separate mounts (/tmp, /dev/shm, and
	// /work for projects) — capping each one is not the same as capping their sum,
	// and it is the sum that hostile code fills. When set, Preflight fails unless
	// tmp+shm+work fits inside it; an unset WorkDiskMB is derived as the budget's
	// remainder so the mounts sum to exactly the budget. 0 = no aggregate check
	// (per-mount defaults still apply). All of these are tmpfs, so pages are also
	// charged to the container's memory cgroup — the budget bounds host RAM/disk,
	// not a lazily-provisioned overlay.
	DiskBudgetMB int

	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	ProjectTimeout time.Duration
	MaxProjectTime time.Duration
	MaxOutputBytes int

	// Seccomp is the syscall-filter policy applied to the container. Kernel attack
	// surface is the primary escape vector for a shared-kernel runtime, so this is
	// applied EXPLICITLY rather than trusting docker's implicit default (which some
	// daemon configs disable outright when an alternate --runtime is set). Values:
	//   ""            -> docker's built-in default profile
	//   "<path.json>" -> a custom profile file (verified to exist at Preflight)
	//   "unconfined"  -> disable seccomp (NOT for hostile code; opt-out escape hatch)
	// Ignored for Runtime=="runsc" (gVisor), which does its own syscall interception.
	Seccomp string

	// RequirePinnedImages fails Preflight unless Image and ProjectImage are pinned to
	// an immutable @sha256: digest. The sandbox image is the TCB confining hostile
	// code; a mutable tag can be repushed under you. Off by default (dev ergonomics);
	// turn on for a hardened deployment.
	RequirePinnedImages bool

	// SEAM(supply-chain-provenance): today image provenance is "pin by @sha256:
	// digest, then launch the Preflight-verified content ID" (see verifyImageForRun
	// and verifiedImageIDs). That is immutability by pinning. An alternative
	// provenance model (buildpack-built, auto-patched base images carrying signed
	// attestations, the posture some platforms bundle) would attach at the Preflight
	// image-verification step, as an additional or alternative check selected by
	// config. Whatever the provenance story, a run must still launch a
	// content-addressed ID this provider inspected, never a mutable tag. See
	// docs/seams.md#supply-chain-provenance (buildpacks explained there).

	// Preflight pins the daemon endpoint used by every later CLI call. Without
	// this, a change to DOCKER_CONTEXT or ~/.docker/config.json after startup could
	// redirect a run to a remote daemon and invalidate the local broker/teardown
	// assumptions. These fields are internal runtime evidence, not configuration.
	preflightMu     sync.Mutex
	stateMu         sync.RWMutex
	daemonHost      string
	ready           bool
	runtimeVerified bool
	verifiedRuntime string
	// runtimeBannerLine is what the smoke container's `dmesg` printed first, read
	// only under runsc. It is identity information for an operator's log and
	// nothing else: gVisor's own documentation says the banner is trivially forged,
	// so IsolationClass never reads these fields. See RuntimeBanner.
	runtimeBannerLine string
	runtimeBannerRead bool
	// verifiedImageIDs maps the configured image references to the content-addressed
	// IDs whose configs were actually inspected (no VOLUMEs). Runs launch these IDs,
	// not the mutable tags, so a tag re-pointed after Preflight cannot substitute an
	// unverified image (and with it, auto-created unbounded writable volumes).
	verifiedImageIDs map[string]string
	lastVerified     time.Time
	preflightNow     func() time.Time // test clock; nil uses time.Now
}

const (
	dockerDefaultTimeout     = 5 * time.Second
	dockerMaxTimeout         = 30 * time.Second
	dockerProjectTimeout     = 30 * time.Second
	dockerMaxProjectTime     = 120 * time.Second
	dockerDefaultOutputBytes = 64 << 10
	dockerPreflightTimeout   = 10 * time.Second
	dockerPreflightCacheTTL  = 5 * time.Second
)

func (d *DockerSandbox) snippetTimeout(requested time.Duration) time.Duration {
	def, max := d.DefaultTimeout, d.MaxTimeout
	if def <= 0 {
		def = dockerDefaultTimeout
	}
	if max <= 0 {
		max = dockerMaxTimeout
	}
	if requested <= 0 {
		requested = def
	}
	if requested > max {
		requested = max
	}
	return requested
}

func (d *DockerSandbox) projectTimeout(requested time.Duration) time.Duration {
	def, max := d.ProjectTimeout, d.MaxProjectTime
	if def <= 0 {
		def = dockerProjectTimeout
	}
	if max <= 0 {
		max = dockerMaxProjectTime
	}
	if requested <= 0 {
		requested = def
	}
	if requested > max {
		requested = max
	}
	return requested
}

func (d *DockerSandbox) maxOutput() int {
	if d.MaxOutputBytes > 0 {
		return d.MaxOutputBytes
	}
	return dockerDefaultOutputBytes
}

// containerSocketPath is where the broker socket is mounted inside the container.
const containerSocketPath = "/run/host-api.sock"

// dockerBroker is the Unix-socket transport adapter for one provider-neutral
// brokerSession. The container stays on --network none and the socket contains no
// credential; the shared Go core authorizes every raw target and injects the token.
type dockerBroker struct {
	dir      string
	sock     string
	listener net.Listener
	srv      *http.Server
	core     *brokerSession
}

// traceSnapshot returns the run's bounded, metadata-only CallTrace, or nil when the
// run brokered no calls. Nil-safe so RunJavaScript can call it unconditionally
// (a run with no grant has a nil broker).
func (b *dockerBroker) traceSnapshot() *CallTrace {
	if b == nil {
		return nil
	}
	return b.core.traceSnapshot()
}

// Close stops the broker and removes its socket dir. Safe to call on a nil broker.
func (b *dockerBroker) Close() {
	if b == nil {
		return
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
	if b.srv != nil {
		_ = b.srv.Close()
	}
	b.core.Close()
	if b.dir != "" {
		_ = os.RemoveAll(b.dir)
	}
}

// startDockerBroker is the test seam that binds a known token to a grant.
// Production uses brokerSessionForGrant, so the minted token never leaves the
// provider-neutral lifecycle.
func startDockerBroker(grant *HostAPIGrant, token string) (*dockerBroker, error) {
	core, err := newBrokerSession(grant, token, nil)
	if err != nil {
		return nil, err
	}
	b, err := startDockerBrokerWithCore(core)
	if err != nil {
		core.Close()
	}
	return b, err
}

func startDockerBrokerWithCore(core *brokerSession) (*dockerBroker, error) {
	if core == nil {
		return nil, errors.New("docker broker: core is nil")
	}
	dir, err := os.MkdirTemp("", "crsbx-broker")
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
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RequestURI preserves the target exactly as it appeared on the socket.
		// r.URL.Path has already lost percent-encoding and cannot prove approve==wire.
		resp := core.Call(r.Context(), brokerCall{Method: r.Method, RawTarget: r.RequestURI, Body: r.Body})
		w.Header().Set("Content-Type", resp.ContentType)
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
	})
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	limited := netutil.LimitListener(l, 32)
	go func() { _ = srv.Serve(limited) }()
	return &dockerBroker{dir: dir, sock: sock, listener: limited, srv: srv, core: core}, nil
}

// brokerForRun starts a per-run broker when the run carries a host-API grant and
// returns the docker flags that mount its socket. The credential is minted here and
// injected by the broker, not the container env. Returns a nil broker (and nil
// args) when there is no grant. The caller must defer broker.Close().
func (d *DockerSandbox) brokerForRun(ctx context.Context, grant *HostAPIGrant, timeout time.Duration) (*dockerBroker, []string, error) {
	if grant == nil {
		return nil, nil, nil
	}
	core, err := brokerSessionForGrant(ctx, grant, timeout)
	if err != nil {
		return nil, nil, err
	}
	b, err := startDockerBrokerWithCore(core)
	if err != nil {
		core.Close()
		return nil, nil, err
	}
	return b, []string{
		"-v", b.sock + ":" + containerSocketPath,
		"-e", "HOST_API_SOCKET=" + containerSocketPath,
	}, nil
}

// DefaultDocker returns a DockerSandbox with conservative limits.
func DefaultDocker(image string) *DockerSandbox {
	if image == "" {
		image = "node:22-alpine"
	}
	return &DockerSandbox{
		Image:          image,
		ProjectImage:   "plimsoll/sandbox:latest",
		Memory:         "256m",
		PidsLimit:      "256",
		CPUs:           "1",
		DefaultTimeout: dockerDefaultTimeout,
		MaxTimeout:     dockerMaxTimeout,
		ProjectTimeout: dockerProjectTimeout,
		MaxProjectTime: dockerMaxProjectTime,
		MaxOutputBytes: dockerDefaultOutputBytes,
	}
}

func validateDockerImage(image string) error {
	if strings.TrimSpace(image) == "" {
		return errors.New("docker image is required")
	}
	if image != strings.TrimSpace(image) {
		return fmt.Errorf("docker image %q has surrounding whitespace", image)
	}
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("docker image %q starts with '-' and would be parsed as a docker run option", image)
	}
	return nil
}

// tmpDiskMB / shmDiskMB / workDiskMB are the effective per-mount tmpfs sizes.
func (d *DockerSandbox) tmpDiskMB() int {
	if d.TmpDiskMB > 0 {
		return d.TmpDiskMB
	}
	return 16
}

func (d *DockerSandbox) shmDiskMB() int {
	if d.ShmDiskMB > 0 {
		return d.ShmDiskMB
	}
	return 16
}

func (d *DockerSandbox) workDiskMB() int {
	if d.WorkDiskMB > 0 {
		return d.WorkDiskMB
	}
	// With an aggregate budget, an unset /work takes the remainder so the
	// writable mounts sum to exactly the budget.
	if d.DiskBudgetMB > 0 {
		return d.DiskBudgetMB - d.tmpDiskMB() - d.shmDiskMB()
	}
	return 128
}

// validateWritableBudget fails closed on a writable-storage configuration whose
// mounts cannot fit the aggregate budget. Checked at Preflight so readiness —
// not a hostile run — is what surfaces a misconfigured envelope.
func (d *DockerSandbox) validateWritableBudget() error {
	if d.TmpDiskMB < 0 || d.ShmDiskMB < 0 || d.WorkDiskMB < 0 || d.DiskBudgetMB < 0 {
		return errors.New("docker writable-storage sizes cannot be negative")
	}
	if d.DiskBudgetMB == 0 {
		return nil
	}
	tmp, shm, work := d.tmpDiskMB(), d.shmDiskMB(), d.workDiskMB()
	if work < 1 {
		return fmt.Errorf("docker disk budget %d MiB leaves no room for /work after /tmp (%d) + /dev/shm (%d); raise SANDBOX_DISK_MB or shrink the fixed mounts", d.DiskBudgetMB, tmp, shm)
	}
	if sum := tmp + shm + work; sum > d.DiskBudgetMB {
		return fmt.Errorf("docker writable mounts total %d MiB (/tmp %d + /dev/shm %d + /work %d), exceeding the %d MiB disk budget", sum, tmp, shm, work, d.DiskBudgetMB)
	}
	return nil
}

// lockdownArgs returns the common `docker run` isolation flags for a named,
// throwaway container. workTmpfs adds a writable work dir for project runs.
func (d *DockerSandbox) lockdownArgs(name string, workTmpfs bool, runtime string) []string {
	args := []string{
		"run", "--rm", "-i",
		"--name", name,
		// Attached stdout/stderr still stream back to this process, but the daemon
		// must not duplicate hostile output into an unbounded json-file on the host.
		"--log-driver", "none",
	}
	// gVisor (or any alternate OCI runtime) when configured — a real kernel
	// boundary around hostile code, not just runc namespaces.
	if runtime != "" {
		args = append(args, "--runtime", runtime)
	}
	args = append(args,
		"--memory", d.Memory,
		"--memory-swap", d.Memory, // == memory disables swap
		"--pids-limit", d.PidsLimit,
		"--cpus", d.CPUs,
		"--read-only", // immutable root fs
		"--tmpfs", fmt.Sprintf("/tmp:rw,noexec,nosuid,size=%dm", d.tmpDiskMB()),
		// Explicitly bound /dev/shm: without this mount the daemon default is a
		// WRITABLE 64 MiB tmpfs that no other cap accounts for.
		"--tmpfs", fmt.Sprintf("/dev/shm:rw,noexec,nosuid,size=%dm", d.shmDiskMB()),
		"--user", "1000:1000",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
	)
	// Pin an EXPLICIT seccomp policy when one is configured, so kernel attack surface
	// is reduced by an audited profile rather than whatever the daemon defaults to
	// (some configs disable the default profile outright when an alternate runtime is
	// set). "" leaves docker's built-in default in force (there is no keyword to name
	// it explicitly — only a path or "unconfined"). gVisor (runsc) intercepts syscalls
	// in its own user-space kernel, so a host seccomp profile is redundant/conflicting
	// there — skip it for that runtime.
	if runtime != "runsc" && d.Seccomp != "" {
		args = append(args, "--security-opt", "seccomp="+d.Seccomp)
	}
	// Always fully network-isolated. When a host-API capability is granted, the
	// container still has NO network — it reaches the host API only through a
	// bind-mounted unix socket (see brokerForRun), so egress is restricted to
	// exactly the broker, nothing else.
	args = append(args, "--network", "none")
	if workTmpfs {
		workFlag := fmt.Sprintf("/work:rw,noexec,nosuid,size=%dm,mode=1777", d.workDiskMB())
		args = append(args, "--tmpfs", workFlag, "--workdir", "/work")
	}
	return args
}

func (d *DockerSandbox) Name() string { return "docker" }

// SupportsProjects is true: the project image bakes the TS toolchain.
func (d *DockerSandbox) SupportsProjects() bool { return true }

func (d *DockerSandbox) SupportsJavaScriptGrants() bool { return true }

// SupportsProjectGrants is true: a project run mounts the same per-run broker socket
// and preloads the host.* client into every step process (node --import), so project
// files reach the host API over the exact shared brokerSession the snippet path uses.
func (d *DockerSandbox) SupportsProjectGrants() bool { return true }

// IsolationClass depends on the OCI runtime: gVisor/runsc puts a user-space kernel
// between guest and host (a real hostile-code boundary → Kernel), while the default
// runc shares the host kernel (namespaces only → Container, NOT a hostile-code
// boundary on its own). This is exactly the distinction the "docker" name hides.
func (d *DockerSandbox) IsolationClass() IsolationClass {
	d.stateMu.RLock()
	verified := d.ready && d.runtimeVerified && d.verifiedRuntime == d.Runtime
	d.stateMu.RUnlock()
	if d.Runtime == "runsc" && verified {
		return IsolationKernel
	}
	return IsolationContainer
}

func (d *DockerSandbox) preflightTime() time.Time {
	if d.preflightNow != nil {
		return d.preflightNow()
	}
	return time.Now()
}

// Preflight resolves the effective Docker context, contacts the daemon, and verifies
// a configured OCI runtime is registered there. This makes readiness and the
// reported isolation tier conservative instead of trusting only a client-side PATH
// or runtime label while the daemon is unavailable/misconfigured. This verifies
// daemon registration and executable basename; it is configuration evidence, not
// cryptographic runtime attestation.
func (d *DockerSandbox) Preflight(ctx context.Context) (retErr error) {
	// Readiness is public and runs can also trigger lazy Preflight. Never let a
	// request flood build an unbounded goroutine queue behind a mutex while one
	// daemon probe is in flight. A concurrent caller may use the last recently
	// verified ready state; an unready provider fails quickly and may retry.
	if !d.preflightMu.TryLock() {
		now := d.preflightTime()
		d.stateMu.RLock()
		cacheAge := now.Sub(d.lastVerified)
		stillReady := d.ready && d.daemonHost != "" && d.verifiedRuntime == d.Runtime &&
			!d.lastVerified.IsZero() && cacheAge >= 0 && cacheAge < dockerPreflightCacheTTL
		d.stateMu.RUnlock()
		if stillReady {
			return nil
		}
		return errors.New("docker preflight is already in progress")
	}
	defer d.preflightMu.Unlock()

	// Cache a recent successful probe so unauthenticated readiness polling cannot
	// continuously execute docker CLI calls. Keep the prior ready state live while
	// a refresh is in flight; only an actual failed refresh invalidates admission.
	now := d.preflightTime()
	d.stateMu.RLock()
	pinnedHost := d.daemonHost
	cacheAge := now.Sub(d.lastVerified)
	recentlyReady := d.ready && pinnedHost != "" && d.verifiedRuntime == d.Runtime &&
		!d.lastVerified.IsZero() && cacheAge >= 0 && cacheAge < dockerPreflightCacheTTL
	d.stateMu.RUnlock()
	if recentlyReady {
		return nil
	}
	defer func() {
		if retErr == nil {
			return
		}
		d.stateMu.Lock()
		d.ready = false
		d.runtimeVerified = false
		d.stateMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, dockerPreflightTimeout)
	defer cancel()

	// A failed refresh makes the provider not-ready, but never changes the pinned
	// endpoint. In-flight runs have already snapshotted their endpoint/isolation and
	// remain able to tear down on the daemon where they started.
	if err := validateDockerImage(d.Image); err != nil {
		return err
	}
	if err := validateDockerImage(d.ProjectImage); err != nil {
		return err
	}
	if d.ModuleImage != "" {
		if err := validateDockerImage(d.ModuleImage); err != nil {
			return err
		}
	}
	if err := d.validateWritableBudget(); err != nil {
		return err
	}
	if d.RequirePinnedImages {
		for _, img := range d.configuredImages() {
			if !isDigestPinned(img) {
				return fmt.Errorf("image %q is not pinned to an immutable @sha256: digest (RequirePinnedImages is on)", img)
			}
		}
	}
	// A custom seccomp profile must exist before we promise to enforce it; "default"
	// and "unconfined" are docker keywords, not files.
	if p := d.Seccomp; p != "" && p != "unconfined" && p != "default" {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("seccomp profile %q is not readable: %w", p, err)
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker CLI not found on PATH: %w", err)
	}
	if pinnedHost == "" {
		// The container boundary assumes a LOCAL daemon: the broker bind-mounts a
		// Unix socket, and force-remove must target the same host. Resolve the active
		// context exactly once; later probes deliberately verify this pinned endpoint
		// instead of following mutable DOCKER_CONTEXT/config state.
		if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); dockerHostIsRemote(host) {
			return fmt.Errorf("DOCKER_HOST=%q points to a remote daemon; plimsoll requires a local daemon (unix socket) so its broker and teardown hold", host)
		}
		var err error
		pinnedHost, err = effectiveDockerHost(ctx)
		if err != nil {
			return err
		}
		if dockerHostIsRemote(pinnedHost) {
			return fmt.Errorf("effective Docker context points to remote daemon %q; plimsoll requires a local Unix socket", pinnedHost)
		}
	}
	runtimeVerified, err := verifyDockerDaemon(ctx, pinnedHost, d.Runtime)
	if err != nil {
		return err
	}
	// An image-declared VOLUME would make `docker run` silently auto-create an
	// anonymous WRITABLE host volume — bypassing --read-only and every tmpfs size
	// bound above (an unbounded host-disk write channel). Refuse such images, and
	// record the content-addressed ID each verified reference resolved to: runs
	// launch that ID, never the mutable tag, so this check cannot be bypassed by
	// re-pointing the tag after Preflight. This also requires both images to exist
	// on the pinned daemon, so readiness reflects the exact artifacts runs will
	// use rather than a lazy first pull.
	images := d.configuredImages()
	verifiedIDs := make(map[string]string, len(images))
	for _, img := range images {
		id, err := verifyImageForRun(ctx, pinnedHost, img)
		if err != nil {
			return err
		}
		verifiedIDs[img] = id
	}
	d.stateMu.Lock()
	d.daemonHost = pinnedHost
	d.ready = true
	d.runtimeVerified = runtimeVerified
	d.verifiedRuntime = d.Runtime
	d.verifiedImageIDs = verifiedIDs
	d.lastVerified = d.preflightTime()
	d.stateMu.Unlock()
	return nil
}

// isDigestPinned reports whether an image reference is pinned to an immutable
// content digest (…@sha256:<hex>) rather than a mutable tag.
func isDigestPinned(image string) bool {
	const marker = "@sha256:"
	i := strings.LastIndex(image, marker)
	if i <= 0 {
		return false
	}
	digest := image[i+len(marker):]
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// dockerHostIsRemote reports whether a DOCKER_HOST value targets a daemon off this
// host. Empty, unix://, and absolute socket paths are local; every other form is
// rejected rather than guessed to be a local daemon.
func dockerHostIsRemote(host string) bool {
	if host == "" {
		return false
	}
	return !strings.HasPrefix(host, "unix://") && !filepath.IsAbs(host)
}

// effectiveDockerHost asks the CLI to resolve DOCKER_HOST, DOCKER_CONTEXT, and the
// persisted active context using Docker's own precedence rules. Checking only an
// environment variable is insufficient: a saved SSH/TCP context can otherwise run
// hostile code on a remote daemon where local broker and teardown assumptions fail.
func effectiveDockerHost(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "context", "inspect", "--format", `{{(index .Endpoints "docker").Host}}`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("resolve effective Docker context: %w: %s", err, strings.TrimSpace(string(out)))
	}
	host := strings.TrimSpace(string(out))
	if host == "" {
		return "", errors.New("resolve effective Docker context: empty daemon endpoint")
	}
	return host, nil
}

func verifyDockerDaemon(ctx context.Context, host, runtime string) (bool, error) {
	cmd := exec.CommandContext(ctx, "docker", "--host", host, "info", "--format", `{{json .Runtimes}}`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("docker daemon is not ready: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var runtimes map[string]struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &runtimes); err != nil {
		return false, fmt.Errorf("docker daemon returned unparseable runtime metadata: %w", err)
	}
	if runtime != "" {
		cfg, ok := runtimes[runtime]
		if !ok {
			return false, fmt.Errorf("configured OCI runtime %q is not registered with the Docker daemon", runtime)
		}
		if runtime == "runsc" && filepath.Base(cfg.Path) != "runsc" {
			return false, fmt.Errorf("OCI runtime %q is registered with path %q, not a runsc executable", runtime, cfg.Path)
		}
	}
	return runtime == "runsc", nil
}

// verifyImageForRun inspects an image on the pinned daemon and returns the
// content-addressed ID runs must launch. It rejects an image whose config
// declares VOLUMEs: for each declared volume `docker run` auto-creates an
// anonymous writable volume on the host, which is exempt from --read-only and
// has no size bound — exactly the aggregate-writable-storage hole this provider
// promises is closed. Returning the ID from the same inspect binds that check to
// the exact image content, so a tag re-pointed after Preflight cannot swap in an
// unverified config. Requires the image to be present (inspect does not pull).
func verifyImageForRun(ctx context.Context, host, image string) (string, error) {
	// One whole-object inspect: a compound template like `{{.Id}} {{json
	// .Config.Volumes}}` fails on daemons that omit the empty Volumes key, and two
	// separate inspects would let the tag move between reading the ID and the
	// volume config.
	args, err := dockerArgs(host, "image", "inspect", "--format", "{{json .}}", image)
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker image %q is not inspectable on the pinned daemon (build or pull it before serving): %w: %s", image, err, strings.TrimSpace(string(out)))
	}
	id, volumes, err := parseImageIDAndVolumes(out)
	if err != nil {
		return "", fmt.Errorf("docker image %q: %w", image, err)
	}
	if len(volumes) > 0 {
		return "", fmt.Errorf("docker image %q declares VOLUME %s; docker would auto-create unbounded writable host volumes for it, so this image is refused — rebuild it without VOLUME", image, strings.Join(volumes, ", "))
	}
	return id, nil
}

// parseImageIDAndVolumes decodes `docker image inspect --format '{{json .}}'`
// output into the content-addressed ID and the declared volume paths (daemons
// omit the Volumes key entirely when none are declared). Anything malformed
// fails closed — an image whose identity or volume config cannot be read is not
// runnable evidence.
func parseImageIDAndVolumes(out []byte) (string, []string, error) {
	var inspect struct {
		ID     string `json:"Id"`
		Config struct {
			Volumes map[string]json.RawMessage `json:"Volumes"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &inspect); err != nil {
		return "", nil, fmt.Errorf("returned unparseable inspect output: %w", err)
	}
	if !strings.HasPrefix(inspect.ID, "sha256:") {
		return "", nil, fmt.Errorf("returned no content-addressed image ID (got %q)", inspect.ID)
	}
	paths := make([]string, 0, len(inspect.Config.Volumes))
	for p := range inspect.Config.Volumes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return inspect.ID, paths, nil
}

// SmokeTest proves the EXACT configured image/runtime/seccomp combination
// enforces the writable-storage contract by running one throwaway lockdown
// container per image and checking, from inside, that the root filesystem
// refuses writes and that every writable mount is a tmpfs carrying the exact
// size and noexec/nosuid options this provider promised. Preflight verifies
// configuration; this verifies behavior. It starts real containers, so it is
// for startup/deploy readiness — not per-request or unauthenticated poll paths.
func (d *DockerSandbox) SmokeTest(ctx context.Context) error {
	if err := d.ensurePreflight(ctx); err != nil {
		return err
	}
	state, err := d.executionState()
	if err != nil {
		return err
	}
	// Probe the verified content IDs — the exact artifacts runs launch.
	probes := []struct {
		ref       string
		id        string
		workTmpfs bool
	}{
		{ref: d.Image, id: state.imageID, workTmpfs: false},
		{ref: d.ProjectImage, id: state.projectImageID, workTmpfs: true},
	}
	if d.ModuleImage != "" {
		// The module image is a project image with a worker in it: the same
		// runner, the same writable /work, the same lockdown to prove.
		probes = append(probes, struct {
			ref       string
			id        string
			workTmpfs bool
		}{ref: d.ModuleImage, id: state.moduleImageID, workTmpfs: true})
	}
	d.stateMu.Lock()
	d.runtimeBannerLine, d.runtimeBannerRead = "", false
	d.stateMu.Unlock()
	// The grant path is a host Unix socket mounted into the container. Whether the
	// configured runtime lets a guest connect to one is a runtime property (runsc
	// refuses unless registered with --host-uds=open), so the first probe container
	// also mounts a throwaway socket and must reach it. Without this, a runtime that
	// cannot broker grants would report ready and then fail every grant run.
	sock, closeSock, err := startSmokeSocket()
	if err != nil {
		return err
	}
	defer closeSock()
	for i, p := range probes {
		// The banner read is attempted once, in the first probe container, and only
		// when the runtime is runsc: under runc the same envelope (uid 1000, no
		// capabilities, the daemon's seccomp default) gets "klogctl: Operation not
		// permitted", and a host kernel log is not something a probe should read.
		readBanner := i == 0 && state.runtime == "runsc"
		socketPath := ""
		if i == 0 {
			socketPath = sock
		}
		if err := d.smokeProbe(ctx, state, p.id, p.workTmpfs, readBanner, socketPath); err != nil {
			return fmt.Errorf("smoke failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
		}
	}
	return nil
}

// startSmokeSocket listens on a throwaway host Unix socket the way brokerForRun
// does (same directory shape, same 0666 mode for the uid-1000 guest) and answers
// each connection's first line with "pong". The returned function stops it.
func startSmokeSocket() (path string, closeFn func(), err error) {
	dir, err := os.MkdirTemp("", "crsbx-smoke-sock")
	if err != nil {
		return "", nil, err
	}
	path = filepath.Join(dir, "host-api.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = l.Close()
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("pong\n"))
			}(c)
		}
	}()
	return path, func() { _ = l.Close(); _ = os.RemoveAll(dir) }, nil
}

// RuntimeBanner returns the first line the smoke container read from `dmesg`, and
// whether a line was read at all. It is a diagnostic, not evidence: gVisor prints
// "Starting gVisor..." there, and gVisor's documentation warns in the same breath
// that the banner is easily replicated by an attacker. So the value is for an
// operator reading a startup log ("the runtime that answered was the one I
// configured"), never for a decision. IsolationClass does not consult it, a run is
// never refused or admitted because of it, and an unreadable banner does not fail
// SmokeTest. The read is attempted only under runsc; under runc read is false.
func (d *DockerSandbox) RuntimeBanner() (line string, read bool) {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return d.runtimeBannerLine, d.runtimeBannerRead
}

// smokeProbeScript is the node program the smoke container runs. The banner and
// socket blocks are appended, not toggled, so a script built without them contains
// no dmesg and no socket connect at all.
func smokeProbeScript(readBanner bool, socket bool) string {
	const storage = `const fs = require("fs");
const mounts = fs.readFileSync("/proc/mounts", "utf8");
let rootWritable = false;
try { fs.writeFileSync("/plimsoll-smoke", "x"); rootWritable = true; } catch (e) {}
const writable = [];
const seen = new Set();
for (const line of mounts.trim().split("\n")) {
  const mnt = line.split(/\s+/)[1];
  if (!mnt || seen.has(mnt)) continue;
  seen.add(mnt);
  let st;
  try { st = fs.statSync(mnt); } catch (e) { continue; }
  try {
    if (st.isDirectory()) {
      const p = mnt.replace(/\/$/, "") + "/.crsbx-probe";
      fs.writeFileSync(p, "x");
      fs.unlinkSync(p);
      writable.push(mnt);
    } else if (st.isFile()) {
      fs.closeSync(fs.openSync(mnt, "a"));
      writable.push(mnt);
    }
  } catch (e) {}
}
let banner = null;
`
	// Bounded three ways: head -c caps the bytes, the timeout caps the wait, and a
	// failure is reported as text rather than thrown. stderr is folded into stdout
	// so a refusal ("klogctl: Operation not permitted") is what gets recorded.
	const banner = `try {
  const head = require("child_process").execFileSync("sh", ["-c", "dmesg 2>&1 | head -c 512"],
    { encoding: "latin1", timeout: 3000, maxBuffer: 65536, stdio: ["ignore", "pipe", "ignore"] });
  banner = { head: head };
} catch (e) {
  banner = { error: String((e && e.message) || e).slice(0, 200) };
}
`
	const finish = `function finish(socket) { process.stdout.write(JSON.stringify({ rootWritable, mounts, writable, banner, socket })); }
`
	// The connect is bounded by its own timeout and every outcome, including a
	// refusal, is reported as data rather than thrown, so the storage evidence above
	// is never lost to the socket check.
	const socketProbe = `(function () {
  var done = false;
  var s = require("net").connect("` + containerSocketPath + `");
  function end(v) { if (done) return; done = true; try { s.destroy(); } catch (e) {} finish(v); }
  s.setTimeout(3000, function () { end({ error: "timeout" }); });
  s.on("connect", function () { s.write("ping\n"); });
  s.on("data", function (d) { end({ ok: true, reply: String(d).trim().slice(0, 32) }); });
  s.on("error", function (e) { end({ error: String((e && e.code) || e).slice(0, 64) }); });
})();
`
	script := storage
	if readBanner {
		script += banner
	}
	script += finish
	if socket {
		return script + socketProbe
	}
	return script + "finish(null);\n"
}

// bannerFirstLine reduces whatever the smoke container read to one bounded line
// of printable ASCII, so the value is safe to put on a log line. The runtime, not
// the guest, produced it, but the bound and the character filter cost nothing.
func bannerFirstLine(head string) string {
	line, _, _ := strings.Cut(head, "\n")
	line = strings.TrimRight(line, "\r")
	var b strings.Builder
	for _, r := range line {
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
		if b.Len() >= 120 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// smokeProbe runs the storage probe inside one lockdown container and verifies
// the mount table it reports. The probe does not trust mount flags: it attempts
// an actual write at EVERY mount point, so the writable set is proven
// exhaustively rather than assumed from the flags this provider happened to
// pass. Only mounts that can persist guest bytes count — directories (file
// creation) and regular files (append). Device-node mounts are excluded:
// docker's masked /proc paths are /dev/null binds whose writes discard, not
// storage.
func (d *DockerSandbox) smokeProbe(ctx context.Context, state dockerExecutionState, image string, workTmpfs bool, readBanner bool, socketPath string) error {
	probe := smokeProbeScript(readBanner, socketPath != "")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "crsbx-smoke-" + randID()
	// Override any image ENTRYPOINT (the project image's is the runner protocol):
	// the probe must be exactly `node -` reading the script from stdin.
	runArgs := d.lockdownArgs(name, workTmpfs, state.runtime)
	if socketPath != "" {
		// Mounted exactly as brokerForRun mounts the per-run broker socket.
		runArgs = append(runArgs, "-v", socketPath+":"+containerSocketPath)
	}
	runArgs = append(runArgs, "--entrypoint", "node", image, "-")
	args, err := dockerArgs(state.host, runArgs...)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(probe)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		d.forceRemove(state.host, name)
		return fmt.Errorf("probe container failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var report struct {
		RootWritable bool     `json:"rootWritable"`
		Mounts       string   `json:"mounts"`
		Writable     []string `json:"writable"`
		Banner       *struct {
			Head  string `json:"head"`
			Error string `json:"error"`
		} `json:"banner"`
		Socket *struct {
			OK    bool   `json:"ok"`
			Reply string `json:"reply"`
			Error string `json:"error"`
		} `json:"socket"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return fmt.Errorf("probe returned unparseable output: %w", err)
	}
	if socketPath != "" {
		reason := "no socket result reported"
		switch {
		case report.Socket != nil && report.Socket.OK && report.Socket.Reply == "pong":
			reason = ""
		case report.Socket != nil && report.Socket.OK:
			reason = fmt.Sprintf("connected but the reply was %q", bannerFirstLine(report.Socket.Reply))
		case report.Socket != nil:
			reason = bannerFirstLine(report.Socket.Error)
		}
		if reason != "" {
			return fmt.Errorf("a host Unix socket mounted at %s is not reachable from inside the container (%s), so no host-API grant could be brokered; for runsc, register the runtime with --host-uds=open (docker/install-gvisor.sh does) and restart docker", containerSocketPath, reason)
		}
	}
	if readBanner {
		// Recorded before the storage checks and independent of their outcome; it
		// changes nothing below. A failed read is logged and left unavailable.
		switch {
		case report.Banner != nil && report.Banner.Head != "":
			line := bannerFirstLine(report.Banner.Head)
			d.stateMu.Lock()
			d.runtimeBannerLine, d.runtimeBannerRead = line, true
			d.stateMu.Unlock()
			slog.Info("docker smoke: runtime banner (diagnostic identity only, forgeable, not isolation evidence)",
				"runtime", state.runtime, "banner", line)
		case report.Banner != nil:
			slog.Info("docker smoke: runtime banner unavailable (diagnostic only; readiness unaffected)",
				"runtime", state.runtime, "reason", bannerFirstLine(report.Banner.Error))
		default:
			slog.Info("docker smoke: runtime banner not reported (diagnostic only; readiness unaffected)",
				"runtime", state.runtime)
		}
	}
	if report.RootWritable {
		return errors.New("root filesystem accepted a write; --read-only is not in force")
	}
	expected := []struct {
		path   string
		sizeMB int
	}{
		{"/tmp", d.tmpDiskMB()},
		{"/dev/shm", d.shmDiskMB()},
	}
	if workTmpfs {
		expected = append(expected, struct {
			path   string
			sizeMB int
		}{"/work", d.workDiskMB()})
	}
	paths := make([]string, 0, len(expected))
	for _, want := range expected {
		if err := checkTmpfsMount(report.Mounts, want.path, want.sizeMB); err != nil {
			return err
		}
		paths = append(paths, want.path)
	}
	// The tmpfs checks above prove the PROMISED mounts are bounded; this proves
	// the promised mounts are the ONLY ones that accept writes, so the aggregate
	// budget really is the full writable sum.
	return checkWritableSet(report.Writable, paths)
}

// checkWritableSet asserts the probe's actually-writable mount set is exactly
// the promised one. An extra entry is unaccounted writable storage outside the
// aggregate budget; a missing entry means a promised mount refused writes and
// runs would fail in ways readiness never observed.
func checkWritableSet(got, want []string) error {
	g, w := slices.Clone(got), slices.Clone(want)
	sort.Strings(g)
	sort.Strings(w)
	if !slices.Equal(g, w) {
		return fmt.Errorf("writable mounts inside the container are %v, want exactly %v — the aggregate storage budget does not cover the difference", g, w)
	}
	return nil
}

// checkTmpfsMount asserts one /proc/mounts entry is a tmpfs with the exact
// promised size plus noexec and nosuid. A missing size option fails closed: a
// runtime that does not report the bound cannot prove it enforced one.
func checkTmpfsMount(mounts, path string, sizeMB int) error {
	wantSize := fmt.Sprintf("size=%dk", sizeMB*1024)
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != path {
			continue
		}
		if fields[2] != "tmpfs" {
			return fmt.Errorf("%s is mounted as %q, not tmpfs", path, fields[2])
		}
		opts := strings.Split(fields[3], ",")
		for _, required := range []string{"noexec", "nosuid", wantSize} {
			if !slices.Contains(opts, required) {
				return fmt.Errorf("%s mount options %q lack %q — the writable-storage bound is not verifiably in force", path, fields[3], required)
			}
		}
		return nil
	}
	return fmt.Errorf("%s is not present in the container mount table", path)
}

type dockerExecutionState struct {
	host      string
	runtime   string
	isolation IsolationClass
	// imageID/projectImageID are the Preflight-verified content IDs runs launch in
	// place of the mutable Image/ProjectImage references.
	imageID        string
	projectImageID string
	moduleImageID  string // "" when no module image is configured
}

func (d *DockerSandbox) executionState() (dockerExecutionState, error) {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	if !d.ready || d.daemonHost == "" || d.verifiedRuntime != d.Runtime {
		return dockerExecutionState{}, errors.New("docker provider is not ready for its current configuration")
	}
	imageID, projectImageID := d.verifiedImageIDs[d.Image], d.verifiedImageIDs[d.ProjectImage]
	moduleImageID := ""
	if d.ModuleImage != "" {
		moduleImageID = d.verifiedImageIDs[d.ModuleImage]
	}
	if imageID == "" || projectImageID == "" || (d.ModuleImage != "" && moduleImageID == "") {
		// The configured references changed since Preflight verified them; running
		// the new tags would launch content whose volume config was never checked.
		return dockerExecutionState{}, errors.New("docker images are not the Preflight-verified ones; re-run Preflight")
	}
	isolation := IsolationContainer
	if d.Runtime == "runsc" && d.runtimeVerified {
		isolation = IsolationKernel
	}
	return dockerExecutionState{
		host:           d.daemonHost,
		runtime:        d.verifiedRuntime,
		isolation:      isolation,
		imageID:        imageID,
		projectImageID: projectImageID,
		moduleImageID:  moduleImageID,
	}, nil
}

// configuredImages lists every image reference this provider will launch, each
// once: the snippet image, the project image, and the module image when set.
// Preflight verifies and pins exactly this set.
func (d *DockerSandbox) configuredImages() []string {
	images := []string{d.Image}
	for _, img := range []string{d.ProjectImage, d.ModuleImage} {
		if img == "" || slices.Contains(images, img) {
			continue
		}
		images = append(images, img)
	}
	return images
}

func (d *DockerSandbox) ensurePreflight(ctx context.Context) error {
	if err := d.Preflight(ctx); err != nil {
		return err
	}
	_, err := d.executionState()
	return err
}

func dockerArgs(host string, args ...string) ([]string, error) {
	if host == "" {
		return nil, errors.New("docker daemon endpoint is not verified")
	}
	return append([]string{"--host", host}, args...), nil
}

// dockerInfraExit reports whether a non-zero `docker run` exit is the docker CLI /
// daemon failing to START or run the container (125 = daemon could not run the
// container: bad image, rejected flag, OOM at create; 126 = entrypoint not
// executable; 127 = entrypoint not found) rather than the guest code exiting
// non-zero. These carry a docker/OCI-level diagnostic on stderr, so we key off both
// the exit code AND that marker to avoid misreading a guest `process.exit(127)` as
// infrastructure. Such runs never enforced isolation, so they must surface as
// infrastructure errors, not benign non-zero results.
func dockerInfraExit(code int, stderr string) bool {
	switch code {
	case 125, 126, 127:
	default:
		return false
	}
	markers := []string{
		"docker:",
		"Error response from daemon",
		"OCI runtime",
		"executable file not found",
		"no such file or directory",
		"cannot connect to the docker daemon",
		"failed to create",
		"error during container init",
	}
	low := strings.ToLower(stderr)
	for _, m := range markers {
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// randID returns a short random hex string for a unique container name.
func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *DockerSandbox) RunJavaScript(ctx context.Context, req Request) (Result, error) {
	if err := ValidateRequest(req); err != nil {
		return Result{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	if err := validateDockerImage(d.Image); err != nil {
		return Result{Sandbox: d.Name()}, err
	}
	if err := d.ensurePreflight(ctx); err != nil {
		return Result{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	execState, err := d.executionState()
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	isolation := execState.isolation
	if err := CheckMinimumIsolation(isolation, req.MinimumIsolation); err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}
	timeout := d.snippetTimeout(req.Timeout)

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Name the container so we can force-remove it. On timeout, CommandContext
	// kills the `docker run` *client*, but the container keeps running until its
	// work finishes (an infinite loop would never stop). Force-removing by name
	// guarantees the workload is torn down even when the client was killed.
	name := "crsbx-" + randID()

	broker, capArgs, err := d.brokerForRun(runCtx, req.Grant, timeout)
	if err != nil {
		return Result{Sandbox: d.Name()}, err
	}
	defer broker.Close()
	args := append(d.lockdownArgs(name, false, execState.runtime), capArgs...)
	// Launch the Preflight-verified content ID, not the mutable tag.
	args = append(args, execState.imageID, "node", "-") // read the script from stdin
	args, err = dockerArgs(execState.host, args...)
	if err != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, err
	}

	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.Stdin = bytes.NewReader([]byte(withHostSDK(req.Code, req.Grant)))
	var stdout, stderr cappedBuffer
	stdout.limit = d.maxOutput()
	stderr.limit = d.maxOutput()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)
	if runCtx.Err() != nil {
		d.forceRemove(execState.host, name)
	}

	res := Result{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
		Duration:        duration,
		Sandbox:         d.Name(),
		Isolation:       isolation,
		// Metadata-only evidence of the run's brokered host.* calls. Nil unless the
		// run carried a grant that made calls; it never affects execution below.
		CallTrace: broker.traceSnapshot(),
	}

	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = 124
		return res, nil
	}
	if runCtx.Err() != nil {
		return Result{Sandbox: d.Name(), Isolation: isolation}, runCtx.Err()
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code := exitErr.ExitCode()
			// The docker CLI/daemon exits 125/126/127 when it could not START or run
			// the container (bad image, rejected lockdown flag, entrypoint missing). A
			// run that never launched never enforced isolation, so it is an
			// infrastructure error — NOT a benign "your code exited non-zero".
			if dockerInfraExit(code, stderr.String()) {
				return Result{Sandbox: d.Name()}, fmt.Errorf("docker failed to run the container (exit %d): %s", code, strings.TrimSpace(stderr.String()))
			}
			// User code (or node) exited non-zero: a normal result, not an error.
			res.ExitCode = code
			return res, nil
		}
		// docker missing / failed to start the container: infrastructure error.
		return Result{Sandbox: d.Name()}, err
	}
	return res, nil
}

// projectStdoutCap bounds the JSON the runner writes back. The runner caps each
// step's output at 1 MiB and stops on the first failure, so this is generous.
const projectStdoutCap = 16 << 20

// runnerSentinel must match sandbox/runner.mjs.
const runnerSentinel = "<<<CRSBX_RESULT>>>"

// runnerReport is the decoded post-sentinel report from docker/runner.mjs.
type runnerReport struct {
	Steps              []StepResult
	Artifacts          []Artifact
	ArtifactsTruncated bool
	Err                string // runner-reported structured setup failure; "" = none
}

// parseRunnerOutput locates the runner's sentinel-framed JSON report in the
// container's captured stdout and decodes it. found=false means no sentinel was
// present (the runner never reported); a sentinel followed by undecodable JSON
// is (zero report, true, error). Step output precedes the sentinel and is
// discarded here — the runner's report is the last thing written, so the LAST
// sentinel is authoritative even when hostile step output printed one earlier.
func parseRunnerOutput(out string) (runnerReport, bool, error) {
	idx := strings.LastIndex(out, runnerSentinel)
	if idx < 0 {
		return runnerReport{}, false, nil
	}
	var parsed struct {
		Steps []struct {
			Command         string `json:"command"`
			Stdout          string `json:"stdout"`
			Stderr          string `json:"stderr"`
			StdoutTruncated bool   `json:"stdoutTruncated"`
			StderrTruncated bool   `json:"stderrTruncated"`
			ExitCode        int    `json:"exitCode"`
			TimedOut        bool   `json:"timedOut"`
			DurationMs      int64  `json:"durationMs"`
		} `json:"steps"`
		Artifacts []struct {
			Path    string `json:"path"`
			Content []byte `json:"content"` // base64 decoded by encoding/json
		} `json:"artifacts"`
		ArtifactsTruncated bool   `json:"artifactsTruncated"`
		Error              string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out[idx+len(runnerSentinel):]), &parsed); err != nil {
		return runnerReport{}, true, err
	}
	rep := runnerReport{ArtifactsTruncated: parsed.ArtifactsTruncated, Err: parsed.Error}
	for _, a := range parsed.Artifacts {
		rep.Artifacts = append(rep.Artifacts, Artifact{Path: a.Path, Content: a.Content})
	}
	for _, s := range parsed.Steps {
		rep.Steps = append(rep.Steps, StepResult{
			Command:         s.Command,
			Stdout:          s.Stdout,
			Stderr:          s.Stderr,
			StdoutTruncated: s.StdoutTruncated,
			StderrTruncated: s.StderrTruncated,
			ExitCode:        s.ExitCode,
			TimedOut:        s.TimedOut,
			Duration:        time.Duration(s.DurationMs) * time.Millisecond,
		})
	}
	return rep, true, nil
}

func (d *DockerSandbox) RunProject(ctx context.Context, req ProjectRequest) (ProjectResult, error) {
	if err := ValidateProjectRequest(req); err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	if err := validateDockerImage(d.ProjectImage); err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}
	if err := d.ensurePreflight(ctx); err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	execState, err := d.executionState()
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	if err := CheckMinimumIsolation(execState.isolation, req.MinimumIsolation); err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: execState.isolation}, err
	}
	return d.runPlan(ctx, execState, execState.projectImageID, req)
}

// runPlan launches one runner container from a Preflight-verified image ID with
// req as its plan and classifies what came back. RunProject and RunModule share
// it: a module run is a project run whose one step is the worker, so every
// lockdown, timeout, output cap and outcome rule is written once.
func (d *DockerSandbox) runPlan(ctx context.Context, execState dockerExecutionState, imageID string, req ProjectRequest) (ProjectResult, error) {
	isolation := execState.isolation
	timeout := d.projectTimeout(req.Timeout)

	// The runner enforces a per-step timeout; the outer context is a hard backstop
	// with a small grace so the runner reports cleanly before docker is killed.
	runCtx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	// A grant mounts the same per-run broker socket the snippet path uses; the runner
	// preloads hostSDKModule(grant) into every step so project files reach host.* over
	// the shared brokerSession. Nil grant → nil broker, no socket, empty HostSDK.
	broker, capArgs, err := d.brokerForRun(runCtx, req.Grant, timeout)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	defer broker.Close()

	plan := struct {
		Files []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"files"`
		Steps         []string `json:"steps"`
		StepTimeoutMs int64    `json:"stepTimeoutMs"`
		Artifacts     []string `json:"artifacts"`
		HostSDK       string   `json:"hostSDK,omitempty"`
	}{Steps: req.Steps, StepTimeoutMs: timeout.Milliseconds(), Artifacts: req.Artifacts, HostSDK: hostSDKModule(req.Grant)}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}{Path: f.Path, Content: f.Content})
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return ProjectResult{Sandbox: d.Name()}, err
	}

	name := "crsbx-" + randID()

	// ProjectImage's entrypoint is `node /runner.mjs`; the plan arrives on stdin.
	// Launch the Preflight-verified content ID, not the mutable tag. capArgs (the
	// broker socket bind + HOST_API_SOCKET) are docker options, so they precede the
	// image; they are empty for a no-grant run.
	args := d.lockdownArgs(name, true, execState.runtime)
	args = append(args, capArgs...)
	args = append(args, imageID)
	args, err = dockerArgs(execState.host, args...)
	if err != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, err
	}
	cmd := exec.CommandContext(runCtx, "docker", args...)
	cmd.Stdin = bytes.NewReader(planJSON)
	var stdout, stderr cappedBuffer
	stdout.limit = projectStdoutCap
	stderr.limit = d.maxOutput()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runCtx.Err() != nil {
		d.forceRemove(execState.host, name)
	}

	if runCtx.Err() == context.DeadlineExceeded {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeTimedOut, Detail: "run exceeded the time budget"}, nil
	}
	if runCtx.Err() != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation}, runCtx.Err()
	}

	report, found, parseErr := parseRunnerOutput(stdout.String())
	if !found {
		// The runner never reported. Distinguish two very different causes:
		//   - docker itself could not START the container (125/126/127 with a
		//     docker/OCI diagnostic): the sandbox boundary never launched. That is an
		//     INFRASTRUCTURE error (a returned error → CodeInternal at the RPC edge),
		//     not a typed run outcome.
		//   - otherwise the boundary launched but the runner vanished (e.g. OOM-killed
		//     inside the sandbox): execution state unknown → ProtocolError, with
		//     stderr as the best available diagnostic.
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && dockerInfraExit(exitErr.ExitCode(), stderr.String()) {
			return ProjectResult{Sandbox: d.Name(), Isolation: isolation},
				fmt.Errorf("docker failed to run the project container (exit %d): %s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && runErr != nil {
			msg = runErr.Error()
		}
		if msg == "" {
			msg = "sandbox produced no result"
		}
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeProtocolError, Detail: msg}, nil
	}
	if parseErr != nil {
		return ProjectResult{Sandbox: d.Name(), Isolation: isolation, Outcome: ProjectOutcomeProtocolError, Detail: "could not parse sandbox result"}, nil
	}

	res := ProjectResult{
		Sandbox:            d.Name(),
		Isolation:          isolation,
		Outcome:            ProjectOutcomeCompleted,
		Steps:              report.Steps,
		Artifacts:          report.Artifacts,
		ArtifactsTruncated: report.ArtifactsTruncated,
		// Metadata-only evidence of the run's brokered host.* calls; nil unless the
		// run carried a grant that made calls. Never affects the outcome above.
		CallTrace: broker.traceSnapshot(),
	}
	if report.Err != "" {
		// The runner reported a structured failure around step execution (illegal
		// file path, unwritable file, over-budget result): request-attributable.
		res.Outcome, res.Detail = ProjectOutcomeSetupFailed, report.Err
	}
	return res, nil
}

// SupportsModules reports whether a module image is configured; RunModule
// returns ErrUnsupported otherwise.
func (d *DockerSandbox) SupportsModules() bool { return d.ModuleImage != "" }

// moduleResultsArtifact is the path, under /work, the worker writes its record to
// and the run captures as its one artifact.
const moduleResultsArtifact = "results.bin"

// RunModule runs a model baked into ModuleImage once per row through the same
// runner and lockdown as a project: the parameter table is written into /work as
// text (shortest round-trip decimals, so every value reaches the worker exactly),
// one step runs the worker in table mode with the result budget on its command
// line, and the results come back as one artifact decoded here. The worker
// refuses a table whose results could exceed the budget before it runs a row
// (ValidateModuleRequest applied the width-1 necessary condition already), so
// results are never truncated: that refusal is ErrInvalidRequest, and a worker
// that accepted the table and still overran the artifact budget is a protocol
// error, never a shorter answer.
func (d *DockerSandbox) RunModule(ctx context.Context, req ModuleRequest) (ModuleResult, error) {
	if err := ValidateModuleRequest(req); err != nil {
		return ModuleResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	if d.ModuleImage == "" {
		return ModuleResult{Sandbox: d.Name(), Isolation: d.IsolationClass()},
			fmt.Errorf("%w: no module image is configured (SANDBOX_DOCKER_MODULE_IMAGE)", ErrUnsupported)
	}
	if err := d.ensurePreflight(ctx); err != nil {
		return ModuleResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	execState, err := d.executionState()
	if err != nil {
		return ModuleResult{Sandbox: d.Name(), Isolation: d.IsolationClass()}, err
	}
	isolation := execState.isolation
	if err := CheckMinimumIsolation(isolation, req.MinimumIsolation); err != nil {
		return ModuleResult{Sandbox: d.Name(), Isolation: isolation}, err
	}

	var table strings.Builder
	for _, row := range req.Rows {
		for j, v := range row {
			if j > 0 {
				table.WriteByte(' ')
			}
			table.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
		}
		table.WriteByte('\n')
	}
	step := fmt.Sprintf("sim-worker --table /models/%s.so params.txt %s %s %s %d",
		req.Model, moduleResultsArtifact,
		strconv.FormatFloat(req.EndTime, 'g', -1, 64), strconv.FormatFloat(req.Step, 'g', -1, 64),
		MaxModuleResultBytes)
	started := time.Now()
	pr, err := d.runPlan(ctx, execState, execState.moduleImageID, ProjectRequest{
		Files:     []File{{Path: "params.txt", Content: table.String()}},
		Steps:     []string{step},
		Timeout:   req.Timeout,
		Artifacts: []string{moduleResultsArtifact},
	})
	res := ModuleResult{Sandbox: d.Name(), Isolation: isolation, Duration: time.Since(started)}
	if err != nil {
		return res, err
	}
	return interpretModuleRun(res, pr, req)
}

// interpretModuleRun turns the runner's report of the one worker step into a
// ModuleResult. The worker's exit codes are its contract (docker/sim/worker.c):
// 0 done; 1 the module failed to load or validate; 2 usage; 3 the table was
// malformed; 4 the results could exceed the byte budget, refused before any row
// ran; 5 the output was unwritable. 1 to 3 are request-attributable, so
// setup_failed with the worker's diagnostic; 4 is ErrInvalidRequest; anything
// else, including a signal, is a protocol error.
func interpretModuleRun(res ModuleResult, pr ProjectResult, req ModuleRequest) (ModuleResult, error) {
	res.Outcome, res.Detail = pr.Outcome, pr.Detail
	if pr.Outcome != ProjectOutcomeCompleted {
		return res, nil
	}
	if len(pr.Steps) != 1 {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, fmt.Sprintf("runner reported %d steps for the one worker step", len(pr.Steps))
		return res, nil
	}
	st := pr.Steps[0]
	res.Stdout, res.Stderr = st.Stdout, st.Stderr
	diag := strings.TrimSpace(st.Stderr)
	if st.TimedOut {
		res.Outcome, res.Detail = ProjectOutcomeTimedOut, "the worker exceeded the time budget"
		return res, nil
	}
	switch st.ExitCode {
	case 0:
	case 4:
		return res, fmt.Errorf("%w: %s", ErrInvalidRequest, diag)
	case 1, 2, 3:
		res.Outcome, res.Detail = ProjectOutcomeSetupFailed, "the worker refused the request: "+diag
		return res, nil
	default:
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, fmt.Sprintf("the worker exited %d: %s", st.ExitCode, diag)
		return res, nil
	}
	if pr.ArtifactsTruncated {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "the worker accepted the table but its results exceeded the artifact budget"
		return res, nil
	}
	var rec []byte
	found := false
	for _, a := range pr.Artifacts {
		if a.Path == moduleResultsArtifact {
			rec, found = a.Content, true
		}
	}
	if !found {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "the worker exited 0 without writing its results"
		return res, nil
	}
	runs, width, err := DecodeModuleResults(rec, len(req.Rows), req.RowWidth())
	if err != nil {
		res.Outcome, res.Detail = ProjectOutcomeProtocolError, "undecodable worker results: "+err.Error()
		return res, nil
	}
	res.Runs, res.Width = runs, width
	return res, nil
}

// forceRemove is the hard teardown after the docker CLI is killed by a context.
// Killing `docker run` does not guarantee the container stops, so retry and log
// instead of silently leaving hostile code alive indefinitely.
func (d *DockerSandbox) forceRemove(host, name string) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		args, argErr := dockerArgs(host, "rm", "-f", name)
		if argErr != nil {
			cancel()
			slog.Error("docker: cannot force-remove container without a pinned daemon endpoint", "container", name, "error", argErr)
			return
		}
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		cancel()
		if err == nil {
			return
		}
		missing := strings.Contains(string(out), "No such container")
		if missing && attempt == 3 {
			return
		}
		lastErr = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	slog.Error("docker: failed to force-remove timed-out sandbox container",
		"container", name, "attempts", 3, "error", lastErr)
}

// cappedBuffer collects up to limit bytes and silently drops the rest, so a
// runaway program cannot exhaust memory through its output. Truncation is
// reported out-of-band via Truncated — the retained prefix is never annotated
// with an in-band marker, so consumers see exactly the bytes the guest wrote.
type cappedBuffer struct {
	buf     bytes.Buffer
	limit   int
	dropped bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.limit - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
			c.dropped = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.dropped = true
	}
	// Always report the full length written so the pipe is not blocked.
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// Truncated reports whether the cap dropped any bytes.
func (c *cappedBuffer) Truncated() bool { return c.dropped }
