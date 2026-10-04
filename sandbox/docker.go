package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
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
	// (docker/sim.Dockerfile): the supervised worker plus the AOT-compiled simulators
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

	// GuestUID is the uid (and gid) every sandbox process runs as; its identity check
	// runs as GuestUID + 1. 0 = defaultGuestUID. Preflight refuses one this host's
	// /etc/passwd or /etc/group names.
	GuestUID int

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
	// verifiedGuestUID is the guest uid the last Preflight checked; a different one
	// is not ready until Preflight runs again.
	verifiedGuestUID int
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
	// verifiedImageEnvs are those images' environments, as their configs declare them
	// for the platform a run selects: what guest processes start with (guestArgv).
	verifiedImageEnvs map[string][]string
	// verifiedManifestIDs are the platform manifests selected from each verified
	// outer image index. An empty value means this Docker store did not expose a
	// verifiable manifest descriptor.
	verifiedManifestIDs map[string]string
	verifiedPlatform    string
	lastVerified        time.Time
	// provenImageIDs are the image IDs the last successful SmokeTest probed, by
	// reference; nil until one has run. Runs launch only these once it has: a tag
	// re-pointed after startup names content whose lockdown, runner guard and
	// languages nobody proved (review F1).
	provenImageIDs map[string]string
	preflightNow   func() time.Time // test clock; nil uses time.Now
	preflightWait  time.Duration    // bounded wait on preflight contention; 0 uses the default

	// projectLanguages are the interpreters the project image ran in SmokeTest.
	projectLanguages []Language
	// sessions are the open sessions, the opens in flight and the container removals
	// still running (docker_session.go).
	sessions sessionkit.Registry
	// pool is the session pool, when StartSessionPool started one (docker_pool.go).
	pool atomic.Pointer[dockerPool]
}

const (
	dockerDefaultTimeout     = 5 * time.Second
	dockerMaxTimeout         = 30 * time.Second
	dockerProjectTimeout     = 30 * time.Second
	dockerMaxProjectTime     = 120 * time.Second
	dockerDefaultOutputBytes = 64 << 10
	dockerPreflightTimeout   = 10 * time.Second
	dockerPreflightCacheTTL  = 5 * time.Second

	// dockerPreflightWaitDefault bounds how long a caller that loses the preflight
	// race waits for the in-flight probe to publish its result. A probe is a few
	// docker CLI calls, so this covers the normal case comfortably while keeping
	// the worst case bounded for latency-sensitive callers like readiness polls.
	dockerPreflightWaitDefault = 2 * time.Second
	dockerPreflightPoll        = 20 * time.Millisecond
)

// snippetCeiling and projectCeiling are the longest a snippet or project run may
// take; the timeout functions cut a request to them and Environments states them.
func (d *DockerSandbox) snippetCeiling() time.Duration {
	if d.MaxTimeout > 0 {
		return d.MaxTimeout
	}
	return dockerMaxTimeout
}

func (d *DockerSandbox) projectCeiling() time.Duration {
	if d.MaxProjectTime > 0 {
		return d.MaxProjectTime
	}
	return dockerMaxProjectTime
}

func (d *DockerSandbox) snippetTimeout(requested time.Duration) time.Duration {
	def, max := d.DefaultTimeout, d.snippetCeiling()
	if def <= 0 {
		def = dockerDefaultTimeout
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
	def, max := d.ProjectTimeout, d.projectCeiling()
	if def <= 0 {
		def = dockerProjectTimeout
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
func (d *DockerSandbox) lockdownArgs(name string, expires time.Time, workTmpfs bool, runtime string) []string {
	args := []string{
		"run", "--rm", "-i",
		"--name", name,
		// Attached stdout/stderr still stream back to this process, but the daemon
		// must not duplicate hostile output into an unbounded json-file on the host.
		"--log-driver", "none",
	}
	// The container's lifetime, so ReconcileOrphans reaps it if it outlives its CLI
	// and every removal attempt (review F2).
	args = append(args, expiresLabelArgs(expires)...)
	return append(args, d.lockdownFlags(workTmpfs, runtime)...)
}

// launch is the tail of a docker run that starts argv in imageID, whatever the
// image's ENTRYPOINT and CMD say: every process plimsoll starts is one it chose.
func launch(imageID string, argv []string) []string {
	return append([]string{"--entrypoint", argv[0], imageID}, argv[1:]...)
}

// containerExpiry is when a container started under ctx may be reaped
// (dockerExpiresLabel): ctx's deadline, which ends what runs in it. Every caller's
// context has one; without one, the longest a project run may take from now.
func (d *DockerSandbox) containerExpiry(ctx context.Context) time.Time {
	if t, ok := ctx.Deadline(); ok {
		return t
	}
	return time.Now().Add(d.projectCeiling())
}

// lockdownFlags are the flags that confine a container, shared by a run's container
// and a session's.
func (d *DockerSandbox) lockdownFlags(workTmpfs bool, runtime string) []string {
	var args []string
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
		"--user", d.guestUser(),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		// Limits the run states rather than inherits from the docker daemon: no core
		// files (a crashing guest would otherwise run the host's core_pattern
		// handler), 4096 descriptors (well above what a build or test step holds open
		// at once, against the daemon's default that is often 1048576), and an IPC
		// namespace of its own, said explicitly.
		"--ulimit", "core=0",
		"--ulimit", "nofile=4096:4096",
		"--ipc", "private",
		// WARNING: an image's HEALTHCHECK makes dockerd run the image's command inside
		// this container on an interval, as the sandbox user, with the image's
		// environment: a process plimsoll did not start, beside guest code (measured
		// 2026-10-02: a 1-second check ran in a lockdown container until this flag).
		"--no-healthcheck",
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

// guestUID is the uid every sandbox process runs as.
func (d *DockerSandbox) guestUID() int {
	if d.GuestUID == 0 {
		return defaultGuestUID
	}
	return d.GuestUID
}

// guestUser is guestUID as docker's --user value, the group the same number.
func (d *DockerSandbox) guestUser() string {
	u := strconv.Itoa(d.guestUID())
	return u + ":" + u
}

// checkerUser is the user a session's identity check runs as: not the guest's, so no
// process of the session can open the check's stdout or signal it, and with no
// capabilities it can read every process's stat and command line and nothing more
// (measured under runc and gVisor, 2026-10-01).
func (d *DockerSandbox) checkerUser() string {
	u := strconv.Itoa(d.guestUID() + 1)
	return u + ":" + u
}

// validateGuestUID refuses a guest uid outside 1 to maxGuestUID (never root; the guest
// and its identity check below nobody and inside a default user-namespace mapping), and
// one whose uid or uid + 1 is in a band systemd allocates through its own account
// lookup, never in /etc/passwd, so checkGuestUIDUnused could not see a holder: homed
// users (60001 to 60513), greeter users (60578 to 60705) and dynamic service users
// (61184 to 65519; systemd.io/UIDS-GIDS).
func validateGuestUID(uid int) error {
	if uid < 1 || uid > maxGuestUID {
		return fmt.Errorf("SANDBOX_GUEST_UID %d is outside 1 to %d: never root, and it and the identity check's uid (one more) must stay below nobody (65534) and inside a user-namespace mapping of 65,536 uids", uid, maxGuestUID)
	}
	for _, band := range [][2]int{{60001, 60513}, {60578, 60705}, {61184, 65519}} {
		for _, id := range []int{uid, uid + 1} {
			if id >= band[0] && id <= band[1] {
				return fmt.Errorf("SANDBOX_GUEST_UID %d: %d is in %d to %d, a band systemd gives to accounts it never writes to /etc/passwd, so a holder could not be ruled out", uid, id, band[0], band[1])
			}
		}
	}
	return nil
}

func dockerArgs(host string, args ...string) ([]string, error) {
	if host == "" {
		return nil, errors.New("docker daemon endpoint is not verified")
	}
	return append([]string{"--host", host}, args...), nil
}

// randID returns a short random hex string for a unique container name.
func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SupportsModules reports whether a module image is configured; RunModule
// returns ErrUnsupported otherwise.
func (d *DockerSandbox) SupportsModules() bool { return d.ModuleImage != "" }

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
