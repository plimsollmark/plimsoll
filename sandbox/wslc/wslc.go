// Package wslc runs plimsoll snippets and projects in WSL containers (WSLC), the
// container runtime Microsoft ships inside WSL on Windows, by starting wslc.exe through
// WSL interop from a plimsolld running in a WSL distribution. Design, the facts read
// from Microsoft's published source and the checks only a Windows machine can make (the
// startup smoke test and the live tests). Operator guide: docs/wslc.md.
//
// What the wall is. A WSLC session is one Hyper-V virtual machine running one rootful
// dockerd. The CLI's default session is one per Windows user and per elevation
// (wslc-cli-<user>, or wslc-cli-admin-<user> for an elevated caller), and named sessions
// can exist beside it. The provider has two modes (SANDBOX_WSLC_MODE):
//
//   - shared (chosen by setting SANDBOX_WSLC_MODE=shared): every run is a container in the default session, under runc
//     in that VM, beside the others: they share its Linux kernel, its dockerd and its
//     storage disk. The tier is container, never vm and never kernel, and it is weaker
//     than the docker provider under runc, because WSLC cannot apply five of the controls
//     that provider applies (Absent lists them: no read-only root, no seccomp choice and
//     no no-new-privileges, no process limit, no user namespaces). The smoke test records
//     which session it landed in.
//   - per-run (the default): every run gets a session of its own (perrun.go): a fresh VM booted from a
//     fresh copy of a template disk this provider builds itself (template.go), deleted
//     after the run. The VM wall is Hyper-V's, the controls Absent lists are still absent
//     inside it, and the Windows components around it run with the user's rights. The tier
//     is container, stated with PerRunQualification, unless the operator sets
//     SANDBOX_WSLC_ACCEPT_VM_TIER=1 (Config.AcceptVMTier); then it is vm, stated with
//     PerRunAcceptedQualification.
//
// Microsoft states that WSL is not a security sandbox for running untrusted code (wsl.dev,
// security model). That is why the per-run mode reports container by default: every floor
// (a request's minimum, SANDBOX_MIN_ISOLATION, placement across daemons) compares against
// the tier reported here, so a vm or kernel floor refuses this provider unless its operator
// has accepted that statement. Hardened mode refuses this provider in both modes.
//
// What the provider does about it. Every run starts with every control WSLC has (runArgv),
// every argument is a fixed flag or a checked ID (exec.go), the runner's plan travels over
// stdin, and the startup smoke test runs a probe through the same path and refuses to
// serve unless the container it got is the one argued for: loopback the only network
// interface, only the promised tmpfs mounts writable anywhere in the filesystem (a real
// write at every mount point and every writable-looking directory), no capability, the
// guest uid, the memory limit, the ulimits, a seccomp filter in force, no Windows folder
// mounted, no GPU device, and the session VM's boot ID. In the per-run mode it runs the
// probe in two fresh sessions and requires two boot IDs never seen before. The tier stated
// is configuration and provider evidence plus that startup smoke test, never runtime
// attestation.
//
// Not supported: host-API grants (with no network, a container has no path to the
// broker), plimsoll sessions, module runs.
package wslc

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

// Name is the SANDBOX_PROVIDER value.
const Name = "wslc"

// DefaultPath is where the WSL package installs wslc.exe, as a WSL distribution sees it.
const DefaultPath = "/mnt/c/Program Files/WSL/wslc.exe"

// MinVersion is the oldest WSL package this provider runs on: 3.0.5 is the first release
// whose wslc has --cap-drop (microsoft/WSL pull request 41681, released 2026-11-03).
const MinVersion = "3.0.5"

// GuestUID is the uid and gid every process in a container runs as: the docker
// provider's default, a uid no account in the image or the session VM uses, so it owns
// nothing in the image (the image's own user, node, is uid 1000).
const GuestUID = 61000

// Absent names the controls the docker provider applies that WSLC cannot, each in plain
// words. The startup log, -h and docs/wslc.md state them. Describe has no field for them:
// one would be a change to the public protocol, which this provider does not make.
var Absent = []string{
	"read-only root filesystem (no --read-only): approximated by a non-root uid with no capability in a root-owned image, and the smoke test proves no place outside the tmpfs mounts accepts a write",
	"seccomp profile choice and no-new-privileges (no --security-opt): the smoke test refuses to serve unless dockerd's default seccomp filter is in force, and reports NoNewPrivs as read",
	"process limit (no --pids-limit): only --ulimit nproc, which counts every process of the guest uid in the session VM; the shared mode therefore runs one run at a time, so no run can use up the count for another",
	"user namespaces (no userns-remap): container uid 0 would be the session VM's uid 0; every run is non-root with every capability dropped",
	"log driver choice (no --log-driver): a run's output also goes to dockerd's log in the session VM until the container is removed",
	"init process (no --init in wslc container run): the runner is process 1 in the container",
}

// Mode is how runs map to WSLC sessions (SANDBOX_WSLC_MODE).
type Mode string

const (
	// ModeShared runs every run as a container in the default session (tier container).
	ModeShared Mode = "shared"
	// ModePerRun gives every run a session, a VM, of its own (tier container, or vm with
	// Config.AcceptVMTier).
	ModePerRun Mode = "per-run"
)

// Config is the provider's configuration. Zero sizes and timeouts take the defaults.
type Config struct {
	// Mode is per-run when empty.
	Mode Mode
	// Path is wslc.exe as this distribution sees it (DefaultPath when empty).
	Path string
	// Image is the image every run starts: plimsoll's sandbox image or one built FROM it
	// (node for snippets, and the project runner, the native helper, at its usual path,
	// root's and the bytes this plimsolld carries: the smoke test refuses any other).
	Image string
	// RequirePinnedImage refuses an Image that is not name@sha256:digest, and an image
	// whose inspected RepoDigests do not include that digest.
	RequirePinnedImage bool
	// MemoryMB and CPUs are each container's limits (--memory, --cpus).
	MemoryMB int
	CPUs     float64
	// DiskMB is the sum of the four tmpfs mounts; /work takes what /tmp, /var/tmp and
	// /dev/shm (16 MiB each) leave.
	DiskMB int
	// Nproc is --ulimit nproc: the most processes the guest uid may have in the session
	// VM at once (the shared mode runs one run at a time, so that is one run's).
	Nproc int
	// DefaultTimeout and MaxTimeout bound a run's own budget; StartAllowance is the time
	// on top of it for wslc to start the container, which on a cold session includes
	// booting the VM (WSLC's own boot timeout is 30 s).
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	StartAllowance time.Duration

	// The per-run mode only.
	//
	// MaxSessions is the most runs in sessions of their own at once (default 2): each live
	// session held about 0.9 GB of Windows memory when measured on a real WSLC session, and four at once took
	// Windows' free memory from 6.2 to 3.7 GB on a 31 GiB laptop.
	MaxSessions int
	// RunRoot is the directory, on a Windows drive, for the template and the run disks, as
	// this distribution mounts it; empty is the Windows user's local application data
	// folder plus plimsoll-wslc. Only names this provider creates are ever deleted in it.
	RunRoot string
	// PowerShell and Mkfs are powershell.exe and mkfs.ext4 as this distribution sees
	// them (DefaultPowerShell and /usr/sbin/mkfs.ext4 when empty).
	PowerShell string
	Mkfs       string

	// GVisor makes gVisor's runsc the runtime inside every run's session VM (per-run mode
	// only; gvisor.go). RunscPath is the runsc binary as this distribution sees it and
	// RunscSHA512 its digest (both required with GVisor, and checked at startup);
	// RunscHelpers names the files runsc needs from gvisor-bin/ beside it, each with its
	// digest. Nothing is downloaded: the operator supplies the files.
	GVisor       bool
	RunscPath    string
	RunscSHA512  string
	RunscHelpers map[string]string

	// AcceptVMTier (SANDBOX_WSLC_ACCEPT_VM_TIER=1, per-run mode only; FromEnv refuses the
	// variable in the shared mode whatever its value) is the operator
	// accepting Microsoft's statement that WSL is not a security sandbox for running
	// untrusted code, for this daemon: the per-run mode then reports vm, stated with
	// PerRunAcceptedQualification, and a vm or kernel floor admits it. Off, the per-run
	// mode reports container, and such a floor refuses it before anything starts. gVisor
	// inside the VMs does not change the tier either way.
	AcceptVMTier bool
}

const (
	defaultMemoryMB       = 512
	defaultCPUs           = 1.0
	defaultNproc          = 256
	smallTmpfsMB          = 16
	defaultWorkMB         = 128
	defaultTimeout        = 30 * time.Second
	defaultMaxTimeout     = 120 * time.Second
	defaultStartAllowance = 60 * time.Second
	nofileLimit           = 4096
	maxNproc              = 65536
	defaultMaxSessions    = 2
	maxMaxSessions        = 16
	defaultMkfs           = "/usr/sbin/mkfs.ext4"
)

func (c *Config) withDefaults() {
	if c.Mode == "" {
		c.Mode = ModePerRun
	}
	if c.Path == "" {
		c.Path = DefaultPath
	}
	if c.MaxSessions == 0 && c.Mode == ModePerRun {
		c.MaxSessions = defaultMaxSessions
	}
	if c.PowerShell == "" {
		c.PowerShell = DefaultPowerShell
	}
	if c.Mkfs == "" {
		c.Mkfs = defaultMkfs
	}
	if c.MemoryMB == 0 {
		c.MemoryMB = defaultMemoryMB
	}
	if c.CPUs == 0 {
		c.CPUs = defaultCPUs
	}
	if c.Nproc == 0 {
		c.Nproc = defaultNproc
	}
	if c.DefaultTimeout == 0 {
		c.DefaultTimeout = defaultTimeout
	}
	if c.MaxTimeout == 0 {
		c.MaxTimeout = defaultMaxTimeout
	}
	if c.StartAllowance == 0 {
		c.StartAllowance = defaultStartAllowance
	}
}

// workMB is /work's size.
func (c Config) workMB() int {
	if c.DiskMB > 0 {
		return c.DiskMB - 3*smallTmpfsMB
	}
	return defaultWorkMB
}

// acceptVMTierPerRunOnly is the refusal of SANDBOX_WSLC_ACCEPT_VM_TIER in the shared mode:
// FromEnv's for any value of the variable there, validate's for AcceptVMTier.
const acceptVMTierPerRunOnly = "SANDBOX_WSLC_ACCEPT_VM_TIER applies to SANDBOX_WSLC_MODE=per-run only: the shared mode has no VM of its own to accept"

func (c Config) validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if !strings.HasPrefix(c.Path, "/") {
		add("SANDBOX_WSLC_PATH must be an absolute path (got %q)", c.Path)
	}
	switch c.Mode {
	case ModeShared:
		if c.MaxSessions != 0 || c.RunRoot != "" {
			add("SANDBOX_WSLC_MAX_SESSIONS and SANDBOX_WSLC_RUN_ROOT apply to SANDBOX_WSLC_MODE=per-run only")
		}
		if c.GVisor || c.RunscPath != "" || c.RunscSHA512 != "" || len(c.RunscHelpers) > 0 {
			add("SANDBOX_WSLC_GVISOR and SANDBOX_WSLC_RUNSC_* apply to SANDBOX_WSLC_MODE=per-run only: the shared mode runs in the caller's own default session, whose docker settings this provider never rewrites")
		}
		if c.AcceptVMTier {
			add("%s", acceptVMTierPerRunOnly)
		}
	case ModePerRun:
		if c.MaxSessions < 1 || c.MaxSessions > maxMaxSessions {
			add("SANDBOX_WSLC_MAX_SESSIONS must be between 1 and %d (got %d)", maxMaxSessions, c.MaxSessions)
		}
		if c.RunRoot != "" && (!strings.HasPrefix(c.RunRoot, "/") || path.Clean(c.RunRoot) != c.RunRoot) {
			add("SANDBOX_WSLC_RUN_ROOT must be a clean absolute path (got %q)", c.RunRoot)
		}
		for _, prog := range []string{c.PowerShell, c.Mkfs} {
			if !strings.HasPrefix(prog, "/") {
				add("the per-run mode's programs must be absolute paths (got %q)", prog)
			}
		}
		c.validateGVisor(add)
	default:
		add("SANDBOX_WSLC_MODE must be %s or %s (got %q)", ModeShared, ModePerRun, c.Mode)
	}
	switch {
	case c.Image == "":
		add("SANDBOX_WSLC_IMAGE is required: the image every run starts (plimsoll's sandbox image, or one built FROM it)")
	case !safeArg.MatchString(c.Image) || strings.HasPrefix(c.Image, "-"):
		add("SANDBOX_WSLC_IMAGE %q is not a plain image reference (letters, digits and . _ : / @ - only, not starting with -)", c.Image)
	case c.RequirePinnedImage && !pinned(c.Image):
		add("SANDBOX_REQUIRE_PINNED_IMAGES=1 needs SANDBOX_WSLC_IMAGE as %s", providerkit.PinForm)
	}
	if c.MemoryMB < 64 {
		add("SANDBOX_MEMORY_MB must be at least 64 for wslc (got %d)", c.MemoryMB)
	}
	if c.CPUs <= 0 || c.CPUs > 64 {
		add("SANDBOX_CPUS must be above 0 and at most 64 for wslc (got %v)", c.CPUs)
	}
	if c.DiskMB != 0 && c.workMB() < 16 {
		add("SANDBOX_DISK_MB must leave /work at least 16 MiB after /tmp, /var/tmp and /dev/shm (%d MiB each): at least %d", smallTmpfsMB, 3*smallTmpfsMB+16)
	}
	if c.Nproc < 16 || c.Nproc > maxNproc {
		add("SANDBOX_WSLC_NPROC must be between 16 and %d (got %d)", maxNproc, c.Nproc)
	}
	if c.DefaultTimeout <= 0 || c.MaxTimeout < c.DefaultTimeout || c.StartAllowance <= 0 {
		add("the wslc timeouts are inconsistent (default %v, max %v, start allowance %v)", c.DefaultTimeout, c.MaxTimeout, c.StartAllowance)
	}
	if len(problems) > 0 {
		return fmt.Errorf("wslc: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Provider is the WSL containers sandbox.
type Provider struct {
	cfg Config

	mu sync.RWMutex
	// state is what the last successful smoke test proved; nil until then, and every run
	// is refused (not dispatched) while it is nil.
	state *verified
	// removeTries and removePause bound the forced removal after a run that did not end
	// cleanly (tests shorten the pause).
	removeTries int
	removePause time.Duration

	// pr is the per-run mode's state; nil in the shared mode.
	pr *perRunState
	// turn is the shared mode's one place: --ulimit nproc counts the guest uid's processes
	// across the whole session VM, so one run could use up the count for the others, and
	// the shared mode therefore runs one run at a time. nil in the
	// per-run mode, where every run has a VM of its own.
	turn chan struct{}
	// drives maps a Windows drive letter to its mount here (from /proc/self/mountinfo).
	drives map[string]string
	// listTimeout, listPoll and teardownTimeout bound a session's listing and its polite
	// end (tests shorten them).
	listTimeout     time.Duration
	listPoll        time.Duration
	teardownTimeout time.Duration
}

// verified is the execution state the smoke test proved: the image every run starts,
// by the ID wslc reported, and the evidence read.
type verified struct {
	imageID  string
	imageEnv []string
	evidence Evidence
}

// New checks the configuration and builds the provider. It starts nothing: Preflight
// and SmokeTest do.
func New(cfg Config) (*Provider, error) {
	cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg, removeTries: 3, removePause: 500 * time.Millisecond,
		// WSLC's own boot timeout is 30 s; a measurement on a real WSLC session saw a name listed 0.05 to 0.18 s
		// after `enter` started, and 60 s is that measurement's limit for a polite end.
		listTimeout: 30 * time.Second, listPoll: 100 * time.Millisecond, teardownTimeout: 60 * time.Second}
	if cfg.Mode == ModeShared {
		p.turn = make(chan struct{}, 1)
	}
	if cfg.Mode == ModePerRun {
		p.pr = &perRunState{live: map[string]*holder{}, seen: map[string]struct{}{}, alive: make(chan struct{}, cfg.MaxSessions)}
	}
	return p, nil
}

func (*Provider) Name() string { return Name }

// IsolationClass is vm in the per-run mode when the operator has accepted Microsoft's
// statement (Config.AcceptVMTier), and container otherwise: in the per-run mode without
// it, and always in the shared mode. Every floor compares against this one value, so
// nothing else needs to know the setting.
func (p *Provider) IsolationClass() sandbox.IsolationClass {
	if p.cfg.Mode == ModePerRun && p.cfg.AcceptVMTier {
		return sandbox.IsolationVM
	}
	return sandbox.IsolationContainer
}

// Mode is the configured mode.
func (p *Provider) Mode() Mode                   { return p.cfg.Mode }
func (*Provider) SupportsProjects() bool         { return true }
func (*Provider) SupportsModules() bool          { return false }
func (*Provider) SupportsJavaScriptGrants() bool { return false }
func (*Provider) SupportsProjectGrants() bool    { return false }

// Environments states the image ID the smoke test read, the ceiling, and the language it
// proved. The selected manifest is not established (wslc reports the image's ID and its
// repository digests, not the platform manifest a run used), so SoftwareIdentity is empty
// and a caller's software rule fails closed.
func (p *Provider) Environments() sandbox.Environments {
	env := sandbox.Environments{
		JavaScript: sandbox.PayloadEnvironment{MaxTimeout: p.cfg.MaxTimeout},
		Project:    sandbox.PayloadEnvironment{MaxTimeout: p.cfg.MaxTimeout},
	}
	if s := p.current(); s != nil {
		env.JavaScript.Identity = imageIdentity(s.imageID)
		env.Project.Identity = imageIdentity(s.imageID)
		env.Project.Languages = []sandbox.Language{sandbox.LanguageJavaScript}
	}
	return env
}

func imageIdentity(id string) string { return "wslc-image:" + id }

// Evidence returns what the last successful smoke test read, and false before one.
func (p *Provider) Evidence() (Evidence, bool) {
	if s := p.current(); s != nil {
		return s.evidence, true
	}
	return Evidence{}, false
}

func (p *Provider) current() *verified {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// RunModule is unsupported: no simulator worker image is built for WSLC.
func (*Provider) RunModule(context.Context, sandbox.ModuleRequest) (sandbox.ModuleResult, error) {
	return sandbox.ModuleResult{}, sandbox.NotDispatched(sandbox.RefusalUnsupported,
		fmt.Errorf("%w: module runs are not built for wslc", sandbox.ErrUnsupported))
}

// admit is every check before a run dispatches: the request's floor, its software rule,
// no grant, and a smoke test that has passed. Each refusal ran nothing.
func (p *Provider) admit(floor sandbox.IsolationClass, rule sandbox.SoftwareRule, grant *sandbox.HostAPIGrant) (*verified, error) {
	if err := sandbox.CheckMinimumIsolation(p.IsolationClass(), floor); err != nil {
		if errors.Is(err, sandbox.ErrInsufficientIsolation) && p.cfg.Mode == ModePerRun && !p.cfg.AcceptVMTier {
			// The floor is above container: say which setting would meet it, keeping the
			// mark and the sentinel.
			err = fmt.Errorf("%w; the wslc per-run mode counts as container against a floor unless the operator sets SANDBOX_WSLC_ACCEPT_VM_TIER=1", err)
		}
		return nil, err
	}
	if err := rule.Check(""); err != nil {
		return nil, err
	}
	if grant != nil {
		return nil, sandbox.NotDispatched(sandbox.RefusalUnsupported,
			fmt.Errorf("%w: host-API grants are not built for wslc (a container with no network has no path to the broker)", sandbox.ErrUnsupported))
	}
	s := p.current()
	if s == nil {
		return nil, sandbox.NotDispatched(sandbox.RefusalEnvironment, errors.New("wslc: the startup smoke test has not passed"))
	}
	return s, nil
}

func (p *Provider) clamp(req time.Duration) time.Duration {
	return providerkit.ClampTimeout(req, p.cfg.DefaultTimeout, p.cfg.MaxTimeout)
}

// cpusArg is --cpus's value: the shortest decimal that reads back as CPUs.
func cpusArg(cpus float64) string { return strconv.FormatFloat(cpus, 'f', -1, 64) }

// pinned reports whether an image reference is pinned by a digest (providerkit.PinnedDigest).
func pinned(image string) bool {
	_, ok := providerkit.PinnedDigest(image)
	return ok
}
