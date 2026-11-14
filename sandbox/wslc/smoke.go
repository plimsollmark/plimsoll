package wslc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// Evidence is what the startup smoke test read: the software it ran on and the
// container it got. It is reported at startup and kept for Describe's environments; it is
// configuration and provider evidence plus the smoke test, never runtime attestation.
type Evidence struct {
	WSLVersion  string   // wslc version, e.g. 3.0.5.0
	ImageID     string   // the ID every run starts
	RepoDigests []string // the image's repository digests, as wslc reported them
	// Read in the session VM through `wslc system session run`.
	KernelRelease string
	BootID        string
	Moby          string // dockerd --version, first line
	// Read inside the probe container, as the guest uid.
	Seccomp        string // /proc/self/status Seccomp: 2 is a filter in force
	SeccompFilters string
	NoNewPrivs     string // 0: WSLC cannot set no-new-privileges
	CapBnd         string
	PidsMax        string // the container cgroup's pids.max; "max" is no limit
	NprocLimit     int    // RLIMIT_NPROC, per uid across the session VM
	MemoryMax      int64
	Writable       []string // places that accepted a real write: the tmpfs mounts alone
	WalkedEntries  int
	Unlistable     int // directories the guest uid cannot list, so the walk could not enter
	ReadAt         time.Time

	Mode Mode
	// The GPU device, which sessions the CLI creates always have: read in
	// the session VM ("present: " and its ls -l line, or "absent") and in the probe's
	// container ("absent": the smoke test refuses a container that has it).
	GPUInSessionVM string
	GPUInContainer string
	// SessionVMWindowsMounts are the session VM's mounts of Windows folders (9p, virtiofs,
	// drvfs), as "type options mountpoint": what WSL brings into every session VM (the GPU
	// driver folders, read-only, and the share they come through). None reaches a run's
	// container: the probe refuses any.
	SessionVMWindowsMounts []string
	// Session is, in the shared mode, the session the smoke test landed in: the default
	// session for the caller's user and elevation.
	Session string
	// The per-run mode: the two sessions the smoke test ran its probe in, each a VM whose
	// boot ID differs from the other's, the default session's and this distribution's;
	// and the template disk the runs boot from.
	RunSessions          []RunSessionEvidence
	DefaultSessionBootID string
	DistroBootID         string
	RunRoot              string // the Windows directory of the template and the run disks
	TemplateBytes        int64
	TemplateBuild        time.Duration
	// GVisor is what the smoke test read about gVisor in the per-run VMs; nil when
	// SANDBOX_WSLC_GVISOR is off.
	GVisor *GVisorEvidence
}

// RunSessionEvidence is one per-run session the smoke test used.
type RunSessionEvidence struct {
	Name     string
	BootID   string
	Uptime   string        // /proc/uptime in the session VM, read before the probe ran
	Result   time.Duration // from the copy of the template to the probe's result
	Teardown time.Duration // from the result to the session gone and its directory deleted
}

// Preflight checks what it can without starting the session VM: wslc.exe is where the
// configuration says, and it is the WSL release this provider needs; in the per-run mode,
// powershell.exe and mkfs.ext4 are where the configuration says too. It runs at startup
// and on every /readyz.
func (p *Provider) Preflight(ctx context.Context) error {
	if p.pr != nil {
		for _, prog := range []string{p.cfg.PowerShell, p.cfg.Mkfs} {
			if st, err := os.Stat(prog); err != nil || !st.Mode().IsRegular() {
				return fmt.Errorf("wslc: the per-run mode needs %s (a regular file): %v", prog, err)
			}
		}
		if p.cfg.GVisor {
			if err := p.checkGVisorPresent(); err != nil {
				return err
			}
		}
	}
	_, err := p.version(ctx)
	return err
}

// version runs `wslc version --format json`, which prints the package version without a
// session (VersionCommand.cpp at WSL master c7a28eb1), and refuses a release before
// MinVersion.
func (p *Provider) version(ctx context.Context) (string, error) {
	st, err := os.Stat(p.cfg.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("wslc: %s does not exist: this Windows host has no WSL containers (they come with WSL %s or later, installed by `wsl --update`, which restarts WSL)", p.cfg.Path, MinVersion)
	case err != nil:
		return "", fmt.Errorf("wslc: %s: %w", p.cfg.Path, err)
	case !st.Mode().IsRegular():
		return "", fmt.Errorf("wslc: %s is not a regular file", p.cfg.Path)
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := p.output(vctx, "version", "--format", "json")
	if err != nil {
		return "", err
	}
	var v struct {
		Client struct {
			Version string
		}
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("wslc version: unreadable answer: %w", err)
	}
	if !versionAtLeast(v.Client.Version, MinVersion) {
		return "", fmt.Errorf("wslc: WSL %q is older than %s, the first release whose wslc can drop capabilities (--cap-drop); update WSL at a quiet moment (wsl --update restarts every WSL VM)", v.Client.Version, MinVersion)
	}
	return v.Client.Version, nil
}

var versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)

// versionAtLeast compares dotted numeric versions; an unreadable one is never at least.
func versionAtLeast(got, want string) bool {
	if !versionRE.MatchString(got) || !versionRE.MatchString(want) {
		return false
	}
	g, w := strings.Split(got, "."), strings.Split(want, ".")
	for i := 0; i < max(len(g), len(w)); i++ {
		gi, wi := 0, 0
		if i < len(g) {
			gi, _ = strconv.Atoi(g[i])
		}
		if i < len(w) {
			wi, _ = strconv.Atoi(w[i])
		}
		if gi != wi {
			return gi > wi
		}
	}
	return true
}

var imageIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// inspectImage reads the configured image's ID, repository digests, platform,
// environment and volumes, and refuses an image a run could not start safely.
func (p *Provider) inspectImage(ctx context.Context) (id string, digests, env []string, err error) {
	out, err := p.output(ctx, "image", "inspect", p.cfg.Image)
	if err != nil {
		return "", nil, nil, err
	}
	var images []struct {
		Id           string
		RepoDigests  []string
		Architecture string
		Os           string
		Config       struct {
			Env     []string
			Volumes map[string]any
		}
	}
	if err := json.Unmarshal(out, &images); err != nil {
		return "", nil, nil, fmt.Errorf("wslc image inspect: unreadable answer: %w", err)
	}
	if len(images) != 1 {
		return "", nil, nil, fmt.Errorf("wslc image inspect %s: %d images answered, want 1", p.cfg.Image, len(images))
	}
	img := images[0]
	switch {
	case !imageIDRE.MatchString(img.Id):
		return "", nil, nil, fmt.Errorf("wslc image inspect: the image ID %q is not sha256:<64 hex>", img.Id)
	case img.Os != "linux":
		return "", nil, nil, fmt.Errorf("wslc image inspect: the image is for %q, not linux", img.Os)
	case len(img.Config.Volumes) > 0:
		// A VOLUME gives every container a writable mount no tmpfs bound covers.
		return "", nil, nil, errors.New("wslc: the image declares VOLUME mounts, which would be writable storage outside the tmpfs bounds; refused")
	}
	if m := pinnedRE.FindStringSubmatch(p.cfg.Image); m != nil {
		// The digest is the content address; the repository name may be written with or
		// without its registry, so only the digest is compared.
		if !slices.ContainsFunc(img.RepoDigests, func(d string) bool { return strings.HasSuffix(d, "@"+m[1]) }) {
			return "", nil, nil, fmt.Errorf("wslc: the image's repository digests %v do not include the pinned %s", img.RepoDigests, m[1])
		}
	}
	if err := checkImageEnv(img.Config.Env); err != nil {
		return "", nil, nil, err
	}
	return img.Id, img.RepoDigests, img.Config.Env, nil
}

// checkImageEnv refuses an image environment the runner could not hand to its steps
// exactly, or one the C library or dynamic loader would read before plimsoll's
// /usr/bin/env -i clears it (the docker provider's checkLoaderEnv says why).
func checkImageEnv(env []string) error {
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			return fmt.Errorf("wslc: the image's environment entry %q is not NAME=value", kv)
		}
		switch {
		case strings.HasPrefix(name, "LD_"), name == "GLIBC_TUNABLES", name == "LOCPATH", name == "NLSPATH", name == "GCONV_PATH":
			return fmt.Errorf("wslc: the image sets %s, which the C library or dynamic loader reads before any program in the container runs; refused (bake the setting into the image)", name)
		}
	}
	return nil
}

// sessionRead runs a fixed read-only command in a session VM itself (as root, through
// `wslc system session run`; session "" is the default one) and returns its first line.
func (p *Provider) sessionRead(ctx context.Context, session string, argv ...string) (string, error) {
	var args []string
	if session != "" {
		args = append(args, "--session", session)
	}
	out, err := p.output(ctx, append(append(args, "system", "session", "run"), argv...)...)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(line), nil
}

// probeFile and probeStep are the smoke test's one-step project.
const (
	probeFile = "probe.js"
	probeStep = "node " + probeFile
)

// tmpfsMounts are the four places a run may write, each a bounded tmpfs.
var tmpfsMounts = []string{"/dev/shm", "/tmp", "/var/tmp", workDir}

// SmokeTest proves at startup that a run gets the container this package argues for,
// through the same path every run takes, and serves nothing if it does not. It reads the
// image, then in the shared mode reads the session VM's kernel, boot ID and dockerd
// version, runs probe.js as a runner step in a container started by runArgv, checks what
// the probe read, and records which session it landed in. The per-run mode is
// smokePerRun.
func (p *Provider) SmokeTest(ctx context.Context) error {
	ver, err := p.version(ctx)
	if err != nil {
		return err
	}
	// A cold session boots its VM here (WSLC's boot timeout is 30 s).
	ictx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	id, digests, env, err := p.inspectImage(ictx)
	if err != nil {
		return err
	}
	if p.pr != nil {
		return p.smokePerRun(ctx, ver, id, digests, env)
	}
	kernel, err := p.sessionRead(ictx, "", "uname", "-r")
	if err != nil {
		return err
	}
	bootID, err := p.sessionRead(ictx, "", "cat", "/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	// The dockerd version is software identity for the log, not a boundary property, so a
	// failed read is recorded as such rather than refusing startup.
	moby, err := p.sessionRead(ictx, "", "dockerd", "--version")
	if err != nil {
		moby = "unread"
	}
	gpu, err := p.vmGPU(ictx, "")
	if err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	mounts, err := p.vmWindowsMounts(ictx, "")
	if err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	cand := &verified{imageID: id, imageEnv: env}
	out, err := p.runIn(ctx, cand, "", []runnerwire.File{{Path: probeFile, Content: probeScript}}, []string{probeStep}, nil, 60*time.Second)
	if err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	ev, err := p.checkProbe(out, env, kernel, bootID, nil)
	if err != nil {
		return err
	}
	ev.Mode, ev.WSLVersion, ev.ImageID, ev.RepoDigests, ev.Moby, ev.ReadAt = ModeShared, ver, id, digests, moby, time.Now().UTC()
	ev.GPUInSessionVM, ev.SessionVMWindowsMounts = gpu, mounts
	ev.Session = p.landedSession(ictx, bootID)
	cand.evidence = ev
	p.mu.Lock()
	p.state = cand
	p.mu.Unlock()
	return nil
}

// checkProbe holds one probe run's report to the container runArgv asks for.
func (p *Provider) checkProbe(out planRun, env []string, kernel, bootID string, gv *gvisorProof) (Evidence, error) {
	if !out.reported {
		return Evidence{}, fmt.Errorf("wslc smoke test: no authenticated runner report (wslc exit %d): the image must be plimsoll's sandbox image or built FROM it", out.exit)
	}
	if out.result.Outcome != sandbox.ProjectOutcomeCompleted || len(out.result.Steps) != 1 || out.result.Steps[0].ExitCode != 0 {
		return Evidence{}, fmt.Errorf("wslc smoke test: the probe step did not complete (%s, %s)", out.result.Outcome, out.result.Detail)
	}
	var rep boundaryReport
	if err := json.Unmarshal([]byte(out.result.Steps[0].Stdout), &rep); err != nil {
		return Evidence{}, fmt.Errorf("wslc smoke test: unreadable probe report: %w", err)
	}
	ev, err := p.checkBoundary(rep, env, kernel, bootID, gv)
	if err != nil {
		return Evidence{}, fmt.Errorf("wslc smoke test: %w", err)
	}
	return ev, nil
}

// landedSession is the default session the shared mode's runs land in: the listed
// wslc-cli-* session whose VM has the boot ID the smoke test read. Which
// one it is depends on whether plimsolld's interop caller is elevated.
func (p *Provider) landedSession(ctx context.Context, bootID string) string {
	names, err := p.listSessions(ctx)
	if err != nil {
		return "unread: " + err.Error()
	}
	var cands []string
	for _, n := range names {
		if strings.HasPrefix(n, "wslc-cli-") && safeArg.MatchString(n) {
			cands = append(cands, n)
		}
	}
	for _, n := range cands {
		if b, err := p.sessionRead(ctx, n, "cat", "/proc/sys/kernel/random/boot_id"); err == nil && b == bootID {
			return n
		}
	}
	return fmt.Sprintf("unidentified: no listed default session (%s) has boot ID %s", strings.Join(cands, ", "), bootID)
}

// gpuDevice is the device WSL's GPU sharing gives a Linux kernel.
const gpuDevice = "/dev/dxg"

// vmGPU is whether the session VM has the GPU device: "present: " and its ls -l line, or
// "absent".
func (p *Provider) vmGPU(ctx context.Context, session string) (string, error) {
	line, err := p.sessionRead(ctx, session, "ls", "-l", gpuDevice)
	switch {
	case err == nil && strings.HasSuffix(line, gpuDevice):
		return "present: " + line, nil
	case err != nil && strings.Contains(err.Error(), "No such file"):
		return "absent", nil
	case err != nil:
		return "", fmt.Errorf("reading %s in the session VM: %w", gpuDevice, err)
	}
	return "", fmt.Errorf("reading %s in the session VM: unexpected answer %q", gpuDevice, line)
}

// vmWindowsMounts lists the session VM's mounts of Windows folders.
func (p *Provider) vmWindowsMounts(ctx context.Context, session string) ([]string, error) {
	var args []string
	if session != "" {
		args = append(args, "--session", session)
	}
	out, err := p.output(ctx, append(args, "system", "session", "run", "cat", "/proc/self/mounts")...)
	if err != nil {
		return nil, fmt.Errorf("reading the session VM's mounts: %w", err)
	}
	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && slices.Contains(windowsFSTypes, f[2]) && len(found) < 32 {
			found = append(found, f[2]+" "+strings.SplitN(f[3], ",", 2)[0]+" "+unescapeMount(f[1]))
		}
	}
	return found, nil
}

// smokePerRun is the per-run mode's smoke test: find the run root, sweep what an earlier
// plimsolld left, build the template, then run the probe twice, each in a
// fresh session opened exactly as a run's is, and require two VMs never seen before: boot
// IDs that differ from each other, from the default session's and from this
// distribution's. Each session is torn down before the next one starts, and the smoke test
// requires both teardowns to finish and both directories to be gone.
func (p *Provider) smokePerRun(ctx context.Context, ver, id string, digests, env []string) error {
	if err := p.resolveRoot(ctx); err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	if _, err := p.sweep(true); err != nil {
		return fmt.Errorf("wslc smoke test: the startup sweep: %w", err)
	}
	distro, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	ictx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	defBoot, err := p.sessionRead(ictx, "", "cat", "/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Errorf("wslc smoke test: the default session's boot ID: %w", err)
	}
	ev := Evidence{Mode: ModePerRun, WSLVersion: ver, ImageID: id, RepoDigests: digests,
		DistroBootID: strings.TrimSpace(string(distro)), DefaultSessionBootID: defBoot, RunRoot: p.pr.root.win}
	p.pr.seenBootID(ev.DistroBootID)
	p.pr.seenBootID(ev.DefaultSessionBootID)
	tpl, err := p.buildTemplate(ctx, id)
	if err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	// The template's own folder and disk file: a right set directly on either is not in
	// the run root's list.
	if err := p.checkTemplateACL(ctx, p.pr.root.win); err != nil {
		return fmt.Errorf("wslc smoke test: %w", err)
	}
	p.pr.mu.Lock()
	p.pr.template = tpl.win
	p.pr.mu.Unlock()
	ev.TemplateBytes, ev.TemplateBuild = tpl.bytes, tpl.built
	cand := &verified{imageID: id, imageEnv: env}
	for i := 0; i < 2; i++ {
		got, rs, err := p.smokeSession(ctx, cand, env)
		if err != nil {
			return fmt.Errorf("wslc smoke test, per-run session %d: %w", i+1, err)
		}
		if i == 0 {
			got.Mode, got.WSLVersion, got.ImageID, got.RepoDigests = ev.Mode, ev.WSLVersion, ev.ImageID, ev.RepoDigests
			got.DistroBootID, got.DefaultSessionBootID, got.RunRoot = ev.DistroBootID, ev.DefaultSessionBootID, ev.RunRoot
			got.TemplateBytes, got.TemplateBuild = ev.TemplateBytes, ev.TemplateBuild
			ev = got
		}
		if i > 0 && p.cfg.GVisor && !sameGVisor(ev.GVisor, got.GVisor) {
			return fmt.Errorf("wslc smoke test: the two per-run sessions read different gVisor evidence: %+v and %+v", ev.GVisor, got.GVisor)
		}
		ev.RunSessions = append(ev.RunSessions, rs)
	}
	ev.BootID, ev.ReadAt = "", time.Now().UTC() // each run's VM has its own: RunSessions
	cand.evidence = ev
	p.mu.Lock()
	p.state = cand
	p.mu.Unlock()
	return nil
}

// smokeSession runs the probe in one fresh session, opened and torn down as a run's.
func (p *Provider) smokeSession(ctx context.Context, cand *verified, env []string) (Evidence, RunSessionEvidence, error) {
	start := time.Now()
	h, boot, err := p.openRunSession(ctx)
	if err != nil {
		return Evidence{}, RunSessionEvidence{}, err
	}
	rs := RunSessionEvidence{Name: h.name, BootID: boot}
	giveUp := func(err error) (Evidence, RunSessionEvidence, error) {
		return Evidence{}, rs, errors.Join(err, p.endSession(h, false, false))
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	kernel, err := p.sessionRead(rctx, h.name, "uname", "-r")
	if err != nil {
		return giveUp(err)
	}
	if rs.Uptime, err = p.sessionRead(rctx, h.name, "cat", "/proc/uptime"); err != nil {
		return giveUp(err)
	}
	moby, err := p.sessionRead(rctx, h.name, "dockerd", "--version")
	if err != nil {
		moby = "unread"
	}
	gpu, err := p.vmGPU(rctx, h.name)
	if err != nil {
		return giveUp(err)
	}
	mounts, err := p.vmWindowsMounts(rctx, h.name)
	if err != nil {
		return giveUp(err)
	}
	var out planRun
	var gv *gvisorProof
	var store gvisorStore
	if p.cfg.GVisor {
		if store, err = p.verifyGVisorStore(rctx, h.name); err != nil {
			return giveUp(err)
		}
		proof, ran, err := p.runBoundaryTestUnderGVisor(ctx, rctx, cand, h.name)
		if err != nil {
			return giveUp(err)
		}
		gv, out = &proof, ran
	} else {
		out, err = p.runIn(ctx, cand, h.name, []runnerwire.File{{Path: probeFile, Content: probeScript}}, []string{probeStep}, nil, 60*time.Second)
		if err != nil {
			return giveUp(err)
		}
	}
	rs.Result = time.Since(start)
	ev, checkErr := p.checkProbe(out, env, kernel, boot, gv)
	if checkErr == nil && gv != nil {
		ev.GVisor = p.gvisorEvidence(store, *gv)
	}
	tStart := time.Now()
	if err := p.endSession(h, out.ended == nil && !h.dead(), false); err != nil {
		return Evidence{}, rs, errors.Join(checkErr, fmt.Errorf("the session's teardown: %w", err))
	}
	rs.Teardown = time.Since(tStart)
	if checkErr != nil {
		return Evidence{}, rs, checkErr
	}
	if _, err := os.Stat(h.dir); !errors.Is(err, os.ErrNotExist) {
		return Evidence{}, rs, fmt.Errorf("the session's directory %s is still there after its teardown (%v)", h.dir, err)
	}
	ev.KernelRelease, ev.Moby, ev.GPUInSessionVM, ev.SessionVMWindowsMounts = kernel, moby, gpu, mounts
	return ev, rs, nil
}

// resolveRoot finds the run root, both ways, and makes sure it exists.
func (p *Provider) resolveRoot(ctx context.Context) error {
	if p.drives == nil {
		mi, err := readMountinfo()
		if err != nil {
			return err
		}
		p.drives = driveMounts(mi)
	}
	var root runRoot
	if p.cfg.RunRoot != "" {
		win, err := toWindows(p.drives, p.cfg.RunRoot)
		if err != nil {
			return fmt.Errorf("SANDBOX_WSLC_RUN_ROOT: %w", err)
		}
		root = runRoot{linux: p.cfg.RunRoot, win: win}
	} else {
		lad, err := p.localAppData(ctx)
		if err != nil {
			return err
		}
		linux, err := toLinux(p.drives, lad+"/plimsoll-wslc")
		if err != nil {
			return err
		}
		root = runRoot{linux: linux, win: lad + "/plimsoll-wslc"}
	}
	if err := os.MkdirAll(root.linux, 0o755); err != nil {
		return err
	}
	// One process to a run root: the sweep ends what it finds under the root that no run of
	// its own process holds, so a second process here would end the first's runs.
	if err := lockRoot(root.win); err != nil {
		return err
	}
	// Every run boots a copy of the template kept here: no one else may write here.
	if err := p.checkRootACL(ctx, root.win); err != nil {
		return err
	}
	p.pr.mu.Lock()
	p.pr.root = root
	p.pr.mu.Unlock()
	return nil
}

// boundaryReport is what probe.js prints.
type boundaryReport struct {
	Status      map[string]string `json:"status"`
	Kernel      string            `json:"kernel"`
	ProcVersion string            `json:"procVersion"`
	BootID      string            `json:"bootID"`
	Interfaces  []string          `json:"interfaces"`
	Connect     map[string]string `json:"connect"`
	Mountinfo   []string          `json:"mountinfo"`
	Writable    []string          `json:"writable"`
	Walk        struct {
		Entries    int  `json:"entries"`
		Unlistable int  `json:"unlistable"`
		Truncated  bool `json:"truncated"`
	} `json:"walk"`
	MemoryMax string            `json:"memoryMax"`
	PidsMax   string            `json:"pidsMax"`
	Limits    map[string]string `json:"limits"`
	Resolv    string            `json:"resolv"`
	EnvNames  []string          `json:"envNames"`
	RunnerMem string            `json:"runnerMem"`
	GPU       string            `json:"gpu"`
}

// windowsFSTypes are the filesystems a Windows folder reaches a Linux guest through.
var windowsFSTypes = []string{"9p", "v9fs", "virtiofs", "drvfs", "cifs", "smb3", "fuse", "fuseblk"}

// stepEnvNames are the variables a step may hold besides the image's: what the runner
// and the shell that starts each step set.
var stepEnvNames = []string{"PATH", "HOME", "HOSTNAME", "PWD", "OLDPWD", "SHLVL", "_", "PLIMSOLL_RUNNER_PID"}

// checkBoundary holds the probe's report to the container runArgv asks for.
//
// gv is nil except when gVisor is on, where three readings differ (the filter line inside
// reads 0, the memory limit is not in the container's cgroup view, the kernel and boot ID
// are the Sentry's) and each is replaced by a reading that proves the same property
// (checkGVisorReadings), accepted only together with the proof of gVisor itself; every
// other check below runs as it does without gVisor, except the three mount-table allowances
// checkMounts names.
func (p *Provider) checkBoundary(r boundaryReport, imageEnv []string, kernel, bootID string, gv *gvisorProof) (Evidence, error) {
	ev := Evidence{KernelRelease: kernel, BootID: bootID}
	uid := strconv.Itoa(GuestUID)
	for _, field := range []string{"Uid", "Gid"} {
		ids := strings.Fields(r.Status[field])
		if len(ids) != 4 || slices.ContainsFunc(ids, func(s string) bool { return s != uid }) {
			return ev, fmt.Errorf("the guest's %s is %q, not %s throughout: --user was not applied", field, r.Status[field], uid)
		}
	}
	if g := strings.Fields(r.Status["Groups"]); len(g) > 1 || (len(g) == 1 && g[0] != uid) {
		return ev, fmt.Errorf("the guest has supplementary groups %q", r.Status["Groups"])
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if v := r.Status[field]; strings.Trim(v, "0") != "" || v == "" {
			return ev, fmt.Errorf("the guest's %s is %q, not empty: --cap-drop ALL was not applied", field, v)
		}
	}
	ev.Seccomp, ev.SeccompFilters, ev.NoNewPrivs, ev.CapBnd = r.Status["Seccomp"], r.Status["Seccomp_filters"], r.Status["NoNewPrivs"], r.Status["CapBnd"]
	if gv != nil {
		if err := checkGVisorReadings(r, kernel, bootID, gv); err != nil {
			return ev, err
		}
	} else if ev.Seccomp != "2" {
		// Below Docker's own default filter the provider is not worth serving, and WSLC
		// offers no way to choose a profile.
		return ev, fmt.Errorf("the guest runs with Seccomp %q, not a filter (2): dockerd's default seccomp profile is not in force and WSLC cannot set one; refused", ev.Seccomp)
	}
	if !slices.Equal(r.Interfaces, []string{"lo"}) {
		return ev, fmt.Errorf("the container's network interfaces are %q, not loopback alone: --network none is not in force", r.Interfaces)
	}
	for target, result := range r.Connect {
		if result == "connected" {
			return ev, fmt.Errorf("the guest reached %s with --network none", target)
		}
	}
	if err := checkMounts(r.Mountinfo, p.cfg, gv != nil); err != nil {
		return ev, err
	}
	if r.Walk.Truncated {
		return ev, fmt.Errorf("the writable-place walk stopped at %d entries before it covered the image; refused rather than serve a partly checked filesystem", r.Walk.Entries)
	}
	got := slices.Clone(r.Writable)
	slices.Sort(got)
	want := slices.Clone(tmpfsMounts)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return ev, fmt.Errorf("the places that accepted a write are %q, want exactly %q: with no read-only root, any other one is writable storage a guest can also run programs from", got, want)
	}
	ev.Writable, ev.WalkedEntries, ev.Unlistable = got, r.Walk.Entries, r.Walk.Unlistable
	wantMem := int64(p.cfg.MemoryMB) * 1024 * 1024
	memRead, memFrom := r.MemoryMax, "the container's"
	if gv != nil {
		// Inside gVisor there is no memory.max to read; the limit is on the cgroup that
		// holds gVisor's processes, which only the session VM can read.
		memRead, memFrom = gv.MemoryMax, "the session VM's cgroup for the container's"
	}
	if mem, err := strconv.ParseInt(memRead, 10, 64); err != nil || mem != wantMem {
		return ev, fmt.Errorf("%s memory.max is %q, want %d: --memory was not applied", memFrom, memRead, wantMem)
	}
	ev.MemoryMax = wantMem
	ev.PidsMax = r.PidsMax
	n := strconv.Itoa(p.cfg.Nproc)
	for name, want := range map[string][2]string{
		"Max processes":      {n, n},
		"Max open files":     {strconv.Itoa(nofileLimit), strconv.Itoa(nofileLimit)},
		"Max core file size": {"0", "0"},
	} {
		f := strings.Fields(r.Limits[name])
		if len(f) < 2 || f[0] != want[0] || f[1] != want[1] {
			return ev, fmt.Errorf("the guest's %q limit is %q, want %s %s: --ulimit was not applied", name, r.Limits[name], want[0], want[1])
		}
	}
	ev.NprocLimit = p.cfg.Nproc
	if err := checkResolv(r.Resolv); err != nil {
		return ev, err
	}
	allowed := slices.Clone(stepEnvNames)
	for _, kv := range imageEnv {
		name, _, _ := strings.Cut(kv, "=")
		allowed = append(allowed, name)
	}
	for _, name := range r.EnvNames {
		if !slices.Contains(allowed, name) {
			return ev, fmt.Errorf("a step's environment holds %q, which neither the image nor the runner sets: a variable reached the container from outside", name)
		}
	}
	if r.RunnerMem != "EACCES" && r.RunnerMem != "EPERM" {
		return ev, fmt.Errorf("a step opening the runner's memory got %q, not a refusal: the runner guard is not in force", r.RunnerMem)
	}
	if r.GPU != "absent" {
		return ev, fmt.Errorf("the container's %s (the GPU device the session VM has) reads %q, not absent: a run must not reach the GPU", gpuDevice, r.GPU)
	}
	ev.GPUInContainer = r.GPU
	if gv != nil {
		// Replaced by the gVisor proof above: the kernel is gVisor's, the boot ID is its own,
		// and the container was read from this very session VM by name.
		return ev, nil
	}
	if r.Kernel == "" || r.Kernel != kernel {
		return ev, fmt.Errorf("the container's kernel %q is not the session VM's %q", r.Kernel, kernel)
	}
	if r.BootID == "" || r.BootID != bootID {
		return ev, fmt.Errorf("the container's boot ID %q is not the session VM's %q: the run did not land in the session read", r.BootID, bootID)
	}
	return ev, nil
}

// goferMounts are the only places a 9p mount may appear under gVisor: its root and the
// three files docker bind-mounts into every container, which gVisor serves through its
// gofer process (the VM-side proof requires the container to have no bind or volume, so none
// of them is a folder handed over from Windows).
var goferMounts = []string{"/", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts"}

// checkMounts holds each tmpfs to its bound and options, and refuses any Windows folder.
// A mountinfo line is: id parent major:minor root mountpoint options [optional...] -
// fstype source superoptions. Under gVisor (gv) three things differ, each read from a
// trial's /proc/mounts or from how gVisor serves files, and each narrow: a tmpfs line carries
// no nodev (every capability is already required to be empty, and mknod needs one), its size
// may be stated among the mount options instead of the superblock options, and a 9p mount
// is accepted at goferMounts alone.
func checkMounts(lines []string, cfg Config, gv bool) error {
	sizes := map[string]int{"/tmp": smallTmpfsMB, "/var/tmp": smallTmpfsMB, "/dev/shm": smallTmpfsMB, workDir: cfg.workMB()}
	found := map[string]bool{}
	for _, line := range lines {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 6 || len(g) < 3 {
			return fmt.Errorf("unreadable mountinfo line %q", line)
		}
		target, opts, fstype, super := f[4], strings.Split(f[5], ","), g[0], strings.Split(g[2], ",")
		gofer := gv && fstype == "9p" && slices.Contains(goferMounts, target)
		if !gofer && (slices.Contains(windowsFSTypes, fstype) || strings.HasPrefix(fstype, "fuse.")) {
			return fmt.Errorf("%s is a %s mount: a Windows folder or user-space filesystem reached the container", target, fstype)
		}
		size, promised := sizes[target]
		if !promised {
			continue
		}
		if fstype != "tmpfs" {
			return fmt.Errorf("%s is mounted as %q, not tmpfs", target, fstype)
		}
		for _, o := range []string{"noexec", "nosuid", "nodev"} {
			if !slices.Contains(opts, o) && !(gv && o == "nodev") {
				return fmt.Errorf("%s mount options %q lack %s", target, f[5], o)
			}
		}
		sizeOpt := fmt.Sprintf("size=%dk", size*1024)
		if !slices.Contains(super, sizeOpt) && !(gv && slices.Contains(opts, sizeOpt)) {
			return fmt.Errorf("%s superblock options %q lack size=%dk: the bound is not verifiably in force", target, g[2], size*1024)
		}
		found[target] = true
	}
	for target := range sizes {
		if !found[target] {
			return fmt.Errorf("%s is not in the container's mount table", target)
		}
	}
	return nil
}

// checkResolv refuses a resolver file that names a nameserver other than loopback or a
// search domain: the session VM's settings (a corporate DNS suffix, the host's
// resolvers) are not the guest's business.
func checkResolv(s string) error {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "nameserver":
			if len(f) < 2 || (f[1] != "127.0.0.1" && f[1] != "::1") {
				return fmt.Errorf("the container's resolv.conf names nameserver %q, not loopback", strings.Join(f[1:], " "))
			}
		case "search", "domain":
			if len(f) > 1 && !(len(f) == 2 && f[1] == ".") {
				return fmt.Errorf("the container's resolv.conf carries the %s line %q from outside the container", f[0], line)
			}
		}
	}
	return nil
}

// probeScript is probe.js: it runs as a runner step, as the guest uid, and prints one
// JSON object. Every read is bounded and every failure is recorded as text, so the host
// decides.
const probeScript = `const fs = require("fs"), net = require("net"), os = require("os");
const read = (f, n) => { try { return fs.readFileSync(f, "utf8").slice(0, n || 65536); } catch (e) { return ""; } };
const status = {};
for (const line of read("/proc/self/status").split("\n")) {
  const i = line.indexOf(":");
  if (i > 0) status[line.slice(0, i)] = line.slice(i + 1).trim().slice(0, 128);
}
const limits = {};
for (const line of read("/proc/self/limits").split("\n").slice(1)) {
  const m = line.match(/^(.+?)\s{2,}(\S+)\s+(\S+)/);
  if (m) limits[m[1].trim()] = m[2] + " " + m[3];
}
const interfaces = read("/proc/net/dev").split("\n").slice(2).map(l => l.split(":")[0].trim()).filter(Boolean).slice(0, 16);
const mountinfo = read("/proc/self/mountinfo", 262144).trim().split("\n").filter(Boolean).slice(0, 512);
const unescape = s => s.replace(/\\([0-7]{3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
const fstype = l => ((l.split(" - ")[1] || "").split(" ")[0] || "");
// Kernel interfaces, not storage: proc and sys, and /dev/mqueue (POSIX message queues,
// bounded per uid by RLIMIT_MSGQUEUE), where a write would create a queue.
const kernelTypes = new Set(["proc", "sysfs", "mqueue", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "bpf"]);
const kernelMounts = mountinfo.filter(l => kernelTypes.has(fstype(l))).map(l => unescape(l.split(" ")[4] || ""));
const mountpoints = mountinfo.filter(l => !kernelTypes.has(fstype(l))).map(l => unescape(l.split(" ")[4] || ""));
const tmpfs = new Set(["/tmp", "/var/tmp", "/dev/shm", "/work"]);
const under = (p, d) => p === d || p.startsWith(d + "/");
const inTmpfs = p => [...tmpfs].some(d => under(p, d));
const inKernel = p => under(p, "/proc") || under(p, "/sys") || kernelMounts.some(d => under(p, d));
const writable = new Set();
const probeName = ".plimsoll-write-probe-" + process.pid;
const tryDir = d => {
  const p = (d === "/" ? "" : d) + "/" + probeName;
  try { fs.writeFileSync(p, "x", { flag: "wx" }); fs.unlinkSync(p); writable.add(d); } catch (e) {}
};
const tryFile = f => { try { fs.closeSync(fs.openSync(f, "a")); writable.add(f); } catch (e) {} };
for (const mp of mountpoints) {
  if (!mp || inKernel(mp)) continue;
  let st; try { st = fs.lstatSync(mp); } catch (e) { continue; }
  if (st.isDirectory()) tryDir(mp); else if (st.isFile()) tryFile(mp);
}
const walk = { entries: 0, unlistable: 0, truncated: false };
const stack = ["/"];
while (stack.length) {
  const d = stack.pop();
  if (inKernel(d) || inTmpfs(d)) continue;
  if (++walk.entries > 400000) { walk.truncated = true; break; }
  try { fs.accessSync(d, fs.constants.W_OK); tryDir(d); } catch (e) {}
  let names;
  try { names = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { walk.unlistable++; continue; }
  for (const ent of names) {
    const p = (d === "/" ? "" : d) + "/" + ent.name;
    if (ent.isDirectory()) { stack.push(p); continue; }
    if (!ent.isFile()) continue;
    if (++walk.entries > 400000) { walk.truncated = true; break; }
    try { fs.accessSync(p, fs.constants.W_OK); tryFile(p); } catch (e) {}
  }
}
const runnerPid = process.env.PLIMSOLL_RUNNER_PID || "";
let runnerMem = "unset";
if (runnerPid) { try { fs.closeSync(fs.openSync("/proc/" + runnerPid + "/mem", "r")); runnerMem = "open"; } catch (e) { runnerMem = e.code || "error"; } }
const targets = ["1.1.1.1:443", "8.8.8.8:53", "169.254.169.254:80"];
const connect = {};
const tryConnect = t => new Promise(done => {
  const i = t.lastIndexOf(":");
  const s = net.connect({ host: t.slice(0, i), port: +t.slice(i + 1) });
  const end = r => { connect[t] = r; s.destroy(); done(); };
  s.setTimeout(2000, () => end("timeout"));
  s.on("connect", () => end("connected"));
  s.on("error", e => end(e.code || "error"));
});
Promise.all(targets.map(tryConnect)).then(() => {
  process.stdout.write(JSON.stringify({
    status, kernel: os.release(), procVersion: read("/proc/version", 512).trim(), bootID: read("/proc/sys/kernel/random/boot_id").trim(), interfaces, connect,
    mountinfo, writable: [...writable].sort().slice(0, 200), walk,
    memoryMax: read("/sys/fs/cgroup/memory.max").trim(), pidsMax: read("/sys/fs/cgroup/pids.max").trim(),
    limits, resolv: read("/etc/resolv.conf", 4096), envNames: Object.keys(process.env).sort(), runnerMem,
    gpu: fs.existsSync("/dev/dxg") ? "present" : "absent",
  }));
});
`
