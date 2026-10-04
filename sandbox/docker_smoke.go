package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// checkGuestIDs checks the ids a probe read from /proc/self/status: every uid and
// gid the guest uid, and no supplementary group but it.
func checkGuestIDs(uids, gids, groups []string, uid int) error {
	want := strconv.Itoa(uid)
	if len(uids) == 0 || len(gids) == 0 {
		return errors.New("the probe could not read its uid and gid")
	}
	for _, set := range []struct {
		what string
		ids  []string
	}{{"uid", uids}, {"gid", gids}, {"supplementary group", groups}} {
		for _, id := range set.ids {
			if id != want {
				return fmt.Errorf("the guest runs with %s %s, not the guest uid %d: the runtime did not apply --user", set.what, id, uid)
			}
		}
	}
	return nil
}

// SmokeTest proves the EXACT configured image/runtime/seccomp combination
// enforces the writable-storage contract by running one throwaway lockdown
// container per image and checking, from inside, that the root filesystem
// refuses writes and that every writable mount is a tmpfs carrying the exact
// size and noexec/nosuid options this provider promised, and that its cgroup
// carries exactly the configured process limit (under runsc, the sandbox's host
// cgroup, where gVisor enforces it). For every project or module image it also
// starts the runner as runs do and checks the runner's descriptors from a step.
// Preflight verifies configuration; this verifies behavior. It starts real containers, so it is
// for startup/deploy readiness — not per-request or unauthenticated poll paths.
func (d *DockerSandbox) SmokeTest(ctx context.Context) error {
	// The verified state without the proof check: this is the proof.
	if err := d.preflight(ctx); err != nil {
		return err
	}
	state, err := d.verifiedState()
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
		// when the runtime is runsc: under runc the same envelope (the guest uid, no
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
		if p.workTmpfs {
			if err := d.smokeRunner(ctx, state, p.id); err != nil {
				return fmt.Errorf("runner smoke failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
			}
		}
	}
	if err := d.smokeSnippet(ctx, state); err != nil {
		return fmt.Errorf("snippet smoke failed for image %q under runtime %q: %w", d.Image, state.runtime, err)
	}
	// The languages the project image runs, which Describe states and a session's
	// cells use: node is the runner's own interpreter, python3 is optional.
	langs, err := d.probeLanguages(ctx, state, state.projectImageID)
	if err != nil {
		return fmt.Errorf("language probe failed for image %q under runtime %q: %w", d.ProjectImage, state.runtime, err)
	}
	d.stateMu.Lock()
	d.projectLanguages = langs
	d.stateMu.Unlock()
	// The process limit is a property of the runtime, not of an image, so under runsc
	// it is proven once, on the host, where gVisor enforces it (smokeProbe skips the
	// guest's emulated copy).
	if state.runtime == "runsc" {
		if err := d.proveSandboxPidsLimit(ctx, state, state.imageID); err != nil {
			return fmt.Errorf("smoke failed for image %q under runtime %q: %w", d.Image, state.runtime, err)
		}
	}
	// What was proven is the content probed above, whatever the tags name by now.
	proven := map[string]string{d.Image: state.imageID, d.ProjectImage: state.projectImageID}
	if d.ModuleImage != "" {
		proven[d.ModuleImage] = state.moduleImageID
	}
	d.stateMu.Lock()
	d.provenImageIDs = proven
	d.stateMu.Unlock()
	return nil
}

// startSmokeSocket listens on a throwaway host Unix socket the way brokerForRun
// does (same directory shape, same 0666 mode for the guest uid) and answers
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
// The process limit as the guest's own cgroup states it (v2, then v1). A runtime
// that accepts --pids-limit without applying it leaves "max" here.
let pids = null;
for (const p of ["/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"]) {
  try { pids = { max: fs.readFileSync(p, "utf8").trim().slice(0, 32) }; break; } catch (e) {}
}
// The network interfaces the guest sees. Under --network none that is loopback
// alone; a container that can reach any network has another interface here.
// The ids the guest runs as, from the kernel: every uid and gid (real, effective,
// saved, filesystem) the guest uid, no supplementary group but it. A runtime could
// accept --user and run the guest as someone else.
let ids = null;
try {
  ids = {};
  for (const line of fs.readFileSync("/proc/self/status", "utf8").split("\n")) {
    const [k, ...v] = line.trim().split(/\s+/);
    if (k === "Uid:" || k === "Gid:" || k === "Groups:") ids[k.slice(0, -1).toLowerCase()] = v.slice(0, 64);
  }
} catch (e) {}
let interfaces = null;
try {
  interfaces = fs.readFileSync("/proc/net/dev", "utf8").split("\n").slice(2)
    .map(l => l.split(":")[0].trim()).filter(Boolean).slice(0, 16).map(n => n.slice(0, 32));
} catch (e) {}
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
	const finish = `function finish(socket) { process.stdout.write(JSON.stringify({ rootWritable, mounts, writable, pids, ids, interfaces, banner, socket })); }
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
	// The probe is plimsoll's own program: it starts under sessionkit.ControlArgv, so nothing the
	// image's environment declares can change what it reports.
	runArgs := d.lockdownArgs(name, d.containerExpiry(ctx), workTmpfs, state.runtime)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	if socketPath != "" {
		// Mounted exactly as brokerForRun mounts the per-run broker socket.
		runArgs = append(runArgs, "-v", socketPath+":"+containerSocketPath)
	}
	probeArgv, err := sessionkit.ControlArgv(nil, "node", "-")
	if err != nil {
		return err
	}
	runArgs = append(runArgs, launch(image, probeArgv)...)
	args, err := dockerArgs(state.host, runArgs...)
	if err != nil {
		return err
	}
	cmd := dockerCommand(ctx, args...)
	cmd.Stdin = strings.NewReader(probe)
	out, err := cappedOutput(cmd)
	if err != nil {
		d.forceRemove(state.host, name)
		return fmt.Errorf("probe container failed: %w", err)
	}
	var report struct {
		RootWritable bool     `json:"rootWritable"`
		Mounts       string   `json:"mounts"`
		Writable     []string `json:"writable"`
		Pids         *struct {
			Max string `json:"max"`
		} `json:"pids"`
		IDs *struct {
			UID    []string `json:"uid"`
			GID    []string `json:"gid"`
			Groups []string `json:"groups"`
		} `json:"ids"`
		Interfaces []string `json:"interfaces"`
		Banner     *struct {
			Head  string `json:"head"`
			Error string `json:"error"`
		} `json:"banner"`
		Socket *struct {
			OK    bool   `json:"ok"`
			Reply string `json:"reply"`
			Error string `json:"error"`
		} `json:"socket"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
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
	if err := checkLoopbackOnly(report.Interfaces); err != nil {
		return err
	}
	if report.IDs == nil {
		return errors.New("the probe could not read the ids it runs as from /proc/self/status")
	}
	if err := checkGuestIDs(report.IDs.UID, report.IDs.GID, report.IDs.Groups, d.guestUID()); err != nil {
		return err
	}
	// Under runsc the guest's cgroup files are gVisor's own emulation, where pids.max
	// reads "max" whatever docker was asked for; runsc enforces the limit on the
	// sandbox's host cgroup instead, and SmokeTest proves it there
	// (proveSandboxPidsLimit). Every other runtime is held to the guest's own file.
	if state.runtime != "runsc" {
		pidsMax := ""
		if report.Pids != nil {
			pidsMax = report.Pids.Max
		}
		if err := checkPidsLimit(pidsMax, d.PidsLimit, "inside the container"); err != nil {
			return err
		}
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

// checkLoopbackOnly holds the guest's network interfaces to loopback alone, which
// is what --network none gives under runc and runsc alike (measured 2026-09-29;
// docker's default network adds eth0). It is structural: a probe that only tried to
// connect somewhere would pass on a host that happens to be offline. An unreadable
// list fails too.
func checkLoopbackOnly(ifaces []string) error {
	if len(ifaces) == 1 && ifaces[0] == "lo" {
		return nil
	}
	return fmt.Errorf("the container's network interfaces are %q, not loopback alone; --network none is not in force", ifaces)
}

// smokeSnippet runs one snippet exactly as runs do (runSnippet): the start script, then
// node found through the image's PATH with the image's environment. The start marker
// is written before node is started, so after it a failure to start node would read as
// the guest's exit (127 for an image whose PATH lacks node, a crash for an image
// variable that breaks node); here it refuses startup instead.
func (d *DockerSandbox) smokeSnippet(ctx context.Context, state dockerExecutionState) error {
	const want = "plimsoll-snippet-ok"
	res, err := d.runSnippet(ctx, state, Request{Code: `console.log("` + want + `")`, Timeout: 20 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != want {
		return fmt.Errorf("a snippet printing %q exited %d with stdout %q and stderr %q", want, res.ExitCode, truncateForError(res.Stdout), truncateForError(res.Stderr))
	}
	return nil
}

// smokeRunner starts the runner exactly as runs do (runPlan), then tries the same-uid
// access a project step could make. The standalone storage probe above is not the
// runner and cannot establish the runner's report-channel protection.
func (d *DockerSandbox) smokeRunner(ctx context.Context, state dockerExecutionState, imageID string) error {
	const probe = `const fs=require("node:fs");
const checks=[["/proc/1/fd/0",fs.constants.O_RDONLY],
 ["/proc/1/fd/1",fs.constants.O_RDONLY],["/proc/1/fd/1",fs.constants.O_WRONLY],
 ["/proc/1/mem",fs.constants.O_RDONLY]];
for(const [path,flags] of checks){
  try{const fd=fs.openSync(path,flags);fs.closeSync(fd);process.exit(8);}
  catch(e){if(e.code!=="EACCES" && e.code!=="EPERM") throw e;}
}
`
	res, err := d.runPlan(ctx, state, imageID, ProjectRequest{
		Files:   []File{{Path: "runner-probe.js", Content: probe}},
		Steps:   []string{"node runner-probe.js"},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		return fmt.Errorf("the runner or its descriptor probe failed: outcome %s (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	return nil
}

// probeLanguages runs each interpreter once in the image, through the project path,
// and returns the languages that answered. JavaScript must: the runner is node.
func (d *DockerSandbox) probeLanguages(ctx context.Context, state dockerExecutionState, imageID string) ([]Language, error) {
	res, err := d.runPlan(ctx, state, imageID, ProjectRequest{
		Steps:   []string{`node -e 'console.log("javascript")' && { python3 -c 'print("python")' 2>/dev/null || true; }`},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		return nil, fmt.Errorf("the probe failed: outcome %s (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	var langs []Language
	for _, line := range strings.Fields(res.Steps[0].Stdout) {
		if l := Language(line); l.Known() && !slices.Contains(langs, l) {
			langs = append(langs, l)
		}
	}
	if !slices.Contains(langs, LanguageJavaScript) {
		return nil, errors.New("node did not answer")
	}
	return langs, nil
}

// checkPidsLimit asserts the cgroup that enforces a run's processes carries exactly
// the process limit this provider passed as --pids-limit; where names that cgroup in
// the error. Docker accepts the flag under any runtime, and a runtime can accept it
// without applying it (Kata's Docker runtime left pids.max at "max" and let 204
// processes start against a limit of 64), so a limit that was merely requested is
// not one this provider may promise. An unreadable limit fails closed, and so does a
// configured limit that is not a positive integer: there is then no bound to prove.
func checkPidsLimit(got, want, where string) error {
	n, err := strconv.Atoi(strings.TrimSpace(want))
	if err != nil || n <= 0 {
		return fmt.Errorf("process limit %q is not a positive integer, so there is no bound to prove", want)
	}
	if got == "" {
		return fmt.Errorf("no pids.max was readable %s, so the process limit cannot be proven", where)
	}
	if got != strconv.Itoa(n) {
		return fmt.Errorf("pids.max %s is %q, want %d: the runtime accepted --pids-limit without applying it", where, bannerFirstLine(got), n)
	}
	return nil
}

// proveSandboxPidsLimit proves the process limit where runsc enforces it. gVisor
// applies --pids-limit to the sandbox's cgroup on the host, which holds the sentry,
// the gofer and one host task per guest process (measured 2026-09-28 under
// gVisor 20260907.0: about 30 at idle), while the guest reads gVisor's emulated
// cgroup files, where pids.max is "max" whatever was configured. So one throwaway
// container under the identical lockdown is started detached, and the limit is read
// from the host cgroup of the process docker reports for it. The cgroup path must
// name the container: a PID resolved in another PID namespace (plimsolld inside a
// container of its own) would otherwise read an unrelated process's cgroup, and
// that fails closed rather than proving anything.
func (d *DockerSandbox) proveSandboxPidsLimit(ctx context.Context, state dockerExecutionState, image string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	docker := func(args ...string) (string, error) {
		full, err := dockerArgs(state.host, args...)
		if err != nil {
			return "", err
		}
		out, err := dockerOutput(ctx, full...)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
	name := "crsbx-smoke-pids-" + randID()
	// lockdownArgs starts with "run", "--rm", "-i"; detach so the container is alive
	// while its cgroup is read. --rm stays, and forceRemove covers every exit path.
	runArgs := append([]string{"run", "-d"}, d.lockdownArgs(name, d.containerExpiry(ctx), false, state.runtime)[1:]...)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	holdArgv, err := sessionkit.ControlArgv(nil, "node", "--eval", "setTimeout(() => {}, 30000)")
	if err != nil {
		return err
	}
	runArgs = append(runArgs, launch(image, holdArgv)...)
	defer d.forceRemove(state.host, name)
	id, err := docker(runArgs...)
	if err != nil {
		return fmt.Errorf("process-limit probe container failed: %w", err)
	}
	pidText, err := docker("inspect", "--format", "{{.State.Pid}}", name)
	if err != nil {
		return fmt.Errorf("process-limit probe container could not be inspected: %w", err)
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return fmt.Errorf("docker reported no host process for the process-limit probe container (%q)", bannerFirstLine(pidText))
	}
	listing, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return fmt.Errorf("the sandbox's host cgroup is unreadable, so the process limit cannot be proven: %w", err)
	}
	path, err := hostPidsMaxPath(string(listing), id)
	if err != nil {
		return fmt.Errorf("the sandbox's host cgroup cannot be located, so the process limit cannot be proven: %w", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("the sandbox's host cgroup has no readable pids.max, so the process limit cannot be proven: %w", err)
	}
	if err := checkPidsLimit(strings.TrimSpace(string(got)), d.PidsLimit, "on the sandbox's host cgroup"); err != nil {
		return err
	}
	slog.Info("docker smoke: process limit proven on the sandbox's host cgroup (it also counts the runtime's own tasks)",
		"runtime", state.runtime, "pids_max", d.PidsLimit)
	return nil
}

// hostPidsMaxPath resolves the pids.max file of the cgroup a /proc/<pid>/cgroup
// listing names: the pids controller's line ("N:pids:/path", possibly sharing the
// line with other controllers) on cgroup v1 or a hybrid host, else the unified line
// ("0::/path") on cgroup v2. Docker names a container's cgroup after its full ID
// under both the systemd and cgroupfs drivers, so a path without the ID belongs to
// some other process.
func hostPidsMaxPath(listing, containerID string) (string, error) {
	if len(containerID) < 12 {
		return "", fmt.Errorf("container ID %q is too short to identify its cgroup", containerID)
	}
	var v1, v2 string
	for _, line := range strings.Split(strings.TrimSpace(listing), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case slices.Contains(strings.Split(parts[1], ","), "pids"):
			v1 = parts[2]
		case parts[0] == "0" && parts[1] == "":
			v2 = parts[2]
		}
	}
	rel, path := v2, filepath.Join("/sys/fs/cgroup", v2, "pids.max")
	if v1 != "" {
		rel, path = v1, filepath.Join("/sys/fs/cgroup/pids", v1, "pids.max")
	}
	if rel == "" {
		return "", errors.New("the listing names neither a pids controller nor a unified cgroup")
	}
	if !strings.Contains(rel, containerID) {
		return "", fmt.Errorf("cgroup %q does not name container %s (is plimsolld in another PID namespace?)", bannerFirstLine(rel), containerID[:12])
	}
	return path, nil
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
