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
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/internal/boundary"
	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
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
// for startup/deploy readiness — not per-request or unauthenticated poll paths. Each
// claim is recorded as its check passes, and the record must match dockerClaims
// (docker_claims.go) before the images count as proven.
func (d *DockerSandbox) SmokeTest(ctx context.Context) error {
	proof := dockerClaims.Start()
	// The verified state without the proof check: this is the proof.
	if err := d.preflight(ctx); err != nil {
		return err
	}
	proof.Proved(boundary.SetupReadBack, "SmokeTest")
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
	d.provenGuard = ""
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
		if err := d.smokeProbe(ctx, state, p.id, p.workTmpfs, readBanner, socketPath, proof); err != nil {
			return fmt.Errorf("smoke failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
		}
		if err := d.smokeGuestGuard(ctx, state, p.id, p.workTmpfs, proof); err != nil {
			return fmt.Errorf("guest guard check failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
		}
		if p.workTmpfs {
			// The runner's own file first: the runner below is started only once its
			// bytes are the ones this plimsolld carries. Then the guard, which the
			// session's node programs and the forwarder load (not the runner).
			if err := d.smokeNativeHelper(ctx, state, p.id, proof); err != nil {
				return fmt.Errorf("project runner check failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
			}
			if err := d.smokeGuard(ctx, state, p.id, proof); err != nil {
				return fmt.Errorf("guard smoke failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
			}
			if err := d.smokeRunner(ctx, state, p.id, proof); err != nil {
				return fmt.Errorf("runner smoke failed for image %q under runtime %q: %w", p.ref, state.runtime, err)
			}
		}
	}
	if err := d.smokeSnippet(ctx, state, proof); err != nil {
		return fmt.Errorf("snippet smoke failed for image %q under runtime %q: %w", d.Image, state.runtime, err)
	}
	// The languages the project image runs, which Describe states and a session's
	// cells use: node is the runner's own interpreter, python3 is optional.
	langs, err := d.probeLanguages(ctx, state, state.projectImageID, proof)
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
		if err := d.proveSandboxPidsLimit(ctx, state, state.imageID, proof); err != nil {
			return fmt.Errorf("smoke failed for image %q under runtime %q: %w", d.Image, state.runtime, err)
		}
	}
	if err := proof.Done(); err != nil {
		return err
	}
	// What was proven is the content probed above, whatever the tags name by now.
	proven := map[string]string{d.Image: state.imageID, d.ProjectImage: state.projectImageID}
	if d.ModuleImage != "" {
		proven[d.ModuleImage] = state.moduleImageID
	}
	d.stateMu.Lock()
	d.provenImageIDs = proven
	d.provenGuard = state.guardPolicy
	d.stateMu.Unlock()
	return nil
}

// GuestGuard states the guest guard's policy word and whether the last smoke test proved the
// guard in force (smokeGuestGuard, in every configured image under the configured runtime).
func (d *DockerSandbox) GuestGuard() (policy string, proven bool) {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return d.provenGuard, d.provenGuard != ""
}

// guestGuardCheckTarget is where the smoke test mounts the guard check, read-only, beside the
// guard: a fresh name at the root, as guestGuardTarget is. No run's container gets it.
const guestGuardCheckTarget = "/.plimsoll-guest-guard-check"

// smokeGuestGuard proves, from a program started the way a guest's program is started, that the
// guest guard's filter is on it (findings guest-guard-18 and guest-guard-11). One container of
// image under the lockdown a run gets, with the guard check (guestguard.CheckProgram) mounted
// read-only beside the guard, started as a snippet's node is started: the guard first
// (launch), then plimsoll's start script with the image's environment (guestArgv), which writes
// its start marker and then starts, in node's place, a shell that reads two Seccomp lines and
// then becomes the check (smokeSeccompScript). The check requires the table's answer to each of
// its requests: the self-check request must get the answer only the guard's filter gives (so a
// guard that ran without installing it, or a runtime that ignored it, fails here), a request for
// a user namespace, clone3, a tracing request and a mount request must be refused, and an
// ordinary request (its write of guestguard.CheckOK) must work. A program without the guard's
// filter stops at the first answer, before any request that could make a namespace, so no check
// here runs the road without the guard. Any other outcome refuses startup with what was missing.
// The same holds under runc and gVisor: the guard's answers show through plimsoll's shipped
// profile and docker's default, since among filters that answer a request with an errno the
// newest one's errno wins. Under gVisor the step also requires both Seccomp lines to read 2
// (checkSmokeSeccomp, finding guest-guard-18).
//
// It runs once under each host seccomp profile a run of this state can get
// (guestGuardProfiles, finding guest-guard-26): the default, and the sdk_env variant when one is
// configured and the runtime applies it, so a variant that ended a process for a request the
// guard makes, instead of refusing it, is found here, at startup, not at the first granted run.
//
// In the project image, the one a session's container runs, it runs once more in a session's
// shape (finding guest-guard-10, decision 10 B): the guard in its process-1 mode as process 1
// (launchPID1), under the default profile, the one a session's container applies, and the check
// started as its child. Under gVisor process 1's Seccomp line must then read 2 too, so a
// session's first process is shown to be behind a filter before any session opens; with
// docker's --init it read 0.
func (d *DockerSandbox) smokeGuestGuard(ctx context.Context, state dockerExecutionState, image string, workTmpfs bool, proof *boundary.Proof) error {
	for _, p := range state.guestGuardProfiles() {
		if err := d.smokeGuestGuardUnder(ctx, state, image, workTmpfs, p.path, false); err != nil {
			if p.what == "" {
				return err
			}
			return fmt.Errorf("under %s: %w", p.what, err)
		}
	}
	if workTmpfs && image == state.projectImageID {
		if err := d.smokeGuestGuardUnder(ctx, state, image, workTmpfs, state.seccomp.defaultPath, true); err != nil {
			return fmt.Errorf("in a session's shape (the guest guard as process 1): %w", err)
		}
	}
	proof.Proved(boundary.GuestGuard, "smokeGuestGuard")
	// The code cannot add a writable place of its own: the namespace and the mount it would need
	// are refused (the writable-places claim's second half).
	proof.Proved(boundary.WritablePlaces, "smokeGuestGuard")
	return nil
}

// guestGuardProfile is one host seccomp profile smokeGuestGuard runs the check under: its path
// as lockdownArgs takes it, and what an error calls it ("" for the default, the one profile the
// check's errors meant before the variant was checked too).
type guestGuardProfile struct{ path, what string }

// guestGuardProfiles is every host seccomp profile a run of st can get: the default, and the
// sdk_env variant when the runtime applies it (sdkVariant).
func (st dockerExecutionState) guestGuardProfiles() []guestGuardProfile {
	out := []guestGuardProfile{{path: st.seccomp.defaultPath}}
	if v := st.seccomp.sdkVariant(st.runtime); v != "" {
		out = append(out, guestGuardProfile{path: v, what: "the seccomp profile variant a run whose grant sets sdk_env gets (SANDBOX_DOCKER_SECCOMP_SDK)"})
	}
	return out
}

// sdkVariant is the profile a run whose grant sets sdk_env gets when it is another than the
// default, "" when it is the same or such a run is refused: seccompFor's choice, written as the
// one case where the two differ (a variant is configured and the runtime applies host profiles;
// under runsc none applies). TestSDKVariantMatchesSeccompFor holds the two equal.
func (s dockerSeccomp) sdkVariant(runtime string) string {
	if runtime == "runsc" || s.sdkPath == "" {
		return ""
	}
	return s.sdkPath
}

// smokeSeccompScript runs in node's place, started by the start script as a guest's program is,
// with the check's path as its one argument: it writes process 1's Seccomp line and its own, as
// "plimsoll seccomp 1 VALUE" and "plimsoll seccomp guest VALUE" (VALUE "none" when the line is
// not there), then becomes the check, so the check is the same guest-started process. It reads
// with the shell alone, as the start script reads Uid, so it needs no tool of the image.
const smokeSeccompScript = `for w in 1 guest; do p=$$; [ "$w" = guest ] || p=1; v=none
{ while read -r k x _; do if [ "$k" = Seccomp: ]; then v=$x; break; fi; done < /proc/$p/status; } 2>/dev/null
printf 'plimsoll seccomp %s %s\n' "$w" "$v"; done
exec "$1"`

// smokeSeccompLines splits what the guard check's container wrote into the Seccomp lines of
// smokeSeccompScript (process 1's and the guest's, by name) and the check's own output after
// them. The first line without the script's shape ends the lines.
func smokeSeccompLines(stdout string) (map[string]string, string) {
	lines := map[string]string{}
	for len(lines) < 2 {
		line, rest, ok := strings.Cut(stdout, "\n")
		f := strings.Fields(line)
		if !ok || len(f) != 4 || f[0] != "plimsoll" || f[1] != "seccomp" || (f[2] != "1" && f[2] != "guest") || lines[f[2]] != "" {
			break
		}
		lines[f[2]], stdout = f[3], rest
	}
	return lines, stdout
}

// checkSmokeSeccomp requires, under gVisor, process 1's Seccomp line and the guest's to read 2,
// a filter in force (finding guest-guard-18). Measured under release-20260907.0
// (docker/gvisor.versions), in a container started as a run is started and behind the guard:
// process 1 is the guard's own process, which the start script and the check replace in turn,
// and both lines read 2; without the guard both read 0, since gVisor applies no host profile to
// the processes it runs. In a session's shape process 1 is the guard in its process-1 mode,
// which stays and starts the check as its child, and both lines read 2 again (2026-11-20); with
// docker's --init as process 1 its line read 0. So under gVisor a 2 can only be a filter
// installed inside the container, and process 1's says the container's first process is behind it. Under runc both
// lines read 2 with or without the guard (the host profile), so they say nothing there and are
// not required; the self-check's answer is what proves the guard's filter on either runtime.
func checkSmokeSeccomp(runtime string, lines map[string]string) error {
	if runtime != "runsc" {
		return nil
	}
	for _, w := range []struct{ key, name string }{{"1", "process 1"}, {"guest", "the guest's program"}} {
		v, ok := lines[w.key]
		if !ok {
			return fmt.Errorf("under gVisor the guard check did not read the Seccomp line of %s, so whether a filter is in force there is not known; nothing is served until it reads 2", w.name)
		}
		if v != "2" {
			return fmt.Errorf("under gVisor the Seccomp line of %s reads %q, not 2: no seccomp filter is in force on it, so it does not run behind the guest guard; nothing is served until it does", w.name, v)
		}
	}
	return nil
}

// smokeGuestGuardUnder is one run of smokeGuestGuard's check, under the host seccomp profile
// seccomp (which lockdownArgs leaves out under gVisor, as for every run); with pid1, in a
// session's shape, the guard staying as process 1 (launchPID1).
func (d *DockerSandbox) smokeGuestGuardUnder(ctx context.Context, state dockerExecutionState, image string, workTmpfs bool, seccomp string, pid1 bool) error {
	files, err := dockerProcessFiles()
	if err != nil {
		return err
	}
	check, err := writeGuestGuardCheck(files.guard)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "crsbx-smoke-" + providerkit.RandHex(8)
	runArgs := d.lockdownArgs(name, d.containerExpiry(ctx), workTmpfs, state.runtime, seccomp)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	runArgs = append(runArgs, "--mount", bindMountSpec(check, guestGuardCheckTarget))
	started := startMarker()
	argv, err := guestArgv(started, state.guestEnv(image), "/bin/sh", "-c", smokeSeccompScript, "sh", guestGuardCheckTarget)
	if err != nil {
		return err
	}
	start := launch
	if pid1 {
		start = launchPID1
	}
	tail, err := start(state.guard, image, argv)
	if err != nil {
		return err
	}
	args, err := dockerArgs(state.host, append(runArgs, tail...)...)
	if err != nil {
		return err
	}
	cmd := dockerCommand(ctx, args...)
	var stdout, stderr providerkit.Capture
	stdout.Limit, stderr.Limit = 4096, 4096
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if err != nil {
		d.forceRemove(state.host, name)
	}
	if ended := ctx.Err(); ended != nil {
		return fmt.Errorf("the guard check did not finish: %w", ended)
	}
	code := 0
	if err != nil {
		code = exitCodeOf(err) // -1 when the CLI failed without an exit code of its own
	}
	if _, guestStarted := afterMarker(stderr.String(), started); !guestStarted {
		if refusal, ok := guestGuardRefusal(code, stderr.String()); ok {
			return errors.New(refusal)
		}
		return fmt.Errorf("docker did not start the guard check (%v): %s", err, truncateForError(strings.TrimSpace(stderr.String())))
	}
	if err != nil && code < 0 {
		return fmt.Errorf("the docker CLI failed during the guard check: %w", err)
	}
	lines, out := smokeSeccompLines(stdout.String())
	if code != 0 || out != guestguard.CheckOK {
		return guestGuardCheckFailed(runtime.GOARCH, code, out)
	}
	return checkSmokeSeccomp(state.runtime, lines)
}

// guestGuardCheckFailed is smokeGuestGuard's refusal when the check started but did not end
// with exit 0 and its line (finding guest-guard-30), worded by what the exit says, since only one
// exit says the filter is missing: the self-check's. An exit of a later attempt says the filter
// is on but answers one request otherwise than its table; the ordinary request's says every
// refusal was right and something refuses more than the table; exit 0 with another output, and
// an exit the check never uses (such as 159, 128 plus SIGSYS, when a seccomp profile kills a
// request), say the check itself did not run as built, so whether the filter is on is not known.
func guestGuardCheckFailed(goarch string, code int, stdout string) error {
	const after = "; the guard refuses namespaces, mounts, clone3 and tracing to guest code, and nothing is served until the guard check passes"
	table, err := guestguard.Load()
	if err != nil {
		return err
	}
	attempts, err := table.CheckAttempts(goarch)
	if err != nil {
		return err
	}
	if code == 0 {
		return fmt.Errorf("the guard check exited 0 but wrote %q, not its line, so it did not run as it was built and whether the guest guard's filter is on is not known (exit 0)%s", truncateForError(stdout), after)
	}
	for i, a := range attempts {
		if a.Exit != code {
			continue
		}
		if i == 0 {
			return fmt.Errorf("a program started as a guest's program is started is not behind the guest guard's filter: %s (exit %d)%s", table.CheckExitSays(goarch, code), code, after)
		}
		return fmt.Errorf("a program started as a guest's program is started is behind the guest guard's filter (the self-check got the answer only that filter gives), but the filter does not answer as its table says: %s (exit %d)%s", table.CheckExitSays(goarch, code), code, after)
	}
	if code == guestguard.CheckExitOrdinary {
		return fmt.Errorf("the guest guard's filter gave every answer the guard check requires, but %s, so the guard's filter or a seccomp profile in front of the check refuses more than the guard's table says (exit %d)%s", table.CheckExitSays(goarch, code), code, after)
	}
	return fmt.Errorf("the guard check ended with exit %d, a code it never uses, so something outside the check ended it (an exit above 128 is 128 plus the signal that ended it: 159 is SIGSYS, which a seccomp profile that kills a request sends, and 137 is SIGKILL) and whether the guest guard's filter is on is not known%s", code, after)
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
// The resolver configuration the guest sees, which must be plimsoll's fixed file and
// nothing of the host's.
let resolv = null;
try { resolv = fs.readFileSync("/etc/resolv.conf", "latin1").slice(0, 4096); } catch (e) {}
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
	const finish = `function finish(socket) { process.stdout.write(JSON.stringify({ node: process.version, rootWritable, mounts, writable, pids, ids, interfaces, resolv, banner, socket })); }
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
func (d *DockerSandbox) smokeProbe(ctx context.Context, state dockerExecutionState, image string, workTmpfs bool, readBanner bool, socketPath string, proof *boundary.Proof) error {
	probe := smokeProbeScript(readBanner, socketPath != "")

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "crsbx-smoke-" + providerkit.RandHex(8)
	// The probe is plimsoll's own program: it starts under sessionkit.ControlArgv, so nothing the
	// image's environment declares can change what it reports.
	runArgs := d.lockdownArgs(name, d.containerExpiry(ctx), workTmpfs, state.runtime, state.seccomp.defaultPath)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	if socketPath != "" {
		// Mounted exactly as brokerForRun mounts the per-run broker socket.
		runArgs = append(runArgs, "--mount", bindMount(socketPath, containerSocketPath, false))
	}
	probeArgv, err := sessionkit.ControlArgv(nil, sessionkit.StartupNodeArgv("-")...)
	if err != nil {
		return err
	}
	tail, err := launch(state.guard, image, probeArgv)
	if err != nil {
		return err
	}
	runArgs = append(runArgs, tail...)
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
		Node         string   `json:"node"`
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
		Resolv     *string  `json:"resolv"`
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
	// Every node program of plimsoll's own in this image starts with
	// sessionkit.NodeSignalFlag (the granted-run forwarder, a session's programs; the
	// project runner is the native helper), so a node that would refuse it is refused here,
	// with the version it needs, before any run.
	if err := sessionkit.CheckNodeVersion(report.Node); err != nil {
		return err
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
		proof.Proved(boundary.GrantSocket, "smokeProbe")
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
	if err := proof.Check(boundary.LoopbackOnly, "smokeProbe", checkLoopbackOnly(report.Interfaces)); err != nil {
		return err
	}
	if err := proof.Check(boundary.FixedResolver, "smokeProbe", checkGuestResolvConf(report.Resolv)); err != nil {
		return err
	}
	if report.IDs == nil {
		return errors.New("the probe could not read the ids it runs as from /proc/self/status")
	}
	if err := proof.Check(boundary.GuestUser, "smokeProbe", checkGuestIDs(report.IDs.UID, report.IDs.GID, report.IDs.Groups, d.guestUID())); err != nil {
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
		if err := proof.Check(boundary.ProcessLimit, "smokeProbe", checkPidsLimit(pidsMax, d.PidsLimit, "inside the container")); err != nil {
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
	proof.Proved(boundary.WritableBounds, "smokeProbe")
	// The tmpfs checks above prove the PROMISED mounts are bounded; this proves
	// the promised mounts are the ONLY ones that accept writes, so the aggregate
	// budget really is the full writable sum (the root's refusal is checked above).
	return proof.Check(boundary.WritablePlaces, "smokeProbe", checkWritableSet(report.Writable, paths))
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

// checkGuestResolvConf holds the guest's /etc/resolv.conf to guestResolvConf byte for
// byte, so no search domain, nameserver, option or other line of the host's reaches
// guest code whatever the host's file holds. An unreadable file fails too. The error
// states counts, never the file's values, which may be the host's.
func checkGuestResolvConf(got *string) error {
	if got == nil {
		return errors.New("the probe could not read the container's /etc/resolv.conf")
	}
	if *got == guestResolvConf {
		return nil
	}
	var search, nameservers, other int
	for _, line := range strings.Split(*got, "\n") {
		switch f := strings.Fields(line); {
		case len(f) == 0 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], ";"):
		case f[0] == "search" || f[0] == "domain":
			search++
		case f[0] == "nameserver":
			nameservers++
		default:
			other++
		}
	}
	return fmt.Errorf("the container's /etc/resolv.conf is not the fixed file plimsoll mounts (%d bytes: %d search or domain lines, %d nameserver lines, %d other lines), so the host's resolver settings may reach guest code", len(*got), search, nameservers, other)
}

// smokeSnippet runs one snippet exactly as runs do (runSnippet): the start script, then
// node found through the image's PATH with the image's environment. The start marker
// is written before node is started, so after it a failure to start node would read as
// the guest's exit (127 for an image whose PATH lacks node, a crash for an image
// variable that breaks node); here it refuses startup instead.
func (d *DockerSandbox) smokeSnippet(ctx context.Context, state dockerExecutionState, proof *boundary.Proof) error {
	const want = "plimsoll-snippet-ok"
	res, err := d.runSnippet(ctx, state, Request{Code: `console.log("` + want + `")`, Timeout: 20 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != want {
		return fmt.Errorf("a snippet printing %q exited %d with stdout %q and stderr %q", want, res.ExitCode, truncateForError(res.Stdout), truncateForError(res.Stderr))
	}
	proof.Proved(boundary.RunPath, "smokeSnippet")
	return nil
}

// smokeNativeHelper holds a project image's runner, the native helper at
// nativehelper.InContainer, to the bytes this plimsolld carries (nativeHelperWant): a
// regular file, root's, writable by no one else, with that SHA-256. An image built before
// the helper replaced the Node runner has no file there, and an image built for another
// plimsoll has other bytes; either is refused here, at startup, with what to do, instead
// of failing every project call. It runs in a throwaway container under the exact lockdown
// a run gets, as a control program (sessionkit.ControlArgv), so the hash is computed by the
// image's own node: as trustworthy as the image, which is what is being checked against
// plimsolld's copy, not defended against.
func (d *DockerSandbox) smokeNativeHelper(ctx context.Context, state dockerExecutionState, imageID string, proof *boundary.Proof) error {
	want, err := nativeHelperWant()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "crsbx-smoke-helper-" + providerkit.RandHex(8)
	runArgs := d.lockdownArgs(name, d.containerExpiry(ctx), true, state.runtime, state.seccomp.defaultPath)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	argv, err := sessionkit.ControlArgv(nil, sessionkit.NodeArgv("--eval", nativehelper.CheckJS, nativehelper.InContainer)...)
	if err != nil {
		return err
	}
	tail, err := launch(state.guard, imageID, argv)
	if err != nil {
		return err
	}
	runArgs = append(runArgs, tail...)
	args, err := dockerArgs(state.host, runArgs...)
	if err != nil {
		return err
	}
	cmd := dockerCommand(ctx, args...)
	cmd.Stdin = strings.NewReader("")
	out, err := cappedOutput(cmd)
	if err != nil {
		d.forceRemove(state.host, name)
		return fmt.Errorf("project runner check container failed: %w", err)
	}
	var report nativehelper.FileReport
	if err := json.Unmarshal(out, &report); err != nil {
		return fmt.Errorf("project runner check returned unparseable output: %w", err)
	}
	if err := report.Check(want); err != nil {
		return fmt.Errorf("%w; %s", err, nativeHelperFix)
	}
	proof.Proved(boundary.ControlChannel, "smokeNativeHelper")
	return nil
}

// nativeHelperFix is what every refusal smokeNativeHelper makes tells an operator to do.
const nativeHelperFix = "plimsoll starts that file as the project runner of every project call; rebuild plimsoll's images from this plimsolld's source (make docker-images), or, for an image of your own built on an older plimsoll image, rebuild it on the current one (docs/guest-dependencies.md)"

// smokeRunner starts the runner exactly as runs do (runPlan), then tries the same-uid
// access a project step could make. The standalone storage probe above is not the
// runner and cannot establish the runner's report-channel protection.
func (d *DockerSandbox) smokeRunner(ctx context.Context, state dockerExecutionState, imageID string, proof *boundary.Proof) error {
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
		Steps:   []string{sessionkit.GuestNode + " runner-probe.js"},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		return fmt.Errorf("the runner or its descriptor probe failed: outcome %s (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	proof.Proved(boundary.RunPath, "smokeRunner")
	proof.Proved(boundary.ControlChannel, "smokeRunner")
	return nil
}

// guardHolderJS is the program smokeGuard starts as a session starts its control
// programs: it clears LD_PRELOAD, so the guard stays its own, and runs guardCheckJS
// (its first argument) as its child, a process of the guest user like a session's code,
// with its own PID and the library's path as arguments, and prints what the child said.
const guardHolderJS = `const cp=require("node:child_process");delete process.env.LD_PRELOAD;
const r=cp.spawnSync(process.execPath,["--disable-sigusr1","-e",process.argv[1],String(process.pid),process.argv[2]],{encoding:"utf8",timeout:10000,maxBuffer:4096,env:{PATH:process.env.PATH}});
process.stdout.write(r.stdout||"");
if(r.error||r.status!==0){process.stderr.write(String(r.error||r.stderr).slice(0,300));process.exit(1)}`

// guardCheckJS reports, as JSON, whether the guard library is a file at its path, the
// checker's own uid, the uid the kernel lists the holder's /proc/<pid>/environ under (the
// guest's while the holder is dumpable, root once it is not: so under runc and under
// gVisor, measured 2026-11-19, while gVisor leaves /proc/<pid>/fd the guest's either
// way), and what opening the holder's input and output descriptors gave.
const guardCheckJS = `const fs=require("node:fs");const [pid,lib]=process.argv.slice(1);const out={uid:process.getuid()};
try{out.lib=fs.statSync(lib).isFile()?"file":"not a file"}catch(e){out.lib=e.code||"unreadable"}
try{out.owner=fs.statSync("/proc/"+pid+"/environ").uid}catch(e){out.owner=-1;out.ownerError=e.code||"unknown"}
for(const [k,p,f] of [["fd0","/proc/"+pid+"/fd/0",fs.constants.O_RDONLY],["fd1","/proc/"+pid+"/fd/1",fs.constants.O_WRONLY]]){
try{fs.closeSync(fs.openSync(p,f));out[k]="open"}catch(e){out[k]=e.code||"unknown"}}
process.stdout.write(JSON.stringify(out));`

// smokeGuard proves the runner guard in a project image: the library is there, and a
// program started exactly as a session starts its sweep, its quiesce and each cell
// relay (sessionControlArgv) is non-dumpable, so a process of the guest user can open
// none of its descriptors. The granted-run forwarder loads the same
// library. A loader that cannot find a library named by LD_PRELOAD starts the program
// without it and without a word (measured on the Alpine image, 2026-11-19), so nothing
// but a check like this one notices an image without it. It runs in a throwaway
// container under the exact lockdown a run gets.
func (d *DockerSandbox) smokeGuard(ctx context.Context, state dockerExecutionState, imageID string, proof *boundary.Proof) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "crsbx-smoke-guard-" + providerkit.RandHex(8)
	runArgs := d.lockdownArgs(name, d.containerExpiry(ctx), true, state.runtime, state.seccomp.defaultPath)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	argv, err := sessionControlArgv(nil, sessionkit.NodeArgv("--eval", guardHolderJS, guardCheckJS, dockerRunnerGuard))
	if err != nil {
		return err
	}
	tail, err := launch(state.guard, imageID, argv)
	if err != nil {
		return err
	}
	runArgs = append(runArgs, tail...)
	args, err := dockerArgs(state.host, runArgs...)
	if err != nil {
		return err
	}
	cmd := dockerCommand(ctx, args...)
	cmd.Stdin = strings.NewReader("")
	out, err := cappedOutput(cmd)
	if err != nil {
		d.forceRemove(state.host, name)
		return fmt.Errorf("guard check container failed: %w", err)
	}
	var report guardReport
	if err := json.Unmarshal(out, &report); err != nil {
		return fmt.Errorf("guard check returned unparseable output: %w", err)
	}
	return proof.Check(boundary.ControlChannel, "smokeGuard", report.check())
}

// guardReport is what guardCheckJS prints.
type guardReport struct {
	Lib        string `json:"lib"`
	UID        *int   `json:"uid"`
	Owner      *int   `json:"owner"`
	OwnerError string `json:"ownerError"`
	FD0        string `json:"fd0"`
	FD1        string `json:"fd1"`
}

// guardUsers says what the library protects, for every refusal smokeGuard makes.
const guardUsers = "plimsoll loads it, through LD_PRELOAD, into a session's sweep, quiesce and cell relays and the granted-run forwarder, to make each non-dumpable (a Linux setting that stops other programs of the same user from opening its descriptors or reading its memory)"

// check reads the report. Each refusal names the protection that is missing.
func (r guardReport) check() error {
	if r.Lib != "file" {
		return fmt.Errorf("the image has no runner guard library at %s (%s); %s, and a loader that cannot find it starts the program unprotected without a word, so the image is refused", dockerRunnerGuard, bannerFirstLine(r.Lib), guardUsers)
	}
	if r.UID == nil || r.Owner == nil {
		return errors.New("the guard check reported no uid or no owner for the guarded program, so its protection cannot be proven")
	}
	if *r.Owner < 0 {
		return fmt.Errorf("the guard check could not read the guarded program's /proc entry (%s), so its protection cannot be proven", bannerFirstLine(r.OwnerError))
	}
	if *r.Owner == *r.UID {
		return fmt.Errorf("a program started as a session starts its control programs, with LD_PRELOAD=%s, is still dumpable: the kernel lists its /proc/<pid>/environ as the guest user's (uid %d); %s", dockerRunnerGuard, *r.UID, guardUsers)
	}
	for _, o := range []struct{ what, code string }{{"input", r.FD0}, {"output", r.FD1}} {
		if o.code != "EACCES" && o.code != "EPERM" {
			return fmt.Errorf("a process of the guest user opening the guarded program's %s descriptor got %q, want it refused for permission; %s", o.what, bannerFirstLine(o.code), guardUsers)
		}
	}
	return nil
}

// probeLanguages runs each interpreter once in the image, through the project path,
// and returns the languages that answered. JavaScript must: the runner is node.
func (d *DockerSandbox) probeLanguages(ctx context.Context, state dockerExecutionState, imageID string, proof *boundary.Proof) ([]Language, error) {
	res, err := d.runPlan(ctx, state, imageID, ProjectRequest{
		Steps:   []string{LanguageProbe()},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		return nil, fmt.Errorf("the probe failed: outcome %s (%s), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	langs := ProbedLanguages(res.Steps[0].Stdout)
	if !slices.Contains(langs, LanguageJavaScript) {
		return nil, errors.New("node did not answer")
	}
	proof.Proved(boundary.Languages, "probeLanguages")
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
func (d *DockerSandbox) proveSandboxPidsLimit(ctx context.Context, state dockerExecutionState, image string, proof *boundary.Proof) error {
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
	name := "crsbx-smoke-pids-" + providerkit.RandHex(8)
	// lockdownArgs starts with "run", "--rm", "-i"; detach so the container is alive
	// while its cgroup is read. --rm stays, and forceRemove covers every exit path.
	runArgs := append([]string{"run", "-d"}, d.lockdownArgs(name, d.containerExpiry(ctx), false, state.runtime, state.seccomp.defaultPath)[1:]...)
	if state.platform != "" {
		runArgs = append(runArgs, "--platform", state.platform)
	}
	holdArgv, err := sessionkit.ControlArgv(nil, sessionkit.NodeArgv("--eval", "setTimeout(() => {}, 30000)")...)
	if err != nil {
		return err
	}
	tail, err := launch(state.guard, image, holdArgv)
	if err != nil {
		return err
	}
	runArgs = append(runArgs, tail...)
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
	if err := proof.Check(boundary.ProcessLimit, "proveSandboxPidsLimit", checkPidsLimit(strings.TrimSpace(string(got)), d.PidsLimit, "on the sandbox's host cgroup")); err != nil {
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
