package openshell

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

const (
	// smokeTimeout bounds the whole smoke test; the first create on a gateway may pull
	// the image.
	smokeTimeout = 120 * time.Second
	// minSwept is the fewest paths the write sweep must have tried. A probe that
	// swept nothing would report an empty writable set and prove nothing.
	minSwept = 100
)

// smokeEvidence is what the last passing SmokeTest measured.
type smokeEvidence struct {
	GatewayVersion string
	Sandbox        string
	PolicyHash     string
	Node           string
	// Swept paths had a write attempted; Writable are the directories that accepted
	// one (all at or beneath /tmp), WritableFiles the regular files outside the
	// sandbox's own /tmp that opened for append (none).
	Swept         int
	Writable      []string
	WritableFiles []string
	// Egress is each connection attempt's outcome (an error code; never "open").
	Egress map[string]string
	// DNS is what example.com resolved to inside: a synthetic mapping address, not a
	// real resolution. Interfaces are the network interfaces the guest sees.
	DNS        string
	Interfaces []string
	// The sandbox's own cgroup limits, read inside it. pids.max is the gateway-wide
	// process limit.
	MemoryMax, CPUMax, PidsMax string
	// TmpMount is /tmp's line in /proc/mounts (the last, if it is mounted over).
	TmpMount string
	// The runner round trip with a project at the size ceiling.
	PlanBytes int
	RoundTrip time.Duration
	// The kill proof: the hung command's processes alive before its exec stream was
	// cancelled, and how long after the cancellation none were left.
	HungProcesses int
	KillConfirmed time.Duration
}

// lastSmoke returns the last passing SmokeTest's measurements, or nil.
func (p *Provider) lastSmoke() *smokeEvidence {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.smoke
}

// SmokeTest proves on one throwaway sandbox what every run relies on, using the run
// paths themselves:
//   - the gateway runs the docker driver (the tier);
//   - a sandbox is created with the run policy and limits and reads both back exactly;
//   - from inside, a write attempted at every candidate path succeeds only under /tmp
//     (Landlock enforces the policy; this is proven, not assumed), no connection leaves
//     the sandbox, and the sandbox's own cgroup carries the requested memory and CPU
//     limits;
//   - the runner round-trips a project at the 4 MiB ceiling through the project exec
//     path, stdin plan and sentinel report included, and the step cannot open the
//     runner's plan descriptor, report descriptor or memory;
//   - a hung command and the process it started are killed when their exec stream is
//     cancelled, confirmed gone by a second exec: the mechanism behind every timeout.
//
// It creates one sandbox and deletes it afterwards, so the daemon runs it once at
// startup, never on a poll path.
func (p *Provider) SmokeTest(ctx context.Context) error {
	if err := p.cfg.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, smokeTimeout)
	defer cancel()
	tier, err := p.checkDriver(ctx)
	if err != nil {
		return fmt.Errorf("openshell smoke: %w", err)
	}
	b, err := p.create(ctx)
	if err != nil {
		return fmt.Errorf("openshell smoke: %w", err)
	}
	defer p.deleteLater(b)
	ev := smokeEvidence{GatewayVersion: p.gatewayVersion(), Sandbox: b.name, PolicyHash: p.policyHash}

	if err := p.smokeProbe(ctx, b, &ev); err != nil {
		return fmt.Errorf("openshell smoke: %w", err)
	}
	if err := p.smokeRunner(ctx, b, tier, &ev); err != nil {
		return fmt.Errorf("openshell smoke: runner round trip: %w", err)
	}
	if err := p.smokeKill(ctx, b, &ev); err != nil {
		return fmt.Errorf("openshell smoke: %w", err)
	}

	p.mu.Lock()
	p.smoke = &ev
	p.mu.Unlock()
	slog.Info("openshell smoke passed",
		"gateway_version", ev.GatewayVersion, "tier", tier.String(), "policy_hash", ev.PolicyHash,
		"swept", ev.Swept, "writable", ev.Writable, "egress", ev.Egress, "dns", ev.DNS, "interfaces", ev.Interfaces,
		"memory_max", ev.MemoryMax, "cpu_max", ev.CPUMax, "pids_max", ev.PidsMax, "tmp_mount", ev.TmpMount,
		"plan_bytes", ev.PlanBytes, "round_trip", ev.RoundTrip,
		"hung_processes", ev.HungProcesses, "kill_confirmed_after", ev.KillConfirmed)
	return nil
}

// smokeProbeScript runs with `node -`. The write sweep attempts a write at every
// candidate: each mount point, the standard top-level directories, OpenShell's own,
// HOME and the working directory, and every directory beneath a candidate that can be
// listed (the kernel's /proc and /sys trees only at their mount points). A directory
// gets a file created and removed; a regular file an append-open that writes nothing.
// Device nodes are skipped: a write to one (/dev/null) discards, it does not store.
// Then it tries to leave the sandbox, and reads its own cgroup limits.
const smokeProbeScript = `const fs = require("fs"), net = require("net"), dns = require("dns");
const report = { node: process.version };
const mounts = fs.readFileSync("/proc/mounts", "utf8").trim().split("\n").map(l => l.split(" ")[1].replace(/\\040/g, " "));
const mountSet = new Set(mounts);
const kernel = p => p === "/proc" || p.startsWith("/proc/") || p === "/sys" || p.startsWith("/sys/");
const queue = ["/", "/bin", "/boot", "/dev", "/dev/shm", "/dev/mqueue", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt",
  "/opt", "/root", "/run", "/sbin", "/srv", "/tmp", "/usr", "/usr/local", "/var", "/var/tmp", "/var/log", "/sandbox",
  "/.openshell", "/work", process.env.HOME || "/", process.cwd(), ...mounts];
const seen = new Set(), writable = [], writableFiles = [];
const probeName = "/.plimsoll-write-probe-" + process.pid;
let swept = 0;
while (queue.length && swept < 50000) {
  const p = queue.shift();
  if (seen.has(p)) continue;
  seen.add(p);
  if (kernel(p) && !mountSet.has(p)) continue;
  let st;
  try { st = fs.lstatSync(p); } catch { continue; }
  swept++;
  if (st.isDirectory()) {
    const f = (p === "/" ? "" : p) + probeName;
    try { fs.writeFileSync(f, "x"); fs.unlinkSync(f); writable.push(p); } catch {}
    if (kernel(p)) continue;
    let ents = [];
    try { ents = fs.readdirSync(p, { withFileTypes: true }); } catch {}
    for (const d of ents) if (d.isDirectory() || d.isFile()) queue.push((p === "/" ? "" : p) + "/" + d.name);
  } else if (st.isFile()) {
    try { fs.closeSync(fs.openSync(p, "a")); writableFiles.push(p); } catch {}
  }
}
Object.assign(report, { swept, writable, writableFiles });
const tcp = (host, port) => new Promise(done => {
  const s = net.connect({ host, port });
  const t = setTimeout(() => { s.destroy(); done("timeout"); }, 3000);
  s.on("connect", () => { clearTimeout(t); s.destroy(); done("open"); });
  s.on("error", e => { clearTimeout(t); done(e.code || String(e)); });
});
const read = f => { try { return fs.readFileSync(f, "utf8").trim(); } catch (e) { return "unreadable: " + e.code; } };
(async () => {
  const egress = {};
  egress["tcp 1.1.1.1:443"] = await tcp("1.1.1.1", 443);
  egress["tcp 8.8.8.8:53"] = await tcp("8.8.8.8", 53);
  try { await fetch("https://example.com", { signal: AbortSignal.timeout(4000) }); egress["https://example.com"] = "open"; }
  catch (e) { egress["https://example.com"] = (e.cause && e.cause.code) || e.name || String(e); }
  report.egress = egress;
  report.dns = await new Promise(done => dns.lookup("example.com", { all: true }, (e, a) => done(e ? e.code : a.map(x => x.address).join(","))));
  report.memoryMax = read("/sys/fs/cgroup/memory.max");
  report.cpuMax = read("/sys/fs/cgroup/cpu.max");
  report.pidsMax = read("/sys/fs/cgroup/pids.max");
  report.tmpMount = read("/proc/mounts").split("\n").filter(l => l.split(" ")[1] === "/tmp").pop() || "";
  report.interfaces = read("/proc/net/dev").split("\n").slice(2).map(l => l.split(":")[0].trim()).filter(Boolean);
  process.stdout.write(JSON.stringify(report));
})();
`

// smokeProbe runs the probe and checks the writable set, egress and limits.
func (p *Provider) smokeProbe(ctx context.Context, b box, ev *smokeEvidence) error {
	pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := p.exec(pctx, b, []string{"node", "-"}, nil, []byte(smokeProbeScript), 1<<20, maxOutputBytes)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	if out.exitCode != 0 {
		return fmt.Errorf("probe exited %d on image %q (an image without node cannot serve runs): %s", out.exitCode, p.cfg.Image, strings.TrimSpace(string(out.stderr)))
	}
	var report struct {
		Node          string            `json:"node"`
		Swept         int               `json:"swept"`
		Writable      []string          `json:"writable"`
		WritableFiles []string          `json:"writableFiles"`
		Egress        map[string]string `json:"egress"`
		DNS           string            `json:"dns"`
		MemoryMax     string            `json:"memoryMax"`
		CPUMax        string            `json:"cpuMax"`
		TmpMount      string            `json:"tmpMount"`
		PidsMax       string            `json:"pidsMax"`
		Interfaces    []string          `json:"interfaces"`
	}
	if err := json.Unmarshal(out.stdout, &report); err != nil {
		return fmt.Errorf("unparseable probe report %q: %w", truncate(out.stdout, 200), err)
	}
	ev.Node, ev.Swept, ev.Writable, ev.WritableFiles = report.Node, report.Swept, report.Writable, report.WritableFiles
	ev.Egress, ev.DNS, ev.Interfaces = report.Egress, report.DNS, report.Interfaces
	ev.MemoryMax, ev.CPUMax, ev.PidsMax, ev.TmpMount = report.MemoryMax, report.CPUMax, report.PidsMax, report.TmpMount
	if err := checkWritable(report.Swept, report.Writable, report.WritableFiles); err != nil {
		return err
	}
	if err := checkEgress(report.Egress); err != nil {
		return err
	}
	if err := checkInterfaces(report.Interfaces); err != nil {
		return err
	}
	if err := checkTmpMount(report.TmpMount, p.cfg.DiskMB); err != nil {
		return err
	}
	return checkLimits(report.MemoryMax, report.CPUMax, p.cfg.memoryMB(), p.cfg.cpus())
}

// checkTmpMount proves the disk cap from inside the sandbox: with DiskMB set, /tmp
// must be a tmpfs of exactly that size (the kernel prints it in KiB) mounted noexec,
// nosuid and nodev. The per-run read-back only proves the gateway kept the driver
// config; this proves the driver turned it into the mount.
func checkTmpMount(line string, diskMB int) error {
	if diskMB <= 0 {
		return nil
	}
	f := strings.Fields(line)
	if len(f) < 4 || f[1] != "/tmp" || f[2] != "tmpfs" {
		return fmt.Errorf("SANDBOX_DISK_MB is set but /tmp is not a tmpfs inside the sandbox (mount line %q); the disk cap is not in force", truncate([]byte(line), 200))
	}
	opts := strings.Split(f[3], ",")
	for _, want := range []string{"noexec", "nosuid", "nodev", "size=" + strconv.Itoa(diskMB*1024) + "k"} {
		if !slices.Contains(opts, want) {
			return fmt.Errorf("/tmp is mounted %q, without %s; the disk cap is not in force as configured", f[3], want)
		}
	}
	return nil
}

// underTmp reports whether path is /tmp or beneath it: the only writable directory
// the policy grants.
func underTmp(path string) bool { return path == "/tmp" || strings.HasPrefix(path, "/tmp/") }

func checkWritable(swept int, dirs, files []string) error {
	if swept < minSwept {
		return fmt.Errorf("the write sweep tried only %d paths, too few to prove the writable set", swept)
	}
	sawTmp := false
	var outside []string
	for _, d := range dirs {
		if d == "/tmp" {
			sawTmp = true
		}
		if !underTmp(d) {
			outside = append(outside, d)
		}
	}
	for _, f := range files {
		if !underTmp(f) {
			outside = append(outside, f)
		}
	}
	if len(outside) > 0 {
		return fmt.Errorf("paths outside /tmp accept writes: %v; the filesystem policy is not in force", outside)
	}
	if !sawTmp {
		return errors.New("/tmp does not accept writes, so projects cannot run")
	}
	return nil
}

func checkEgress(egress map[string]string) error {
	if len(egress) == 0 {
		return errors.New("the probe reported no egress attempts")
	}
	for target, outcome := range egress {
		if outcome == "open" {
			return fmt.Errorf("egress is OPEN to %s; the deny-all network policy is not in force", target)
		}
	}
	return nil
}

// checkInterfaces holds the sandbox to loopback alone, as measured on a v0.1.2
// gateway's docker driver (2026-09-28). The egress attempts above prove only that
// nothing answered at that moment; an interface other than loopback means the
// sandbox has a network path that a policy, not its structure, is holding shut.
func checkInterfaces(ifaces []string) error {
	if len(ifaces) == 1 && ifaces[0] == "lo" {
		return nil
	}
	return fmt.Errorf("the sandbox's network interfaces are %q, not loopback alone", ifaces)
}

// checkLimits compares the sandbox's own cgroup files with the requested limits:
// memory.max in bytes, and cpu.max as "quota period" whose ratio is the CPU count.
func checkLimits(memoryMax, cpuMax string, memoryMB int, cpus float64) error {
	if want := strconv.Itoa(memoryMB << 20); memoryMax != want {
		return fmt.Errorf("the sandbox's memory.max is %q, want %s (%d MiB)", memoryMax, want, memoryMB)
	}
	quota, period, ok := strings.Cut(cpuMax, " ")
	q, qerr := strconv.ParseFloat(quota, 64)
	per, perr := strconv.ParseFloat(period, 64)
	if !ok || qerr != nil || perr != nil || per <= 0 || math.Abs(q/per-cpus) > 0.001 {
		return fmt.Errorf("the sandbox's cpu.max is %q, want a quota of %v CPU", cpuMax, cpus)
	}
	return nil
}

// smokeProject is a project at the size ceiling: a 4 MiB file whose JSON plan is
// about 6 MiB, since encoding/json escapes each '<' as six bytes. Its step writes the
// file's length and SHA-256, which the host compares with its own.
func smokeProject() (sandbox.ProjectRequest, string) {
	const mainJS = `const fs=require("fs"),c=require("crypto");
const pid=process.env.PLIMSOLL_RUNNER_PID;
if(!/^[0-9]+$/.test(pid||"")) throw new Error("runner pid missing");
for(const [path,flags] of [["/fd/0",fs.constants.O_RDONLY],
 ["/fd/1",fs.constants.O_RDONLY],["/fd/1",fs.constants.O_WRONLY],
 ["/mem",fs.constants.O_RDONLY]]){
  try{const fd=fs.openSync("/proc/"+pid+path,flags);fs.closeSync(fd);throw new Error("runner descriptor opened");}
  catch(e){if(e.code!=="EACCES" && e.code!=="EPERM") throw e;}
}
const b=fs.readFileSync("data/blob.txt");` +
		`fs.writeFileSync("out.txt",b.length+" "+c.createHash("sha256").update(b).digest("hex"));`
	const line = "abcdefghi<abcdefghi<abcdefghi<abcdefghi<abcdefghi<abcdefghi<abcdefghi<abcdefghi<abcdefghi<abcdefgh\n"
	size := sandbox.MaxProjectBytes - len(mainJS) - 1024
	blob := strings.Repeat(line, size/len(line)+1)[:size]
	return sandbox.ProjectRequest{
		Files:     []sandbox.File{{Path: "main.js", Content: mainJS}, {Path: "data/blob.txt", Content: blob}},
		Steps:     []string{"node main.js"},
		Artifacts: []string{"out.txt"},
	}, fmt.Sprintf("%d %x", len(blob), sha256.Sum256([]byte(blob)))
}

func (p *Provider) smokeRunner(ctx context.Context, b box, tier sandbox.IsolationClass, ev *smokeEvidence) error {
	req, want := smokeProject()
	if err := sandbox.ValidateProjectRequest(req); err != nil {
		return err
	}
	const stepTimeout = 60 * time.Second
	key, err := runnerwire.NewKey()
	if err != nil {
		return err
	}
	plan := runnerwire.Plan{Steps: req.Steps, StepTimeout: stepTimeout, Artifacts: req.Artifacts, ReportKey: key}
	for _, f := range req.Files {
		plan.Files = append(plan.Files, runnerwire.File(f))
	}
	planJSON, err := plan.Encode()
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, stepTimeout+runnerGrace)
	defer cancel()
	start := time.Now()
	res, err := p.runPlan(rctx, b, tier, planJSON, key, nil)
	ev.PlanBytes, ev.RoundTrip = len(planJSON), time.Since(start)
	if err != nil {
		return err
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		detail := res.Detail
		if len(res.Steps) > 0 {
			detail += " " + truncate([]byte(res.Steps[0].Stderr), 300)
		}
		return fmt.Errorf("outcome %v with %d steps: %s", res.Outcome, len(res.Steps), strings.TrimSpace(detail))
	}
	if len(res.Artifacts) != 1 || string(res.Artifacts[0].Content) != want {
		return fmt.Errorf("the step's artifact does not match the %d-byte plan's content", len(planJSON))
	}
	return nil
}

// smokeKill starts a command that never ends and forks a second that never ends,
// waits until both run, cancels the exec stream, and requires a second exec to find
// neither left.
func (p *Provider) smokeKill(ctx context.Context, b box, ev *smokeEvidence) error {
	marker := "plimsoll-hang-" + randHex(6)
	hang := []string{"sh", "-c", "node -e 'setInterval(() => {}, 1000)' " + marker + " & exec node -e 'setInterval(() => {}, 1000)' " + marker}
	// The counting script reaches the sandbox on stdin, so its own command line does
	// not carry the marker it counts.
	countScript := []byte(`const fs = require("fs"); let n = 0;
for (const d of fs.readdirSync("/proc")) {
  if (!/^[0-9]+$/.test(d)) continue;
  try { if (fs.readFileSync("/proc/" + d + "/cmdline", "latin1").includes("` + marker + `")) n++; } catch {}
}
process.stdout.write(String(n));`)
	count := func() (int, error) {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		out, err := p.exec(cctx, b, []string{"node", "-"}, nil, countScript, 64, maxOutputBytes)
		if err != nil {
			return 0, fmt.Errorf("process count: %w", err)
		}
		if out.exitCode != 0 {
			return 0, fmt.Errorf("process count exited %d: %s", out.exitCode, truncate(out.stderr, 200))
		}
		return strconv.Atoi(string(out.stdout))
	}

	hangCtx, stopHang := context.WithCancel(ctx)
	defer stopHang()
	type result struct {
		out execOutput
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := p.exec(hangCtx, b, hang, nil, nil, maxOutputBytes, maxOutputBytes)
		done <- result{out, err}
	}()
	stop := func() result {
		stopHang()
		return <-done
	}
	for deadline := time.Now().Add(15 * time.Second); ; {
		n, err := count()
		if err != nil {
			stop()
			return err
		}
		if n >= 2 {
			ev.HungProcesses = n
			break
		}
		select {
		case r := <-done:
			return fmt.Errorf("the hung command ended before it was cancelled (exited=%v, exit %d): %v", r.out.exited, r.out.exitCode, r.err)
		default:
		}
		if time.Now().After(deadline) {
			stop()
			return fmt.Errorf("the hung command never started (%d of its processes seen)", n)
		}
		if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
			stop()
			return err
		}
	}
	cancelled := time.Now()
	if r := stop(); r.out.exited {
		return fmt.Errorf("the hung command exited on its own (exit %d)", r.out.exitCode)
	}
	for deadline := time.Now().Add(p.killWait); ; {
		n, err := count()
		if err != nil {
			return err
		}
		if n == 0 {
			ev.KillConfirmed = time.Since(cancelled)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("cancelling the exec stream left %d of its processes running after %v; the run deadline would not stop hostile code", n, time.Since(cancelled).Round(time.Millisecond))
		}
		if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
