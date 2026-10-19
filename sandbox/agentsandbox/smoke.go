package agentsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

const (
	// smokeTimeout bounds the whole smoke test: two claims, each a cold start at worst.
	smokeTimeout = 120 * time.Second
	// minSwept is the fewest paths the write sweep must have tried; a sweep that tried
	// nothing would report an empty writable set and prove nothing.
	minSwept = 100
	// kubeletPort is the kubelet's API on every node, the first thing a pod that could
	// reach its node would try.
	kubeletPort = "10250"
)

// smokeEvidence is what the last passing SmokeTest measured, logged at startup.
type smokeEvidence struct {
	Node       string
	Swept      int
	Writable   []string
	Files      []string
	Egress     map[string]string
	Interfaces []string
	Gateway    string
	Kernel     string
	Seccomp    string
	Queues     string
	Mounts     map[string]string
	Filled     []string
}

// boundaryScript runs as the guest with `node -`; the two %s are the JSON list of
// host:port targets the provider adds (the API server's addresses) and the volumes to fill,
// as [mount path, size limit in bytes] pairs. It reports who it runs as, its environment
// and resolver, a write attempted at every path it can reach, how much each volume took
// before it refused, each connection attempt's outcome, and what kernel answers it.
const boundaryScript = `const fs = require("fs"), net = require("net"), cp = require("child_process");
const extra = %s, fills = %s;
const read = f => { try { return fs.readFileSync(f, "utf8"); } catch (e) { return "unreadable: " + e.code; } };
const status = read("/proc/self/status");
const field = n => ((status.match(new RegExp("^" + n + ":[ \\t]*(.*)$", "m")) || [])[1] || "").trim();
const report = { node: process.version, uid: field("Uid"), gid: field("Gid"), groups: field("Groups"),
  capEff: field("CapEff"), capPrm: field("CapPrm"), noNewPrivs: field("NoNewPrivs"), seccomp: field("Seccomp"),
  env: Object.keys(process.env).sort(), resolv: read("/etc/resolv.conf"), version: read("/proc/version").trim() };
try { report.dmesg = cp.execFileSync("dmesg", { encoding: "utf8", timeout: 3000, maxBuffer: 1 << 20 }).split("\n")[0]; }
catch (e) { report.dmesg = "error: " + (e.code || e.status); }
const mountLines = read("/proc/mounts").trim().split("\n");
report.mounts = mountLines;
const mounts = mountLines.map(l => l.split(" ")[1].replace(/\\040/g, " "));
const mountSet = new Set(mounts);
const kernel = p => p === "/proc" || p.startsWith("/proc/") || p === "/sys" || p.startsWith("/sys/");
const queue = ["/", "/bin", "/dev", "/dev/shm", "/dev/mqueue", "/etc", "/home", "/lib", "/media", "/mnt", "/opt", "/root",
  "/run", "/sbin", "/srv", "/tmp", "/usr", "/usr/local", "/var", "/var/tmp", "/var/log", "/work", process.cwd(), ...mounts];
const seen = new Set(), writable = [], files = [], created = [];
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
    try { fs.writeFileSync(f, "x"); fs.unlinkSync(f); writable.push(p); }
    catch { try { fs.lstatSync(f); created.push(p); fs.unlinkSync(f); } catch {} }
    if (kernel(p)) continue;
    let ents = [];
    try { ents = fs.readdirSync(p, { withFileTypes: true }); } catch {}
    for (const d of ents) if (d.isDirectory() || d.isFile()) queue.push((p === "/" ? "" : p) + "/" + d.name);
  } else if (st.isFile()) {
    try { fs.closeSync(fs.openSync(p, "a")); files.push(p); } catch {}
  }
}
Object.assign(report, { swept, writable, files, created });
report.msgqueue = (read("/proc/self/limits").match(/^Max msgqueue size\s+(\S+)/m) || [])[1] || "";
report.fill = {};
for (const [dir, size] of fills) {
  const f = dir + "/.plimsoll-fill-" + process.pid, b = Buffer.alloc(1 << 20, 120);
  let wrote = 0, code = "none";
  try { const fd = fs.openSync(f, "w"); try { while (wrote <= size + (8 << 20)) { wrote += fs.writeSync(fd, b); } } finally { fs.closeSync(fd); } }
  catch (e) { code = e.code || String(e); }
  try { fs.unlinkSync(f); } catch {}
  report.fill[dir] = { wrote, code };
}
report.interfaces = read("/proc/net/dev").split("\n").slice(2).map(l => l.split(":")[0].trim()).filter(Boolean);
const route = read("/proc/net/route").trim().split("\n").slice(1).map(l => l.trim().split(/\s+/))
  .find(f => f[1] === "00000000" && /^[0-9A-F]{8}$/i.test(f[2] || "") && f[2] !== "00000000");
report.gateway = route ? [6, 4, 2, 0].map(i => parseInt(route[2].substr(i, 2), 16)).join(".") : "";
const tcp = (host, port) => new Promise(done => {
  const s = net.connect({ host, port: +port });
  const t = setTimeout(() => { s.destroy(); done("timeout"); }, 2500);
  s.on("connect", () => { clearTimeout(t); s.destroy(); done("open"); });
  s.on("error", e => { clearTimeout(t); done(e.code || String(e)); });
});
const targets = ["1.1.1.1:443", "8.8.8.8:53", "169.254.169.254:80", ...extra];
if (report.gateway) targets.push(report.gateway + ":` + kubeletPort + `");
(async () => {
  const outcomes = await Promise.all(targets.map(t => { const i = t.lastIndexOf(":"); return tcp(t.slice(0, i).replace(/^\[|\]$/g, ""), t.slice(i + 1)); }));
  report.egress = Object.fromEntries(targets.map((t, i) => ["tcp " + t, outcomes[i]]));
  process.stdout.write(JSON.stringify(report));
})();
`

// runnerScript is a project step: it finds the runner that started it, then tries what
// a step could take from it or from sandboxd (root, pid 1): the plan and report
// descriptors and memory. Every open must be refused.
const runnerScript = `const fs = require("fs");
const ppid = pid => { const s = fs.readFileSync("/proc/" + pid + "/stat", "utf8"); return +s.slice(s.lastIndexOf(")") + 2).split(" ")[1]; };
let pid = process.ppid, runner = 0;
for (let i = 0; i < 8 && pid > 0; i++, pid = ppid(pid)) {
  if (fs.readFileSync("/proc/" + pid + "/cmdline", "utf8").split("\0").includes("` + runnerPath + `")) { runner = pid; break; }
}
if (!runner) { console.log("no runner among this step's ancestors"); process.exit(9); }
const r = "/proc/" + runner, o = fs.constants;
const checks = [[r + "/fd/0", o.O_RDONLY], [r + "/fd/1", o.O_RDONLY], [r + "/fd/1", o.O_WRONLY], [r + "/mem", o.O_RDONLY],
  ["/proc/1/mem", o.O_RDONLY], ["/proc/1/environ", o.O_RDONLY], ["/proc/1/fd/0", o.O_RDONLY]];
const out = {};
for (const [p, flags] of checks) {
  try { fs.closeSync(fs.openSync(p, flags)); out[p + ":" + flags] = "open"; } catch (e) { out[p + ":" + flags] = e.code || String(e); }
}
console.log(JSON.stringify(out));
if (Object.values(out).some(v => v !== "EACCES" && v !== "EPERM")) process.exit(8);
`

// SmokeTest proves at startup, on sandboxes claimed as every run claims them, what the
// read-back cannot see:
//   - the guest runs as the guest uid with no capability, no_new_privs, only PATH and HOME,
//     and the fixed resolver;
//   - a write attempted at every path the guest can reach succeeds only beneath the
//     template's emptyDir mounts and /dev/shm, nowhere else can it even create a file
//     (message queues in /dev/mqueue excepted, while the guest's allowance is bounded), and
//     nowhere is a file outside them open for append;
//   - no connection leaves the pod: the internet, cloud metadata, the API server and the
//     node's kubelet all time out or are unreachable, never open or refused (a refusal is
//     an answer, so the packet left);
//   - the kernel tier's handler really is gVisor: the guest's kernel log is gVisor's;
//   - the vm tier's handler really is a VM: the guest's kernel log begins with a Linux boot
//     and its boot ID is not its node's, and every writable root is a tmpfs of that kernel,
//     so in the VM's memory (no volume is filled: under Kata none keeps its size limit);
//   - under the container tier, a seccomp filter is in force on the guest;
//   - a project step can open neither the runner's plan and report descriptors and memory
//     nor sandboxd's.
//
// The template and namespace policy UIDs and specs it ran on are then the only ones
// accepted; policy changes seen during either test also fail the proof.
//
// Each check is its own claim, as each run is: one command per pod, every request that
// carries sandboxd's token sent before guest code starts. It claims two sandboxes and
// deletes them, so plimsolld runs it once at startup, never on a poll path.
func (p *Provider) SmokeTest(ctx context.Context) error {
	if err := p.Preflight(ctx); err != nil {
		return fmt.Errorf("agentsandbox smoke: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, smokeTimeout)
	defer cancel()
	if err := p.bindPolicies(ctx); err != nil {
		return fmt.Errorf("agentsandbox smoke: %w", err)
	}
	tier := p.IsolationClass()
	p.mu.Lock()
	proving := p.templateSum
	p.mu.Unlock()
	ev, err := p.smokeBoundary(ctx, tier)
	if err != nil {
		return fmt.Errorf("agentsandbox smoke: %w", err)
	}
	if err := p.smokeRunner(ctx); err != nil {
		return fmt.Errorf("agentsandbox smoke: runner: %w", err)
	}
	if err := p.bindPolicies(ctx); err != nil {
		return fmt.Errorf("agentsandbox smoke: %w", err)
	}
	p.mu.Lock()
	p.smoke, p.proven = &ev, proving
	p.mu.Unlock()
	slog.Info("agentsandbox smoke passed", "tier", tier.String(), "template", p.templateName(), "node", ev.Node,
		"swept", ev.Swept, "writable", ev.Writable, "files", ev.Files, "egress", ev.Egress, "interfaces", ev.Interfaces,
		"gateway", ev.Gateway, "kernel", ev.Kernel, "seccomp", ev.Seccomp, "queues", ev.Queues, "mounts", ev.Mounts, "filled", ev.Filled)
	return nil
}

// apiTargets are the API server's addresses as host:port, for the egress check: the
// configured host if it is an address, else what it resolves to here.
func (p *Provider) apiTargets(ctx context.Context) []string {
	u, err := url.Parse(p.cfg.APIServer)
	if err != nil {
		return nil
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}
	}
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.String(), port))
	}
	return out
}

type boundaryReport struct {
	Node       string            `json:"node"`
	UID        string            `json:"uid"`
	GID        string            `json:"gid"`
	Groups     string            `json:"groups"`
	CapEff     string            `json:"capEff"`
	CapPrm     string            `json:"capPrm"`
	NoNewPrivs string            `json:"noNewPrivs"`
	Seccomp    string            `json:"seccomp"`
	Env        []string          `json:"env"`
	Resolv     string            `json:"resolv"`
	Version    string            `json:"version"`
	Dmesg      string            `json:"dmesg"`
	Mounts     []string          `json:"mounts"`
	Swept      int               `json:"swept"`
	Writable   []string          `json:"writable"`
	Files      []string          `json:"files"`
	Created    []string          `json:"created"`
	Msgqueue   string            `json:"msgqueue"`
	Interfaces []string          `json:"interfaces"`
	Gateway    string            `json:"gateway"`
	Egress     map[string]string `json:"egress"`
	Fill       map[string]struct {
		Wrote int64  `json:"wrote"`
		Code  string `json:"code"`
	} `json:"fill"`
}

// smokeBoundary runs the boundary script as a snippet, through the run path itself.
func (p *Provider) smokeBoundary(ctx context.Context, tier sandbox.IsolationClass) (smokeEvidence, error) {
	targets, err := json.Marshal(p.apiTargets(ctx))
	if err != nil {
		return smokeEvidence{}, err
	}
	fills := [][2]any{}
	sizes := p.mounts()
	for _, m := range slices.Sorted(maps.Keys(sizes)) {
		if tier != sandbox.IsolationVM {
			fills = append(fills, [2]any{m, sizes[m]})
		}
	}
	fillJSON, err := json.Marshal(fills)
	if err != nil {
		return smokeEvidence{}, err
	}
	res, err := p.RunJavaScript(ctx, sandbox.Request{Code: fmt.Sprintf(boundaryScript, targets, fillJSON), Timeout: 30 * time.Second})
	if err != nil {
		return smokeEvidence{}, fmt.Errorf("boundary test: %w", err)
	}
	if res.ExitCode != 0 || res.StdoutTruncated {
		return smokeEvidence{}, fmt.Errorf("boundary test exited %d (truncated %t) on image %q: %s", res.ExitCode, res.StdoutTruncated, p.cfg.Image, truncate(res.Stderr, 300))
	}
	var r boundaryReport
	if err := json.Unmarshal([]byte(res.Stdout), &r); err != nil {
		return smokeEvidence{}, fmt.Errorf("unparseable boundary report %q: %w", truncate(res.Stdout, 200), err)
	}
	ev := smokeEvidence{Node: r.Node, Swept: r.Swept, Writable: r.Writable, Files: r.Files, Egress: r.Egress,
		Interfaces: r.Interfaces, Gateway: r.Gateway, Kernel: r.Dmesg, Seccomp: r.Seccomp, Mounts: map[string]string{}}
	roots, err := p.writableRoots()
	if err != nil {
		return ev, err
	}
	for _, line := range r.Mounts {
		if f := strings.Fields(line); len(f) >= 4 && slices.Contains(roots, f[1]) {
			ev.Mounts[f[1]] = f[2] + " " + f[3]
		}
	}
	for m, f := range r.Fill {
		ev.Filled = append(ev.Filled, fmt.Sprintf("%s %d MiB then %s", m, f.Wrote>>20, f.Code))
	}
	slices.Sort(ev.Filled)
	created, qerr := checkMqueue(r)
	if slices.Contains(r.Created, mqueueDir) && qerr == nil {
		ev.Queues = "created in " + mqueueDir + ", at most " + r.Msgqueue + " bytes for the guest's uid"
	}
	fill := checkFill(r, sizes)
	if tier == sandbox.IsolationVM {
		fill = checkRootMountKinds(r.Mounts, roots, []string{"tmpfs"})
	}
	return ev, errors.Join(checkIdentity(r), qerr, checkWritable(r.Swept, slices.Concat(r.Writable, created), r.Files, roots), checkNestedMounts(r.Mounts, roots), fill,
		checkEgress(r.Egress, r.Gateway), checkKernel(tier, r.Dmesg), checkSeccompMode(tier, r.Seccomp))
}

// checkNestedMounts refuses every mount strictly beneath a writable root, at every tier.
// A root's tmpfs and size limit say nothing about a file mounted inside it, including a
// termination log whose parent directory in the image was a symlink to that root.
func checkNestedMounts(mounts, roots []string) error {
	if len(mounts) == 0 {
		return errors.New("the guest reported no mount table")
	}
	for _, line := range mounts {
		f := strings.Fields(line)
		if len(f) != 6 {
			return fmt.Errorf("unparseable guest mount line %q", line)
		}
		// proc mounts escapes space, tab, newline and backslash with octal sequences.
		m := decodeMountPath(f[1])
		if !path.IsAbs(m) || path.Clean(m) != m {
			return fmt.Errorf("guest mount point %q is not a clean absolute path", m)
		}
		for _, root := range roots {
			if strings.HasPrefix(m, root+"/") {
				return fmt.Errorf("mount point %s is beneath writable root %s; the root's memory backing and size limit cannot cover it", m, root)
			}
		}
	}
	return nil
}

// decodeMountPath shares proc's four escape forms across all mount checks.
func decodeMountPath(p string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(p)
}

// checkRootMountKinds requires every writable root to have one of the filesystem
// types permitted by the verified tier's view (the last mount at a path is the one it sees). The per-pod
// check has shown the guest's kernel is the VM's own, so a tmpfs of it lives in the VM's
// memory and cannot reach the node's disk. Its size limit is not checked, since Kata keeps
// none: runtime-rs mounts it with no size and the Go runtime with the VM's whole memory.
func checkRootMountKinds(mounts, roots, allowed []string) error {
	fstype := map[string]string{}
	for _, line := range mounts {
		if f := strings.Fields(line); len(f) >= 3 {
			fstype[decodeMountPath(f[1])] = f[2]
		}
	}
	var errs []error
	for _, r := range roots {
		if t := fstype[r]; !slices.Contains(allowed, t) {
			errs = append(errs, fmt.Errorf("%s is mounted as %q in the guest, outside the allowed filesystem view %v", r, t, allowed))
		}
	}
	return errors.Join(errs...)
}

// checkFill requires every volume to have refused a write once its size limit was full
// (ENOSPC, give or take the last 1 MiB chunk): the cap is the tmpfs's, not a promise.
func checkFill(r boundaryReport, sizes map[string]int64) error {
	var errs []error
	for m, size := range sizes {
		f, ok := r.Fill[m]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s was not filled", m))
		case f.Code != "ENOSPC" || f.Wrote > size+1<<20 || f.Wrote < size-(8<<20):
			errs = append(errs, fmt.Errorf("%s took %d bytes against a size limit of %d and then said %q, not ENOSPC at its limit", m, f.Wrote, size, f.Code))
		}
	}
	return errors.Join(errs...)
}

// smokeRunner runs a project whose one step tries the runner's and sandboxd's
// descriptors and memory, through the project path itself.
func (p *Provider) smokeRunner(ctx context.Context) error {
	res, err := p.RunProject(ctx, sandbox.ProjectRequest{
		Files: []sandbox.File{{Path: "runner-probe.js", Content: runnerScript}}, Steps: []string{"node runner-probe.js"}, Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.Outcome != sandbox.ProjectOutcomeCompleted || len(res.Steps) != 1 || res.Steps[0].ExitCode != 0 {
		detail := ""
		if len(res.Steps) > 0 {
			detail = truncate(res.Steps[0].Stdout, 300)
		}
		return fmt.Errorf("the step reached the runner or sandboxd: outcome %s (%s), %s", res.Outcome, res.Detail, detail)
	}
	return nil
}

// writableRoots are the directories where the guest may write: the template container's
// emptyDir mount paths (the read-back allows no other volume) and /dev/shm, the
// runtime's own sized tmpfs.
func (p *Provider) writableRoots() ([]string, error) { return writableRoots(p.mounts()) }

func writableRoots(mounts map[string]int64) ([]string, error) {
	roots := []string{"/dev/shm"}
	for m := range mounts {
		roots = append(roots, path.Clean(m))
	}
	slices.Sort(roots)
	if !slices.Contains(roots, workDir) {
		return nil, fmt.Errorf("the template mounts no volume at %s, sandboxd's root directory", workDir)
	}
	return roots, nil
}

func checkIdentity(r boundaryReport) error {
	uid := fmt.Sprint(guestUID)
	ids := strings.Join([]string{uid, uid, uid, uid}, "\t")
	var errs []error
	if r.UID != ids || r.GID != ids || r.Groups != "" {
		errs = append(errs, fmt.Errorf("the guest runs as uid %q gid %q groups %q, not %d alone", r.UID, r.GID, r.Groups, guestUID))
	}
	if r.CapEff != "0000000000000000" || r.CapPrm != "0000000000000000" || r.NoNewPrivs != "1" {
		errs = append(errs, fmt.Errorf("the guest holds capabilities %s/%s or lacks no_new_privs (%q)", r.CapEff, r.CapPrm, r.NoNewPrivs))
	}
	if !slices.Equal(r.Env, []string{"HOME", "PATH"}) {
		errs = append(errs, fmt.Errorf("the guest's environment holds %q, not PATH and HOME alone", r.Env))
	}
	var lines []string
	for _, l := range strings.Split(r.Resolv, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if !slices.Equal(lines, []string{"nameserver " + fixedNameserver}) {
		errs = append(errs, fmt.Errorf("the guest's resolver is %q, not the one loopback nameserver", lines))
	}
	return errors.Join(errs...)
}

// mqueueDir is the POSIX message queue filesystem runc mounts in every container. A
// directory there takes no data, but an open with O_CREAT makes a queue: kernel memory in
// the pod's own IPC namespace (the read-back refuses a host one), freed with the pod and
// never on the node's disk, at most RLIMIT_MSGQUEUE bytes for the guest's uid (819,200 by
// default, as 256 queues of ten 8 KiB messages). That allowance is counted per uid across
// the node, so concurrent guests share it: one can deny the others queues, never read
// theirs. Measured on runc 2026-10-17; gVisor offered no writable queue directory.
const mqueueDir = "/dev/mqueue"

// maxMsgqueueBytes is the largest RLIMIT_MSGQUEUE the smoke test accepts for the guest:
// the kernel's default with room, so a node that lifted the limit is refused, not reported.
const maxMsgqueueBytes = 1 << 20

// checkMqueue takes the message queue directory out of the paths where the sweep created
// a file, when the mount there is an mqueue filesystem and the guest's queue allowance is
// finite and small, and returns the rest: anywhere else a create that succeeds is a write.
func checkMqueue(r boundaryReport) ([]string, error) {
	var rest []string
	queues := false
	for _, p := range r.Created {
		if p == mqueueDir {
			queues = true
		} else {
			rest = append(rest, p)
		}
	}
	if !queues {
		return rest, nil
	}
	mounted := slices.ContainsFunc(r.Mounts, func(l string) bool {
		f := strings.Fields(l)
		return len(f) >= 3 && f[1] == mqueueDir && f[2] == "mqueue"
	})
	limit, err := strconv.ParseInt(r.Msgqueue, 10, 64)
	if !mounted || err != nil || limit < 0 || limit > maxMsgqueueBytes {
		return append(rest, mqueueDir), fmt.Errorf("the guest can create message queues in %s with an allowance of %q bytes (mqueue mounted there: %t), not a finite one of at most %d",
			mqueueDir, r.Msgqueue, mounted, maxMsgqueueBytes)
	}
	return rest, nil
}

// checkWritable requires the sweep to have tried enough paths, /work to accept writes,
// and every writable directory and file to lie beneath a writable root.
func checkWritable(swept int, dirs, files, roots []string) error {
	if swept < minSwept {
		return fmt.Errorf("the write sweep tried only %d paths, too few to prove the writable set", swept)
	}
	beneath := func(p string) bool {
		return slices.ContainsFunc(roots, func(r string) bool { return p == r || strings.HasPrefix(p, r+"/") })
	}
	var outside []string
	for _, p := range slices.Concat(dirs, files) {
		if !beneath(p) {
			outside = append(outside, p)
		}
	}
	if len(outside) > 0 {
		return fmt.Errorf("paths outside %v accept writes: %v", roots, outside)
	}
	if !slices.Contains(dirs, workDir) {
		return fmt.Errorf("%s does not accept the guest's writes, so projects cannot run", workDir)
	}
	return nil
}

// checkEgress requires every connection attempt to have gone unanswered or to have been
// refused inside the pod (EACCES, EPERM). A connection refused by its destination is an
// answer: the packet left the pod, so it fails as an open connection does.
func checkEgress(egress map[string]string, gateway string) error {
	if len(egress) == 0 {
		return errors.New("the boundary test reported no connection attempts")
	}
	if gateway == "" {
		return errors.New("the boundary test found no default route, so the node's kubelet was not tried")
	}
	var reached []string
	for target, outcome := range egress {
		switch outcome {
		case "timeout", "EHOSTUNREACH", "ENETUNREACH", "EACCES", "EPERM": // unanswered, or refused before it left
		default:
			reached = append(reached, target+" "+outcome)
		}
	}
	if len(reached) > 0 {
		slices.Sort(reached)
		return fmt.Errorf("connections left the pod: %v; no network policy in force denies the pod's egress", reached)
	}
	return nil
}

// gvisorBoot is the first line of gVisor's kernel log, as its Sentry writes it at boot.
var gvisorBoot = regexp.MustCompile(`^\[ *0\.000000\] Starting gVisor\.\.\.$`)

// linuxBoot is the first line a Linux kernel writes to its log at boot.
var linuxBoot = regexp.MustCompile(`^\[ *0\.000000\] Linux version \S+ `)

// checkKernel holds the kernel tier to gVisor's own kernel log, and the vm tier to a
// Linux kernel's boot line. The runtime class's handler is only a name in the node's
// runtime configuration, which could map runsc to runc; under gVisor an unprivileged guest
// reads gVisor's log, and under runc the host's is refused. The line must be gVisor's boot
// line exactly: a host's log can name gVisor too (live on kind, a runc pod read the host's
// "Killed process (gvisor_sentry)"). Under Kata the guest reads its VM's log, which begins
// with that kernel's boot; so can a runc pod on a node whose log has not yet wrapped, which
// is why the vm tier also needs checkOwnKernel. Like docker's runtime banner this is not
// attestation, but a handler that names one runtime and a guest that sees another kernel is
// refused rather than reported.
func checkKernel(tier sandbox.IsolationClass, dmesg string) error {
	switch {
	case tier == sandbox.IsolationKernel && !gvisorBoot.MatchString(dmesg):
		return fmt.Errorf("the runtime class's handler is runsc but the guest's kernel log begins %q, not gVisor's", truncate([]byte(dmesg), 120))
	case tier == sandbox.IsolationVM && !linuxBoot.MatchString(dmesg):
		return fmt.Errorf("the runtime class's handler is Kata's but the guest's kernel log begins %q, not a Linux kernel's boot", truncate([]byte(dmesg), 120))
	}
	return nil
}

// bootID is the form of /proc/sys/kernel/random/boot_id, a random UUID each boot.
var bootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// checkOwnKernel holds the vm tier to a kernel that is not its node's: the guest's boot ID
// must differ from the one the node's kubelet reports, which is the node kernel's own. A
// runc pod shares its node's kernel and so its boot ID; a Kata pod's VM boots a kernel of
// its own (measured on kind and AKS, 2026-10-18). A node's root could forge both, so this
// catches a node whose Kata handler runs another runtime, not a hostile node; nor a kubelet
// that reads a boot ID of its own container's (systemd-nspawn mounts one), which a runc pod
// on that node would not share.
func checkOwnKernel(tier sandbox.IsolationClass, guest, node string) error {
	if tier != sandbox.IsolationVM {
		return nil
	}
	switch {
	case !bootID.MatchString(guest):
		return fmt.Errorf("the guest's boot ID reads %q, not a boot ID", truncate([]byte(guest), 60))
	case node == "":
		return errors.New("the node reports no boot ID, so the guest's kernel cannot be told from the node's")
	case !bootID.MatchString(strings.ToLower(node)):
		return fmt.Errorf("the node's boot ID reads %q, not a boot ID, so the guest's kernel cannot be told from the node's", truncate([]byte(node), 60))
	case strings.EqualFold(guest, node):
		return fmt.Errorf("the runtime class's handler is Kata's but the guest's boot ID %s is its node's: the pod runs on the node's kernel", guest)
	}
	return nil
}

// checkSeccompMode holds the container tier to a seccomp filter in force on the guest: its
// status says mode 2 (filter), which the read-back's RuntimeDefault or Localhost profile
// should give (checkSeccomp) and a runtime that ignored it would not. It proves a filter,
// not which one. Under gVisor the guest's status is the Sentry's emulation, which says nothing about the
// host filter the Sentry itself runs under, so the kernel tier is held to checkKernel.
func checkSeccompMode(tier sandbox.IsolationClass, mode string) error {
	if tier == sandbox.IsolationContainer && mode != "2" {
		return fmt.Errorf("the container tier needs a seccomp filter on the guest, and its status says mode %q, not 2", mode)
	}
	return nil
}

func truncate[T string | []byte](b T, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// lastSmoke returns what the last passing SmokeTest measured, or nil.
func (p *Provider) lastSmoke() *smokeEvidence {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.smoke
}
