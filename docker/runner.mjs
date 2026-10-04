// In-sandbox project runner. Reads a JSON "plan" from stdin, writes the project
// files into the work dir, runs each step in order (stopping on the first
// failure), and emits the per-step results as one authenticated JSON frame so the
// host can separate them from any incidental output.
//
// Every step runs as this process's uid. The launcher makes this process
// non-dumpable before Node starts, and the check below proves a child cannot open
// its plan descriptor, report descriptor, or memory before the plan is read. The
// host trusts only a frame signed with the plan's reportKey (HMAC-SHA256). The key
// arrives on stdin, is removed from the plan at once, and is never put in the
// environment, argv, a file or the output.
//
// Runs INSIDE the locked-down container (no network, read-only root, non-root).
// It still validates file paths defensively so a plan cannot write outside the
// work dir even within the sandbox.
import { spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdirSync, writeFileSync, readFileSync, readlinkSync, realpathSync, openSync, fstatSync, closeSync, constants } from "node:fs";
import { resolve, dirname } from "node:path";

const WORK = resolve(process.env.PLIMSOLL_WORK || "/work");
const MARKER = "<<<PLIMSOLL_REPORT_V3>>>"; // must match runnerwire.Marker
let reportKey = null; // set from the plan; a frame without it cannot verify
const MAX_STEP_OUTPUT = 1 << 20; // 1 MiB per step stream
const MAX_ARTIFACT_BYTES = 8 << 20; // 8 MiB total across all captured artifacts
const MAX_STEPS_JSON = 3 << 20; // encoded step metadata/output across the run
const MAX_RESULT_JSON = 15 << 20; // host cap is 16 MiB; reserve framing headroom

// A loader may silently ignore a missing LD_PRELOAD library. Verify the effect on
// this exact process, not just that the launcher named the library. The probe is a
// child with our uid, just like a project step. Clear LD_PRELOAD before spawning it
// and all later steps so the guard is confined to the runner.
function verifyRunnerIsolation() {
  delete process.env.LD_PRELOAD;
  const probe = `const fs=require("node:fs");
const p="/proc/"+process.ppid;
const checks=[[p+"/fd/0",fs.constants.O_RDONLY],[p+"/fd/1",fs.constants.O_RDONLY],
  [p+"/fd/1",fs.constants.O_WRONLY],[p+"/mem",fs.constants.O_RDONLY]];
const results=[];
for(const [path,flags] of checks){
  try{const fd=fs.openSync(path,flags);fs.closeSync(fd);results.push("open");}
  catch(e){results.push(e.code||"unknown");}
}
process.stdout.write(results.join(","));`;
  const r = spawnSync(process.execPath, ["-e", probe], {
    encoding: "utf8", timeout: 5000, maxBuffer: 4096,
  });
  const codes = (r.stdout ?? "").split(",");
  if (r.error || r.status !== 0 || codes.length !== 4 ||
      codes.some(code => code !== "EACCES" && code !== "EPERM")) {
    throw new Error("runner descriptor and memory isolation could not be proven");
  }
}

function emit(payload) {
  let encoded = JSON.stringify(payload);
  // Artifacts are best-effort. If path/metadata escaping pushes a valid result
  // over the host framing budget, drop artifacts from the end but always emit
  // complete JSON; a truncated sentinel payload is unusable. Dropping any is
  // reported via the machine-readable artifactsTruncated flag.
  while (Buffer.byteLength(encoded) > MAX_RESULT_JSON && payload.artifacts?.length) {
    payload.artifacts.pop();
    payload.artifactsTruncated = true;
    encoded = JSON.stringify(payload);
  }
  if (Buffer.byteLength(encoded) > MAX_RESULT_JSON) {
    encoded = JSON.stringify({ error: "sandbox result exceeds the encoded response budget" });
  }
  const body = Buffer.from(encoded, "utf8");
  // Without a key the frame is still written, so the host sees a report arrive, but
  // its MAC cannot verify and the host classifies the run as a protocol error.
  const mac = reportKey ? createHmac("sha256", reportKey).update(body).digest("hex") : "0".repeat(64);
  process.stdout.write(Buffer.concat([Buffer.from("\n" + MARKER + " " + body.length + " " + mac + "\n"), body]));
}

function capEncodedSteps(steps, step) {
  if (Buffer.byteLength(JSON.stringify({ steps })) <= MAX_STEPS_JSON) return;

  // Preserve the command/outcome, then fit stdout and stderr into the remaining
  // ENCODED JSON budget. JSON escaping can expand a control byte to six bytes,
  // so raw string lengths are not a safe cap. Truncation is reported via the
  // step's stdoutTruncated/stderrTruncated flags, never an in-band marker.
  const values = { stdout: step.stdout, stderr: step.stderr };
  step.stdout = "";
  step.stderr = "";
  let encodedSize = Buffer.byteLength(JSON.stringify({ steps }));
  for (const field of ["stdout", "stderr"]) {
    const value = values[field] ?? "";
    let low = 0;
    let high = value.length;
    let best = "";
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const candidate = value.slice(0, mid);
      // The empty string's JSON encoding ("") is already in encodedSize.
      const delta = Buffer.byteLength(JSON.stringify(candidate)) - 2;
      if (encodedSize + delta <= MAX_STEPS_JSON) {
        best = candidate;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    if (best.length < value.length) step[field + "Truncated"] = true;
    step[field] = best;
    encodedSize += Buffer.byteLength(JSON.stringify(best)) - 2;
  }
}

// captureArtifacts reads each requested (existing) file under WORK and returns
// {artifacts: [{path, content}], truncated} with base64 content, bounded by
// MAX_ARTIFACT_BYTES; truncated reports that an existing file was dropped. A path
// is resolved through any links first and must still lie under WORK, and the file
// is opened without following a final link, so a link planted in WORK cannot pull
// in a file from elsewhere in the sandbox.
function captureArtifacts(paths) {
  const out = [];
  let total = 0;
  let workReal;
  try { workReal = realpathSync(WORK); } catch { return { artifacts: out, truncated: false }; }
  for (const p of paths ?? []) {
    const dest = resolve(WORK, p);
    if (dest !== WORK && !dest.startsWith(WORK + "/")) continue; // never escape WORK
    let real;
    try { real = realpathSync(dest); } catch { continue; } // missing
    if (real !== workReal && !real.startsWith(workReal + "/")) continue; // a link out of WORK
    let fd;
    try { fd = openSync(real, constants.O_RDONLY | constants.O_NOFOLLOW); } catch { continue; }
    try {
      // O_NOFOLLOW guards only the last component: a step left running can swap a
      // parent directory for a link between realpathSync and openSync. The kernel
      // knows what was opened, so ask it, and keep only a file inside WORK.
      let opened;
      try { opened = readlinkSync("/proc/self/fd/" + fd); } catch { continue; }
      if (!opened.startsWith(workReal + "/")) continue;
      const info = fstatSync(fd);
      if (!info.isFile()) continue; // skip dirs, devices, fifos
      if (total + info.size > MAX_ARTIFACT_BYTES) return { artifacts: out, truncated: true };
      const buf = readFileSync(fd);
      total += buf.length;
      out.push({ path: p, content: buf.toString("base64") });
    } finally {
      closeSync(fd);
    }
  }
  return { artifacts: out, truncated: false };
}

try {
  verifyRunnerIsolation();
  const plan = JSON.parse(readFileSync(0, "utf8"));
  // Take the key and drop it from the plan before anything else runs.
  const key = Buffer.from(typeof plan.reportKey === "string" ? plan.reportKey : "", "hex");
  delete plan.reportKey;
  if (key.length !== 32) throw new Error("plan carries no report key");
  reportKey = key;

  for (const f of plan.files ?? []) {
    const dest = resolve(WORK, f.path ?? "");
    if (dest !== WORK && !dest.startsWith(WORK + "/")) {
      throw new Error(`illegal file path: ${f.path}`);
    }
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.content ?? "");
  }

  // When the run carries a host-API grant, preload the brokered host.* client into
  // every Node step process as a global (node --import), so project files use the
  // SAME globalThis[host] contract as a snippet instead of an import. Written outside
  // WORK so it is never linted/compiled as project source nor captured as an artifact.
  // The module only defines the global; the unix socket (HOST_API_SOCKET, in the
  // plan's env) and the host-side bearer stay outside the guest.
  //
  // Steps start with the runner's environment plus the plan's env entries, which win.
  // The docker provider starts this runner with none of the image's environment (so
  // nothing the image declares can change what the runner does) and hands that
  // environment to the steps here instead.
  const stepEnv = { ...process.env };
  for (const entry of Array.isArray(plan.env) ? plan.env : []) {
    const eq = typeof entry === "string" ? entry.indexOf("=") : -1;
    if (eq <= 0) throw new Error("plan env entry is not NAME=value");
    stepEnv[entry.slice(0, eq)] = entry.slice(eq + 1);
  }
  stepEnv.PLIMSOLL_RUNNER_PID = String(process.pid);
  if (typeof plan.hostSDK === "string" && plan.hostSDK.length > 0) {
    const sdkPath = "/tmp/plimsoll-host.mjs";
    writeFileSync(sdkPath, plan.hostSDK);
    const preload = "--import=file://" + sdkPath;
    stepEnv.NODE_OPTIONS = stepEnv.NODE_OPTIONS ? stepEnv.NODE_OPTIONS + " " + preload : preload;
  }

  const steps = [];
  for (const command of plan.steps ?? []) {
    const start = Date.now();
    const r = spawnSync("sh", ["-c", command], {
      cwd: WORK,
      env: stepEnv,
      encoding: "utf8",
      timeout: plan.stepTimeoutMs || undefined,
      // SIGKILL, not Node's default SIGTERM: a step that ignores SIGTERM would run on
      // past its budget until the outer backstop killed the container and every
      // step's report with it.
      killSignal: "SIGKILL",
      maxBuffer: MAX_STEP_OUTPUT,
    });
    const timedOut = r.error?.code === "ETIMEDOUT";
    // Exceeding maxBuffer (ENOBUFS) kills the child and truncates the offending
    // stream at the cap; flag the stream(s) that plausibly hit it.
    const overflowed = r.error?.code === "ENOBUFS";
    const stdout = r.stdout ?? "";
    const stderr = r.stderr ?? (r.error ? String(r.error.message) : "");
    const step = {
      command: String(command).slice(0, 16 << 10),
      stdout,
      stderr,
      stdoutTruncated: overflowed && Buffer.byteLength(stdout) >= MAX_STEP_OUTPUT,
      stderrTruncated: overflowed && Buffer.byteLength(stderr) >= MAX_STEP_OUTPUT,
      exitCode: timedOut ? 124 : (r.status ?? -1),
      timedOut,
      durationMs: Date.now() - start,
    };
    steps.push(step);
    capEncodedSteps(steps, step);
    if (timedOut || (r.status ?? 1) !== 0) break; // stop the chain on failure
  }

  // Capture artifacts even if a step failed, so partial output is still returned.
  const captured = captureArtifacts(plan.artifacts);
  emit({ steps, artifacts: captured.artifacts, artifactsTruncated: captured.truncated });
} catch (err) {
  emit({ error: String(err?.message ?? err) });
}
