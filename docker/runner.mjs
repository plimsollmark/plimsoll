// In-sandbox project runner. Reads a JSON "plan" from stdin, writes the project
// files into the work dir, runs each step in order (stopping on the first
// failure), and emits the per-step results as JSON after a sentinel so the host
// can separate them from any incidental output.
//
// Runs INSIDE the locked-down container (no network, read-only root, non-root).
// It still validates file paths defensively so a plan cannot write outside the
// work dir even within the sandbox.
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";

const WORK = resolve(process.env.PLIMSOLL_WORK || "/work");
const SENTINEL = "<<<CRSBX_RESULT>>>";
const MAX_STEP_OUTPUT = 1 << 20; // 1 MiB per step stream
const MAX_ARTIFACT_BYTES = 8 << 20; // 8 MiB total across all captured artifacts
const MAX_STEPS_JSON = 3 << 20; // encoded step metadata/output across the run
const MAX_RESULT_JSON = 15 << 20; // host cap is 16 MiB; reserve framing headroom

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
  process.stdout.write("\n" + SENTINEL + encoded);
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
// MAX_ARTIFACT_BYTES; truncated reports that an existing file was dropped.
function captureArtifacts(paths) {
  const out = [];
  let total = 0;
  for (const p of paths ?? []) {
    const dest = resolve(WORK, p);
    if (dest !== WORK && !dest.startsWith(WORK + "/")) continue; // never escape WORK
    if (!existsSync(dest)) continue;
    const info = statSync(dest);
    if (!info.isFile()) continue; // skip dirs
    if (total + info.size > MAX_ARTIFACT_BYTES) return { artifacts: out, truncated: true };
    const buf = readFileSync(dest);
    total += buf.length;
    out.push({ path: p, content: buf.toString("base64") });
  }
  return { artifacts: out, truncated: false };
}

try {
  const plan = JSON.parse(readFileSync(0, "utf8"));

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
  // The module only defines the global; the unix socket (HOST_API_SOCKET, inherited
  // from the container env) and the host-side bearer stay outside the guest.
  let stepEnv; // undefined → spawnSync inherits the container env unchanged
  if (typeof plan.hostSDK === "string" && plan.hostSDK.length > 0) {
    const sdkPath = "/tmp/plimsoll-host.mjs";
    writeFileSync(sdkPath, plan.hostSDK);
    const preload = "--import=file://" + sdkPath;
    stepEnv = { ...process.env };
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
