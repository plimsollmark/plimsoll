// Session checkpoints (Go: client.Checkpoint, Python: SessionCheckpoint), so another
// process can carry on with a session: PlimsollClient.attachSession. A checkpoint is a
// session's public chain head (the ownership generation, the count of calls and the last
// record's digest) and the policy the session stated at open. It holds no secret: not the
// session ID, not a credential. The application keeps it where only it can write: anyone
// holding the caller's credential and a session's checkpoint (or its run records, which
// carry the fingerprint and the head) can take the session over. This client has no store:
// the application owns it, as in Go.

import { PlimsollError } from "./errors.ts";
import { validQualification } from "./record.ts";
import {
  CHECKPOINT_VERSION,
  DAEMON_NAME_PATTERN,
  FLOORS,
  MAX_SOFTWARE_IDENTITY_BYTES,
  SOFTWARE_IDENTITY_PATTERN,
  SOFTWARE_RULE_ID_PATTERN,
} from "./tables.gen.ts";

export type SessionCheckpoint = {
  version: number;
  /** The application's own name for the daemon (ClientOptions.daemonName), never a URL. */
  daemon: string;
  /** The fingerprint: the SHA-256 of the session ID, 64 lowercase hex digits. */
  session: string;
  generation: bigint;
  calls: bigint;
  lastRecordSha256: string;
  provider: string;
  isolation: string;
  isolationQualification: string;
  softwareIdentity: string;
  /** The floor sent at open, as the daemon echoed it; "" for none. */
  openFloor: string;
  /** The ID of the software rule sent at open, "" for none. */
  openRule: string;
  expiresUnixMs: number;
  idleTimeoutMs: number;
  /**
   * The request digest of a call that was sent once with no answer reaching any worker (an
   * attach explained the gap it left), which the session's next call is refused for
   * repeating (CallAlreadySentError); "" for none. A checkpoint carries it until that next
   * call, unless the daemon refused that call with the not-dispatched mark: nothing ran, so
   * the call after it is still the next.
   */
  lostCallSha256: string;
};

const DAEMON_NAME = new RegExp(DAEMON_NAME_PATTERN);
const RULE_ID = new RegExp(SOFTWARE_RULE_ID_PATTERN);
const IDENTITY = new RegExp(SOFTWARE_IDENTITY_PATTERN);
const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const UINT64_MAX = (1n << 64n) - 1n;

/** @internal Whether name is a daemon name: 1 to 64 of [A-Za-z0-9._-], never a URL. */
export function validDaemonName(name: unknown): name is string {
  return typeof name === "string" && DAEMON_NAME.test(name);
}

const isFloor = (s: unknown): s is string => typeof s === "string" && (FLOORS as readonly string[]).includes(s);
const whole = (v: unknown, lo: number, hi: number): v is number => typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi;
const utf8Bytes = (s: string): number => Buffer.byteLength(s, "utf8");

/** What is wrong with cp, or undefined when it is a checkpoint this client can attach with. */
export function checkpointProblem(cp: SessionCheckpoint): string | undefined {
  if (cp === null || typeof cp !== "object") return "not an object";
  if (cp.version !== CHECKPOINT_VERSION) return "unknown version";
  if (!validDaemonName(cp.daemon)) return "the daemon name is not 1 to 64 of [A-Za-z0-9._-]";
  if (typeof cp.session !== "string" || !HEX64.test(cp.session)) return "the fingerprint is not 64 lowercase hex digits";
  if (typeof cp.generation !== "bigint" || cp.generation < 1n || cp.generation > UINT64_MAX) return "the generation is not a positive 64-bit number";
  if (typeof cp.calls !== "bigint" || cp.calls < 0n || cp.calls > UINT64_MAX || typeof cp.lastRecordSha256 !== "string") return "the count of calls is not a 64-bit number";
  if ((cp.calls === 0n) !== (cp.lastRecordSha256 === "") || (cp.calls > 0n && !HEX64.test(cp.lastRecordSha256))) return "the last record does not match the count of calls";
  if (typeof cp.provider !== "string" || cp.provider === "" || utf8Bytes(cp.provider) > 256 || !cp.provider.isWellFormed()) return "the provider is empty or malformed";
  if (!isFloor(cp.isolation)) return "the tier is not one a session runs at";
  if (typeof cp.isolationQualification !== "string" || !validQualification(cp.isolationQualification)) return "the isolation qualification is malformed";
  const id = cp.softwareIdentity;
  if (typeof id !== "string" || (id !== "" && (utf8Bytes(id) > MAX_SOFTWARE_IDENTITY_BYTES || !IDENTITY.test(id)))) return "the software identity is malformed";
  if (cp.openFloor !== "" && !isFloor(cp.openFloor)) return "the open floor is not a tier";
  if (cp.openFloor !== "" && FLOORS.indexOf(cp.isolation as (typeof FLOORS)[number]) < FLOORS.indexOf(cp.openFloor as (typeof FLOORS)[number])) {
    return "the tier is below the open floor";
  }
  if (typeof cp.openRule !== "string" || (cp.openRule !== "" && !RULE_ID.test(cp.openRule))) return "the open rule is not a software rule's ID";
  if (!whole(cp.expiresUnixMs, 1, Number.MAX_SAFE_INTEGER)) return "the expiry is not a positive time";
  if (!whole(cp.idleTimeoutMs, 0, 2 ** 32 - 1)) return "the idle timeout is not a 32-bit number";
  if (typeof cp.lostCallSha256 !== "string" || (cp.lostCallSha256 !== "" && (!HEX64.test(cp.lostCallSha256) || cp.calls === 0n))) {
    return "the lost call is not a request digest of a call the session ran";
  }
  return undefined;
}

function invalid(problem: string): PlimsollError {
  return new PlimsollError("invalid_argument", `plimsoll: invalid session checkpoint: ${problem}`, { notDispatched: "request" });
}

/** Throws (invalid_argument, not dispatched) unless cp validates. */
export function validateCheckpoint(cp: SessionCheckpoint): void {
  const problem = checkpointProblem(cp);
  if (problem) throw invalid(problem);
}

// The JSON form's keys, in the order every official client writes them.
const KEYS = [
  ["version", "version"],
  ["daemon", "daemon"],
  ["session", "session"],
  ["generation", "generation"],
  ["calls", "calls"],
  ["last_record_sha256", "lastRecordSha256"],
  ["provider", "provider"],
  ["isolation", "isolation"],
  ["isolation_qualification", "isolationQualification"],
  ["software_identity", "softwareIdentity"],
  ["open_floor", "openFloor"],
  ["open_rule", "openRule"],
  ["expires_unix_ms", "expiresUnixMs"],
  ["idle_timeout_ms", "idleTimeoutMs"],
  ["lost_call_sha256", "lostCallSha256"],
] as const;

/**
 * The JSON form every official client reads: these snake_case keys, every one present,
 * the generation and the count as decimal strings (a number cannot hold every uint64).
 */
export function checkpointToJSON(cp: SessionCheckpoint): string {
  validateCheckpoint(cp);
  const out: Record<string, unknown> = {};
  for (const [wire, key] of KEYS) {
    const v = cp[key];
    out[wire] = typeof v === "bigint" ? v.toString() : v;
  }
  return JSON.stringify(out);
}

/** Reads the JSON form: one object holding every key and no other. Throws invalid_argument. */
export function parseCheckpoint(text: string): SessionCheckpoint {
  let d: unknown;
  try {
    d = JSON.parse(text);
  } catch (e) {
    throw invalid((e as Error).message);
  }
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw invalid("not an object");
  const o = d as Record<string, unknown>;
  const names = Object.keys(o).sort();
  const want = KEYS.map(([w]) => w as string).sort();
  if (names.length !== want.length || names.some((n, i) => n !== want[i])) throw invalid("the object does not hold exactly the checkpoint's keys");
  for (const k of ["generation", "calls"]) {
    if (typeof o[k] !== "string" || !DECIMAL.test(o[k] as string)) throw invalid(`${k} is not a decimal string with no leading zero`);
  }
  const cp: Record<string, unknown> = {};
  for (const [wire, key] of KEYS) cp[key] = wire === "generation" || wire === "calls" ? BigInt(o[wire] as string) : o[wire];
  validateCheckpoint(cp as SessionCheckpoint);
  return cp as SessionCheckpoint;
}
