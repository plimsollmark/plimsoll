// Errors keep the daemon's one distinction that matters for a retry: whether
// anything ran. A refusal raised before dispatch carries the NotDispatched detail
// and comes back with notDispatched set; anything else may have followed
// execution and is never a safe automatic retry (docs/run-results.md).

import type { RunRecord } from "./record.ts";
import type { WireError, WireRecord } from "./wire.ts";

/** Why a request was refused before any code ran (plimsoll.v1.NotDispatchedReason). */
export type Refusal = "request" | "permission" | "protocol" | "unsupported" | "isolation" | "capacity" | "environment" | "unknown";

/** Why a session ended (plimsoll.v1.SessionEnd), "open" while it has not. */
export type SessionEnd =
  | "open"
  | "closed"
  | "expired"
  | "disk_exceeded"
  | "main_process_ended"
  | "boundary_failed"
  | "sandbox_changed"
  | "shutdown";

/**
 * Connect's status codes, plus the two this client raises itself:
 * "data_loss" for an answer that does not check (the run may have executed),
 * and "invalid_argument" for a request refused before it was sent.
 */
export type Code =
  | "canceled"
  | "unknown"
  | "invalid_argument"
  | "deadline_exceeded"
  | "not_found"
  | "already_exists"
  | "permission_denied"
  | "resource_exhausted"
  | "failed_precondition"
  | "aborted"
  | "out_of_range"
  | "unimplemented"
  | "internal"
  | "unavailable"
  | "data_loss"
  | "unauthenticated";

export class PlimsollError extends Error {
  readonly code: Code;
  /**
   * Set when the daemon stated that nothing ran. Undefined means execution may
   * have occurred, whatever the code.
   */
  readonly notDispatched: Refusal | undefined;
  /** Set when a session call was refused because its session had ended. */
  readonly sessionEnded: { reason: SessionEnd; detail: string } | undefined;
  /**
   * The result the daemon returned, on a "data_loss" error raised after it
   * answered: the record or the isolation evidence did not check, the run may
   * have executed, and this is what came back.
   */
  readonly result: unknown;
  /**
   * The record the daemon sends with a session call that may have run but ended in
   * an error (a version 3 record, as it came off the wire). The Session checks it
   * and keeps it in its chain, so the session goes on; the call's outcome is unknown.
   */
  readonly unanswered: WireRecord | undefined;
  /**
   * That record once the Session has checked it against the call and its chain (Go:
   * UnansweredCallError.Record); undefined otherwise.
   */
  record: RunRecord | undefined;

  constructor(
    code: Code,
    message: string,
    opts: { notDispatched?: Refusal; sessionEnded?: { reason: SessionEnd; detail: string }; result?: unknown; unanswered?: WireRecord; cause?: unknown } = {},
  ) {
    super(message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "PlimsollError";
    this.code = code;
    this.notDispatched = opts.notDispatched;
    this.sessionEnded = opts.sessionEnded;
    this.result = opts.result;
    this.unanswered = opts.unanswered;
  }
}

const REFUSALS: Refusal[] = ["unknown", "request", "permission", "protocol", "unsupported", "isolation", "capacity", "environment"];

const SESSION_ENDS: SessionEnd[] = [
  "open",
  "closed",
  "expired",
  "disk_exceeded",
  "main_process_ended",
  "boundary_failed",
  "sandbox_changed",
  "shutdown",
];

export function sessionEndFromWire(v: string | number | undefined): SessionEnd {
  if (v === undefined) return "open";
  if (typeof v === "number") return SESSION_ENDS[v] ?? "open";
  const name = v.replace(/^SESSION_END_/, "").toLowerCase();
  return name === "unspecified" ? "open" : ((SESSION_ENDS as string[]).includes(name) ? (name as SessionEnd) : "open");
}

// Reads one varint at b[i]; returns [value, next index].
function varint(b: Uint8Array, i: number): [number, number] {
  let v = 0;
  let shift = 0;
  for (; i < b.length && shift < 35; shift += 7) {
    const c = b[i++]!;
    v += (c & 0x7f) * 2 ** shift;
    if ((c & 0x80) === 0) return [v, i];
  }
  throw new Error("bad varint");
}

// Decodes the two tiny detail messages by hand (field 1 an enum, field 2 a
// string), so the client needs no protobuf runtime.
function decodeDetail(b: Uint8Array): { reason: number; detail: string } {
  let reason = 0;
  let detail = "";
  let i = 0;
  while (i < b.length) {
    const [tag, j] = varint(b, i);
    i = j;
    const field = Math.floor(tag / 8);
    const wire = tag & 7;
    if (wire === 0) {
      const [v, k] = varint(b, i);
      i = k;
      if (field === 1) reason = v;
    } else if (wire === 2) {
      const [n, k] = varint(b, i);
      if (k + n > b.length) throw new Error("bad length");
      if (field === 2) detail = Buffer.from(b.subarray(k, k + n)).toString("utf8");
      i = k + n;
    } else {
      throw new Error("unexpected wire type");
    }
  }
  return { reason, detail };
}

// Reads one varint at b[i] as a bigint (an int64 or uint64 field); returns [value,
// next index].
function bigVarint(b: Uint8Array, i: number): [bigint, number] {
  let v = 0n;
  for (let shift = 0n; i < b.length && shift < 70n; shift += 7n) {
    const c = b[i++]!;
    v |= BigInt(c & 0x7f) << shift;
    if ((c & 0x80) === 0) return [v, i];
  }
  throw new Error("bad varint");
}

const RECORD_STRINGS: Record<number, keyof WireRecord> = {
  2: "requestSha256", 3: "resultSha256", 4: "provider", 5: "isolation", 6: "environment", 7: "policy",
  10: "session", 12: "previousSha256", 13: "recordSha256", 14: "softwareIdentity", 15: "softwareRuleId", 16: "unanswered",
};

// Decodes an UnansweredCall detail (field 1, a RunRecord) by hand, into the record's
// proto3 JSON form, so the record checks exactly as one read off a JSON answer.
function decodeUnanswered(b: Uint8Array): WireRecord | undefined {
  let rec: WireRecord | undefined;
  for (let i = 0; i < b.length; ) {
    const [tag, j] = varint(b, i);
    const [n, k] = varint(b, j);
    if ((tag & 7) !== 2 || k + n > b.length) throw new Error("bad detail");
    if (tag >>> 3 === 1) rec = decodeRecord(b.subarray(k, k + n));
    i = k + n;
  }
  return rec;
}

function decodeRecord(b: Uint8Array): WireRecord {
  const m: Record<string, unknown> = {};
  for (let i = 0; i < b.length; ) {
    const [tag, j] = varint(b, i);
    const field = Math.floor(tag / 8);
    const wire = tag & 7;
    i = j;
    if (wire === 0) {
      const [v, k] = bigVarint(b, i);
      i = k;
      if (field === 1) m.version = Number(v);
      else if (field === 8) m.startedUnixMs = BigInt.asIntN(64, v).toString();
      else if (field === 9) m.endedUnixMs = BigInt.asIntN(64, v).toString();
      else if (field === 11) m.sequence = v.toString();
    } else if (wire === 2) {
      const [n, k] = varint(b, i);
      if (k + n > b.length) throw new Error("bad length");
      const name = RECORD_STRINGS[field];
      if (name) m[name] = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(k, k + n));
      i = k + n;
    } else if (wire === 1) {
      i += 8;
    } else if (wire === 5) {
      i += 4;
    } else {
      throw new Error("unexpected wire type");
    }
  }
  return m as WireRecord;
}

/** The error a Connect error body describes, with its plimsoll details restored. */
export function errorFromWire(httpStatus: number, body: WireError | undefined): PlimsollError {
  const code = (body?.code as Code | undefined) ?? httpStatusCode(httpStatus);
  let notDispatched: Refusal | undefined;
  let sessionEnded: { reason: SessionEnd; detail: string } | undefined;
  let unanswered: WireRecord | undefined;
  for (const d of body?.details ?? []) {
    try {
      const bytes = Buffer.from(d.value ?? "", "base64");
      if (d.type === "plimsoll.v1.NotDispatched") {
        notDispatched = REFUSALS[decodeDetail(bytes).reason] ?? "unknown";
      } else if (d.type === "plimsoll.v1.SessionEnded") {
        const m = decodeDetail(bytes);
        sessionEnded = { reason: sessionEndFromWire(m.reason), detail: m.detail };
      } else if (d.type === "plimsoll.v1.UnansweredCall") {
        unanswered = decodeUnanswered(bytes);
      }
    } catch {
      // An undecodable detail states nothing; in particular not that nothing ran.
    }
  }
  return new PlimsollError(code, body?.message ?? `HTTP ${httpStatus}`, { notDispatched, sessionEnded, unanswered: notDispatched ? undefined : unanswered });
}

// Connect's mapping for a response without a Connect error body.
function httpStatusCode(status: number): Code {
  switch (status) {
    case 400:
      return "internal";
    case 401:
      return "unauthenticated";
    case 403:
      return "permission_denied";
    case 404:
      return "unimplemented";
    case 429:
    case 502:
    case 503:
    case 504:
      return "unavailable";
    default:
      return "unknown";
  }
}
