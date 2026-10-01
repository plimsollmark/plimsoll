// Errors keep the daemon's one distinction that matters for a retry: whether
// anything ran. A refusal raised before dispatch carries the NotDispatched detail
// and comes back with notDispatched set; anything else may have followed
// execution and is never a safe automatic retry (docs/run-results.md).

import type { WireError } from "./wire.ts";

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

  constructor(
    code: Code,
    message: string,
    opts: { notDispatched?: Refusal; sessionEnded?: { reason: SessionEnd; detail: string }; result?: unknown; cause?: unknown } = {},
  ) {
    super(message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "PlimsollError";
    this.code = code;
    this.notDispatched = opts.notDispatched;
    this.sessionEnded = opts.sessionEnded;
    this.result = opts.result;
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

/** The error a Connect error body describes, with its plimsoll details restored. */
export function errorFromWire(httpStatus: number, body: WireError | undefined): PlimsollError {
  const code = (body?.code as Code | undefined) ?? httpStatusCode(httpStatus);
  let notDispatched: Refusal | undefined;
  let sessionEnded: { reason: SessionEnd; detail: string } | undefined;
  for (const d of body?.details ?? []) {
    try {
      const bytes = Buffer.from(d.value ?? "", "base64");
      if (d.type === "plimsoll.v1.NotDispatched") {
        notDispatched = REFUSALS[decodeDetail(bytes).reason] ?? "unknown";
      } else if (d.type === "plimsoll.v1.SessionEnded") {
        const m = decodeDetail(bytes);
        sessionEnded = { reason: sessionEndFromWire(m.reason), detail: m.detail };
      }
    } catch {
      // An undecodable detail states nothing; in particular not that nothing ran.
    }
  }
  return new PlimsollError(code, body?.message ?? `HTTP ${httpStatus}`, { notDispatched, sessionEnded });
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
