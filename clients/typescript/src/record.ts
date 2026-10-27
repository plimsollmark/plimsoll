// Run-record digests, computed from docs/run-records.md alone: lowercase hex
// SHA-256 over a length-prefixed encoding, never over protobuf or JSON bytes.
// The golden vectors in record/record_test.go are checked in test/record.test.ts.

import { createHash, type Hash } from "node:crypto";

import { PlimsollError } from "./errors.ts";
import { OUTCOMES, TIERS } from "./tables.gen.ts";

import { wireBytes, WireShapeError, type WireRecord, type WireRunResponse, type WireSoftwareRule } from "./wire.ts";

/** The record encoding version this client computes and checks: every field, every time, for an answered call and an unanswered session call alike. */
export const RECORD_VERSION = 4;

const INSTANCE_FORM = /^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9._:-]{1,127}$/;

/** A record's instance: "" (the provider names none) or a typed reference such as `k8s-pod-uid:` and a pod's UID. */
export function validInstance(s: string): boolean {
  return s === "" || INSTANCE_FORM.test(s);
}

const UNANSWERED_CODES = new Set([
  "canceled", "unknown", "invalid_argument", "deadline_exceeded", "not_found", "already_exists", "permission_denied",
  "resource_exhausted", "failed_precondition", "aborted", "out_of_range", "unimplemented", "internal", "unavailable",
  "data_loss", "unauthenticated",
]);

class Encoder {
  private readonly h: Hash = createHash("sha256");

  constructor(domain: string) {
    this.value(Buffer.from(domain, "utf8"));
  }

  private value(b: Uint8Array): void {
    const n = Buffer.alloc(8);
    n.writeBigUInt64BE(BigInt(b.length));
    this.h.update(n);
    this.h.update(b);
  }

  bytes(name: string, v: Uint8Array): void {
    this.value(Buffer.from(name, "utf8"));
    this.value(v);
  }

  str(name: string, v: string): void {
    // A lone surrogate (JSON can escape one) has no UTF-8 form: Buffer would put
    // U+FFFD in its place and digest other bytes than the daemon did.
    if (!v.isWellFormed()) throw new PlimsollError("data_loss", `plimsoll: ${name} is not well-formed text (a lone surrogate)`);
    this.bytes(name, Buffer.from(v, "utf8"));
  }

  // Integers are decimal ASCII; callers pass bigint for 64-bit values so no
  // millisecond timestamp or sequence number is rounded through a double.
  int(name: string, v: number | bigint): void {
    this.str(name, BigInt(v).toString(10));
  }

  bool(name: string, v: boolean): void {
    this.str(name, v ? "true" : "false");
  }

  floats(name: string, vs: readonly number[]): void {
    const b = Buffer.alloc(8 * vs.length);
    vs.forEach((v, i) => b.writeDoubleBE(v, 8 * i));
    this.bytes(name, b);
  }

  sum(): string {
    return this.h.digest("hex");
  }
}

/** The payload of a request as the digest sees it. */
export type DigestPayload =
  | { kind: "javascript"; code: string; grantProfile: string }
  | { kind: "cell"; language: string; code: string; files: readonly { path: string; content: string }[] }
  | {
      kind: "project";
      grantProfile: string;
      files: readonly { path: string; content: string }[];
      steps: readonly string[];
      artifacts: readonly string[];
    };

export type DigestRequest = {
  protocol: number;
  minimumIsolation: string;
  timeoutMs: number;
  softwareRule: WireSoftwareRule | undefined;
  payload: DigestPayload;
};

/** The request digest of a Run request or a session call (the same fields). */
export function requestDigest(r: DigestRequest): string {
  // A protocol 1 request (the records of version 1) has the first encoding: no software rule.
  const first = r.protocol < 2;
  const e = new Encoder(first ? "plimsoll.run-request.v1" : "plimsoll.run-request.v2");
  e.int("protocol", r.protocol);
  e.str("minimum_isolation", r.minimumIsolation);
  e.int("timeout_ms", r.timeoutMs);
  if (!first) {
    const ids = r.softwareRule?.identities ?? [];
    e.str("software_mode", r.softwareRule?.mode ?? "");
    e.int("software_identities", ids.length);
    for (const id of ids) e.str("software_identity", id);
  }
  const p = r.payload;
  e.str("kind", p.kind);
  if (p.kind === "javascript") {
    e.str("code", p.code);
    e.str("grant_profile", p.grantProfile);
  } else if (p.kind === "cell") {
    e.str("language", p.language);
    e.str("code", p.code);
    e.int("files", p.files.length);
    for (const f of p.files) {
      e.str("file_path", f.path);
      e.str("file_content", f.content);
    }
  } else {
    e.str("grant_profile", p.grantProfile);
    e.int("files", p.files.length);
    for (const f of p.files) {
      e.str("file_path", f.path);
      e.str("file_content", f.content);
    }
    e.int("steps", p.steps.length);
    for (const s of p.steps) e.str("step_command", s);
    e.int("artifacts", p.artifacts.length);
    for (const a of p.artifacts) e.str("artifact_path", a);
  }
  return e.sum();
}


/**
 * Why a live answer's record version is refused: a newer daemon (upgrade the client) or an
 * older one. A live answer must carry the current version; it is never called forged.
 */
function versionProblem(version: number): string {
  return version > RECORD_VERSION
    ? `a newer daemon answered with run record version ${version}; this client reads version ${RECORD_VERSION}: upgrade the client`
    : `the daemon answered with run record version ${version}; this client requires version ${RECORD_VERSION} of a live answer`;
}

/** The wire enum's number; an unknown name is undefined, which fails the check. */
export function outcomeNumber(name: string | number | undefined): number | undefined {
  if (name === undefined) return 0;
  if (typeof name === "number") return name;
  return OUTCOMES[name];
}

const b64 = wireBytes;

/** The result digest of a Run response as it arrived on the wire. */
export function resultDigest(resp: WireRunResponse): string {
  const e = new Encoder("plimsoll.run-result.v1");
  if (resp.javascript) {
    const j = resp.javascript;
    e.str("kind", "javascript");
    e.int("exit_code", j.exitCode ?? 0);
    e.bool("timed_out", j.timedOut ?? false);
    e.bytes("stdout", b64(j.stdout));
    e.bytes("stderr", b64(j.stderr));
    e.bool("stdout_truncated", j.stdoutTruncated ?? false);
    e.bool("stderr_truncated", j.stderrTruncated ?? false);
  } else if (resp.project) {
    const p = resp.project;
    e.str("kind", "project");
    e.int("outcome", outcomeNumber(p.outcome) ?? -1);
    e.str("outcome_detail", p.outcomeDetail ?? "");
    e.bool("artifacts_truncated", p.artifactsTruncated ?? false);
    const steps = p.steps ?? [];
    e.int("steps", steps.length);
    for (const s of steps) {
      e.str("step_command", s.command ?? "");
      e.int("step_exit_code", s.exitCode ?? 0);
      e.bool("step_timed_out", s.timedOut ?? false);
      e.bytes("step_stdout", b64(s.stdout));
      e.bytes("step_stderr", b64(s.stderr));
      e.bool("step_stdout_truncated", s.stdoutTruncated ?? false);
      e.bool("step_stderr_truncated", s.stderrTruncated ?? false);
    }
    const artifacts = p.artifacts ?? [];
    e.int("artifacts", artifacts.length);
    for (const a of artifacts) {
      e.str("artifact_path", a.path ?? "");
      e.bytes("artifact_content", b64(a.content));
    }
  } else if (resp.cell) {
    const c = resp.cell;
    e.str("kind", "cell");
    e.int("exit_code", c.exitCode ?? 0);
    e.bool("timed_out", c.timedOut ?? false);
    e.bytes("stdout", b64(c.stdout));
    e.bytes("stderr", b64(c.stderr));
    e.bool("stdout_truncated", c.stdoutTruncated ?? false);
    e.bool("stderr_truncated", c.stderrTruncated ?? false);
    e.bool("interpreter_started", c.interpreterStarted ?? false);
    e.bool("interpreter_ended", c.interpreterEnded ?? false);
  } else {
    // A module result, or none: this client sends neither, so the record check
    // refuses the response as not of the request's kind, after this digest is
    // computed and found not to match.
    e.str("kind", "");
  }
  return e.sum();
}

/** A record as this client reads it off the wire, every field present. */
export type RunRecord = {
  version: number;
  requestSha256: string;
  resultSha256: string;
  provider: string;
  isolation: string;
  environment: string;
  policy: string;
  softwareIdentity: string;
  softwareRuleId: string;
  startedUnixMs: bigint;
  endedUnixMs: bigint;
  session: string;
  sequence: bigint;
  previousSha256: string;
  /** On an unanswered call's record, the Connect code a session call that may have run ended with. */
  unanswered: string;
  /** The sandbox instance that ran the call, as the response states it, or "". */
  instance: string;
  sha256: string;
};

// big reads a 64-bit integer field the JSON codec sends as a decimal string (or a
// number). Anything else is an answer this client cannot read, a PlimsollError,
// never BigInt's own SyntaxError or RangeError.
function big(v: string | number | undefined, name: string): bigint {
  if (v === undefined) return 0n;
  if ((typeof v === "string" && /^-?[0-9]{1,20}$/.test(v)) || (typeof v === "number" && Number.isSafeInteger(v))) return BigInt(v);
  throw new PlimsollError("data_loss", `plimsoll: the record's ${name} is not an integer`);
}

export function recordFromWire(m: WireRecord): RunRecord {
  return {
    version: m.version ?? 0,
    requestSha256: m.requestSha256 ?? "",
    resultSha256: m.resultSha256 ?? "",
    provider: m.provider ?? "",
    isolation: m.isolation ?? "",
    environment: m.environment ?? "",
    policy: m.policy ?? "",
    softwareIdentity: m.softwareIdentity ?? "",
    softwareRuleId: m.softwareRuleId ?? "",
    startedUnixMs: big(m.startedUnixMs, "startedUnixMs"),
    endedUnixMs: big(m.endedUnixMs, "endedUnixMs"),
    session: m.session ?? "",
    sequence: big(m.sequence, "sequence"),
    previousSha256: m.previousSha256 ?? "",
    unanswered: m.unanswered ?? "",
    instance: m.instance ?? "",
    sha256: m.recordSha256 ?? "",
  };
}

/** A record's own digest, over the fields its version covers (every field but its digest for an unknown version). */
export function recordDigest(r: RunRecord): string {
  const e = new Encoder(`plimsoll.run-record.v${r.version}`);
  for (const name of RECORD_FIELDS[r.version] ?? RECORD_FIELDS[RECORD_VERSION]!) {
    const v = recordField(r, name);
    if (typeof v === "string") e.str(name, v);
    else e.int(name, v);
  }
  return e.sum();
}

/**
 * The fields of each published record version's digest, in order (record.published): a
 * version leaves this table only by a dated, announced decision.
 */
const RECORD_FIELDS: Record<number, readonly string[]> = {
  1: ["request_sha256", "result_sha256", "provider", "isolation", "environment", "policy",
    "started_unix_ms", "ended_unix_ms", "session", "sequence", "previous_sha256"],
  2: ["request_sha256", "result_sha256", "provider", "isolation", "environment", "policy",
    "software_identity", "software_rule_id", "started_unix_ms", "ended_unix_ms", "session", "sequence",
    "previous_sha256"],
  3: ["request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment", "policy",
    "software_identity", "software_rule_id", "started_unix_ms", "ended_unix_ms", "session", "sequence",
    "previous_sha256"],
  4: ["request_sha256", "result_sha256", "unanswered", "provider", "isolation", "environment", "policy",
    "software_identity", "software_rule_id", "instance", "started_unix_ms", "ended_unix_ms", "session",
    "sequence", "previous_sha256"],
};

function recordField(r: RunRecord, name: string): string | bigint {
  switch (name) {
    case "request_sha256": return r.requestSha256;
    case "result_sha256": return r.resultSha256;
    case "unanswered": return r.unanswered;
    case "provider": return r.provider;
    case "isolation": return r.isolation;
    case "environment": return r.environment;
    case "policy": return r.policy;
    case "software_identity": return r.softwareIdentity;
    case "software_rule_id": return r.softwareRuleId;
    case "instance": return r.instance;
    case "started_unix_ms": return r.startedUnixMs;
    case "ended_unix_ms": return r.endedUnixMs;
    case "session": return r.session;
    case "sequence": return r.sequence;
    case "previous_sha256": return r.previousSha256;
  }
  throw new Error(`no record field ${name}`);
}

/** The SHA-256 of a session ID: what a session call's record carries instead of the ID. */
export function sessionFingerprint(sessionId: string): string {
  return createHash("sha256").update(sessionId, "utf8").digest("hex");
}

/**
 * The record ID of a software rule: "exact:<identity>" for one identity, else
 * "approved:sha256:" over the identities sorted in byte order, joined by a zero byte.
 */
export function softwareRuleId(rule: WireSoftwareRule | undefined): string {
  if (!rule || !rule.mode) return "";
  const ids = rule.identities;
  if (ids.length === 1) return `exact:${ids[0]}`;
  const sorted = [...ids].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return "approved:sha256:" + createHash("sha256").update(sorted.join("\x00"), "utf8").digest("hex");
}

export function softwareRuleAllows(rule: WireSoftwareRule | undefined, identity: string): boolean {
  if (!rule || !rule.mode) return true;
  return identity !== "" && rule.identities.includes(identity);
}

// The tiers, weakest first (generated, internal/wiretables).
const TIER_ORDER: readonly string[] = TIERS;

/**
 * Checks the record the daemon sends with an unanswered session call's error
 * (record.CheckUnanswered): the version, no result digest, a Connect code, the digest of
 * the request sent, its software rule and that its software is in it, its own digest,
 * its tier against the call's floor, and its place in the chain.
 * Returns the reason it does not check, or the record.
 */
export function checkUnanswered(
  reqDigest: string,
  floor: string,
  rule: WireSoftwareRule | undefined,
  m: WireRecord,
  fingerprint: string,
  prevSeq: bigint,
  prev: string,
): { record: RunRecord } | { problem: string } {
  const r = recordFromWire(m);
  if (r.version !== RECORD_VERSION) return { problem: versionProblem(r.version) };
  if (!validInstance(r.instance)) return { problem: "the record's instance is not a typed reference" };
  if (r.resultSha256 !== "" || !UNANSWERED_CODES.has(r.unanswered)) return { problem: "an unanswered call's record states a result or no error code" };
  if (r.requestSha256 !== reqDigest) return { problem: `request digest ${r.requestSha256}, the request sent digests to ${reqDigest}` };
  if (r.softwareRuleId !== softwareRuleId(rule) || !softwareRuleAllows(rule, r.softwareIdentity)) {
    return { problem: "the record's software rule is not the request's, or its software is not in it" };
  }
  if (r.sha256 !== recordDigest(r)) return { problem: `record digest ${r.sha256}, its fields digest to ${recordDigest(r)}` };
  if (floor !== "" && !(TIER_ORDER.indexOf(r.isolation) >= TIER_ORDER.indexOf(floor) && TIER_ORDER.indexOf(r.isolation) >= 0)) {
    return { problem: `the unanswered call's record states ${r.isolation || "unknown"}, below the call's minimum ${floor}; execution may have occurred` };
  }
  if (r.session !== fingerprint || r.sequence !== prevSeq + 1n || r.previousSha256 !== prev) {
    return { problem: `the session's chain is broken: call ${r.sequence} after "${r.previousSha256}", this client's last was call ${prevSeq}, "${prev}"` };
  }
  return { record: r };
}

/**
 * Checks everything a record states that the caller can recompute: the version,
 * both digests, the evidence the response repeats, the software rule and the
 * record's own digest. Returns the reason it does not check, or undefined.
 */
export function checkRecord(
  reqDigest: string,
  kind: "javascript" | "project" | "cell",
  rule: WireSoftwareRule | undefined,
  resp: WireRunResponse,
): { record: RunRecord } | { problem: string } {
  if (!resp.record) return { problem: "the response carries no run record" };
  const r = recordFromWire(resp.record);
  let result: string;
  try {
    result = resultDigest(resp);
  } catch (e) {
    if (e instanceof WireShapeError) return { problem: `the answer is malformed: ${e.message}` };
    throw e;
  }
  if (r.version !== RECORD_VERSION) return { problem: versionProblem(r.version) };
  if (r.unanswered !== "") return { problem: "an answered call's record states an unanswered code" };
  // The kind, inside the check as in Go's record.check since 2026-10-26: a result of
  // another kind fails here, before a session's chain moves on, so a daemon caught
  // answering the wrong kind is not used further (review, 2026-10-26).
  const kinds = (["javascript", "project", "module", "cell"] as const).filter((k) => resp[k] !== undefined && resp[k] !== null);
  if (kinds.length > 1) return { problem: `the answer holds ${kinds.length} results; a run has one` };
  if (kinds.length !== 1 || kinds[0] !== kind) return { problem: `the daemon answered a ${kind} request with ${kinds.length === 1 ? kinds[0] : "no"} result` };
  if (r.endedUnixMs < r.startedUnixMs) return { problem: "the record ends before it starts" };
  if (r.requestSha256 !== reqDigest) return { problem: `request digest ${r.requestSha256}, the request sent digests to ${reqDigest}` };
  if (r.resultSha256 !== result) return { problem: `result digest ${r.resultSha256}, the result received digests to ${result}` };
  if (r.provider !== (resp.sandbox ?? "") || r.isolation !== (resp.isolation ?? "")) return { problem: "the record's provider or tier differs from the response's" };
  if (r.environment !== (resp.environment ?? "")) return { problem: "the record's environment differs from the response's" };
  if (r.instance !== (resp.instance ?? "") || !validInstance(r.instance)) {
    return { problem: "the record's instance is not the response's, or not a typed reference" };
  }
  if (
    (r.softwareIdentity !== (resp.softwareIdentity ?? "") || r.softwareRuleId !== softwareRuleId(rule) || !softwareRuleAllows(rule, r.softwareIdentity))
  ) {
    return { problem: "the selected software or admission rule differs from the request and response" };
  }
  if (r.sha256 !== recordDigest(r)) return { problem: `record digest ${r.sha256}, its fields digest to ${recordDigest(r)}` };
  return { record: r };
}
