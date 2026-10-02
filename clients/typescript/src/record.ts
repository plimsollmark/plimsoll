// Run-record digests, computed from docs/run-records.md alone: lowercase hex
// SHA-256 over a length-prefixed encoding, never over protobuf or JSON bytes.
// The golden vectors in record/record_test.go are checked in test/record.test.ts.

import { createHash, type Hash } from "node:crypto";

import type { WireRecord, WireRunResponse, WireSoftwareRule } from "./wire.ts";

/** The record encoding version of an answered call, which this client computes and checks. */
export const RECORD_VERSION = 2;

/** The record encoding version of a session call that may have run but ended in an error. */
export const UNANSWERED_RECORD_VERSION = 3;

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
  const e = new Encoder(r.protocol >= 2 ? "plimsoll.run-request.v2" : "plimsoll.run-request.v1");
  e.int("protocol", r.protocol);
  e.str("minimum_isolation", r.minimumIsolation);
  e.int("timeout_ms", r.timeoutMs);
  if (r.protocol >= 2) {
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

const OUTCOME_NUMBERS: Record<string, number> = {
  PROJECT_OUTCOME_UNSPECIFIED: 0,
  PROJECT_OUTCOME_COMPLETED: 1,
  PROJECT_OUTCOME_SETUP_FAILED: 2,
  PROJECT_OUTCOME_TIMED_OUT: 3,
  PROJECT_OUTCOME_PROTOCOL_ERROR: 4,
};

/** The wire enum's number; an unknown name is undefined, which fails the check. */
export function outcomeNumber(name: string | number | undefined): number | undefined {
  if (name === undefined) return 0;
  if (typeof name === "number") return name;
  return OUTCOME_NUMBERS[name];
}

const b64 = (s: string | undefined): Buffer => Buffer.from(s ?? "", "base64");

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
    // A module result, or none: this client sends neither, so the kind check
    // refuses the response before its digest matters.
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
  /** On a version 3 record, the Connect code a session call that may have run ended with. */
  unanswered: string;
  sha256: string;
};

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
    startedUnixMs: BigInt(m.startedUnixMs ?? 0),
    endedUnixMs: BigInt(m.endedUnixMs ?? 0),
    session: m.session ?? "",
    sequence: BigInt(m.sequence ?? 0),
    previousSha256: m.previousSha256 ?? "",
    unanswered: m.unanswered ?? "",
    sha256: m.recordSha256 ?? "",
  };
}

/** A record's own digest, over every field but its digest. */
export function recordDigest(r: RunRecord): string {
  const e = new Encoder(`plimsoll.run-record.v${r.version}`);
  e.str("request_sha256", r.requestSha256);
  e.str("result_sha256", r.resultSha256);
  if (r.version >= 3) e.str("unanswered", r.unanswered);
  e.str("provider", r.provider);
  e.str("isolation", r.isolation);
  e.str("environment", r.environment);
  e.str("policy", r.policy);
  if (r.version >= 2) {
    e.str("software_identity", r.softwareIdentity);
    e.str("software_rule_id", r.softwareRuleId);
  }
  e.int("started_unix_ms", r.startedUnixMs);
  e.int("ended_unix_ms", r.endedUnixMs);
  e.str("session", r.session);
  e.int("sequence", r.sequence);
  e.str("previous_sha256", r.previousSha256);
  return e.sum();
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

/**
 * Checks the record the daemon sends with an unanswered session call's error
 * (record.CheckUnanswered): version 3, no result digest, a Connect code, the digest of
 * the request sent, its software rule, its own digest, and its place in the chain.
 * Returns the reason it does not check, or the record.
 */
export function checkUnanswered(
  reqDigest: string,
  rule: WireSoftwareRule | undefined,
  m: WireRecord,
  fingerprint: string,
  prevSeq: bigint,
  prev: string,
): { record: RunRecord } | { problem: string } {
  const r = recordFromWire(m);
  if (r.version !== UNANSWERED_RECORD_VERSION) return { problem: `an unanswered call's record is version ${r.version}` };
  if (r.resultSha256 !== "" || !UNANSWERED_CODES.has(r.unanswered)) return { problem: "an unanswered call's record states a result or no error code" };
  if (r.requestSha256 !== reqDigest) return { problem: `request digest ${r.requestSha256}, the request sent digests to ${reqDigest}` };
  if (r.softwareRuleId !== softwareRuleId(rule)) return { problem: "the record's software rule is not the request's" };
  if (r.sha256 !== recordDigest(r)) return { problem: `record digest ${r.sha256}, its fields digest to ${recordDigest(r)}` };
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
  protocol: number,
  rule: WireSoftwareRule | undefined,
  resp: WireRunResponse,
): { record: RunRecord } | { problem: string } {
  if (!resp.record) return { problem: "the response carries no run record" };
  const r = recordFromWire(resp.record);
  const result = resultDigest(resp);
  if (r.version !== 1 && r.version !== RECORD_VERSION) return { problem: `unknown run record version ${r.version}` };
  if (protocol >= 2 && r.version !== RECORD_VERSION) return { problem: `protocol ${protocol} requires record version ${RECORD_VERSION}` };
  if (r.version === 1 && (r.softwareIdentity !== "" || r.softwareRuleId !== "")) return { problem: "a version 1 record cannot carry software fields" };
  if (r.requestSha256 !== reqDigest) return { problem: `request digest ${r.requestSha256}, the request sent digests to ${reqDigest}` };
  if (r.resultSha256 !== result) return { problem: `result digest ${r.resultSha256}, the result received digests to ${result}` };
  if (r.provider !== (resp.sandbox ?? "") || r.isolation !== (resp.isolation ?? "")) return { problem: "the record's provider or tier differs from the response's" };
  if (r.version >= 2 && r.environment !== (resp.environment ?? "")) return { problem: "the record's environment differs from the response's" };
  if (
    r.version >= 2 &&
    (r.softwareIdentity !== (resp.softwareIdentity ?? "") || r.softwareRuleId !== softwareRuleId(rule) || !softwareRuleAllows(rule, r.softwareIdentity))
  ) {
    return { problem: "the selected software or admission rule differs from the request and response" };
  }
  if (r.sha256 !== recordDigest(r)) return { problem: `record digest ${r.sha256}, its fields digest to ${recordDigest(r)}` };
  return { record: r };
}
