// Run-record digests, computed from docs/run-records.md alone: lowercase hex
// SHA-256 over a length-prefixed encoding, never over protobuf or JSON bytes.
// The golden vectors in record/record_test.go are checked in test/record.test.ts.

import { createHash, type Hash } from "node:crypto";

import { PlimsollError } from "./errors.ts";
// The record's version (the one this client computes and checks: every field, every time,
// for an answered call and an unanswered session call alike), its layouts and bounds,
// generated from the Go record and sandbox packages.
import {
  DAEMON_VERSION_PATTERN,
  INSTANCE_PATTERN,
  LAST_WALL_CLOCK_END_VERSION,
  MAX_DAEMON_VERSION_BYTES,
  MAX_QUALIFICATION_BYTES,
  OUTCOMES,
  QUALIFICATION_FORBIDDEN,
  RECORD_FIELDS,
  RECORD_VERSION,
  RETIRED_END_BEFORE_START_TEXT,
  TIERS,
  UNANSWERED_CODES as UNANSWERED_CODE_LIST,
} from "./tables.gen.ts";

import { INT64, UINT32, UINT64, wholeInt, wireBytes, WireShapeError, type WireRecord, type WireRunResponse, type WireSoftwareRule } from "./wire.ts";

const INSTANCE_FORM = new RegExp(INSTANCE_PATTERN);

/** A record's instance: "" (the provider names none) or a typed reference such as `k8s-pod-uid:` and a pod's UID. */
export function validInstance(s: string): boolean {
  return s === "" || INSTANCE_FORM.test(s);
}

// A control character, or a format character that breaks a line or shows text in another
// order than it is stored (record.ValidText), from the generated ranges: the one set every
// field a reader is shown is held to (the table's name is the qualification's, the first
// field it was written for).
const hex = (c: number) => `\\u{${c.toString(16)}}`;
const FORBIDDEN_IN_TEXT = new RegExp(`[${QUALIFICATION_FORBIDDEN.map(([lo, hi]) => `${hex(lo)}-${hex(hi)}`).join("")}]`, "u");

/**
 * Text a record may state where a reader is shown it as it is: UTF-8 with no control
 * character and none of the format characters that break a line or reorder displayed text,
 * as record.ValidText. A lone surrogate is not UTF-8. The provider's name, the tier and the
 * isolation qualification are held to it (shownFields).
 */
export function validText(s: string): boolean {
  return !/\p{Cs}/u.test(s) && !FORBIDDEN_IN_TEXT.test(s);
}

/** A record's fields a reader is shown as the run's evidence, each with the name a refusal gives it, as record.ShownFields. */
export function shownFields(r: RunRecord): readonly (readonly [string, string])[] {
  return [["provider", r.provider], ["isolation", r.isolation], ["isolation qualification", r.isolationQualification]];
}

/**
 * A record's isolation qualification: "" (the provider states none), or at most
 * MAX_QUALIFICATION_BYTES of UTF-8 that validText accepts, as record.ValidQualification.
 */
export function validQualification(s: string): boolean {
  return validText(s) && Buffer.byteLength(s, "utf8") <= MAX_QUALIFICATION_BYTES;
}

const DAEMON_VERSION_FORM = new RegExp(DAEMON_VERSION_PATTERN);

/**
 * A record's daemon version: "", "(devel)", or a module version such as "v0.28.0" or a
 * pseudo-version, at most MAX_DAEMON_VERSION_BYTES (the grammar is ASCII, so characters are
 * bytes), as record.ValidDaemonVersion.
 */
export function validDaemonVersion(s: string): boolean {
  return s === "" || (s.length <= MAX_DAEMON_VERSION_BYTES && DAEMON_VERSION_FORM.test(s));
}

const UNANSWERED_CODES: ReadonlySet<string> = new Set(UNANSWERED_CODE_LIST);

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
  /** The sentence the provider states beside the tier, as the response states it, or "" (record version 5). */
  isolationQualification: string;
  /** Whether a waiting pool sandbox ran the call, as the response states it (record version 5). */
  warm: boolean;
  /** The answering daemon's plimsoll module version, as the response states it (record version 5). */
  daemonVersion: string;
  sha256: string;
};

// big reads a 64-bit integer field the JSON codec sends as a decimal string (or a
// number). Anything else is an answer this client cannot read, a PlimsollError,
// never BigInt's own SyntaxError or RangeError.
function big(v: unknown, name: string, range: readonly [bigint, bigint] = INT64): bigint {
  const n = wholeInt(v, range);
  if (n === undefined) throw new PlimsollError("data_loss", `plimsoll: the record's ${name} is not an integer in one whole decimal`);
  return n;
}

// text and flag read a record field the JSON codec sends as a string or a boolean: absent is "" or false, and any
// other JSON type is an answer this client cannot read, a PlimsollError (Go's protojson and Python's typed reads
// refuse the same), never a TypeError later or a value coerced to the right type.
function text(v: unknown, name: string): string {
  if (v === undefined || v === null) return "";
  if (typeof v !== "string") throw new PlimsollError("data_loss", `plimsoll: the record's ${name} is not text`);
  return v;
}

function flag(v: unknown, name: string): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v !== "boolean") throw new PlimsollError("data_loss", `plimsoll: the record's ${name} is not a boolean`);
  return v;
}

export function recordFromWire(m: WireRecord): RunRecord {
  return {
    version: Number(big(m.version, "version", UINT32)),
    requestSha256: text(m.requestSha256, "requestSha256"),
    resultSha256: text(m.resultSha256, "resultSha256"),
    provider: text(m.provider, "provider"),
    isolation: text(m.isolation, "isolation"),
    environment: text(m.environment, "environment"),
    policy: text(m.policy, "policy"),
    softwareIdentity: text(m.softwareIdentity, "softwareIdentity"),
    softwareRuleId: text(m.softwareRuleId, "softwareRuleId"),
    startedUnixMs: big(m.startedUnixMs, "startedUnixMs"),
    endedUnixMs: big(m.endedUnixMs, "endedUnixMs"),
    session: text(m.session, "session"),
    sequence: big(m.sequence, "sequence", UINT64),
    previousSha256: text(m.previousSha256, "previousSha256"),
    unanswered: text(m.unanswered, "unanswered"),
    instance: text(m.instance, "instance"),
    isolationQualification: text(m.isolationQualification, "isolationQualification"),
    warm: flag(m.warm, "warm"),
    daemonVersion: text(m.daemonVersion, "daemonVersion"),
    sha256: text(m.recordSha256, "recordSha256"),
  };
}

/** A record's own digest, over the fields its version covers (every field but its digest for an unknown version). */
export function recordDigest(r: RunRecord): string {
  const e = new Encoder(`plimsoll.run-record.v${r.version}`);
  for (const name of RECORD_FIELDS[r.version] ?? RECORD_FIELDS[RECORD_VERSION]!) {
    const v = recordField(r, name);
    if (typeof v === "string") e.str(name, v);
    else if (typeof v === "boolean") e.bool(name, v);
    else e.int(name, v);
  }
  return e.sum();
}

/**
 * Which calls each published record version records (record.published's answered and
 * unanswered flags): versions 1 and 2 answered calls only, version 3 unanswered session
 * calls only, versions 4 and 5 both. Published versions are frozen, so this is too; a
 * version missing here records nothing, so a new one is refused until it is added, and a
 * test holds the keys to RECORD_FIELDS' (finding release-85).
 */
export const RECORD_KINDS: Readonly<Record<number, { answered: boolean; unanswered: boolean }>> = {
  1: { answered: true, unanswered: false },
  2: { answered: true, unanswered: false },
  3: { answered: false, unanswered: true },
  4: { answered: true, unanswered: true },
  5: { answered: true, unanswered: true },
};

/**
 * The record records a kind of call its version records, the fields its version does not
 * cover are unset, it states a result digest or,
 * for an unanswered call, an error code, exactly one, and the code is one of the closed
 * set, its tier is one of TIERS (never "unknown" or empty, whatever floor the request
 * named), it does not end before it starts, answered or not, its qualification and daemon
 * version are in their bounds, and its instance is a typed reference (record.statesOnly).
 * The record of a call lost across a takeover is checked by this alone.
 * Returns the reason it fails, or undefined.
 */
export function statesOnlyProblem(r: RunRecord): string | undefined {
  for (const [name, text] of shownFields(r)) {
    if (typeof text !== "string" || !validText(text)) return `the record's ${name} is not UTF-8 or holds a control or bidirectional format character`;
  }
  const unanswered = r.unanswered !== "";
  const kinds = RECORD_KINDS[r.version];
  if (!kinds) return `a version ${r.version} record is not of a published version`;
  if (unanswered && !kinds.unanswered) return `a version ${r.version} record cannot record an unanswered call`;
  if (!unanswered && !kinds.answered) return `a version ${r.version} record records only an unanswered call`;
  const covered = RECORD_FIELDS[r.version] ?? [];
  for (const name of RECORD_FIELDS[RECORD_VERSION]!) {
    const v = recordField(r, name);
    if (!covered.includes(name) && v !== "" && v !== false && v !== 0n) return `a version ${r.version} record does not cover ${name}, so it cannot state one`;
  }
  if (unanswered === (r.resultSha256 !== "")) return "a record states a result or, for an unanswered call, an error code, exactly one";
  if (unanswered && !UNANSWERED_CODES.has(r.unanswered)) return `an unanswered call's record names ${JSON.stringify(r.unanswered)}, not a Connect code`;
  if (!(TIERS as readonly string[]).includes(r.isolation)) return `the record's isolation ${JSON.stringify(r.isolation)} is not a tier (${TIERS.join(", ")})`;
  // A version 1 or 2 record that ends before it starts is refused as a retired reading, not
  // as a forgery (record.LastWallClockEndVersion, retired 2026-11-21).
  if (r.endedUnixMs < r.startedUnixMs && r.version <= LAST_WALL_CLOCK_END_VERSION) return RETIRED_END_BEFORE_START_TEXT;
  if (r.endedUnixMs < r.startedUnixMs) return "the record ends before it starts";
  if (!validInstance(r.instance)) return "the record's instance is not a typed reference";
  if (!validQualification(r.isolationQualification)) return `the record's isolation qualification is over ${MAX_QUALIFICATION_BYTES} bytes`;
  if (!validDaemonVersion(r.daemonVersion)) return `the record's daemon version ${JSON.stringify(r.daemonVersion)} is not a module version or (devel)`;
  return undefined;
}

function recordField(r: RunRecord, name: string): string | bigint | boolean {
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
    case "isolation_qualification": return r.isolationQualification;
    case "warm": return r.warm;
    case "daemon_version": return r.daemonVersion;
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
  const bounds = statesOnlyProblem(r);
  if (bounds !== undefined) return { problem: bounds };
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
  if (r.requestSha256 !== reqDigest) return { problem: `request digest ${r.requestSha256}, the request sent digests to ${reqDigest}` };
  if (r.resultSha256 !== result) return { problem: `result digest ${r.resultSha256}, the result received digests to ${result}` };
  if (r.provider !== (resp.sandbox ?? "") || r.isolation !== (resp.isolation ?? "")) return { problem: "the record's provider or tier differs from the response's" };
  if (r.environment !== (resp.environment ?? "")) return { problem: "the record's environment differs from the response's" };
  if (r.instance !== (resp.instance ?? "") || !validInstance(r.instance)) {
    return { problem: "the record's instance is not the response's, or not a typed reference" };
  }
  if (r.isolationQualification !== (resp.isolationQualification ?? "")) return { problem: "the record's isolation qualification is not the response's" };
  if (r.warm !== (resp.warm ?? false)) return { problem: `the record states warm ${r.warm}, the response ${resp.warm ?? false}` };
  if (r.daemonVersion !== (resp.daemonVersion ?? "")) return { problem: "the record's daemon version is not the response's" };
  const bounds = statesOnlyProblem(r);
  if (bounds !== undefined) return { problem: bounds };
  if (
    (r.softwareIdentity !== (resp.softwareIdentity ?? "") || r.softwareRuleId !== softwareRuleId(rule) || !softwareRuleAllows(rule, r.softwareIdentity))
  ) {
    return { problem: "the selected software or admission rule differs from the request and response" };
  }
  if (r.sha256 !== recordDigest(r)) return { problem: `record digest ${r.sha256}, its fields digest to ${recordDigest(r)}` };
  return { record: r };
}

/**
 * Checks the answer an attach returned for a lost call (AttachSessionResponse.lostAnswer)
 * against that call's record, which the caller has already checked against its
 * checkpoint and the request digest it named (record.CheckLostAnswer): the answer carries
 * exactly that record, which is a live answered call's, and one result of a session call's
 * kind whose result digest is the record's, stating the evidence the record states. The
 * request itself is not at hand, only its digest, so the record's request digest and
 * software rule stand for it. Returns the result's kind, or the reason it does not check.
 */
export function checkLostAnswer(resp: WireRunResponse, lost: RunRecord): { kind: "javascript" | "project" | "cell" } | { problem: string } {
  if (resp === null || typeof resp !== "object" || Array.isArray(resp)) return { problem: "the lost call's answer is not an object" };
  if (!resp.record) return { problem: "the lost call's answer carries no run record" };
  const r = recordFromWire(resp.record);
  if (!sameRecord(r, lost)) return { problem: "the lost call's answer carries another record than the lost call's" };
  if (r.version !== RECORD_VERSION) return { problem: versionProblem(r.version) };
  if (r.unanswered !== "") return { problem: `an answer came for a call whose record states it ended unanswered (${r.unanswered})` };
  const bounds = statesOnlyProblem(r);
  if (bounds !== undefined) return { problem: bounds };
  if (r.sha256 !== recordDigest(r)) return { problem: `record digest ${r.sha256}, its fields digest to ${recordDigest(r)}` };
  const kinds = (["javascript", "project", "module", "cell"] as const).filter((k) => resp[k] !== undefined && resp[k] !== null);
  const kind = kinds[0];
  if (kinds.length !== 1 || kind === "module" || kind === undefined) return { problem: "the lost call's answer holds no one result of a session call's kind" };
  let result: string;
  try {
    result = resultDigest(resp);
  } catch (e) {
    if (e instanceof WireShapeError) return { problem: `the lost call's answer is malformed: ${e.message}` };
    throw e;
  }
  if (r.resultSha256 !== result) return { problem: `result digest ${r.resultSha256}, the lost call's answer digests to ${result}` };
  if (
    r.provider !== (resp.sandbox ?? "") || r.isolation !== (resp.isolation ?? "") || r.environment !== (resp.environment ?? "") ||
    r.instance !== (resp.instance ?? "") || r.isolationQualification !== (resp.isolationQualification ?? "") || r.warm !== (resp.warm ?? false) ||
    r.daemonVersion !== (resp.daemonVersion ?? "") || r.softwareIdentity !== (resp.softwareIdentity ?? "")
  ) {
    return { problem: "the lost call's answer states other evidence than its record" };
  }
  return { kind };
}

// Whether two records read off the wire are the same record, field by field (Go: proto.Equal
// on the wire messages).
function sameRecord(a: RunRecord, b: RunRecord): boolean {
  return (Object.keys(a) as (keyof RunRecord)[]).every((k) => a[k] === b[k]);
}
