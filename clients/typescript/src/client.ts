// A plimsolld client for TypeScript: Connect's JSON protocol over fetch, no
// protobuf runtime and no dependencies. It keeps the official Go client's
// promises (package client): it states the protocol number on every request,
// checks every run record against what it sent and received, checks the
// isolation evidence against the caller's floor, and tracks a session's chain of
// records so a call it did not make is caught.

import { isIP } from "node:net";

import {
  checkRecord,
  checkUnanswered,
  requestDigest,
  sessionFingerprint,
  softwareRuleAllows,
  type DigestPayload,
  type RunRecord,
} from "./record.ts";
import { errorFromWire, PlimsollError, sessionEndFromWire, type SessionEnd } from "./errors.ts";
import type {
  WireAdvice,
  WireCellRun,
  WireCloseSessionResponse,
  WireDescribeResponse,
  WireEnvelope,
  WireError,
  WireOpenSessionResponse,
  WirePayloadEnvironment,
  WireRunResponse,
  WireSessionRunResponse,
  WireSoftwareRule,
} from "./wire.ts";

/** The wire protocol number this client speaks (protocol.Number in Go). */
export const PROTOCOL = 2;

const SERVICE = "plimsoll.v1.SandboxService";

// Above the largest legitimate project response, so a misbehaving daemon cannot
// make the client buffer without bound (the Go client's maxResponseBytes).
const MAX_RESPONSE_BYTES = 32 << 20;

/** How strong the boundary is, weakest first. */
export type Isolation = "none" | "process" | "container" | "kernel" | "vm";

const TIERS: Isolation[] = ["none", "process", "container", "kernel", "vm"];

/** Whether a tier the daemon reported meets a floor. An unknown tier meets nothing. */
export function meets(actual: string, floor: Isolation): boolean {
  const a = TIERS.indexOf(actual as Isolation);
  const f = TIERS.indexOf(floor);
  // A floor is process, container, kernel or vm; anything else is met by nothing.
  return a >= 0 && f >= 1 && a >= f;
}

/** A caller's rule for the selected software: one exact identity, or 1 to 32 approved ones. */
export type SoftwareRule = { mode: "exact" | "approved"; identities: string[] };

export type ClientOptions = {
  /** The daemon's absolute http(s) URL. Cleartext to a non-loopback host needs insecureHttp. */
  baseUrl: string;
  /** Bearer token with the code:run scope. Omit for an open development daemon. */
  token?: string;
  /** Explicitly permits cleartext HTTP to a non-loopback host. Development only. */
  insecureHttp?: boolean;
  /** Named server-side grant profile for snippets (PLIMSOLL_GRANTS_FILE). Empty = no network. */
  javascriptGrantProfile?: string;
  /** Named server-side grant profile for projects. */
  projectGrantProfile?: string;
  /** A fetch implementation; defaults to the global one. */
  fetch?: typeof fetch;
  /**
   * Bounds each HTTP exchange, sending and reading the answer, in milliseconds.
   * Default 6 minutes, as the Go and Python clients. A run's timeoutMs bounds what
   * the daemon executes, not a stalled connection; a call cut off here may have run.
   */
  requestTimeoutMs?: number;
};

const DEFAULT_REQUEST_TIMEOUT_MS = 6 * 60_000;

export type RunOptions = {
  /** Whole-run budget; defaulted and clamped by the daemon. */
  timeoutMs?: number;
  /** The weakest tier this run accepts, checked before dispatch and again on the answer. */
  minimumIsolation?: Exclude<Isolation, "none">;
  software?: SoftwareRule;
  /** An opaque correlation id for the daemon's audit line: [A-Za-z0-9._:-]{1,64}, else dropped. */
  traceId?: string;
  signal?: AbortSignal;
};

/** Evidence every answered run carries: configuration and provider evidence, never attestation. */
export type Evidence = {
  sandbox: string;
  isolation: string;
  softwareIdentity: string;
  environment: string;
  durationMs: number;
  /** The checked run record. */
  record: RunRecord;
};

export type AdviceFinding = {
  pattern: string;
  severity: string;
  remedy: string;
  method: string;
  route: string;
  detail: string;
  suggestedMethod: string;
  suggestedRoute: string;
  extraCalls: number;
  addedLatencyMs: number;
  bytesMoved: number;
};

export type JavaScriptResult = Evidence & {
  /** Guest output decoded as UTF-8 (invalid sequences replaced); the raw bytes are beside it. */
  stdout: string;
  stderr: string;
  stdoutBytes: Uint8Array;
  stderrBytes: Uint8Array;
  /** A non-zero exit code is a normal result: the guest's code failed. */
  exitCode: number;
  timedOut: boolean;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  advice: AdviceFinding[];
};

export type ProjectRequest = {
  files: { path: string; content: string }[];
  /** Shell commands run in order; the run stops at the first that fails. */
  steps: string[];
  /** Relative paths to capture and return. */
  artifacts?: string[];
};

export type ProjectOutcome = "unspecified" | "completed" | "setup_failed" | "timed_out" | "protocol_error";

export type StepResult = {
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
};

export type ProjectResult = Evidence & {
  outcome: ProjectOutcome;
  detail: string;
  steps: StepResult[];
  artifacts: { path: string; content: Uint8Array }[];
  artifactsTruncated: boolean;
  advice: AdviceFinding[];
};

/** An interpreter language: a cell's, and one an environment states. */
export type Language = "javascript" | "python";

/**
 * Where one payload kind runs. languages are the interpreters the daemon's startup
 * checks proved: what a project's steps can invoke, and in a session what a cell may use.
 */
export type PayloadEnvironment = { identity: string; softwareIdentity: string; maxTimeoutMs: number; languages: Language[] };

/** A cell: code for the session's interpreter, with files written into the work directory first. */
export type CellRequest = { language: Language; code: string; files?: { path: string; content: string }[] };

export type CellResult = Evidence & {
  stdout: string;
  stderr: string;
  stdoutBytes: Uint8Array;
  stderrBytes: Uint8Array;
  /** 0: the code ran; 1: it raised (the error is on stderr); 124: the deadline ended it. */
  exitCode: number;
  timedOut: boolean;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  /** This call started a fresh interpreter: nothing an earlier cell defined exists. */
  interpreterStarted: boolean;
  /** The interpreter ended during this call; the next cell starts a fresh one. */
  interpreterEnded: boolean;
};

export type Info = {
  sandbox: string;
  isolation: string;
  protocol: number;
  supportsProject: boolean;
  supportsModule: boolean;
  supportsJavaScriptGrants: boolean;
  supportsProjectGrants: boolean;
  supportsSessions: boolean;
  sessionLifetimeMs: number;
  sessionIdleTimeoutMs: number;
  /** Where a session's calls run (on docker the project image), stated with supportsSessions. */
  sessionEnvironment: PayloadEnvironment;
  environments: { javascript: PayloadEnvironment; project: PayloadEnvironment; module: PayloadEnvironment; policy: string };
  resources: { memoryMb: number; cpus: number; pids: number; diskMb: number };
};

export type SessionOptions = {
  minimumIsolation?: Exclude<Isolation, "none">;
  software?: SoftwareRule;
  /** Shorter than the daemon's own, or omitted for the daemon's. */
  lifetimeMs?: number;
  idleTimeoutMs?: number;
  traceId?: string;
  /**
   * The languages the session's cells will use: a hint, so a daemon with a warm pool
   * hands over a sandbox with those interpreters already running. A cell in any
   * language the daemon states still runs.
   */
  languages?: Language[];
  signal?: AbortSignal;
};

export type SessionSummary = { session: string; calls: bigint; lastRecordSha256: string; end: SessionEnd };

function validateBaseUrl(raw: string, insecureHttp: boolean): string {
  if (raw === "" || raw !== raw.trim()) throw new PlimsollError("invalid_argument", "plimsoll: base URL must be non-empty with no surrounding whitespace");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new PlimsollError("invalid_argument", "plimsoll: base URL must be an absolute HTTP or HTTPS URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new PlimsollError("invalid_argument", "plimsoll: base URL scheme must be http or https");
  if (u.username || u.password || u.search || raw.includes("?") || raw.includes("#")) {
    throw new PlimsollError("invalid_argument", "plimsoll: userinfo, query and fragment are not permitted in the base URL");
  }
  const host = u.hostname.replace(/^\[|\]$/g, "");
  // A host is loopback by name or as an address, never by a prefix: 127.evil.example is a
  // domain name, and the token must not go to it in cleartext.
  const loopback = host === "localhost" || host === "::1" || (isIP(host) === 4 && host.startsWith("127."));
  if (u.protocol === "http:" && !loopback && !insecureHttp) {
    throw new PlimsollError("invalid_argument", "plimsoll: cleartext HTTP to a non-loopback daemon requires insecureHttp");
  }
  return u.toString().replace(/\/+$/, "");
}

function timeoutMs(ms: number | undefined): number {
  if (ms === undefined || !(ms > 0)) return 0;
  return Math.min(Math.max(1, Math.round(ms)), 2 ** 31 - 1);
}

function durationMs(ms: number | undefined): number {
  if (ms === undefined || !(ms > 0)) return 0;
  return Math.min(Math.round(ms), 2 ** 32 - 1);
}

function validateRule(rule: SoftwareRule | undefined): WireSoftwareRule | undefined {
  if (!rule) return undefined;
  const ids = rule.identities;
  const ok =
    (rule.mode === "exact" ? ids.length === 1 : rule.mode === "approved" && ids.length >= 1 && ids.length <= 32) &&
    new Set(ids).size === ids.length &&
    ids.every((id) => id.length > 0 && id.length <= 256 && /^[A-Za-z0-9._:/@+-]+$/.test(id));
  if (!ok) {
    throw new PlimsollError("invalid_argument", "plimsoll: software rule needs exact with one identity or approved with 1 to 32 identities", {
      notDispatched: "request",
    });
  }
  return { mode: rule.mode, identities: [...ids] };
}

// The intersection of a session's rule and a call's: neither can be weakened.
function mergeRules(a: WireSoftwareRule | undefined, b: WireSoftwareRule | undefined): WireSoftwareRule | undefined {
  if (!a) return b;
  if (!b) return a;
  const ids = a.identities.filter((id) => b.identities.includes(id));
  if (ids.length === 0) {
    throw new PlimsollError("invalid_argument", "plimsoll: the call's software rule shares no identity with the session's", { notDispatched: "request" });
  }
  return { mode: ids.length === 1 ? "exact" : "approved", identities: ids };
}

const num = (v: string | number | undefined): number => Number(v ?? 0);
const bytes = (s: string | undefined): Uint8Array => new Uint8Array(Buffer.from(s ?? "", "base64"));
const text = (b: Uint8Array): string => Buffer.from(b).toString("utf8");

function adviceFromWire(a: WireAdvice[] | undefined): AdviceFinding[] {
  return (a ?? []).map((f) => ({
    pattern: f.pattern ?? "",
    severity: f.severity ?? "",
    remedy: f.remedy ?? "",
    method: f.method ?? "",
    route: f.route ?? "",
    detail: f.detail ?? "",
    suggestedMethod: f.suggestedMethod ?? "",
    suggestedRoute: f.suggestedRoute ?? "",
    extraCalls: f.extraCalls ?? 0,
    addedLatencyMs: num(f.addedLatencyMs),
    bytesMoved: num(f.bytesMoved),
  }));
}

function evidence(resp: WireRunResponse, record: RunRecord): Evidence {
  return {
    sandbox: resp.sandbox ?? "",
    isolation: resp.isolation ?? "",
    softwareIdentity: resp.softwareIdentity ?? "",
    environment: resp.environment ?? "",
    durationMs: num(resp.durationMs),
    record,
  };
}

function javascriptResult(resp: WireRunResponse, record: RunRecord): JavaScriptResult {
  const j = resp.javascript ?? {};
  const out = bytes(j.stdout);
  const err = bytes(j.stderr);
  return {
    ...evidence(resp, record),
    stdout: text(out),
    stderr: text(err),
    stdoutBytes: out,
    stderrBytes: err,
    exitCode: j.exitCode ?? 0,
    timedOut: j.timedOut ?? false,
    stdoutTruncated: j.stdoutTruncated ?? false,
    stderrTruncated: j.stderrTruncated ?? false,
    advice: adviceFromWire(j.advice),
  };
}

function outcomeFromWire(v: string | number | undefined): ProjectOutcome {
  const names: ProjectOutcome[] = ["unspecified", "completed", "setup_failed", "timed_out", "protocol_error"];
  if (typeof v === "number") return names[v] ?? "unspecified";
  const name = (v ?? "").replace(/^PROJECT_OUTCOME_/, "").toLowerCase();
  return (names as string[]).includes(name) ? (name as ProjectOutcome) : "unspecified";
}

function projectResult(resp: WireRunResponse, record: RunRecord): ProjectResult {
  const p = resp.project ?? {};
  return {
    ...evidence(resp, record),
    outcome: outcomeFromWire(p.outcome),
    detail: p.outcomeDetail ?? "",
    steps: (p.steps ?? []).map((s) => ({
      command: s.command ?? "",
      stdout: text(bytes(s.stdout)),
      stderr: text(bytes(s.stderr)),
      exitCode: s.exitCode ?? 0,
      timedOut: s.timedOut ?? false,
      durationMs: num(s.durationMs),
      stdoutTruncated: s.stdoutTruncated ?? false,
      stderrTruncated: s.stderrTruncated ?? false,
    })),
    artifacts: (p.artifacts ?? []).map((a) => ({ path: a.path ?? "", content: bytes(a.content) })),
    artifactsTruncated: p.artifactsTruncated ?? false,
    advice: adviceFromWire(p.advice),
  };
}

function cellResult(resp: WireRunResponse, record: RunRecord): CellResult {
  const c = resp.cell ?? {};
  const out = bytes(c.stdout);
  const err = bytes(c.stderr);
  return {
    ...evidence(resp, record),
    stdout: text(out),
    stderr: text(err),
    stdoutBytes: out,
    stderrBytes: err,
    exitCode: c.exitCode ?? 0,
    timedOut: c.timedOut ?? false,
    stdoutTruncated: c.stdoutTruncated ?? false,
    stderrTruncated: c.stderrTruncated ?? false,
    interpreterStarted: c.interpreterStarted ?? false,
    interpreterEnded: c.interpreterEnded ?? false,
  };
}

type Payload =
  | { javascript: { code: string; grantProfile?: string } }
  | { project: { files: ProjectRequest["files"]; steps: string[]; artifacts: string[]; grantProfile?: string } }
  | { cell: WireCellRun & { files: { path: string; content: string }[] } };

// A lone surrogate has no UTF-8 form, so no protobuf string can hold one, though JSON
// carries it as an escape: the daemon would refuse the request after it arrived, with
// no not-dispatched mark. Every request is checked here before it is sent instead.
function refuseIllFormed(v: unknown, at: string): void {
  if (typeof v === "string") {
    if (!v.isWellFormed()) {
      throw new PlimsollError("invalid_argument", `plimsoll: ${at} is not well-formed text (a lone surrogate)`, { notDispatched: "request" });
    }
  } else if (Array.isArray(v)) {
    v.forEach((x, i) => refuseIllFormed(x, `${at}[${i}]`));
  } else if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) refuseIllFormed(x, `${at}.${k}`);
  }
}

// Reads an answer the daemon gave. A broken or hostile daemon can answer in any shape, so
// anything but a PlimsollError thrown while it is checked or decoded (a TypeError from a
// number where bytes belong, say) is data loss: the call may have run.
function decoded<T>(read: () => T): T {
  try {
    return read();
  } catch (e) {
    if (e instanceof PlimsollError) throw e;
    throw new PlimsollError("data_loss", `plimsoll: the daemon's answer is malformed (${e instanceof Error ? e.message : String(e)})`, { cause: e });
  }
}

function digestPayload(p: Payload): DigestPayload {
  if ("javascript" in p) return { kind: "javascript", code: p.javascript.code, grantProfile: p.javascript.grantProfile ?? "" };
  if ("cell" in p) return { kind: "cell", language: p.cell.language, code: p.cell.code, files: p.cell.files };
  return { kind: "project", grantProfile: p.project.grantProfile ?? "", files: p.project.files, steps: p.project.steps, artifacts: p.project.artifacts };
}

export class PlimsollClient {
  private readonly base: string;
  private readonly token: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly requestTimeoutMs: number;
  /** @internal */ readonly jsGrant: string;
  /** @internal */ readonly projectGrant: string;

  constructor(opts: ClientOptions) {
    this.base = validateBaseUrl(opts.baseUrl, opts.insecureHttp ?? false);
    this.token = opts.token;
    this.fetchImpl = opts.fetch ?? fetch;
    const rt = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    if (typeof rt !== "number" || !(rt > 0) || rt > 2 ** 31 - 1) {
      throw new PlimsollError("invalid_argument", "plimsoll: requestTimeoutMs must be a positive number of milliseconds");
    }
    this.requestTimeoutMs = rt;
    this.jsGrant = opts.javascriptGrantProfile ?? "";
    this.projectGrant = opts.projectGrantProfile ?? "";
  }

  /** @internal One unary Connect call with the JSON codec. */
  async call<T>(method: string, body: unknown, signal?: AbortSignal): Promise<T> {
    // Aborted before it was sent (a session call waiting its turn, say): nothing left
    // this process, so it is a refusal, not a call that may have run.
    if (signal?.aborted) throw new PlimsollError("canceled", `plimsoll: ${method} was canceled before it was sent`, { notDispatched: "request", cause: signal.reason });
    refuseIllFormed(body, "the request");
    const headers: Record<string, string> = { "Content-Type": "application/json", "Connect-Protocol-Version": "1" };
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    const deadline = AbortSignal.timeout(this.requestTimeoutMs);
    const both = signal ? AbortSignal.any([signal, deadline]) : deadline;
    // Neither error is marked not-dispatched: the request may have reached the daemon.
    const cut = (e: unknown): PlimsollError | undefined => {
      if (signal?.aborted) return new PlimsollError("canceled", "plimsoll: the call was canceled", { cause: e });
      if (deadline.aborted) return new PlimsollError("deadline_exceeded", `plimsoll: ${method} did not finish within ${this.requestTimeoutMs} ms`, { cause: e });
      return undefined;
    };
    let res: Response;
    try {
      // A Connect call is never redirected, and fetch's default follows a 307 or 308 by
      // sending the request again, the code in it included, wherever it points (it
      // drops the token only across origins). So a redirect is the answer, an error.
      res = await this.fetchImpl(`${this.base}/${SERVICE}/${method}`, { method: "POST", headers, body: JSON.stringify(body), signal: both, redirect: "manual" });
    } catch (e) {
      throw cut(e) ?? new PlimsollError("unavailable", `plimsoll: ${(e as Error).message}`, { cause: e });
    }
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      void res.body?.cancel().catch(() => undefined);
      throw new PlimsollError("unknown", `plimsoll: ${method} was answered with a redirect (HTTP ${res.status}), which this client never follows`);
    }
    let raw: string;
    try {
      raw = await readCapped(res, both);
    } catch (e) {
      if (e instanceof PlimsollError) throw e;
      throw cut(e) ?? new PlimsollError("unavailable", `plimsoll: reading the answer to ${method}: ${(e as Error).message}`, { cause: e });
    }
    let parsed: unknown;
    try {
      parsed = raw.length ? JSON.parse(raw) : {};
    } catch {
      parsed = undefined;
    }
    if (!res.ok) throw errorFromWire(res.status, parsed as WireError | undefined);
    if (parsed === undefined || typeof parsed !== "object") throw new PlimsollError("internal", "plimsoll: the daemon's answer is not a JSON message");
    return parsed as T;
  }

  /** The daemon's own statement of its provider, tier and what it supports. */
  async describe(signal?: AbortSignal): Promise<Info> {
    const m = await this.call<WireDescribeResponse>("Describe", {}, signal);
    return decoded(() => this.info(m));
  }

  private info(m: WireDescribeResponse): Info {
    const env = (e: WirePayloadEnvironment | undefined): PayloadEnvironment => ({
      identity: e?.identity ?? "",
      softwareIdentity: e?.softwareIdentity ?? "",
      maxTimeoutMs: e?.maxTimeoutMs ?? 0,
      languages: (e?.languages ?? []).filter((l): l is Language => l === "javascript" || l === "python"),
    });
    return {
      sandbox: m.sandbox ?? "",
      isolation: m.isolation ?? "",
      protocol: m.protocol ?? 0,
      supportsProject: m.supportsProject ?? false,
      supportsModule: m.supportsModule ?? false,
      supportsJavaScriptGrants: m.supportsJavascriptGrants ?? false,
      supportsProjectGrants: m.supportsProjectGrants ?? false,
      supportsSessions: m.supportsSessions ?? false,
      sessionLifetimeMs: m.sessionLifetimeMs ?? 0,
      sessionIdleTimeoutMs: m.sessionIdleTimeoutMs ?? 0,
      sessionEnvironment: env(m.sessionEnvironment),
      environments: {
        javascript: env(m.javascriptEnvironment),
        project: env(m.projectEnvironment),
        module: env(m.moduleEnvironment),
        policy: m.policy ?? "",
      },
      resources: {
        memoryMb: m.resources?.memoryMb ?? 0,
        cpus: m.resources?.cpus ?? 0,
        pids: m.resources?.pids ?? 0,
        diskMb: m.resources?.diskMb ?? 0,
      },
    };
  }

  /** Runs a JavaScript snippet in a fresh sandbox. */
  async runJavaScript(code: string, opts: RunOptions = {}): Promise<JavaScriptResult> {
    const resp = await this.exchange("Run", this.envelope(opts, validateRule(opts.software)), { javascript: { code, grantProfile: this.jsGrant || undefined } }, opts);
    return decoded(() => finish(resp.run, resp.record, javascriptResult, "javascript", opts.minimumIsolation));
  }

  /** Writes a multi-file project into a fresh sandbox and runs its steps in order. */
  async runProject(req: ProjectRequest, opts: RunOptions = {}): Promise<ProjectResult> {
    const resp = await this.exchange("Run", this.envelope(opts, validateRule(opts.software)), projectPayload(req, this.projectGrant), opts);
    return decoded(() => finish(resp.run, resp.record, projectResult, "project", opts.minimumIsolation));
  }

  /**
   * Opens a session: one sandbox kept for many calls, files persisting, and of
   * processes only the interpreters runCell keeps. Only on a daemon whose Describe
   * states supportsSessions.
   */
  async openSession(opts: SessionOptions = {}): Promise<Session> {
    const rule = validateRule(opts.software);
    for (const l of opts.languages ?? []) {
      if (l !== "javascript" && l !== "python") {
        throw new PlimsollError("invalid_argument", `plimsoll: unknown language ${JSON.stringify(l)} in the hint`, { notDispatched: "request" });
      }
    }
    const m = await this.call<WireOpenSessionResponse>(
      "OpenSession",
      {
        protocol: PROTOCOL,
        minimumIsolation: opts.minimumIsolation,
        traceId: opts.traceId,
        lifetimeMs: durationMs(opts.lifetimeMs) || undefined,
        idleTimeoutMs: durationMs(opts.idleTimeoutMs) || undefined,
        softwareRule: rule,
        languages: opts.languages?.length ? [...new Set(opts.languages)] : undefined,
      },
      opts.signal,
    );
    const s = decoded(() => new Session(this, m, rule, opts.minimumIsolation));
    if (decoded(() => s.fingerprint !== sessionFingerprint(m.sessionId ?? ""))) {
      // The session exists on the daemon either way, and nothing else holds its ID.
      await s.close().catch(() => undefined);
      throw new PlimsollError("data_loss", "plimsoll: the daemon's session fingerprint does not match its session ID; the session was closed");
    }
    if (opts.minimumIsolation && !meets(s.isolation, opts.minimumIsolation)) {
      await s.close().catch(() => undefined);
      throw new PlimsollError("data_loss", `plimsoll: the session opened at ${s.isolation}, below the requested ${opts.minimumIsolation}`);
    }
    if (!softwareRuleAllows(rule, m.softwareIdentity ?? "")) {
      await s.close().catch(() => undefined);
      throw new PlimsollError("data_loss", "plimsoll: the session's selected software is outside the requested rule");
    }
    return s;
  }

  /** @internal */
  envelope(opts: RunOptions, rule: WireSoftwareRule | undefined): WireEnvelope {
    return {
      protocol: PROTOCOL,
      minimumIsolation: opts.minimumIsolation,
      traceId: opts.traceId,
      timeoutMs: timeoutMs(opts.timeoutMs) || undefined,
      softwareRule: rule,
    };
  }

  // Sends one Run and checks its record.
  private async exchange(method: "Run", env: WireEnvelope, payload: Payload, opts: RunOptions): Promise<{ run: WireRunResponse; record: RunRecord }> {
    const resp = await this.call<WireRunResponse>(method, { ...env, ...payload }, opts.signal);
    return decoded(() => this.checked(env, payload, resp));
  }

  private checked(env: WireEnvelope, payload: Payload, resp: WireRunResponse): { run: WireRunResponse; record: RunRecord } {
    const checked = checkRecord(
      requestDigest({ protocol: env.protocol, minimumIsolation: env.minimumIsolation ?? "", timeoutMs: env.timeoutMs ?? 0, softwareRule: env.softwareRule, payload: digestPayload(payload) }),
      env.protocol,
      env.softwareRule,
      resp,
    );
    if ("problem" in checked) throw new PlimsollError("data_loss", `plimsoll: ${checked.problem}`, { result: resp });
    const r = checked.record;
    if (r.session !== "" || r.sequence !== 0n || r.previousSha256 !== "") {
      throw new PlimsollError("data_loss", "plimsoll: a single run's record carries session fields", { result: resp });
    }
    return { run: resp, record: r };
  }
}

/** @internal */
export function projectPayload(req: ProjectRequest, grantProfile: string): Payload {
  return {
    project: {
      files: req.files.map((f) => ({ path: f.path, content: f.content })),
      steps: [...req.steps],
      artifacts: [...(req.artifacts ?? [])],
      grantProfile: grantProfile || undefined,
    },
  };
}

// Maps a checked response and applies the two checks that follow the record:
// the result is of the request's kind, and the tier meets the floor.
function finish<T extends Evidence>(
  resp: WireRunResponse,
  record: RunRecord,
  map: (r: WireRunResponse, rec: RunRecord) => T,
  kind: "javascript" | "project" | "cell",
  floor: Isolation | undefined,
): T {
  const kinds = (["javascript", "project", "module", "cell"] as const).filter((k) => resp[k] !== undefined && resp[k] !== null);
  if (kinds.length > 1) throw new PlimsollError("data_loss", `plimsoll: the answer holds ${kinds.length} results; a run has one`, { result: resp });
  if (!resp[kind]) throw new PlimsollError("data_loss", "plimsoll: the daemon's result is not of the request's kind", { result: resp });
  const out = map(resp, record);
  if (floor && !meets(out.isolation, floor)) {
    throw new PlimsollError("data_loss", `plimsoll: result isolation ${out.isolation} is below the requested ${floor}; execution may have occurred`, { result: out });
  }
  return out;
}

/**
 * An open session. Calls are serialized here as they are on the daemon, so the
 * chain this client tracks follows the daemon's; a record that does not continue
 * it means someone else holding the session ID made a call. A call that ends
 * without an answer this client can check (any error not marked notDispatched)
 * may have run, so the session refuses every later call, marked notDispatched.
 */
export class Session {
  /** The SHA-256 of the session ID, as the session's records carry it. */
  readonly fingerprint: string;
  /** The tier the daemon measured when the session opened. */
  readonly isolation: string;
  readonly sandbox: string;
  /** The selected software the daemon stated at open. */
  readonly softwareIdentity: string;
  readonly expiresAtMs: number;
  readonly idleTimeoutMs: number;
  // The session ID is a capability: it goes to the daemon and nowhere else.
  readonly #id: string;
  readonly #client: PlimsollClient;
  readonly #rule: WireSoftwareRule | undefined;
  // The floor given at open: every call carries it unless the call asks for more.
  readonly #floor: Exclude<Isolation, "none"> | undefined;
  #calls = 0n;
  #last = "";
  #end: { reason: SessionEnd; detail: string } | undefined;
  // Set once a call ended without an answer this client could check: the daemon may
  // have run it and moved its chain on, so every later call would run and then fail
  // the chain check. They are refused here instead, before anything is sent.
  #unknown: string | undefined;
  #queue: Promise<unknown> = Promise.resolve();

  /** @internal */
  constructor(client: PlimsollClient, m: WireOpenSessionResponse, rule: WireSoftwareRule | undefined, floor?: Exclude<Isolation, "none">) {
    this.#client = client;
    this.#id = m.sessionId ?? "";
    this.#rule = rule;
    this.#floor = floor;
    this.fingerprint = m.session ?? "";
    this.isolation = m.isolation ?? "";
    this.sandbox = m.sandbox ?? "";
    this.softwareIdentity = m.softwareIdentity ?? "";
    this.expiresAtMs = num(m.expiresUnixMs);
    this.idleTimeoutMs = m.idleTimeoutMs ?? 0;
  }

  /**
   * Why this client sends nothing more on the session, once a call ended without an
   * answer it could check (the call may have run); undefined while it is usable.
   */
  get stopped(): string | undefined {
    return this.#unknown;
  }

  /** The session's end once a response reported it, else undefined. */
  get ended(): { reason: SessionEnd; detail: string } | undefined {
    return this.#end;
  }

  /** The number of calls this client has seen executed, and the last record's digest. */
  get chain(): { calls: bigint; lastRecordSha256: string } {
    return { calls: this.#calls, lastRecordSha256: this.#last };
  }

  async runJavaScript(code: string, opts: RunOptions = {}): Promise<JavaScriptResult> {
    opts = this.#withFloor(opts);
    const run = await this.#call({ javascript: { code, grantProfile: this.#client.jsGrant || undefined } }, opts);
    return decoded(() => finish(run.run, run.record, javascriptResult, "javascript", opts.minimumIsolation));
  }

  /** Runs a project in the session; its files persist for later calls. */
  async runProject(req: ProjectRequest, opts: RunOptions = {}): Promise<ProjectResult> {
    opts = this.#withFloor(opts);
    const run = await this.#call(projectPayload(req, this.#client.projectGrant), opts);
    return decoded(() => finish(run.run, run.record, projectResult, "project", opts.minimumIsolation));
  }

  /**
   * Runs code in the session's interpreter for req.language, which keeps what
   * earlier cells defined unless the result says a fresh one started. req.files are
   * written into the session's work directory, the interpreter's working directory,
   * before the code runs. A cell carries no grant.
   */
  async runCell(req: CellRequest, opts: RunOptions = {}): Promise<CellResult> {
    if (req.language !== "javascript" && req.language !== "python") {
      throw new PlimsollError("invalid_argument", `plimsoll: unknown cell language ${JSON.stringify(req.language)}`, { notDispatched: "request" });
    }
    opts = this.#withFloor(opts);
    const files = (req.files ?? []).map((f) => ({ path: f.path, content: f.content }));
    const run = await this.#call({ cell: { language: req.language, code: req.code, files } }, opts);
    return decoded(() => finish(run.run, run.record, cellResult, "cell", opts.minimumIsolation));
  }

  // The call's options with the session's floor, unless the call asks for more.
  #withFloor(opts: RunOptions): RunOptions {
    const a = this.#floor;
    const b = opts.minimumIsolation;
    if (!a || (b && TIERS.indexOf(b) >= TIERS.indexOf(a))) return opts;
    return { ...opts, minimumIsolation: a };
  }

  #serial<T>(f: () => Promise<T>): Promise<T> {
    const next = this.#queue.then(f, f);
    this.#queue = next.catch(() => undefined);
    return next;
  }

  #call(payload: Payload, opts: RunOptions): Promise<{ run: WireRunResponse; record: RunRecord }> {
    const rule = mergeRules(this.#rule, validateRule(opts.software));
    return this.#serial(async () => {
      if (this.#unknown !== undefined) {
        throw new PlimsollError(
          "failed_precondition",
          `plimsoll: an earlier call of this session ended without an answer this client could check (${this.#unknown}); it may have run, so this client sends nothing more on the session: open a new one`,
          { notDispatched: "request" },
        );
      }
      const env = this.#client.envelope(opts, rule);
      // Before the digest, which cannot encode such text either.
      refuseIllFormed({ ...env, ...payload }, "the request");
      const digest = requestDigest({ protocol: env.protocol, minimumIsolation: env.minimumIsolation ?? "", timeoutMs: env.timeoutMs ?? 0, softwareRule: rule, payload: digestPayload(payload) });
      try {
        return await this.#exchange(payload, opts, rule, env, digest);
      } catch (e) {
        if (e instanceof PlimsollError && e.notDispatched) throw e;
        if (e instanceof PlimsollError && e.unanswered) {
          // The call may have run, and the daemon chained its record: check it and keep
          // it in the chain, so the session goes on and the call is not hidden.
          let checked = checkUnanswered(digest, env.minimumIsolation ?? "", rule, e.unanswered, this.fingerprint, this.#calls, this.#last);
          if ("record" in checked) {
            // With no response to compare it with, the record's evidence must be what the
            // session stated at open.
            const r = checked.record;
            if (r.provider !== this.sandbox || r.isolation !== this.isolation || r.softwareIdentity !== this.softwareIdentity) {
              checked = {
                problem: `the unanswered call's record names ${r.provider} at "${r.isolation}" running "${r.softwareIdentity}", the session opened as ${this.sandbox} at "${this.isolation}" running "${this.softwareIdentity}"`,
              };
            }
          }
          if ("problem" in checked) {
            this.#unknown = checked.problem;
            throw new PlimsollError("data_loss", `plimsoll: ${checked.problem}`, { cause: e });
          }
          this.#calls = checked.record.sequence;
          this.#last = checked.record.sha256;
          e.record = checked.record; // the checked record, as Go's UnansweredCallError carries it
          throw e;
        }
        this.#unknown = e instanceof Error ? e.message : String(e);
        throw e;
      }
    });
  }

  async #exchange(
    payload: Payload,
    opts: RunOptions,
    rule: WireSoftwareRule | undefined,
    env: ReturnType<PlimsollClient["envelope"]>,
    digest: string,
  ): Promise<{ run: WireRunResponse; record: RunRecord }> {
    let m: WireSessionRunResponse;
    try {
      m = await this.#client.call<WireSessionRunResponse>("SessionRun", { ...env, sessionId: this.#id, ...payload }, opts.signal);
    } catch (e) {
      if (e instanceof PlimsollError && e.sessionEnded) this.#end = e.sessionEnded;
      throw e;
    }
    return decoded(() => this.#chained(m, env, rule, digest));
  }

  #chained(m: WireSessionRunResponse, env: ReturnType<PlimsollClient["envelope"]>, rule: WireSoftwareRule | undefined, digest: string): { run: WireRunResponse; record: RunRecord } {
    const run = m.run;
    if (!run) throw new PlimsollError("data_loss", "plimsoll: the session call's answer carries no run");
    const end = sessionEndFromWire(m.ended);
    if (end !== "open") this.#end = { reason: end, detail: m.endDetail ?? "" };
    const checked = checkRecord(digest, env.protocol, rule, run);
    if ("problem" in checked) throw new PlimsollError("data_loss", `plimsoll: ${checked.problem}`, { result: run });
    const r = checked.record;
    if (r.session !== this.fingerprint || r.sequence !== this.#calls + 1n || r.previousSha256 !== this.#last) {
      throw new PlimsollError(
        "data_loss",
        `plimsoll: the session's chain is broken: call ${r.sequence} after "${r.previousSha256}", this client's last was call ${this.#calls}, "${this.#last}"`,
        { result: run },
      );
    }
    this.#calls = r.sequence;
    this.#last = r.sha256;
    return { run, record: r };
  }

  /**
   * Ends the session (or collects one that ended by itself) and checks the
   * daemon's count of executed calls against the chain this client saw.
   */
  close(signal?: AbortSignal): Promise<SessionSummary> {
    return this.#serial(async () => {
      const m = await this.#client.call<WireCloseSessionResponse>("CloseSession", { protocol: PROTOCOL, sessionId: this.#id }, signal);
      const sum: SessionSummary = decoded(() => ({
        session: m.session ?? "",
        calls: BigInt(m.calls ?? 0),
        lastRecordSha256: m.lastRecordSha256 ?? "",
        end: sessionEndFromWire(m.ended),
      }));
      this.#end ??= { reason: sum.end, detail: "" };
      if (sum.session !== this.fingerprint || sum.calls !== this.#calls || sum.lastRecordSha256 !== this.#last) {
        throw new PlimsollError(
          "data_loss",
          `plimsoll: the daemon counts ${sum.calls} calls ending "${sum.lastRecordSha256}", this client saw ${this.#calls} ending "${this.#last}"`,
          { result: sum },
        );
      }
      return sum;
    });
  }
}

// Reads the answer under the call's signal itself, since a fetch implementation
// need not tie its body to the signal it was given.
async function readCapped(res: Response, signal: AbortSignal): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  let onAbort = () => {};
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason);
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), aborted]);
      if (done) break;
      n += value.length;
      if (n > MAX_RESPONSE_BYTES) {
        throw new PlimsollError("resource_exhausted", `plimsoll: the daemon's answer exceeds ${MAX_RESPONSE_BYTES} bytes`);
      }
      chunks.push(value);
    }
  } catch (e) {
    void reader.cancel().catch(() => undefined);
    throw e;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  return Buffer.concat(chunks).toString("utf8");
}
