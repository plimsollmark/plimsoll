// The proto3 JSON forms of plimsoll.v1 messages this client sends and reads
// (proto/plimsoll/v1/sandbox.proto). Field names are protobuf's lowerCamelCase
// JSON names; bytes are base64; 64-bit integers arrive as strings; enums as their
// names; a field at its zero value is omitted, which is why everything read is
// optional.

export type WireSoftwareRule = { mode: string; identities: string[] };

export type WireJavaScriptRun = { code: string; grantProfile?: string };

export type WireProjectRun = {
  files?: { path: string; content: string }[];
  steps?: string[];
  artifacts?: string[];
  grantProfile?: string;
};

export type WireEnvelope = {
  protocol: number;
  minimumIsolation?: string;
  traceId?: string;
  timeoutMs?: number;
  softwareRule?: WireSoftwareRule;
  /** Run only, with a cell: the daemon may run it in a waiting pool member. */
  preferWarm?: boolean;
};

/** A session's call to its interpreter (sessions.md, "Interpreters"). */
export type WireCellRun = { language: string; code: string; files?: { path: string; content: string }[] };

export type WireRunRequest = WireEnvelope & { javascript?: WireJavaScriptRun; project?: WireProjectRun; cell?: WireCellRun };

/** A session call: the run request with the session ID and the current ownership generation (a uint64, as a decimal string). */
export type WireSessionRunRequest = WireRunRequest & { sessionId: string; generation: string };

export type WireRecord = {
  version?: number;
  requestSha256?: string;
  resultSha256?: string;
  provider?: string;
  isolation?: string;
  environment?: string;
  policy?: string;
  startedUnixMs?: string | number;
  endedUnixMs?: string | number;
  session?: string;
  sequence?: string | number;
  previousSha256?: string;
  unanswered?: string;
  softwareIdentity?: string;
  softwareRuleId?: string;
  instance?: string;
  isolationQualification?: string;
  warm?: boolean;
  daemonVersion?: string;
  recordSha256?: string;
};

export type WireAdvice = {
  pattern?: string;
  severity?: string;
  remedy?: string;
  method?: string;
  route?: string;
  detail?: string;
  suggestedMethod?: string;
  suggestedRoute?: string;
  extraCalls?: number;
  addedLatencyMs?: string | number;
  bytesMoved?: string | number;
};

export type WireJavaScriptResult = {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  timedOut?: boolean;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
  advice?: WireAdvice[];
};

export type WireStepResult = {
  command?: string;
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  timedOut?: boolean;
  durationMs?: string | number;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
};

export type WireProjectResult = {
  steps?: WireStepResult[];
  outcome?: string | number;
  artifacts?: { path?: string; content?: string }[];
  outcomeDetail?: string;
  artifactsTruncated?: boolean;
  advice?: WireAdvice[];
};

export type WireCellResult = {
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  timedOut?: boolean;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
  interpreterStarted?: boolean;
  interpreterEnded?: boolean;
};

export type WireRunResponse = {
  sandbox?: string;
  isolation?: string;
  durationMs?: string | number;
  record?: WireRecord;
  softwareIdentity?: string;
  environment?: string;
  instance?: string;
  warm?: boolean;
  isolationQualification?: string;
  daemonVersion?: string;
  javascript?: WireJavaScriptResult;
  project?: WireProjectResult;
  module?: unknown;
  cell?: WireCellResult;
};

export type WireSessionRunResponse = { run?: WireRunResponse; ended?: string | number; endDetail?: string };

export type WirePayloadEnvironment = { identity?: string; maxTimeoutMs?: number; softwareIdentity?: string; languages?: string[] };

export type WireDescribeResponse = {
  sandbox?: string;
  isolation?: string;
  supportsProject?: boolean;
  supportsJavascriptGrants?: boolean;
  supportsProjectGrants?: boolean;
  supportsModule?: boolean;
  protocol?: number;
  javascriptEnvironment?: WirePayloadEnvironment;
  projectEnvironment?: WirePayloadEnvironment;
  moduleEnvironment?: WirePayloadEnvironment;
  resources?: { memoryMb?: number; cpus?: number; pids?: number; diskMb?: number };
  policy?: string;
  supportsSessions?: boolean;
  sessionLifetimeMs?: number;
  sessionIdleTimeoutMs?: number;
  maxSessionsPerCaller?: number;
  maxSessionsPerOwner?: number;
  sessionEnvironment?: WirePayloadEnvironment;
  sessionPool?: number;
  isolationQualification?: string;
};

export type WireOpenSessionRequest = {
  protocol: number;
  minimumIsolation?: string;
  traceId?: string;
  lifetimeMs?: number;
  idleTimeoutMs?: number;
  softwareRule?: WireSoftwareRule;
  languages?: string[];
  owner?: string;
  warmOnly?: boolean;
};

export type WireOpenSessionResponse = {
  generation?: string | number;
  /** The floor and software rule the open sent, as the daemon keeps them. */
  minimumIsolation?: string;
  softwareRule?: WireSoftwareRule;
  sessionId?: string;
  session?: string;
  sandbox?: string;
  isolation?: string;
  expiresUnixMs?: string | number;
  idleTimeoutMs?: number;
  softwareIdentity?: string;
  isolationQualification?: string;
};

export type WireCloseSessionRequest = { protocol: number; sessionId: string; generation: string };

/** A session's public chain head, the uint64s as decimal strings (plimsoll.v1.SessionCheckpoint). */
export type WireSessionCheckpoint = { generation?: string | number; calls?: string | number; lastRecordSha256?: string };

export type WireAttachSessionRequest = { protocol: number; session: string; checkpoint: WireSessionCheckpoint; traceId?: string; lostRequestSha256?: string };

export type WireAttachSessionResponse = { sessionInfo?: WireOpenSessionResponse; checkpoint?: WireSessionCheckpoint; lostRecord?: WireRecord };

export type WireCloseSessionResponse = {
  session?: string;
  calls?: string | number;
  lastRecordSha256?: string;
  ended?: string | number;
};

/** A Connect error body: https://connectrpc.com/docs/protocol#error-end-stream */
export type WireError = {
  code?: string;
  message?: string;
  details?: { type?: string; value?: string }[];
};

/** A bytes field that is not base64 text: the answer is not the protocol's. */
export class WireShapeError extends Error {}

/**
 * Decodes a bytes field of the daemon's answer. Only a string (or an absent field) is
 * accepted: the answer is parsed JSON, and Buffer.from given an object with a
 * "length" allocates that many bytes and reads each index, so a 30-byte
 * {"length":2000000000} would cost 2 GB and a blocked event loop past the
 * response's 32 MiB cap (Claude Security scan, 2026-10-27).
 *
 * The text must be base64 throughout, standard or URL-safe, padded or not, as protobuf
 * JSON and Connect error details may carry it, and as the Python client reads it:
 * Buffer.from skips any character outside the alphabet, so "CAY!" read as "CAY", and a
 * refusal detail with a stray character marked a call nothing ran in where the Go and
 * Python clients believe nothing of the detail (finding hunt-quality-93).
 *
 * The padding is counted off the end, not stripped with a pattern: /=+$/ is tried from
 * every "=" of a run that is not at the end, so an answer holding a million "=" and one
 * letter took minutes on one synchronous call that no deadline can cut (finding
 * hunt-security-35). The alphabet test left is one anchored character class: one pass.
 */
export function wireBytes(v: unknown): Buffer {
  if (v === undefined || v === null) return Buffer.alloc(0);
  if (typeof v !== "string") throw new WireShapeError(`a bytes field holds a ${Array.isArray(v) ? "list" : typeof v}, not base64 text`);
  const core = v.slice(0, v.length - trailing(v, "="));
  // Node's base64 decoder reads both alphabets, as Python's does with its URL-safe
  // characters translated.
  if (!/^[A-Za-z0-9+/_-]*$/.test(core) || core.length % 4 === 1) throw new WireShapeError("a bytes field is not base64 text");
  return Buffer.from(core, "base64");
}

/** How many times ch (one UTF-16 unit) ends s, counted from the end in one pass. */
export function trailing(s: string, ch: string): number {
  const c = ch.charCodeAt(0);
  let n = 0;
  while (n < s.length && s.charCodeAt(s.length - 1 - n) === c) n++;
  return n;
}
