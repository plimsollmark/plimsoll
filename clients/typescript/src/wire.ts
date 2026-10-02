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
};

/** A session's call to its interpreter (sessions.md, "Interpreters"). */
export type WireCellRun = { language: string; code: string; files?: { path: string; content: string }[] };

export type WireRunRequest = WireEnvelope & { javascript?: WireJavaScriptRun; project?: WireProjectRun };

export type WireSessionRunRequest = WireRunRequest & { sessionId: string };

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
  sessionEnvironment?: WirePayloadEnvironment;
};

export type WireOpenSessionRequest = {
  protocol: number;
  minimumIsolation?: string;
  traceId?: string;
  lifetimeMs?: number;
  idleTimeoutMs?: number;
  softwareRule?: WireSoftwareRule;
};

export type WireOpenSessionResponse = {
  sessionId?: string;
  session?: string;
  sandbox?: string;
  isolation?: string;
  expiresUnixMs?: string | number;
  idleTimeoutMs?: number;
  softwareIdentity?: string;
};

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
