// The piece both add-ons share: one sandbox per conversation, behind a key the
// framework supplies (a Trigger.dev run id, a Mastra thread id). It is the
// framework-neutral half of Trigger.dev's code-sandbox recipe: warm at the start
// of a turn without blocking, reuse for every executeCode call, dispose when the
// conversation goes to sleep.
//
// On a daemon that keeps sessions (Describe's supportsSessions: docker with a
// project image, openshell) a key holds one plimsoll session, and every call is a
// cell: code run in an interpreter the session keeps alive, so variables and
// loaded data survive between calls as they do in a notebook, and the files a call
// is given or writes stay in the work directory. On any other daemon, and for a
// call without a key, each call runs in a fresh sandbox through a small runner that
// prints the last expression the same way; nothing persists. The tool's output says
// which, so the model is never told state survived when it did not. A daemon without
// projects (wasm) runs a fresh call as a JavaScript snippet, and refuses Python and
// files before sending anything.
//
// Whether earlier state exists is something only the sandbox knows: this instance
// forgets a key when it is disposed or idles out, and a conversation that resumes
// in another process starts with a new instance. So a call says what is new rather
// than what was lost: freshInterpreter whenever its interpreter just started,
// freshSandbox whenever it is the first answered call in a newly opened sandbox,
// the conversation's first call included.
//
// Every kept sandbox holds one of the daemon's session slots, which every user of an
// app that shares one token draws on. So a key names the user it belongs to, and this
// instance holds at most maxSessionsPerOwner sandboxes per user (and maxSessions in
// all, when set): a conversation over the cap first closes the least recently used
// sandbox with no call in flight, whose next call then says freshSandbox. These caps
// count what this instance holds. Every open also names its owner (as a keyed digest),
// so a daemon with SANDBOX_MAX_SESSIONS_PER_OWNER does the same across every process
// of the app: a session it closes there refuses its next call as replaced, and the
// call runs once more in a new sandbox, saying freshSandbox.

import { createHash } from "node:crypto";

import { PlimsollClient, type Info, type Isolation, type Language, type ProjectResult, type Session } from "./client.ts";
import { PlimsollError, type Refusal } from "./errors.ts";

export type SessionMode = "auto" | "always" | "never";

/** The languages a tool offers, the first being the default. */
export type ToolLanguages = readonly [Language, ...Language[]];

export const DEFAULT_LANGUAGES: ToolLanguages = ["python", "javascript"];

/**
 * Which sandbox a call uses, from the application, never from a model's tool call. A
 * conversation names its owner, the user it belongs to, whom maxSessionsPerOwner
 * counts; a string (a Trigger.dev run id) names no owner and counts only against
 * maxSessions.
 */
export type SandboxKey = string | { owner: string; conversation: string };

// One string per key: JSON keeps a pair from aliasing another pair, or a string key,
// as a separator could.
function keyId(key: SandboxKey): string {
  const parts = typeof key === "string" ? [key] : key && typeof key === "object" ? [key.owner, key.conversation] : [];
  if (parts.length === 0 || parts.some((p) => typeof p !== "string" || p === "")) {
    throw new PlimsollError("invalid_argument", "plimsoll: a sandbox key is a nonempty string, or a nonempty owner and conversation", { notDispatched: "request" });
  }
  return JSON.stringify(parts);
}

const ownerOf = (key: SandboxKey): string | undefined => (typeof key === "string" ? undefined : key.owner);

const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// Refusal reasons that can mean the daemon is no longer the one the cached Describe
// described.
const DAEMON_CHANGED: ReadonlySet<Refusal> = new Set<Refusal>(["unsupported", "environment", "protocol", "isolation"]);

// Runs a stage before the code is sent to a sandbox (resolving the key, building the
// client, the Describe, opening the sandbox). Whatever fails there ran nothing, so the
// stage decides the mark, not the error's class: a transport error, a proxy's 503 or
// the client's own check of an open is as much a refusal as the daemon's. A mark already
// given is kept, with its code; an unmarked failure is marked reason environment, the
// rule the Python CodeExecutor applies to a failed Describe.
async function beforeDispatch<T>(stage: () => T | Promise<T>): Promise<T> {
  try {
    return await stage();
  } catch (e) {
    if (e instanceof PlimsollError && e.notDispatched) throw e;
    if (e instanceof PlimsollError) {
      throw new PlimsollError(e.code, e.message, { notDispatched: "environment", sessionEnded: e.sessionEnded, result: e.result, cause: e });
    }
    throw new PlimsollError("unknown", errorText(e), { notDispatched: "environment", cause: e });
  }
}

// Puts whether the code ran at the front of the error's message, once. Every stage
// before dispatch runs in beforeDispatch, so an error that is not a PlimsollError came
// from the dispatch or after it: the code may have run, and it is wrapped unmarked.
function saysWhetherItRan(e: unknown): PlimsollError {
  const err = e instanceof PlimsollError ? e : new PlimsollError("unknown", errorText(e), { cause: e });
  const lead = err.notDispatched ? `Nothing ran (${err.notDispatched}): ` : "The code may have run, and there is no checked answer for it: ";
  if (!err.message.startsWith(lead)) err.message = lead + err.message;
  return err;
}

function canceledBeforeSent(signal: AbortSignal): PlimsollError {
  return new PlimsollError("canceled", "plimsoll: the call was canceled before it was sent", { notDispatched: "request", cause: signal.reason });
}

// The promise, or a not-dispatched refusal as soon as the signal aborts: the call stops
// waiting, and whatever it waited for goes on.
function untilAborted<T>(p: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(canceledBeforeSent(signal));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(canceledBeforeSent(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

/** @internal The first 12 hex digits of the key's SHA-256: names it in a log line without its IDs. */
export function keyDigest(key: SandboxKey): string {
  return createHash("sha256").update(keyId(key), "utf8").digest("hex").slice(0, 12);
}

export type CodeSandboxesOptions = {
  /**
   * The daemon's client, or a function that builds it on first use: a
   * module-level tool can then be declared before its environment is read
   * (Trigger.dev indexes task modules at deploy time, without runtime secrets).
   */
  client: PlimsollClient | (() => PlimsollClient);
  /**
   * "auto" (default) keeps a session per key when the daemon supports sessions,
   * else runs each call fresh. "always" fails when it does not; "never" always
   * runs fresh.
   */
  sessions?: SessionMode;
  /** The languages the tool offers, the first being the default. Default python, then javascript. */
  languages?: ToolLanguages;
  /**
   * The weakest tier a run accepts; checked before dispatch and on the answer. Default
   * kernel (a verified gVisor runtime), the weakest tier fit for hostile code; set
   * "container" for local development against an ordinary docker daemon.
   */
  minimumIsolation?: Exclude<Isolation, "none">;
  /** Per-call budget. */
  timeoutMs?: number;
  /** Asked of the daemon when a session opens; the daemon's own caps apply. */
  sessionLifetimeMs?: number;
  sessionIdleTimeoutMs?: number;
  /**
   * Close a key's session after this long without a call, so a conversation
   * that never reaches its dispose hook does not hold a daemon slot until the
   * session's lifetime ends. Default 10 minutes; 0 never.
   */
  idleCloseMs?: number;
  /**
   * Sandboxes one owner may hold in this instance. Default 3: a person rarely works in
   * more than a few conversations at once, and the conversation whose sandbox is closed
   * loses its variables and files, never an answer (its next call says freshSandbox).
   * 0 = no cap. It counts this instance only; for an app running as many processes
   * (serverless functions, Trigger.dev workers), set the daemon's
   * SANDBOX_MAX_SESSIONS_PER_OWNER, which counts them all.
   */
  maxSessionsPerOwner?: number;
  /**
   * Sandboxes this instance holds across owners, closed the same way: the share of
   * the daemon's SANDBOX_MAX_SESSIONS this app may take, which only the operator knows.
   * Default 0, no cap of its own. A daemon at its cap refuses the open (not dispatched,
   * reason capacity); closing an idle sandbox then is not done for you, because the
   * daemon gives the same refusal for its rate limit, which a close does not help.
   */
  maxSessions?: number;
  /** Characters of stdout and of stderr returned to the model; the rest is cut and marked. */
  maxOutputChars?: number;
  /**
   * Called when closing a sandbox fails. A "data_loss" error here means the
   * daemon counted calls this client has no answer for: a call that ended
   * without one (an abort, a timeout, a dropped connection, a proxy's error),
   * or, if none did, someone else holding the session ID. Default: console.warn, naming
   * the key only by a digest, since a key can hold a user's ID. The error never
   * contains the session ID. A callback that throws, or returns a promise that
   * rejects, is logged the same way; it never stops a close or the next open.
   */
  onCloseError?: (key: SandboxKey, err: unknown) => void;
};

/** What the executeCode tool takes. */
export type ExecuteCodeInput = {
  code: string;
  language?: Language;
  files?: { path: string; content: string }[];
};

/** What the executeCode tool returns to the model. */
export type ExecuteCodeOutput = {
  language: Language;
  exitCode: number;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  /** Output was cut, by the daemon's cap or by maxOutputChars. */
  truncated: boolean;
  /**
   * This call's interpreter, and its sandbox, were still running when it answered, so
   * what it defined can be there for the conversation's next call in this language:
   * false without a kept interpreter, and when a deadline or the sandbox's end ended
   * them. Not a promise: the sandbox can still end before the next call (its lifetime,
   * the disk check after a call), and that call's freshInterpreter says what survived.
   */
  stateKept: boolean;
  /**
   * This call's interpreter had just started: nothing earlier calls defined in this
   * language exists (the first call, a deadline, a crash, a new sandbox).
   */
  freshInterpreter?: true;
  /**
   * This call's sandbox was still running when it answered, so its files can be there
   * for the next call: false without a kept sandbox, and when it ended. The next call's
   * freshSandbox says whether they are.
   */
  filesPersist: boolean;
  /**
   * This call ran in a newly opened sandbox: no file an earlier call wrote or was
   * given is there (the first call, a disposed or idle sandbox, one that ended).
   */
  freshSandbox?: true;
  /** The tier the code ran behind: configuration and provider evidence, not attestation. */
  isolation: string;
  /** SHA-256 of the run record checked by the client before this result was returned. */
  recordSha256: string;
};

type Entry = {
  key: SandboxKey;
  owner: string | undefined;
  /** When a call last started or ended here, for the least-recently-used close. */
  used: number;
  session: Promise<Session>;
  opened?: Session;
  timer?: ReturnType<typeof setTimeout>;
  /** A call in this sandbox has been answered: the next one is not its first. */
  answered: boolean;
  /** Calls in flight, which the idle close waits for. */
  busy: number;
};

/** @internal A fresh call on a daemon without projects: the code as a snippet, its last value printed. Node and QuickJS alike. */
export function snippetRunner(code: string): string {
  return [
    "(() => {",
    "  const show = (v) => {",
    '    if (typeof require === "function") { try { return require("node:util").inspect(v, { depth: 4 }); } catch (_) {} }',
    "    try { const s = JSON.stringify(v); if (s !== undefined) return s; } catch (_) {}",
    "    return String(v);",
    "  };",
    `  const v = (0, eval)(${JSON.stringify(code)});`,
    "  Promise.resolve(v).then((v) => { if (v !== undefined) console.log(show(v)); });",
    "})();",
    "",
  ].join("\n");
}

/**
 * @internal A fresh run prints its last expression as a cell does, through these
 * runners, and takes what a cell takes: top-level await, and imports from the work
 * directory (Python's own imports first, in isolated mode, as the session kernel
 * does; Node's require resolving from the work directory, and the image's baked
 * packages above it).
 */
export const RUNNERS: Record<Language, { path: string; file: string; step: string; source: string }> = {
  python: {
    path: ".plimsoll/run.py",
    file: ".plimsoll/cell.py",
    step: "python3 -I .plimsoll/run.py",
    // As the session kernel runs a cell: at module level, an event loop only for code
    // that awaits at the top level, so the cell's own asyncio.run works.
    source: [
      "import ast, asyncio, inspect, linecache, sys",
      "sys.path.insert(0, '')",
      // UTF-8, as the client wrote it: the guest gets the image's environment, and an
      // image whose locale is not UTF-8 would otherwise misread non-ASCII code.
      "src = open('.plimsoll/cell.py', encoding='utf-8').read()",
      "linecache.cache['cell'] = (len(src), None, src.splitlines(True), 'cell')",
      "tree = ast.parse(src, 'cell', 'exec')",
      "last = ast.Expression(tree.body.pop().value) if tree.body and isinstance(tree.body[-1], ast.Expr) else None",
      "ns = {'__name__': '__main__', '__builtins__': __builtins__}",
      "flags = ast.PyCF_ALLOW_TOP_LEVEL_AWAIT",
      "loop = asyncio.new_event_loop()",
      "def settle(r):",
      "    return loop.run_until_complete(r) if inspect.isawaitable(r) else r",
      "settle(eval(compile(tree, 'cell', 'exec', flags=flags), ns))",
      "if last is not None:",
      "    value = settle(eval(compile(last, 'cell', 'eval', flags=flags), ns))",
      "    if value is not None:",
      "        print(repr(value))",
      "",
    ].join("\n"),
  },
  javascript: {
    path: ".plimsoll/run.cjs",
    file: ".plimsoll/cell.js",
    step: "node --expose-internals .plimsoll/run.cjs",
    source: [
      "const fs = require('node:fs'), util = require('node:util'), vm = require('node:vm');",
      // The names a cell in the session's `node -e` interpreter sees as globals.
      "globalThis.require = require('node:module').createRequire(process.cwd() + '/');",
      "globalThis.module = { exports: {} }; globalThis.exports = globalThis.module.exports;",
      "globalThis.__dirname = '.'; globalThis.__filename = '[eval]';",
      // Top-level await comes from Node's private module internal/repl/await (the
      // REPL's own rewrite of a cell), which only --expose-internals makes loadable. It
      // is not a public API. The suite runs this runner on the node that runs the suite:
      // 22.18.0 in CI, the line of the project image's node:22 base; it also passed on
      // 26.3.1 on 2026-10-07. If a Node release moves or removes it, the require below
      // fails and the cell runs without the rewrite: a cell that awaits at the top level
      // then fails visibly (a SyntaxError on stderr, exit code 1), and so does the runner
      // test "imports from the work directory and awaits at the top level"; a cell
      // without top-level await runs as before.
      "let tla = null;",
      "try { tla = require('internal/repl/await').processTopLevelAwait; } catch {}",
      "const src = fs.readFileSync('.plimsoll/cell.js', 'utf8');",
      "let wrapped = null;",
      "if (tla) { try { wrapped = tla(src); } catch {} }",
      "(async () => {",
      "  let v;",
      "  if (wrapped) {",
      "    const out = await vm.runInThisContext(wrapped, { filename: 'cell.js' });",
      "    v = out === undefined ? undefined : out.value;",
      "  } else {",
      "    v = vm.runInThisContext(src, { filename: 'cell.js' });",
      "    if (v instanceof Promise) v = await v;",
      "  }",
      "  if (v !== undefined) console.log(util.inspect(v, { depth: 4 }));",
      "})().catch((e) => { console.error(e); process.exitCode = 1; });",
      "",
    ].join("\n"),
  },
};

export class CodeSandboxes {
  readonly #opts: CodeSandboxesOptions;
  readonly #entries = new Map<string, Entry>();
  #clock = 0;
  #info: Promise<Info> | undefined;
  #client: PlimsollClient | undefined;

  constructor(opts: CodeSandboxesOptions) {
    this.#opts = opts;
  }

  get client(): PlimsollClient {
    const c = this.#opts.client;
    return (this.#client ??= typeof c === "function" ? c() : c);
  }

  /** The languages the tool offers, the first being the default. */
  get languages(): ToolLanguages {
    return this.#opts.languages ?? DEFAULT_LANGUAGES;
  }

  // Building the client is part of the Describe's stage: neither runs any code.
  #describe(): Promise<Info> {
    this.#info ??= beforeDispatch(() => this.client.describe()).catch((e: unknown) => {
      this.#info = undefined; // retry the next time instead of caching a failure
      throw e;
    });
    return this.#info;
  }

  /** Whether calls under a key share one sandbox on this daemon. */
  async persistent(): Promise<boolean> {
    const mode = this.#opts.sessions ?? "auto";
    if (mode === "never") return false;
    const info = await this.#describe();
    if (!info.supportsSessions && mode === "always") {
      throw new PlimsollError("unimplemented", `plimsoll: the daemon (${info.sandbox}) does not keep sessions`, { notDispatched: "unsupported" });
    }
    return info.supportsSessions;
  }

  /**
   * Starts creating the key's sandbox and returns at once. A failure here is
   * not lost: the next run under the key opens a session again. A warm is a guess
   * (a new chat the user may never type in), so it never closes another sandbox to
   * make room: with the key's owner, or this instance, at its cap it does nothing,
   * and the key's first call opens the sandbox, closing the least recently used idle
   * one then. On a daemon with SANDBOX_MAX_SESSIONS_PER_OWNER a warm that opens is an
   * open like any other: the daemon counts it, and at its cap closes that user's least
   * recently used session there.
   */
  warm(key: SandboxKey): void {
    const id = keyId(key); // an invalid key is the caller's mistake, said at once
    if (this.#entries.has(id) || !this.#hasRoom(ownerOf(key))) return;
    void this.#session(key).catch(() => undefined);
  }

  // Whether one more sandbox fits under both caps without closing any.
  #hasRoom(owner: string | undefined): boolean {
    const under = (match: (e: Entry) => boolean, cap: number) => cap <= 0 || [...this.#entries.values()].filter(match).length < cap;
    return (owner === undefined || under((e) => e.owner === owner, this.#opts.maxSessionsPerOwner ?? 3)) && under(() => true, this.#opts.maxSessions ?? 0);
  }

  /**
   * Runs one call of the tool under the key, or under the key a function returns (an
   * add-on reading it from its framework's context, so a failure to find it is this
   * call's refusal). Every error it throws is a PlimsollError whose message starts with
   * whether the code ran: "Nothing ran (<reason>): " when it carries a not-dispatched
   * mark, "The code may have run, and there is no checked answer for it: " otherwise. A
   * failure before the code was sent (the key, the client, the Describe, the sandbox's
   * open) is marked, reason environment unless the daemon gave one. A framework hands
   * its model only the message (Mastra's error-text, the AI SDK's tool error), and that
   * is the one thing the model must not guess.
   */
  async run(key: SandboxKey | undefined | (() => SandboxKey | undefined), input: ExecuteCodeInput, signal?: AbortSignal): Promise<ExecuteCodeOutput> {
    try {
      return await this.#run(key, input, signal);
    } catch (e) {
      const err = saysWhetherItRan(e);
      // The Describe decides the mode and the languages for every call, and a daemon
      // can change under a long-lived process (restarted with sessions on or off, or
      // another image, tier or protocol). A refusal that says so drops it, and the next
      // call reads it again; a capacity or request refusal says nothing of the daemon.
      if (err.notDispatched && DAEMON_CHANGED.has(err.notDispatched)) this.#info = undefined;
      throw err;
    }
  }

  async #run(keyOrResolver: SandboxKey | undefined | (() => SandboxKey | undefined), input: ExecuteCodeInput, signal?: AbortSignal): Promise<ExecuteCodeOutput> {
    const { key, id, info, language, files, persistent } = await beforeDispatch(async () => {
      const key = typeof keyOrResolver === "function" ? keyOrResolver() : keyOrResolver;
      const id = key === undefined ? undefined : keyId(key);
      // A fresh run's runner and cell file live under .plimsoll/; a file of the call's
      // own there would replace them.
      const files = input.files ?? [];
      const reserved = files.find((f) => f.path === ".plimsoll" || f.path.startsWith(".plimsoll/"));
      if (reserved) {
        throw new PlimsollError("invalid_argument", `plimsoll: ${JSON.stringify(reserved.path)} is under .plimsoll/, which the sandbox's runner reserves`, {
          notDispatched: "request",
        });
      }
      const language = input.language ?? this.languages[0];
      if (!this.languages.includes(language)) {
        throw new PlimsollError("invalid_argument", `plimsoll: this tool runs ${this.languages.join(" or ")}, not ${language}`, { notDispatched: "request" });
      }
      // The Describe is shared with other calls, so an abort stops this call's wait for
      // it, not the Describe.
      const info = await untilAborted(this.#describe(), signal);
      const proved = info.environments.project.languages;
      // A daemon that states no languages predates the statement: let it try.
      if (proved.length > 0 && !proved.includes(language)) {
        throw new PlimsollError("unimplemented", `plimsoll: the sandbox image has no ${language} interpreter (it runs ${proved.join(", ")})`, {
          notDispatched: "unsupported",
        });
      }
      // Without a key there is no conversation to scope a sandbox to, and sharing
      // one across conversations would hand one user's files to another.
      const persistent = key !== undefined && (await untilAborted(this.persistent(), signal));
      return { key, id, info, language, files, persistent };
    });
    const opts = { timeoutMs: this.#opts.timeoutMs, minimumIsolation: this.#floor, signal };
    if (key === undefined || !persistent) {
      return this.#fresh(info, language, input.code, files, opts);
    }
    let retried = false;
    for (;;) {
      // A call already aborted opens no sandbox.
      if (signal?.aborted) throw canceledBeforeSent(signal);
      // The call holds its entry from here, the open included, so the idle close
      // cannot let the sandbox go while the call waits for it to open.
      const entry = this.#entryFor(key);
      entry.busy++;
      entry.used = ++this.#clock;
      let session: Session | undefined;
      try {
        // The open sends no code: a failure there (the daemon unreachable, a proxy's
        // 503, the client's own check of the session it opened) ran nothing.
        session = await beforeDispatch(() => untilAborted(entry.session, signal));
        // From here the cell may have been sent: an unmarked error stays unmarked.
        const r = await session.runCell({ language, code: input.code, files }, opts);
        // Read once the call has answered: the session runs its calls in order, so of
        // calls made at once only the first to answer finds the sandbox new.
        const first = !entry.answered;
        entry.answered = true;
        // What the call defined, and the files it wrote, can be there for the next call
        // only if its interpreter, and the sandbox, outlived it; the next call's fresh
        // flags say whether they did.
        const ended = session.ended !== undefined;
        if (ended) this.#drop(key, session); // the next call opens a new one
        return {
          ...this.#cut(language, r.exitCode, r.timedOut, r.stdout, r.stderr, r.stdoutTruncated || r.stderrTruncated),
          stateKept: !r.interpreterEnded && !ended,
          ...(r.interpreterStarted ? { freshInterpreter: true as const } : {}),
          filesPersist: !ended,
          ...(first ? { freshSandbox: true as const } : {}),
          isolation: r.isolation,
          recordSha256: r.record.sha256,
        };
      } catch (e) {
        // Aborted while its sandbox opened: nothing was sent, and a sandbox no call has
        // used is not kept for a call that has gone (the open finishes, then closes).
        if (!session && signal?.aborted) {
          if (entry.busy === 1 && !entry.answered && this.#entries.get(id!) === entry) void this.#dispose(id!);
          throw e;
        }
        // A call refused because its session had ended ran nothing, so it is
        // safe to run once more in a new sandbox; anything else is not.
        if (!retried && session && e instanceof PlimsollError && e.sessionEnded && e.notDispatched) {
          retried = true;
          this.#drop(key, session);
          continue;
        }
        // A call that may have run without an answer this client could check leaves
        // the session unusable (the Session refuses its later calls), so the next call
        // opens a new sandbox and says so with freshSandbox. One whose record the
        // Session checked and chained (e.record) leaves it usable, and so does a refusal.
        if (session && (session.stopped !== undefined || session.ended !== undefined)) this.#drop(key, session);
        throw e;
      } finally {
        entry.busy--;
        entry.used = ++this.#clock;
        this.#touch(id!);
      }
    }
  }

  /** Closes the key's sandbox, if it has one. Safe to call more than once. */
  dispose(key: SandboxKey): Promise<void> {
    return this.#dispose(keyId(key));
  }

  /** Closes every sandbox this instance holds, for shutdown. */
  async disposeAll(): Promise<void> {
    await Promise.all([...this.#entries.keys()].map((id) => this.#dispose(id)));
  }

  // Forgets the entry at once, before the first await, so a cap counts it gone, and
  // resolves once the daemon has closed the session and given its slot back.
  async #dispose(id: string): Promise<void> {
    const entry = this.#entries.get(id);
    if (!entry) return;
    this.#entries.delete(id);
    if (entry.timer) clearTimeout(entry.timer);
    const session = await entry.session.catch(() => undefined);
    // An ended session is collected the same way.
    await session?.close().catch((e: unknown) => this.#closeError(entry.key, e));
  }

  get #floor(): Exclude<Isolation, "none"> {
    return this.#opts.minimumIsolation ?? "kernel";
  }

  // A fresh sandbox for one call: the files, the code and a runner that prints the
  // last expression, as one project.
  async #fresh(
    info: Info,
    language: Language,
    code: string,
    files: { path: string; content: string }[],
    opts: { timeoutMs?: number; minimumIsolation: Exclude<Isolation, "none">; signal?: AbortSignal },
  ): Promise<ExecuteCodeOutput> {
    if (!info.supportsProject) {
      // A snippet is all this daemon runs (wasm): JavaScript, without files.
      if (language !== "javascript") {
        throw new PlimsollError("unimplemented", `plimsoll: the daemon (${info.sandbox}) runs JavaScript snippets only, not ${language}`, {
          notDispatched: "unsupported",
        });
      }
      if (files.length > 0) {
        throw new PlimsollError("unimplemented", `plimsoll: the daemon (${info.sandbox}) runs JavaScript snippets only, which take no files`, {
          notDispatched: "unsupported",
        });
      }
      const r = await this.client.runJavaScript(snippetRunner(code), opts);
      return {
        ...this.#cut(language, r.exitCode, r.timedOut, r.stdout, r.stderr, r.stdoutTruncated || r.stderrTruncated),
        stateKept: false,
        filesPersist: false,
        isolation: r.isolation,
        recordSha256: r.record.sha256,
      };
    }
    const runner = RUNNERS[language];
    const r: ProjectResult = await this.client.runProject(
      {
        files: [...files, { path: runner.file, content: code }, { path: runner.path, content: runner.source }],
        steps: [runner.step],
      },
      opts,
    );
    const step = r.steps[0];
    if (!step) {
      // No step report: the outcome says what ended the run (a timeout, a lost report),
      // not whether the code had started, so there is no exit code to give. Unmarked,
      // as anything that may have run is; the checked result rides on the error.
      throw new PlimsollError(
        "unknown",
        `plimsoll: the run ended ${r.outcome} without a step report (${r.detail}). It was not retried; running it again could repeat what it did.`,
        { result: r },
      );
    }
    return {
      ...this.#cut(language, step.exitCode, step.timedOut || r.outcome === "timed_out", step.stdout, step.stderr, step.stdoutTruncated || step.stderrTruncated),
      stateKept: false,
      filesPersist: false,
        isolation: r.isolation,
        recordSha256: r.record.sha256,
    };
  }

  #session(key: SandboxKey): Promise<Session> {
    return this.#entryFor(key).session;
  }

  // The key's entry, opening a session for it when it has none. The idle close is
  // armed once the session is open: an open slower than the idle interval is not idle.
  #entryFor(key: SandboxKey): Entry {
    const id = keyId(key);
    let entry = this.#entries.get(id);
    if (!entry) {
      const owner = ownerOf(key);
      // Room first: sandboxes over a cap are closed before this one opens, so the
      // daemon has their slots back by then.
      const freed = [
        ...(owner === undefined ? [] : this.#makeRoom((x) => x.owner === owner, this.#opts.maxSessionsPerOwner ?? 3, "this user")),
        ...this.#makeRoom(() => true, this.#opts.maxSessions ?? 0, "this app"),
      ];
      const e: Entry = { key, owner, used: ++this.#clock, session: undefined as unknown as Promise<Session>, answered: false, busy: 0 };
      // How another sandbox's close went never decides this open.
      const session = (e.session = Promise.allSettled(freed).then(() => this.#open(owner)));
      entry = e;
      this.#entries.set(id, e);
      // A failed open leaves no entry behind, so the next call tries again.
      session.then(
        (s) => {
          e.opened = s;
          if (this.#entries.get(id) === e) this.#touch(id);
        },
        () => {
          if (this.#entries.get(id) === e) this.#entries.delete(id);
        },
      );
    }
    return entry;
  }

  async #open(owner: string | undefined): Promise<Session> {
    if (!(await this.persistent())) throw new PlimsollError("unimplemented", "plimsoll: the daemon does not keep sessions", { notDispatched: "unsupported" });
    // The tool's languages are the hint: a daemon with a warm pool hands over a
    // sandbox with their interpreters running, and drops any it does not run. The
    // owner lets a daemon with SANDBOX_MAX_SESSIONS_PER_OWNER hold the user to its cap
    // across every process of the app, which this instance's own cap cannot see.
    return this.client.openSession({
      minimumIsolation: this.#floor,
      lifetimeMs: this.#opts.sessionLifetimeMs,
      idleTimeoutMs: this.#opts.sessionIdleTimeoutMs,
      languages: [...this.languages],
      owner,
    });
  }

  // Closes the least recently used idle sandboxes among those that match until fewer
  // than cap remain, and returns their closes. With every one busy, nothing can make
  // room, and the new one is refused before anything is opened.
  #makeRoom(match: (e: Entry) => boolean, cap: number, whose: string): Promise<void>[] {
    if (cap <= 0) return [];
    const freed: Promise<void>[] = [];
    let held = [...this.#entries.values()].filter(match).length;
    while (held >= cap) {
      const victim = this.#leastRecent(match);
      if (victim === undefined) {
        throw new PlimsollError("resource_exhausted", `plimsoll: ${whose} has ${held} sandboxes, the most this tool keeps, each with a call in flight`, {
          notDispatched: "capacity",
        });
      }
      freed.push(this.#dispose(victim));
      held--;
    }
    return freed;
  }

  #leastRecent(match: (e: Entry) => boolean): string | undefined {
    let best: [string, Entry] | undefined;
    for (const [id, e] of this.#entries) {
      if (e.busy === 0 && match(e) && (best === undefined || e.used < best[1].used)) best = [id, e];
    }
    return best?.[0];
  }

  // Forgets an ended session at once, so the next call under the key opens a
  // new one, and collects its end from the daemon in the background. Only the call
  // that removes the entry closes it: a session's entry leaves the map only through
  // here or #dispose, each of which closes it, so two calls sharing a session that
  // ended (a model step's parallel tool calls) send one CloseSession and report a
  // failed close once.
  #drop(key: SandboxKey, session: Session): void {
    const id = keyId(key);
    const entry = this.#entries.get(id);
    if (entry?.opened !== session) return;
    this.#entries.delete(id);
    if (entry.timer) clearTimeout(entry.timer);
    void session.close().catch((e: unknown) => this.#closeError(key, e));
  }

  // Never throws: it runs on the paths that close a sandbox, and an open that made room
  // waits for those closes, so an app's reporting must not decide whether a close
  // finishes or the next user's sandbox opens.
  #closeError(key: SandboxKey, err: unknown): void {
    // A key can hold a user's ID (an email, in some apps), so a log line names it only
    // by a digest, enough to tell one conversation's lines from another's.
    const failed = `plimsoll: closing the sandbox for key ${keyDigest(key)} failed:`;
    const callback = this.#opts.onCloseError;
    if (!callback) {
      console.warn(failed, errorText(err));
      return;
    }
    // A callback that throws, or returns a promise that rejects, is logged in its place.
    const callbackFailed = (e: unknown) => console.warn(failed, errorText(err), "; and onCloseError, reporting it, failed:", errorText(e));
    try {
      void Promise.resolve(callback(key, err)).catch(callbackFailed);
    } catch (e) {
      callbackFailed(e);
    }
  }

  #touch(id: string): void {
    const entry = this.#entries.get(id);
    const ms = this.#opts.idleCloseMs ?? 10 * 60_000;
    if (!entry || ms <= 0) return;
    if (entry.timer) clearTimeout(entry.timer);
    // A call in flight keeps its sandbox; the call's end arms the timer again.
    entry.timer = setTimeout(() => {
      if (this.#entries.get(id) === entry && entry.busy === 0) void this.#dispose(id);
    }, ms);
    entry.timer.unref?.();
  }

  #cut(language: Language, exitCode: number, timedOut: boolean, stdout: string, stderr: string, truncated: boolean) {
    const max = this.#opts.maxOutputChars ?? 16_000;
    // Never end on the first half of a surrogate pair: a lone surrogate is not valid
    // Unicode, and a strict provider can refuse the request that carries it back.
    const cut = (s: string) => {
      if (s.length <= max) return s;
      const c = s.charCodeAt(max - 1);
      return s.slice(0, c >= 0xd800 && c <= 0xdbff ? max - 1 : max);
    };
    return {
      language,
      exitCode,
      timedOut,
      stdout: cut(stdout),
      stderr: cut(stderr),
      truncated: truncated || stdout.length > max || stderr.length > max,
    };
  }
}
