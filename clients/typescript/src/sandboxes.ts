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
// which, so the model is never told state survived when it did not.

import { PlimsollClient, type Info, type Isolation, type Language, type ProjectResult, type Session } from "./client.ts";
import { PlimsollError } from "./errors.ts";

export type SessionMode = "auto" | "always" | "never";

/** The languages a tool offers, the first being the default. */
export type ToolLanguages = readonly [Language, ...Language[]];

export const DEFAULT_LANGUAGES: ToolLanguages = ["python", "javascript"];

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
  /** The weakest tier a run accepts; checked before dispatch and on the answer. */
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
  /** Characters of stdout and of stderr returned to the model; the rest is cut and marked. */
  maxOutputChars?: number;
  /**
   * Called when closing a sandbox fails. A "data_loss" error here means the
   * daemon counted calls this client did not make: someone else held the
   * session ID. Default: console.warn. The error never contains the session ID.
   */
  onCloseError?: (key: string, err: unknown) => void;
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
  /** This call ran in an interpreter that keeps variables between the conversation's calls. */
  stateKept: boolean;
  /** Variables from earlier calls in this language are gone (a deadline, a crash, a new sandbox). */
  interpreterRestarted?: true;
  /** Whether the files of this call are there for the next call. */
  filesPersist: boolean;
  /** Set when the previous sandbox had ended and this call ran in a new one, without its files. */
  sandboxReplaced?: true;
  /** The tier the code ran behind: configuration and provider evidence, not attestation. */
  isolation: string;
};

type Entry = {
  session: Promise<Session>;
  opened?: Session;
  timer?: ReturnType<typeof setTimeout>;
  /** The languages whose interpreter has run a cell in this sandbox. */
  ran: Set<Language>;
};

/** @internal A fresh run prints its last expression as a cell does, through these runners. */
export const RUNNERS: Record<Language, { path: string; file: string; step: string; source: string }> = {
  python: {
    path: ".plimsoll/run.py",
    file: ".plimsoll/cell.py",
    step: "python3 .plimsoll/run.py",
    source: [
      "import ast",
      "src = open('.plimsoll/cell.py').read()",
      "tree = ast.parse(src, 'cell', 'exec')",
      "last = ast.Expression(tree.body.pop().value) if tree.body and isinstance(tree.body[-1], ast.Expr) else None",
      "ns = {'__name__': '__main__'}",
      "exec(compile(tree, 'cell', 'exec'), ns)",
      "if last is not None:",
      "    value = eval(compile(last, 'cell', 'eval'), ns)",
      "    if value is not None:",
      "        print(repr(value))",
      "",
    ].join("\n"),
  },
  javascript: {
    path: ".plimsoll/run.cjs",
    file: ".plimsoll/cell.js",
    step: "node .plimsoll/run.cjs",
    source: [
      "const fs = require('node:fs'), util = require('node:util'), vm = require('node:vm');",
      "Promise.resolve(vm.runInThisContext(fs.readFileSync('.plimsoll/cell.js', 'utf8'), { filename: 'cell.js' })).then((v) => {",
      "  if (v !== undefined) console.log(util.inspect(v, { depth: 4 }));",
      "});",
      "",
    ].join("\n"),
  },
};

export class CodeSandboxes {
  readonly #opts: CodeSandboxesOptions;
  readonly #entries = new Map<string, Entry>();
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

  #describe(): Promise<Info> {
    this.#info ??= this.client.describe().catch((e: unknown) => {
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
   * not lost: the next run under the key opens a session again.
   */
  warm(key: string): void {
    void this.#session(key).catch(() => undefined);
  }

  /** Runs one call of the tool under the key. */
  async run(key: string | undefined, input: ExecuteCodeInput, signal?: AbortSignal): Promise<ExecuteCodeOutput> {
    const language = input.language ?? this.languages[0];
    if (!this.languages.includes(language)) {
      throw new PlimsollError("invalid_argument", `plimsoll: this tool runs ${this.languages.join(" or ")}, not ${language}`, { notDispatched: "request" });
    }
    const info = await this.#describe();
    const proved = info.environments.project.languages;
    // A daemon that states no languages predates the statement: let it try.
    if (proved.length > 0 && !proved.includes(language)) {
      throw new PlimsollError("unimplemented", `plimsoll: the sandbox image has no ${language} interpreter (it runs ${proved.join(", ")})`, {
        notDispatched: "unsupported",
      });
    }
    const files = input.files ?? [];
    const opts = { timeoutMs: this.#opts.timeoutMs, minimumIsolation: this.#opts.minimumIsolation, signal };
    // Without a key there is no conversation to scope a sandbox to, and sharing
    // one across conversations would hand one user's files to another.
    if (key === undefined || !(await this.persistent())) {
      return this.#fresh(language, input.code, files, opts);
    }
    let replaced = false;
    let lost = false; // a replaced sandbox had run this language: its state is gone
    for (;;) {
      const entry = await this.#entry(key);
      const session = await entry.session;
      try {
        const r = await session.runCell({ language, code: input.code, files }, opts);
        this.#touch(key);
        const restarted = r.interpreterStarted && (entry.ran.has(language) || lost);
        entry.ran.add(language);
        if (session.ended) this.#drop(key, session); // the next call opens a new one
        return {
          ...this.#cut(language, r.exitCode, r.timedOut, r.stdout, r.stderr, r.stdoutTruncated || r.stderrTruncated),
          stateKept: true,
          ...(restarted ? { interpreterRestarted: true as const } : {}),
          filesPersist: true,
          ...(replaced ? { sandboxReplaced: true as const } : {}),
          isolation: r.isolation,
        };
      } catch (e) {
        // A call refused because its session had ended ran nothing, so it is
        // safe to run once more in a new sandbox; anything else is not.
        if (!replaced && e instanceof PlimsollError && e.sessionEnded && e.notDispatched) {
          replaced = true;
          lost = entry.ran.has(language);
          this.#drop(key, session);
          continue;
        }
        throw e;
      }
    }
  }

  /** Closes the key's sandbox, if it has one. Safe to call more than once. */
  async dispose(key: string): Promise<void> {
    const entry = this.#entries.get(key);
    if (!entry) return;
    this.#entries.delete(key);
    if (entry.timer) clearTimeout(entry.timer);
    const session = await entry.session.catch(() => undefined);
    // An ended session is collected the same way.
    await session?.close().catch((e: unknown) => this.#closeError(key, e));
  }

  /** Closes every sandbox this instance holds, for shutdown. */
  async disposeAll(): Promise<void> {
    await Promise.all([...this.#entries.keys()].map((k) => this.dispose(k)));
  }

  // A fresh sandbox for one call: the files, the code and a runner that prints the
  // last expression, as one project.
  async #fresh(
    language: Language,
    code: string,
    files: { path: string; content: string }[],
    opts: { timeoutMs?: number; minimumIsolation?: Exclude<Isolation, "none">; signal?: AbortSignal },
  ): Promise<ExecuteCodeOutput> {
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
      // The runner never started: the outcome says why (a bad file path, a timeout).
      return {
        ...this.#cut(language, r.outcome === "timed_out" ? 124 : 1, r.outcome === "timed_out", "", `plimsoll: the run ${r.outcome}: ${r.detail}`, false),
        stateKept: false,
        filesPersist: false,
        isolation: r.isolation,
      };
    }
    return {
      ...this.#cut(language, step.exitCode, step.timedOut || r.outcome === "timed_out", step.stdout, step.stderr, step.stdoutTruncated || step.stderrTruncated),
      stateKept: false,
      filesPersist: false,
      isolation: r.isolation,
    };
  }

  #entry(key: string): Promise<Entry> {
    return this.#session(key).then(() => this.#entries.get(key)!);
  }

  #session(key: string): Promise<Session> {
    let entry = this.#entries.get(key);
    if (!entry) {
      const session = this.persistent().then((ok) => {
        if (!ok) throw new PlimsollError("unimplemented", "plimsoll: the daemon does not keep sessions", { notDispatched: "unsupported" });
        return this.client.openSession({
          minimumIsolation: this.#opts.minimumIsolation,
          lifetimeMs: this.#opts.sessionLifetimeMs,
          idleTimeoutMs: this.#opts.sessionIdleTimeoutMs,
        });
      });
      const e: Entry = { session, ran: new Set() };
      entry = e;
      this.#entries.set(key, e);
      // A failed open leaves no entry behind, so the next call tries again.
      session.then(
        (s) => (e.opened = s),
        () => {
          if (this.#entries.get(key) === e) this.#entries.delete(key);
        },
      );
      this.#touch(key);
    }
    return entry.session;
  }

  // Forgets an ended session at once, so the next call under the key opens a
  // new one, and collects its end from the daemon in the background.
  #drop(key: string, session: Session): void {
    const entry = this.#entries.get(key);
    if (entry?.opened === session) {
      this.#entries.delete(key);
      if (entry.timer) clearTimeout(entry.timer);
    }
    void session.close().catch((e: unknown) => this.#closeError(key, e));
  }

  #closeError(key: string, err: unknown): void {
    if (this.#opts.onCloseError) this.#opts.onCloseError(key, err);
    else console.warn(`plimsoll: closing the sandbox for ${key} failed:`, err instanceof Error ? err.message : err);
  }

  #touch(key: string): void {
    const entry = this.#entries.get(key);
    const ms = this.#opts.idleCloseMs ?? 10 * 60_000;
    if (!entry || ms <= 0) return;
    if (entry.timer) clearTimeout(entry.timer);
    entry.timer = setTimeout(() => void this.dispose(key), ms);
    entry.timer.unref?.();
  }

  #cut(language: Language, exitCode: number, timedOut: boolean, stdout: string, stderr: string, truncated: boolean) {
    const max = this.#opts.maxOutputChars ?? 16_000;
    const cut = (s: string) => (s.length > max ? s.slice(0, max) : s);
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
