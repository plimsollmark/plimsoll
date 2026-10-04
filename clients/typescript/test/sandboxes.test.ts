// CodeSandboxes, the per-conversation layer both add-ons share, against the
// daemons client_test.go serves: the in-memory session provider (whose cells answer
// "<language> <n>: <code>" and list their files on stderr), the wasm provider, and
// projectEcho, which answers a fresh call's project with the plan it received.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { CodeSandboxes, PlimsollClient, PlimsollError } from "../src/index.ts";
import { RUNNERS, snippetRunner } from "../src/sandboxes.ts";

const wasmUrl = process.env.PLIMSOLL_WASM_URL;
const sessionsUrl = process.env.PLIMSOLL_SESSIONS_URL;
const echoUrl = process.env.PLIMSOLL_ECHO_URL;
const skip = !wasmUrl || !sessionsUrl || !echoUrl ? "run through `go test ./clients/typescript`" : false;

// A client that counts the procedures it calls.
function counting(url: string): { client: PlimsollClient; calls: string[] } {
  const calls: string[] = [];
  const client = new PlimsollClient({
    baseUrl: url,
    fetch: (input, init) => {
      calls.push(String(input).split("/").pop()!);
      return fetch(input, init);
    },
  });
  return { client, calls };
}

test("on a daemon with sessions, a key keeps one interpreter", { skip }, async () => {
  const { client, calls } = counting(sessionsUrl!);
  const s = new CodeSandboxes({ client });
  s.warm("run-a");
  const a = await s.run("run-a", { code: "x = 1" });
  const b = await s.run("run-a", { code: "x + 1", files: [{ path: "in/data.csv", content: "a,b" }] });
  assert.equal(a.language, "python", "python is the default");
  assert.equal(a.stdout, "python 1: x = 1");
  assert.equal(b.stdout, "python 2: x + 1", "the second call ran in the same interpreter");
  assert.equal(b.stderr, "in/data.csv\n", "the cell carried its files");
  assert.equal(a.freshInterpreter, true, "the first call starts from nothing");
  assert.equal(a.freshSandbox, true);
  assert.equal(b.stateKept, true);
  assert.equal(b.filesPersist, true);
  assert.equal(b.freshInterpreter, undefined);
  assert.equal(b.freshSandbox, undefined);
  assert.equal(b.isolation, "container");
  assert.match(a.recordSha256, /^[0-9a-f]{64}$/);
  assert.match(b.recordSha256, /^[0-9a-f]{64}$/);
  assert.notEqual(a.recordSha256, b.recordSha256, "different checked cell records have different digests");
  const js = await s.run("run-a", { code: "1", language: "javascript" });
  assert.equal(js.stdout, "javascript 1: 1");
  assert.equal(js.freshInterpreter, true, "a language's first cell has no earlier state");
  assert.equal(js.freshSandbox, undefined, "but the sandbox's files are there");
  assert.equal(calls.filter((c) => c === "OpenSession").length, 1);
  await s.dispose("run-a");
  await s.dispose("run-a"); // twice is fine
  assert.equal(calls.filter((c) => c === "CloseSession").length, 1);
});

test("keys never share a sandbox", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  assert.equal((await s.run("a", { code: "1" })).stdout, "python 1: 1");
  assert.equal((await s.run("b", { code: "1" })).stdout, "python 1: 1");
  await s.disposeAll();
});

test("without a key, or with sessions off, a call runs fresh with its files and a runner", { skip }, async () => {
  const { client, calls } = counting(echoUrl!);
  const s = new CodeSandboxes({ client });
  const r = await s.run("run-a", { code: "print(1)", files: [{ path: "data.csv", content: "a" }] });
  const plan = JSON.parse(r.stdout);
  assert.deepEqual(plan.files, ["data.csv", ".plimsoll/cell.py", ".plimsoll/run.py"]);
  assert.deepEqual(plan.steps, ["python3 -I .plimsoll/run.py"]);
  assert.equal(plan.cell, "print(1)");
  assert.equal(r.stateKept, false);
  assert.equal(r.filesPersist, false);
  assert.equal(r.isolation, "container");
  assert.match(r.recordSha256, /^[0-9a-f]{64}$/);
  assert.ok(!calls.includes("OpenSession"));
  const js = JSON.parse((await s.run(undefined, { code: "1", language: "javascript" })).stdout);
  assert.deepEqual(js.steps, ["node --expose-internals .plimsoll/run.cjs"]);

  const never = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }), sessions: "never" });
  // The fake provider refuses single runs, which proves no session was used.
  await assert.rejects(never.run("k", { code: "1" }), { notDispatched: "unsupported" });
});

test("a language the tool does not offer, or the daemon cannot run, is refused before dispatch", { skip }, async () => {
  const jsOnly = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: echoUrl! }), languages: ["javascript"] });
  await assert.rejects(jsOnly.run(undefined, { code: "1", language: "python" }), { notDispatched: "request" });
  assert.equal((await jsOnly.run(undefined, { code: "1" })).language, "javascript", "the first offered language is the default");
});

test("sessions: always fails on a daemon without them", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: wasmUrl! }), sessions: "always" });
  await assert.rejects(s.run("k", { code: "1" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "unsupported");
});

test("an ended sandbox is replaced once, and the output says what is new", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  assert.equal((await s.run("k", { code: "1" })).stdout, "python 1: 1");
  await s.run("k", { code: "x = 1" });
  await fetch(`${sessionsUrl}/test/end-sessions`, { method: "POST" });
  const r = await s.run("k", { code: "2" });
  assert.equal(r.stdout, "python 1: 2", "a new sandbox answered");
  assert.equal(r.freshSandbox, true);
  assert.equal(r.freshInterpreter, true, "the python state of the old sandbox is gone");
  const next = await s.run("k", { code: "3" });
  assert.equal(next.stdout, "python 2: 3");
  assert.equal(next.freshSandbox, undefined);
  assert.equal(next.freshInterpreter, undefined);
  await s.disposeAll();
});

// stateKept and filesPersist promise the next call what this one left, so a call
// whose interpreter or sandbox ended during it promises nothing.
test("a call whose interpreter or sandbox ended does not say its state is kept", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  await s.run("k", { code: "x = 1" });
  const spun = await s.run("k", { code: "plimsoll-fake:past-deadline" });
  assert.equal(spun.timedOut, true);
  assert.equal(spun.stateKept, false, "the deadline ended the interpreter");
  assert.equal(spun.filesPersist, true, "the sandbox is still there");
  const after = await s.run("k", { code: "x" });
  assert.equal(after.freshInterpreter, true);
  assert.equal(after.stateKept, true);
  const last = await s.run("k", { code: "plimsoll-fake:ends-session" });
  assert.equal(last.exitCode, 0);
  assert.equal(last.stateKept, false, "the sandbox ended after the call");
  assert.equal(last.filesPersist, false);
  const next = await s.run("k", { code: "y = 1" });
  assert.equal(next.freshSandbox, true);
  await s.disposeAll();
});

// The Trigger.dev recipe disposes when a chat suspends; the resumed turn's first
// call runs in a new sandbox and must not claim the old one's state.
test("the first call after a dispose says its sandbox and interpreter are new", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  await s.run("k", { code: "x = 1" });
  await s.run("k", { code: "x" });
  await s.dispose("k");
  const r = await s.run("k", { code: "x + 1" });
  assert.equal(r.stdout, "python 1: x + 1", "a new interpreter answered");
  assert.equal(r.freshSandbox, true);
  assert.equal(r.freshInterpreter, true);
  // So does one let go by the idle close.
  const idle = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }), idleCloseMs: 20 });
  await idle.run("k", { code: "x = 1" });
  await new Promise((r) => setTimeout(r, 100));
  const after = await idle.run("k", { code: "x" });
  assert.equal(after.stdout, "python 1: x");
  assert.equal(after.freshSandbox, true);
  assert.equal(after.freshInterpreter, true);
  await s.disposeAll();
  await idle.disposeAll();
});

test("the idle close waits for a call in flight", { skip }, async () => {
  const calls: string[] = [];
  const slow = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      calls.push(String(input).split("/").pop()!);
      const res = await fetch(input, init);
      if (String(input).endsWith("/SessionRun")) await new Promise((r) => setTimeout(r, 150));
      return res;
    },
  });
  const s = new CodeSandboxes({ client: slow, idleCloseMs: 50 });
  await s.run("k", { code: "x = 1" }); // longer than the idle close
  const r = await s.run("k", { code: "x" });
  assert.equal(r.stdout, "python 2: x", "the same interpreter answered");
  assert.equal(r.freshSandbox, undefined);
  assert.equal(calls.filter((c) => c === "OpenSession").length, 1);
  await s.disposeAll();
});

// An open slower than the idle close is not idle: the call that waits for it gets
// its answer, and the idle close counts from when the sandbox is open.
test("a session that opens slower than the idle close still answers", { skip }, async () => {
  const slowOpen = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (String(input).endsWith("/OpenSession")) await new Promise((r) => setTimeout(r, 150));
      return res;
    },
  });
  const s = new CodeSandboxes({ client: slowOpen, idleCloseMs: 20 });
  const r = await s.run("k", { code: "x = 1" });
  assert.equal(r.exitCode, 0, r.stderr);
  assert.equal(r.stateKept, true);
  s.warm("w"); // a warm whose open outlasts the idle close
  await new Promise((r) => setTimeout(r, 400));
  const w = await s.run("w", { code: "y = 1" });
  assert.equal(w.exitCode, 0, w.stderr);
  await s.disposeAll();
});

test("on a daemon without projects a JavaScript call runs as a snippet; Python and files are refused before dispatch", { skip }, async () => {
  const { client, calls } = counting(wasmUrl!);
  const s = new CodeSandboxes({ client });
  const r = await s.run("k", { code: "var rows = [1, 2, 3];\nconsole.log('printed');\nrows.reduce((a, b) => a + b, 0)", language: "javascript" });
  assert.equal(r.exitCode, 0, r.stderr);
  assert.equal(r.stdout, "printed\n6\n");
  assert.equal(r.stateKept, false);
  assert.equal(r.filesPersist, false);
  assert.equal(r.isolation, "process");
  assert.match(r.recordSha256, /^[0-9a-f]{64}$/);
  const failed = await s.run(undefined, { code: "throw new Error('boom')", language: "javascript" });
  assert.notEqual(failed.exitCode, 0);
  assert.match(failed.stderr, /boom/);
  const sent = calls.filter((c) => c === "Run").length;
  await assert.rejects(s.run("k", { code: "1" }), { notDispatched: "unsupported", message: /JavaScript snippets only, not python/ });
  await assert.rejects(s.run("k", { code: "1", language: "javascript", files: [{ path: "a.txt", content: "a" }] }), {
    notDispatched: "unsupported",
    message: /take no files/,
  });
  assert.equal(calls.filter((c) => c === "Run").length, sent, "nothing was sent for the refused calls");
});

test("output beyond maxOutputChars is cut and marked", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }), maxOutputChars: 6 });
  const r = await s.run("k", { code: "print('abcdefgh')" });
  assert.equal(r.stdout, "python");
  assert.equal(r.truncated, true);
  await s.disposeAll();
});

test("a floor the daemon cannot meet is refused before dispatch", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }), minimumIsolation: "kernel" });
  await assert.rejects(s.run("k", { code: "1" }), { notDispatched: "isolation" });
});

test("a close that finds calls this client did not make is reported, not swallowed", { skip }, async () => {
  const errors: unknown[] = [];
  // Rewrite the daemon's close count, as if another holder of the ID had called.
  const client = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (!String(input).endsWith("/CloseSession") || !res.ok) return res;
      const body = await res.json();
      body.calls = "9";
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });
  const s = new CodeSandboxes({ client, onCloseError: (_k, e) => errors.push(e) });
  await s.run("k", { code: "1" });
  await s.dispose("k");
  assert.equal(errors.length, 1);
  assert.equal((errors[0] as PlimsollError).code, "data_loss");
});

test("the snippet runner prints the last value on node too", () => {
  const out = execFileSync(process.execPath, ["-e", snippetRunner("const rows = [1, 2, 3];\nconsole.log('printed');\nrows.reduce((a, b) => a + b, 0)")], {
    encoding: "utf8",
  });
  assert.equal(out, "printed\n6\n");
});

// The runners a fresh call sends print the last expression as a cell does. They are
// fixed programs of this package, run here on this machine's node and python3.
for (const language of ["javascript", "python"] as const) {
  const runner = RUNNERS[language];
  const bin = language === "python" ? "python3" : process.execPath;
  let available = true;
  try {
    execFileSync(bin, ["--version"], { stdio: "ignore" });
  } catch {
    available = false;
  }
  test(`the ${language} runner prints the last expression`, { skip: available ? false : `${bin} is not installed` }, () => {
    const dir = mkdtempSync(join(tmpdir(), "plimsoll-runner-"));
    mkdirSync(join(dir, ".plimsoll"));
    writeFileSync(join(dir, runner.path), runner.source);
    const code = language === "python" ? "rows = [1, 2, 3]\nprint('printed')\nsum(rows)" : "const rows = [1, 2, 3];\nconsole.log('printed');\nrows.reduce((a, b) => a + b, 0)";
    writeFileSync(join(dir, runner.file), code);
    const [cmd, ...args] = runner.step.split(" ");
    const out = execFileSync(cmd === "node" ? process.execPath : cmd!, args, { cwd: dir, encoding: "utf8" });
    assert.equal(out, "printed\n6\n");
  });

  // What a session cell takes, a fresh run takes too: a module from the work
  // directory (and, in Node, require at all), and top-level await.
  test(`the ${language} runner imports from the work directory and awaits at the top level`, { skip: available ? false : `${bin} is not installed` }, () => {
    const dir = mkdtempSync(join(tmpdir(), "plimsoll-runner-"));
    mkdirSync(join(dir, ".plimsoll"));
    writeFileSync(join(dir, runner.path), runner.source);
    if (language === "python") {
      writeFileSync(join(dir, "helper.py"), "x = 5\n");
      writeFileSync(join(dir, "json.py"), "raise SystemExit('a work-directory json.py ran')\n");
      writeFileSync(join(dir, runner.file), "import asyncio, helper\nawait asyncio.sleep(0)\nhelper.x + 1");
    } else {
      writeFileSync(join(dir, "helper.js"), "module.exports = { x: 5 };\n");
      writeFileSync(join(dir, runner.file), "const helper = require('./helper.js');\nawait new Promise((r) => setTimeout(r, 1));\nhelper.x + 1");
    }
    const [cmd, ...args] = runner.step.split(" ");
    const out = execFileSync(cmd === "node" ? process.execPath : cmd!, args, { cwd: dir, encoding: "utf8" });
    assert.equal(out, "6\n");
  });

  // Code a session cell runs, a fresh run runs too: Python's asyncio.run (a fresh run
  // used to run the whole cell inside a running loop, where it raises), and Node's
  // CommonJS names, which a cell in the session's node -e interpreter sees as globals
  // (v0.15.0 review, M8).
  test(`the ${language} runner runs what a session cell runs`, { skip: available ? false : `${bin} is not installed` }, () => {
    const dir = mkdtempSync(join(tmpdir(), "plimsoll-runner-"));
    mkdirSync(join(dir, ".plimsoll"));
    writeFileSync(join(dir, runner.path), runner.source);
    writeFileSync(
      join(dir, runner.file),
      language === "python"
        ? "import asyncio\nasync def f():\n    return 41\nif __name__ == '__main__':\n    x = asyncio.run(f())\nx + 1"
        : "[typeof module, typeof exports, typeof require, __dirname, __filename].join(' ')",
    );
    const [cmd, ...args] = runner.step.split(" ");
    const out = execFileSync(cmd === "node" ? process.execPath : cmd!, args, { cwd: dir, encoding: "utf8" });
    assert.equal(out, language === "python" ? "42\n" : "'object object function . [eval]'\n");
  });
}

// A call whose answer is lost after it ran: the conversation's next call opens a new
// sandbox, says so, and answers, where a client that kept the session would have
// run it there and then failed the chain check.
test("after a call that ended without an answer, the next call gets a new sandbox", { skip }, async () => {
  let drop = false;
  const lossy = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (drop && String(input).endsWith("/SessionRun")) throw new TypeError("the connection dropped after the daemon answered");
      return res;
    },
  });
  const closeErrors: unknown[] = [];
  const s = new CodeSandboxes({ client: lossy, onCloseError: (_k, e) => closeErrors.push(e) });
  await s.run("k", { code: "x = 1" });
  drop = true;
  await assert.rejects(s.run("k", { code: "x" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === undefined);
  drop = false;
  const r = await s.run("k", { code: "x" });
  assert.equal(r.exitCode, 0, r.stderr);
  assert.equal(r.freshSandbox, true, "the next call says its sandbox is new");
  await s.disposeAll();
});

// A call that may have run but whose record the Session checked and chained leaves the
// session usable: the conversation's next call runs in the same sandbox (v0.15.0
// review, L22).
test("after an unanswered call the Session checked, the conversation keeps its sandbox", { skip: !process.env.PLIMSOLL_BREAKING_URL && "run through `go test ./clients/typescript`" }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: process.env.PLIMSOLL_BREAKING_URL! }), languages: ["javascript"] });
  const first = await s.run("k", { code: "1", language: "javascript" });
  assert.equal(first.freshSandbox, true);
  await assert.rejects(s.run("k", { code: "2", language: "javascript" }), (e: unknown) => e instanceof PlimsollError && e.record?.sequence === 2n);
  const third = await s.run("k", { code: "3", language: "javascript" });
  assert.equal(third.freshSandbox, undefined, "the sandbox is the same one");
  await s.disposeAll();
});

// Two calls made at once on a new conversation: only the first to answer says its
// sandbox is new (v0.15.0 review, L24).
test("of calls made at once, only the first to answer finds the sandbox new", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  const [a, b] = await Promise.all([s.run("k", { code: "1" }), s.run("k", { code: "2" })]);
  assert.equal([a.freshSandbox, b.freshSandbox].filter(Boolean).length, 1, JSON.stringify([a, b]));
  await s.disposeAll();
});

// A file under .plimsoll/ is refused before anything is sent: a fresh run's runner
// lives there (v0.15.0 review, L24).
test("the .plimsoll/ directory is reserved", async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: "http://127.0.0.1:1" }), sessions: "never" });
  await assert.rejects(s.run(undefined, { code: "1", files: [{ path: ".plimsoll/run.py", content: "x" }] }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request");
});
