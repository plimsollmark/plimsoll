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
import { RUNNERS } from "../src/sandboxes.ts";

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
  assert.equal(b.stateKept, true);
  assert.equal(b.filesPersist, true);
  assert.equal(b.interpreterRestarted, undefined);
  assert.equal(b.isolation, "container");
  const js = await s.run("run-a", { code: "1", language: "javascript" });
  assert.equal(js.stdout, "javascript 1: 1");
  assert.equal(js.interpreterRestarted, undefined, "a language's first cell is not a restart");
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
  assert.deepEqual(plan.steps, ["python3 .plimsoll/run.py"]);
  assert.equal(plan.cell, "print(1)");
  assert.equal(r.stateKept, false);
  assert.equal(r.filesPersist, false);
  assert.equal(r.isolation, "container");
  assert.ok(!calls.includes("OpenSession"));
  const js = JSON.parse((await s.run(undefined, { code: "1", language: "javascript" })).stdout);
  assert.deepEqual(js.steps, ["node .plimsoll/run.cjs"]);

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

test("an ended sandbox is replaced once, and the output says what was lost", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  assert.equal((await s.run("k", { code: "1" })).stdout, "python 1: 1");
  await fetch(`${sessionsUrl}/test/end-sessions`, { method: "POST" });
  const r = await s.run("k", { code: "2" });
  assert.equal(r.stdout, "python 1: 2", "a new sandbox answered");
  assert.equal(r.sandboxReplaced, true);
  assert.equal(r.interpreterRestarted, true, "the python state of the old sandbox is gone");
  const next = await s.run("k", { code: "3" });
  assert.equal(next.stdout, "python 2: 3");
  assert.equal(next.sandboxReplaced, undefined);
  assert.equal(next.interpreterRestarted, undefined);
  await s.disposeAll();
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
}
