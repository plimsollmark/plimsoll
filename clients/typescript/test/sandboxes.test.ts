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
import { ownerDigest } from "../src/client.ts";
import { RUNNERS, keyDigest, snippetRunner } from "../src/sandboxes.ts";

const wasmUrl = process.env.PLIMSOLL_WASM_URL;
const sessionsUrl = process.env.PLIMSOLL_SESSIONS_URL;
const echoUrl = process.env.PLIMSOLL_ECHO_URL;
const ownerCapUrl = process.env.PLIMSOLL_OWNER_CAP_URL;
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  assert.equal((await s.run("a", { code: "1" })).stdout, "python 1: 1");
  assert.equal((await s.run("b", { code: "1" })).stdout, "python 1: 1");
  await s.disposeAll();
});

test("without a key, or with sessions off, a call runs fresh with its files and a runner", { skip }, async () => {
  const { client, calls } = counting(echoUrl!);
  const s = new CodeSandboxes({ minimumIsolation: "container", client });
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

  const never = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }), sessions: "never" });
  // The fake provider refuses single runs, which proves no session was used.
  await assert.rejects(never.run("k", { code: "1" }), { notDispatched: "unsupported" });
});

test("a language the tool does not offer, or the daemon cannot run, is refused before dispatch", { skip }, async () => {
  const jsOnly = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: echoUrl! }), languages: ["javascript"] });
  await assert.rejects(jsOnly.run(undefined, { code: "1", language: "python" }), { notDispatched: "request" });
  assert.equal((await jsOnly.run(undefined, { code: "1" })).language, "javascript", "the first offered language is the default");
});

test("sessions: always fails on a daemon without them", { skip }, async () => {
  const s = new CodeSandboxes({ minimumIsolation: "process", client: new PlimsollClient({ baseUrl: wasmUrl! }), sessions: "always" });
  await assert.rejects(s.run("k", { code: "1" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "unsupported");
});

test("an ended sandbox is replaced once, and the output says what is new", { skip }, async () => {
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
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

// An end this client has no name for (a daemon newer than the client) is still an end:
// the answer promises nothing to the next call, which opens a new sandbox.
test("a call whose session ended for a reason this client cannot name does not say its state is kept", { skip }, async () => {
  let rename = true;
  const client = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (!rename || !String(input).endsWith("/SessionRun") || !res.ok) return res;
      const body = await res.json();
      body.ended = "SESSION_END_HOST_LOST"; // the envelope's end is outside the record
      body.endDetail = "the host went away";
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });
  const s = new CodeSandboxes({ minimumIsolation: "container", client, onCloseError: () => undefined });
  const r = await s.run("k", { code: "x = 1" });
  assert.equal(r.stateKept, false);
  assert.equal(r.filesPersist, false);
  rename = false;
  const next = await s.run("k", { code: "x" });
  assert.equal(next.freshSandbox, true, "the next call opened a new sandbox");
  assert.equal(next.stdout, "python 1: x");
  await s.disposeAll();
});

// Two tool calls of one model step (the AI SDK runs them with Promise.all) whose session
// ends during the first, or was replaced before them: both calls let the session go, and
// it is closed once, with no close error.
test("a session that ends under two calls at once is closed once, and a failed close is reported once", { skip: skip || (!ownerCapUrl && "run through `go test ./clients/typescript`") }, async () => {
  const step = async (url: string, codes: [string, string], before?: () => Promise<void>, closeFails = false) => {
    const procedures: string[] = [];
    const closeErrors: unknown[] = [];
    const client = new PlimsollClient({
      baseUrl: url,
      fetch: async (input, init) => {
        procedures.push(String(input).split("/").pop()!);
        const res = await fetch(input, init);
        if (!closeFails || !String(input).endsWith("/CloseSession") || !res.ok) return res;
        const body = await res.json();
        body.calls = "9"; // a count this client never saw: the close fails its check
        return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      },
    });
    const s = new CodeSandboxes({ minimumIsolation: "container", client, onCloseError: (_k, e) => closeErrors.push(e) });
    const key = { owner: "alice", conversation: "one" };
    await s.run(key, { code: "x = 1" });
    await before?.();
    const [a, b] = await Promise.all([s.run(key, { code: codes[0] }), s.run(key, { code: codes[1] })]);
    await new Promise((r) => setTimeout(r, 100)); // the ended session's close runs in the background
    const closes = procedures.filter((p) => p === "CloseSession").length;
    const errors = [...closeErrors];
    await s.disposeAll();
    return { a, b, closes, closeErrors: errors };
  };

  // The first call's answer says its session ended (the fake's disk-exceeded end); the
  // second, queued behind it, is refused for that end and runs once more, fresh.
  const ended = await step(sessionsUrl!, ["plimsoll-fake:ends-session", "x"]);
  assert.equal(ended.a.filesPersist, false);
  assert.equal(ended.b.freshSandbox, true);
  assert.equal(ended.closes, 1);
  assert.deepEqual(ended.closeErrors, []);

  // The daemon replaced the session for another of the user's conversations, as another
  // process past SANDBOX_MAX_SESSIONS_PER_OWNER would: both calls are refused and rerun.
  const other = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: ownerCapUrl! }) });
  const replaced = await step(ownerCapUrl!, ["x", "x"], async () => {
    await other.run({ owner: "alice", conversation: "two" }, { code: "1" });
  });
  await other.disposeAll();
  assert.equal(replaced.a.freshSandbox !== replaced.b.freshSandbox, true, "the first rerun says its sandbox is new");
  assert.equal(replaced.closes, 1);
  assert.deepEqual(replaced.closeErrors, []);

  // A close that fails its check is the app's to hear about once, not once per call.
  const failed = await step(sessionsUrl!, ["plimsoll-fake:ends-session", "x"], undefined, true);
  assert.equal(failed.closes, 1);
  assert.equal(failed.closeErrors.length, 1);
  assert.equal((failed.closeErrors[0] as PlimsollError).code, "data_loss");
});

// Nothing is sent to a sandbox before the Describe answers and the session opens, so a
// failure there ran nothing, whether or not the daemon marked it: the stage decides the
// mark, and the model reads it in the lead.
test("a failure before the code is sent says nothing ran, whatever failed", { skip }, async () => {
  const proxy = (procedure: string) => (input: RequestInfo | URL, init?: RequestInit) =>
    String(input).endsWith(`/${procedure}`) ? Promise.resolve(new Response("upstream down", { status: 503 })) : fetch(input, init);
  const openTampered = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (!String(input).endsWith("/OpenSession") || !res.ok) return res;
      const body = await res.json();
      body.session = "00".repeat(32); // a fingerprint that is not the ID's: the client closes it
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });
  const cases: [string, CodeSandboxes, string][] = [
    ["the daemon is unreachable", new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: "http://127.0.0.1:1" }) }), "unavailable"],
    ["a proxy answers Describe 503", new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl!, fetch: proxy("Describe") }) }), "unavailable"],
    ["the lazy client cannot be built", new CodeSandboxes({ minimumIsolation: "container", client: () => new PlimsollClient({ baseUrl: "ftp://daemon" }) }), "invalid_argument"],
    ["a proxy answers OpenSession 503", new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl!, fetch: proxy("OpenSession") }) }), "unavailable"],
    ["the opened session fails the client's check", new CodeSandboxes({ minimumIsolation: "container", client: openTampered }), "data_loss"],
    [
      "Describe's connection drops after it was sent",
      new CodeSandboxes({
        minimumIsolation: "container",
        client: new PlimsollClient({
          baseUrl: sessionsUrl!,
          fetch: async (input, init) => {
            await fetch(input, init);
            throw new TypeError("socket hang up");
          },
        }),
      }),
      "unavailable",
    ],
  ];
  for (const [name, s, code] of cases) {
    await assert.rejects(s.run({ owner: "alice", conversation: name }, { code: "1" }), (e: unknown) => {
      assert.ok(e instanceof PlimsollError, name);
      assert.equal(e.notDispatched, "environment", name);
      assert.equal(e.code, code, name);
      assert.match(e.message, /^Nothing ran \(environment\): (plimsoll: |HTTP 503$)/, name);
      return true;
    });
    await s.disposeAll();
  }
  // persistent() says the same of its Describe.
  await assert.rejects(new CodeSandboxes({ client: new PlimsollClient({ baseUrl: "http://127.0.0.1:1" }) }).persistent(), { notDispatched: "environment" });
});

// The lead comes from the stage for an error of any class: a key resolver or a client
// factory throwing their own error ran nothing; an error once the code may have been
// sent says so.
test("an error that is not a PlimsollError gets the lead its stage implies", { skip }, async () => {
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: echoUrl! }) });
  await assert.rejects(
    s.run(() => {
      throw new Error("no run id in this turn");
    }, { code: "1" }),
    (e: unknown) => e instanceof PlimsollError && e.notDispatched === "environment" && e.message === "Nothing ran (environment): no run id in this turn",
  );
  const factory = new CodeSandboxes({
    minimumIsolation: "container",
    client: () => {
      throw new TypeError("PLIMSOLL_URL is not set");
    },
  });
  await assert.rejects(factory.run(undefined, { code: "1" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "environment" && e.cause instanceof TypeError);
  // Once the project was sent, an error of any class may follow execution.
  const client = new PlimsollClient({ baseUrl: echoUrl! });
  const sent = client.runProject.bind(client);
  client.runProject = async (...args) => {
    await sent(...args);
    throw new TypeError("a bug after the answer");
  };
  await assert.rejects(
    new CodeSandboxes({ minimumIsolation: "container", client }).run(undefined, { code: "1" }),
    (e: unknown) =>
      e instanceof PlimsollError && e.notDispatched === undefined && e.message === "The code may have run, and there is no checked answer for it: a bug after the answer",
  );
});

// onCloseError is the app's code: a callback that throws or rejects is logged, and never
// stops a close or the open that waited for it.
test("an onCloseError that throws or rejects breaks no close and no open", { skip }, async () => {
  const failingClose = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (!String(input).endsWith("/CloseSession") || !res.ok) return res;
      const body = await res.json();
      body.calls = "9"; // every close fails the client's check
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });
  const warned: string[] = [];
  const unhandled: unknown[] = [];
  const onUnhandled = (e: unknown) => void unhandled.push(e);
  const warn = console.warn;
  console.warn = (...args: unknown[]) => void warned.push(args.join(" "));
  process.on("unhandledRejection", onUnhandled);
  try {
    for (const onCloseError of [
      () => {
        throw new Error("the logger is not configured");
      },
      async () => {
        throw new Error("the logger is not configured");
      },
    ]) {
      const s = new CodeSandboxes({ minimumIsolation: "container", client: failingClose, maxSessionsPerOwner: 1, onCloseError });
      const alice = (conversation: string) => ({ owner: "alice", conversation });
      await s.run(alice("a"), { code: "1" });
      // b's open first closes a, whose close fails and whose callback fails.
      assert.equal((await s.run(alice("b"), { code: "1" })).stdout, "python 1: 1");
      await s.dispose(alice("b")); // resolves
      await new Promise((r) => setTimeout(r, 20));
    }
  } finally {
    console.warn = warn;
    process.off("unhandledRejection", onUnhandled);
  }
  assert.deepEqual(unhandled, []);
  assert.equal(warned.length, 4, warned.join("\n"));
  for (const line of warned) assert.match(line, /closing the sandbox for key [0-9a-f]{12} failed: .*onCloseError, reporting it, failed: the logger is not configured/);
});

// The Describe decides the mode for every call, and a long-lived process can outlive the
// daemon it described: a refusal that says the daemon may have changed reads it again,
// a capacity or request refusal does not.
test("a refusal that says the daemon may have changed reads its Describe again", { skip }, async () => {
  let describes = 0;
  const client = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (String(input).endsWith("/SessionRun")) await new Promise((r) => setTimeout(r, 200));
      if (!String(input).endsWith("/Describe") || !res.ok) return res;
      describes++;
      const body = await res.json();
      // The first answer is a daemon started without sessions; later ones, the same
      // daemon restarted with them on.
      if (describes === 1) body.supportsSessions = false;
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });
  const s = new CodeSandboxes({ minimumIsolation: "container", client, maxSessionsPerOwner: 1 });
  const alice = (conversation: string) => ({ owner: "alice", conversation });
  // Run fresh, which the sessions fake refuses (unsupported): the daemon is not the one
  // described, so the next call asks again and opens a session.
  await assert.rejects(s.run(alice("a"), { code: "1" }), { notDispatched: "unsupported" });
  assert.equal((await s.run(alice("a"), { code: "1" })).stdout, "python 1: 1");
  assert.equal(describes, 2);
  // A request refusal and a capacity refusal leave the Describe as it is.
  await assert.rejects(s.run(alice("a"), { code: "1", language: "cobol" as never }), { notDispatched: "request" });
  const busy = s.run(alice("a"), { code: "2" });
  await new Promise((r) => setTimeout(r, 80));
  await assert.rejects(s.run(alice("b"), { code: "1" }), { notDispatched: "capacity" });
  await busy;
  assert.equal(describes, 2);
  await s.disposeAll();
  // A floor the daemon refuses (isolation) reads it again too.
  const vm = new CodeSandboxes({ minimumIsolation: "vm", client });
  await assert.rejects(vm.run("k", { code: "1" }), { notDispatched: "isolation" });
  await assert.rejects(vm.run("k", { code: "1" }), { notDispatched: "isolation" });
  assert.equal(describes, 4);
});

// The Trigger.dev recipe disposes when a chat suspends; the resumed turn's first
// call runs in a new sandbox and must not claim the old one's state.
test("the first call after a dispose says its sandbox and interpreter are new", { skip }, async () => {
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  await s.run("k", { code: "x = 1" });
  await s.run("k", { code: "x" });
  await s.dispose("k");
  const r = await s.run("k", { code: "x + 1" });
  assert.equal(r.stdout, "python 1: x + 1", "a new interpreter answered");
  assert.equal(r.freshSandbox, true);
  assert.equal(r.freshInterpreter, true);
  // So does one let go by the idle close.
  const idle = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }), idleCloseMs: 20 });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: slow, idleCloseMs: 50 });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: slowOpen, idleCloseMs: 20 });
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
  const s = new CodeSandboxes({ minimumIsolation: "process", client });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }), maxOutputChars: 6 });
  const r = await s.run("k", { code: "print('abcdefgh')" });
  assert.equal(r.stdout, "python");
  assert.equal(r.truncated, true);
  await s.disposeAll();
});

test("a floor the daemon cannot meet is refused before dispatch, and the default floor is kernel", { skip }, async () => {
  const s = new CodeSandboxes({ client: new PlimsollClient({ baseUrl: sessionsUrl! }), minimumIsolation: "vm" });
  await assert.rejects(s.run("k", { code: "1" }), { notDispatched: "isolation" });
  // No floor given: a container daemon is refused, for a session and a fresh run alike.
  const { client, calls } = counting(sessionsUrl!);
  await assert.rejects(new CodeSandboxes({ client }).run("k", { code: "1" }), { notDispatched: "isolation" });
  await assert.rejects(new CodeSandboxes({ client: new PlimsollClient({ baseUrl: echoUrl! }) }).run(undefined, { code: "1" }), { notDispatched: "isolation" });
  assert.equal(calls.filter((c) => c === "SessionRun").length, 0);
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client, onCloseError: (_k, e) => errors.push(e) });
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

  // A guest gets the image's environment, so the runner must read the cell as the UTF-8
  // the client wrote, whatever the image's locale. LC_ALL=C with UTF-8 mode off (which
  // Python turns on by itself in the C locale) stands in for such an image: there the
  // locale's encoding is ASCII.
  if (language === "python") {
    test("the python runner reads non-ASCII code under a locale that is not UTF-8", { skip: available ? false : `${bin} is not installed` }, () => {
      const dir = mkdtempSync(join(tmpdir(), "plimsoll-runner-"));
      mkdirSync(join(dir, ".plimsoll"));
      writeFileSync(join(dir, runner.path), runner.source);
      writeFileSync(join(dir, runner.file), `s = "h${String.fromCodePoint(0xe9)}llo"\nlen(s)`); // e with an acute accent: two bytes in UTF-8
      const [cmd, ...args] = runner.step.split(" ");
      const out = execFileSync(cmd!, ["-X", "utf8=0", ...args], { cwd: dir, encoding: "utf8", env: { ...process.env, LC_ALL: "C" } });
      assert.equal(out, "5\n");
    });
  }

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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: lossy, onCloseError: (_k, e) => closeErrors.push(e) });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: process.env.PLIMSOLL_BREAKING_URL! }), languages: ["javascript"] });
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
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  const [a, b] = await Promise.all([s.run("k", { code: "1" }), s.run("k", { code: "2" })]);
  assert.equal([a.freshSandbox, b.freshSandbox].filter(Boolean).length, 1, JSON.stringify([a, b]));
  await s.disposeAll();
});

// A file under .plimsoll/ is refused before anything is sent: a fresh run's runner
// lives there (v0.15.0 review, L24).
test("the .plimsoll/ directory is reserved", async () => {
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: "http://127.0.0.1:1" }), sessions: "never" });
  await assert.rejects(s.run(undefined, { code: "1", files: [{ path: ".plimsoll/run.py", content: "x" }] }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request");
});

// A daemon slot per kept sandbox, shared by every user of the app's token: one user's
// conversations past the cap close that user's least recently used sandbox.
test("one user's sandboxes past the cap close their least recently used, whose next call says so", { skip }, async () => {
  const { client, calls } = counting(sessionsUrl!);
  const s = new CodeSandboxes({ minimumIsolation: "container", client, maxSessionsPerOwner: 2 });
  const alice = (conversation: string) => ({ owner: "alice", conversation });
  await s.run(alice("a"), { code: "x = 1" });
  await s.run(alice("b"), { code: "x = 1" });
  await s.run(alice("a"), { code: "x" }); // a is now the more recent
  await s.run({ owner: "bob", conversation: "a" }, { code: "x = 1" }); // counted for bob
  const c = await s.run(alice("c"), { code: "x = 1" });
  assert.equal(c.freshSandbox, true);
  assert.equal(calls.filter((x) => x === "CloseSession").length, 1, "b was closed before c opened");
  assert.equal((await s.run(alice("a"), { code: "x" })).stdout, "python 3: x", "a kept its interpreter");
  assert.equal((await s.run({ owner: "bob", conversation: "a" }, { code: "x" })).stdout, "python 2: x", "bob's is not alice's to close");
  const b = await s.run(alice("b"), { code: "x" });
  assert.equal(b.stdout, "python 1: x", "b's interpreter is gone, and the call says so");
  assert.equal(b.freshSandbox, true);
  assert.equal(b.freshInterpreter, true);
  await s.disposeAll();
});

test("maxSessions caps the instance across users and keys without one", { skip }, async () => {
  const { client, calls } = counting(sessionsUrl!);
  const s = new CodeSandboxes({ minimumIsolation: "container", client, maxSessions: 2 });
  await s.run("r1", { code: "1" });
  await s.run({ owner: "alice", conversation: "a" }, { code: "1" });
  await s.run("r3", { code: "1" });
  assert.equal(calls.filter((x) => x === "CloseSession").length, 1);
  assert.equal((await s.run({ owner: "alice", conversation: "a" }, { code: "2" })).stdout, "python 2: 2", "r1 was the one closed");
  await s.disposeAll();
});

test("with every one of a user's sandboxes busy, one more is refused before anything opens", { skip }, async () => {
  const calls: string[] = [];
  const slow = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      calls.push(String(input).split("/").pop()!);
      const res = await fetch(input, init);
      if (String(input).endsWith("/SessionRun")) await new Promise((r) => setTimeout(r, 200));
      return res;
    },
  });
  const s = new CodeSandboxes({ minimumIsolation: "container", client: slow, maxSessionsPerOwner: 1 });
  await s.persistent();
  const first = s.run({ owner: "alice", conversation: "a" }, { code: "1" });
  await new Promise((r) => setTimeout(r, 80));
  s.warm({ owner: "alice", conversation: "b" }); // a hint: no room is not an error here
  await assert.rejects(s.run({ owner: "alice", conversation: "b" }, { code: "1" }), { code: "resource_exhausted", notDispatched: "capacity" });
  assert.equal((await first).exitCode, 0);
  assert.equal(calls.filter((x) => x === "OpenSession").length, 1);
  await s.disposeAll();
});

// A warm is a guess (Trigger.dev warms in every new run's onTurnStart, a user's idle new
// tab included), so it never evicts the conversation in use: at the cap it does nothing,
// and the new conversation's first call makes room as any call does.
test("a warm never closes another sandbox; at the cap it waits for the first call", { skip }, async () => {
  const { client, calls } = counting(sessionsUrl!);
  const count = (p: string) => calls.filter((x) => x === p).length;
  const s = new CodeSandboxes({ minimumIsolation: "container", client, maxSessionsPerOwner: 1 });
  const alice = (conversation: string) => ({ owner: "alice", conversation });
  await s.run(alice("in-use"), { code: "x = 1" });
  s.warm(alice("new-tab")); // the user opened a second chat and typed nothing
  await new Promise((r) => setTimeout(r, 50));
  const kept = await s.run(alice("in-use"), { code: "x" });
  assert.equal(kept.stdout, "python 2: x", "the conversation in use kept its interpreter");
  assert.equal(kept.freshSandbox, undefined);
  assert.equal(count("OpenSession"), 1);
  assert.equal(count("CloseSession"), 0);
  // The new tab's first real call opens its sandbox, closing the idle one then.
  assert.equal((await s.run(alice("new-tab"), { code: "1" })).freshSandbox, true);
  assert.equal(count("CloseSession"), 1);
  await s.disposeAll();
  // With room under both caps, a warm opens at once.
  const roomy = counting(sessionsUrl!);
  const r = new CodeSandboxes({ minimumIsolation: "container", client: roomy.client, maxSessionsPerOwner: 2, maxSessions: 2 });
  await r.run(alice("a"), { code: "1" });
  r.warm(alice("b"));
  r.warm("run-1"); // the instance's cap is reached by b: nothing
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(roomy.calls.filter((x) => x === "OpenSession").length, 2);
  assert.equal(roomy.calls.filter((x) => x === "CloseSession").length, 0);
  await r.disposeAll();
});

test("a key is a nonempty string or a nonempty owner and conversation", { skip }, async () => {
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }) });
  for (const key of ["", { owner: "", conversation: "a" }, { owner: "alice", conversation: "" }]) {
    // The message, all a framework shows its model, says first that nothing ran.
    await assert.rejects(s.run(key, { code: "1" }), { notDispatched: "request", message: /^Nothing ran \(request\): plimsoll: / });
  }
  // A string key and a pair never name one sandbox.
  assert.equal((await s.run('["alice","a"]', { code: "1" })).stdout, "python 1: 1");
  assert.equal((await s.run({ owner: "alice", conversation: "a" }, { code: "2" })).stdout, "python 1: 2");
  await s.disposeAll();
});

test("a call aborted before or while its sandbox opens sends nothing and keeps no sandbox", { skip }, async () => {
  const calls: string[] = [];
  const slowOpen = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      calls.push(String(input).split("/").pop()!);
      const res = await fetch(input, init);
      if (String(input).endsWith("/OpenSession")) await new Promise((r) => setTimeout(r, 150));
      return res;
    },
  });
  const s = new CodeSandboxes({ minimumIsolation: "container", client: slowOpen });
  await s.persistent();
  const before = new AbortController();
  before.abort();
  await assert.rejects(s.run("k", { code: "1" }, before.signal), { code: "canceled", notDispatched: "request" });
  assert.equal(calls.filter((x) => x === "OpenSession").length, 0, "already aborted: nothing opened");
  const during = new AbortController();
  const call = s.run("k", { code: "1" }, during.signal);
  setTimeout(() => during.abort(), 30);
  await assert.rejects(call, { code: "canceled", notDispatched: "request" });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(calls.filter((x) => x === "SessionRun").length, 0);
  assert.equal(calls.filter((x) => x === "CloseSession").length, 1, "the sandbox it was opening is closed once open");
  assert.equal((await s.run("k", { code: "x" })).freshSandbox, true);
  await s.disposeAll();
});

test("a call aborted while the shared Describe is pending settles at once and leaves the Describe to others", { skip }, async () => {
  let describes = 0;
  const slowDescribe = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      if (String(input).endsWith("/Describe")) {
        describes++;
        await new Promise((r) => setTimeout(r, 400));
      }
      return fetch(input, init);
    },
  });
  const s = new CodeSandboxes({ minimumIsolation: "container", client: slowDescribe });
  const aborted = new AbortController();
  const started = Date.now();
  const first = s.run("k", { code: "1" }, aborted.signal);
  const second = s.run("k2", { code: "2" });
  setTimeout(() => aborted.abort(), 30);
  await assert.rejects(first, { code: "canceled", notDispatched: "request" });
  assert.ok(Date.now() - started < 300, `settled after ${Date.now() - started} ms, not at the abort`);
  assert.equal((await second).stdout, "python 1: 2", "another call's wait for the same Describe goes on");
  assert.equal(describes, 1);
  await s.disposeAll();
});

test("the owner's digest is the same in every client", () => {
  // The same vector is in client/session_test.go and the Python suite.
  assert.equal(ownerDigest("golden-token-0123456789abcdefghijklmnop", "alice@example.com"), "a7305a43c4fad079f2784707cb25f3deee16b1c4d7da700ee664f5657084f80b");
  assert.equal(ownerDigest(undefined, "alice@example.com"), "b261355cb5012097b8b4ca487cfe786bf9a7fcbc616c9c2fc38469a1c3e5bc8e");
  // Past HMAC's 64-byte block, where a raw key would be replaced by the token_sha256
  // the clients file stores.
  assert.equal(ownerDigest("x".repeat(96), "alice@example.com"), "8ba693de695d11b0bc31a1f6d91c883f07cceca84910df18d7fbb918ee799c8f");
});

test("a sandbox the daemon forgot (a restart) is replaced, and the call runs once more", { skip }, async () => {
  // A restarted daemon has no sessions: the call on the old one is refused as ended
  // (not_found), so the conversation goes on in a new sandbox instead of failing until
  // its idle close. Simulated by sending the next SessionRun with an ID the daemon never gave.
  let forget = false;
  const client = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      if (forget && String(input).endsWith("/SessionRun")) {
        forget = false;
        const body = JSON.parse(String(init?.body));
        body.sessionId = "0".repeat(32);
        return fetch(input, { ...init, body: JSON.stringify(body) });
      }
      return fetch(input, init);
    },
  });
  const s = new CodeSandboxes({ minimumIsolation: "container", client });
  assert.equal((await s.run("k", { code: "1" })).freshSandbox, true);
  forget = true;
  const again = await s.run("k", { code: "2" });
  assert.equal(again.freshSandbox, true, "a new sandbox, said so");
  assert.equal(again.stdout, "python 1: 2");
  await s.disposeAll();
});

test("Describe states the daemon's per-owner cap", { skip: skip || (!ownerCapUrl && "run through `go test ./clients/typescript`") }, async () => {
  const info = await new PlimsollClient({ baseUrl: ownerCapUrl! }).describe();
  assert.equal(info.maxSessionsPerOwner, 1);
  assert.equal(info.maxSessionsPerCaller, 0);
});

test("a daemon's per-owner cap holds across instances, and a replaced sandbox's call runs again fresh", { skip: skip || (!ownerCapUrl && "run through `go test ./clients/typescript`") }, async () => {
  // Two instances stand for two processes of one app; the daemon caps each owner at one.
  const owners: string[] = [];
  const client = new PlimsollClient({
    baseUrl: ownerCapUrl!,
    fetch: async (input, init) => {
      if (String(input).endsWith("/OpenSession")) owners.push(JSON.parse(String(init?.body)).owner);
      return fetch(input, init);
    },
  });
  const a = new CodeSandboxes({ minimumIsolation: "container", client });
  const b = new CodeSandboxes({ minimumIsolation: "container", client });
  const one = { owner: "alice@example.com", conversation: "one" };
  const two = { owner: "alice@example.com", conversation: "two" };
  assert.equal((await a.run(one, { code: "1" })).freshSandbox, true);
  assert.equal((await b.run(two, { code: "2" })).freshSandbox, true);
  // b's open replaced a's sandbox on the daemon: a's next call is refused as replaced,
  // and runs once more in a new sandbox.
  const again = await a.run(one, { code: "3" });
  assert.equal(again.freshSandbox, true);
  assert.equal(again.stdout, "python 1: 3");
  assert.deepEqual(owners, Array(3).fill(ownerDigest(undefined, "alice@example.com")), "the wire carries the digest, never the name");
  await a.disposeAll();
  await b.disposeAll();
});

test("a fresh run with no step report says the code may have run, with no invented exit code", { skip }, async () => {
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: echoUrl! }) });
  const err = await s.run(undefined, { code: "# ECHO:NOSTEP" }).then(
    () => assert.fail("answered as a result"),
    (e: unknown) => e as PlimsollError,
  );
  assert.ok(err instanceof PlimsollError);
  assert.equal(err.notDispatched, undefined, "unmarked: it may have run");
  assert.match(err.message, /^The code may have run, and there is no checked answer for it: plimsoll: the run ended protocol_error without a step report/);
  assert.equal((err.result as { outcome: string }).outcome, "protocol_error");
});

test("a cut never ends on half of a surrogate pair", { skip }, async () => {
  // The fake cell answers "python 1: " and the code: 10 units, then the emoji's two.
  const s = new CodeSandboxes({ minimumIsolation: "container", client: new PlimsollClient({ baseUrl: sessionsUrl! }), maxOutputChars: 11 });
  const r = await s.run("k", { code: String.fromCodePoint(0x1f600) });
  assert.equal(r.stdout, "python 1: ");
  assert.equal(r.truncated, true);
  await s.disposeAll();
});

test("the default close warning names the key by a digest, never its IDs", { skip }, async () => {
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
  const key = { owner: "alice@example.com", conversation: "chat-1" };
  const warned: string[] = [];
  const warn = console.warn;
  console.warn = (...args: unknown[]) => void warned.push(args.join(" "));
  try {
    const s = new CodeSandboxes({ minimumIsolation: "container", client });
    await s.run(key, { code: "1" });
    await s.dispose(key);
  } finally {
    console.warn = warn;
  }
  assert.equal(warned.length, 1);
  assert.doesNotMatch(warned[0], /alice|example|chat-1/);
  assert.match(warned[0], new RegExp(keyDigest(key)));
});
