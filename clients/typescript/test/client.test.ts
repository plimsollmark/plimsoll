// The client against a real daemon handler, served by client_test.go: wasm for
// single runs, the in-memory session provider for sessions.

import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { before, test } from "node:test";

import { meets, PlimsollClient, PlimsollError, PROTOCOL } from "../src/index.ts";
import { errorFromWire, sessionEndFromWire } from "../src/errors.ts";
import { recordDigest, recordFromWire } from "../src/record.ts";

const wasmUrl = process.env.PLIMSOLL_WASM_URL;
const sessionsUrl = process.env.PLIMSOLL_SESSIONS_URL;
const skip = !wasmUrl || !sessionsUrl ? "run through `go test ./clients/typescript`" : false;

let wasm: PlimsollClient;
let sessions: PlimsollClient;
before(() => {
  if (skip) return;
  wasm = new PlimsollClient({ baseUrl: wasmUrl! });
  sessions = new PlimsollClient({ baseUrl: sessionsUrl! });
});

// A fetch that rewrites the daemon's answer before the client reads it.
function tampering(url: string, edit: (body: any) => void): PlimsollClient {
  return new PlimsollClient({
    baseUrl: url,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (!res.ok) return res;
      const body = await res.json();
      edit(body);
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });
}

test("base URLs are checked before anything is sent", () => {
  assert.throws(() => new PlimsollClient({ baseUrl: "http://sandbox.example:8080" }), /insecureHttp/);
  assert.throws(() => new PlimsollClient({ baseUrl: "ftp://127.0.0.1" }), /http or https/);
  assert.throws(() => new PlimsollClient({ baseUrl: "https://u:p@sandbox.example" }), /userinfo/);
  new PlimsollClient({ baseUrl: "https://sandbox.example" });
  new PlimsollClient({ baseUrl: "http://sandbox.example", insecureHttp: true });
  // Loopback is an address, not a name that starts like one.
  assert.throws(() => new PlimsollClient({ baseUrl: "http://127.evil.example:8080" }), /insecureHttp/);
  assert.throws(() => new PlimsollClient({ baseUrl: "http://localhost.evil.example" }), /insecureHttp/);
  new PlimsollClient({ baseUrl: "http://127.0.0.2:8080" });
  new PlimsollClient({ baseUrl: "http://[::1]:8080" });
  new PlimsollClient({ baseUrl: "http://localhost:8080" });
});

// A redirect is never followed: fetch's default would send the code to wherever it
// points. The client refuses it and the redirect's target hears nothing.
test("a redirect is not followed", async () => {
  let elsewhere = 0;
  const other = createServer((_req, res) => {
    elsewhere++;
    res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
  });
  await new Promise<void>((resolve) => other.listen(0, "127.0.0.1", resolve));
  const target = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
  const redirecting = createServer((req, res) => {
    res.writeHead(307, { Location: target + req.url }).end();
  });
  await new Promise<void>((resolve) => redirecting.listen(0, "127.0.0.1", resolve));
  try {
    const c = new PlimsollClient({ baseUrl: `http://127.0.0.1:${(redirecting.address() as AddressInfo).port}`, token: "tok" });
    await assert.rejects(c.runJavaScript("secret()"), (e: unknown) => {
      assert.ok(e instanceof PlimsollError);
      assert.equal(e.code, "unknown");
      assert.equal(e.notDispatched, undefined);
      assert.match(e.message, /redirect \(HTTP 307\)/);
      return true;
    });
    assert.equal(elsewhere, 0);
  } finally {
    redirecting.close();
    other.close();
  }
});

// A daemon that accepts the request and then stalls: before its headers, or after
// them in the middle of its body.
async function stalling(afterHeaders: boolean): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => {
    req.resume();
    if (afterHeaders) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"protocol":');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

for (const afterHeaders of [false, true]) {
  test(`a daemon that stalls ${afterHeaders ? "in its body" : "before answering"} fails the call by the request deadline`, async () => {
    const { url, server } = await stalling(afterHeaders);
    try {
      const c = new PlimsollClient({ baseUrl: url, requestTimeoutMs: 200 });
      const start = Date.now();
      await assert.rejects(c.describe(), (e: unknown) => e instanceof PlimsollError && e.code === "deadline_exceeded" && e.notDispatched === undefined);
      assert.ok(Date.now() - start < 5_000, `took ${Date.now() - start} ms against a 200 ms deadline`);
      // The caller's own signal still wins, as canceled.
      const ac = new AbortController();
      setTimeout(() => ac.abort(), 50);
      await assert.rejects(new PlimsollClient({ baseUrl: url }).describe(ac.signal), { code: "canceled" });
    } finally {
      server.closeAllConnections();
      server.close();
    }
  });
}

test("requestTimeoutMs must be a positive number", () => {
  for (const bad of [0, -1, Number.NaN, 2 ** 31]) {
    assert.throws(() => new PlimsollClient({ baseUrl: "http://127.0.0.1:1", requestTimeoutMs: bad }), /requestTimeoutMs/);
  }
});

test("describe states the daemon's protocol and provider", { skip }, async () => {
  const info = await wasm.describe();
  assert.equal(info.protocol, PROTOCOL);
  assert.equal(info.sandbox, "wasm");
  assert.equal(info.isolation, "process");
  assert.equal(info.supportsSessions, false);
  assert.equal((await sessions.describe()).supportsSessions, true);
});

test("a snippet runs and its record checks", { skip }, async () => {
  const r = await wasm.runJavaScript("console.log(6*7)", { traceId: "ts-1", timeoutMs: 10_000 });
  assert.equal(r.exitCode, 0);
  assert.equal(r.stdout, "42\n");
  assert.equal(r.isolation, "process");
  assert.equal(r.record.provider, "wasm");
  assert.equal(r.record.session, "");
  assert.match(r.record.sha256, /^[0-9a-f]{64}$/);
});

test("a failing snippet is a result, not an error", { skip }, async () => {
  const r = await wasm.runJavaScript("throw new Error('boom')");
  assert.notEqual(r.exitCode, 0);
  assert.match(r.stderr, /boom/);
});

test("a floor above the provider's tier is refused before dispatch", { skip }, async () => {
  await assert.rejects(wasm.runJavaScript("console.log(1)", { minimumIsolation: "container" }), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.code, "failed_precondition");
    assert.equal(e.notDispatched, "isolation");
    return true;
  });
});

test("a changed output byte is data loss, with the result attached", { skip }, async () => {
  const c = tampering(wasmUrl!, (b) => {
    b.javascript.stdout = Buffer.from("43\n").toString("base64");
  });
  await assert.rejects(c.runJavaScript("console.log(42)"), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.code, "data_loss");
    assert.equal(e.notDispatched, undefined);
    assert.match(e.message, /result digest/);
    assert.ok(e.result);
    return true;
  });
});

test("an answer without a record is data loss", { skip }, async () => {
  const c = tampering(wasmUrl!, (b) => delete b.record);
  await assert.rejects(c.runJavaScript("console.log(1)"), { code: "data_loss" });
});

test("a single run's record with session fields is data loss, though its digest checks", { skip }, async () => {
  const c = tampering(wasmUrl!, (b) => {
    b.record.session = "f".repeat(64);
    b.record.sequence = "1";
    b.record.recordSha256 = recordDigest(recordFromWire(b.record));
  });
  await assert.rejects(c.runJavaScript("console.log(1)"), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.code, "data_loss");
    assert.match(e.message, /session fields/);
    return true;
  });
});

test("an answer holding two results is data loss", { skip }, async () => {
  const c = tampering(wasmUrl!, (b) => (b.project = { outcome: "OUTCOME_COMPLETED" }));
  await assert.rejects(c.runJavaScript("console.log(1)"), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.code, "data_loss");
    assert.match(e.message, /holds 2 results/);
    return true;
  });
});

// Whatever shape a broken or hostile daemon answers in, the caller gets a PlimsollError
// saying the call may have run, never a TypeError from deep in the decoder.
test("a malformed answer is data loss, not a raw error", { skip }, async () => {
  const edits: [string, (b: any) => void][] = [
    ["a number for output bytes", (b) => (b.javascript.stdout = 5)],
    ["an object for a record time", (b) => (b.record.startedUnixMs = {})],
    ["a string for the record", (b) => (b.record = "x")],
    ["a number for the result", (b) => (b.javascript = 7)],
    ["a list for the exit code", (b) => (b.javascript.exitCode = [1])],
    ["an object for the provider", (b) => (b.record.provider = {})],
  ];
  const isDataLoss = (e: unknown) => e instanceof PlimsollError && e.code === "data_loss" && e.notDispatched === undefined;
  for (const [name, edit] of edits) {
    await assert.rejects(tampering(wasmUrl!, edit).runJavaScript("console.log(1)"), isDataLoss, name);
  }
  const s = await tampering(sessionsUrl!, (b) => {
    if ("lastRecordSha256" in b) b.calls = "x";
  }).openSession();
  await s.runJavaScript("1");
  await assert.rejects(s.close(), isDataLoss, "a close whose count is not a number");
});

test("an error answer in any shape is a PlimsollError with a known code", async () => {
  const codes = ["canceled", "unknown", "invalid_argument", "deadline_exceeded", "not_found", "already_exists", "permission_denied", "resource_exhausted", "failed_precondition", "aborted", "out_of_range", "unimplemented", "internal", "unavailable", "data_loss", "unauthenticated"];
  const bodies: unknown[] = [{ code: "internal", details: 5 }, { code: 7, message: {} }, { code: "bogus" }, { details: [null, 3, "x"] }, [1], "s"];
  for (const body of bodies) {
    const c = new PlimsollClient({
      baseUrl: "http://127.0.0.1:9",
      fetch: async () => new Response(JSON.stringify(body), { status: 500, headers: { "Content-Type": "application/json" } }),
    });
    await assert.rejects(
      c.runJavaScript("1"),
      (e: unknown) => e instanceof PlimsollError && codes.includes(e.code) && typeof e.message === "string" && e.notDispatched === undefined,
      JSON.stringify(body),
    );
  }
});

test("a tier the record does not state is data loss", { skip }, async () => {
  const c = tampering(wasmUrl!, (b) => (b.isolation = "vm"));
  await assert.rejects(c.runJavaScript("console.log(1)"), { code: "data_loss" });
});

test("a session keeps one sandbox and chains its records", { skip }, async () => {
  const s = await sessions.openSession({ minimumIsolation: "container" });
  assert.equal(s.isolation, "container");
  const a = await s.runJavaScript("1");
  const b = await s.runJavaScript("2");
  // The fake answers its nth call with n "x"s: one sandbox saw both calls.
  assert.equal(a.stdout, "x");
  assert.equal(b.stdout, "xx");
  assert.equal(a.record.sequence, 1n);
  assert.equal(b.record.sequence, 2n);
  assert.equal(b.record.previousSha256, a.record.sha256);
  assert.equal(b.record.session, s.fingerprint);
  const sum = await s.close();
  assert.equal(sum.calls, 2n);
  assert.equal(sum.lastRecordSha256, b.record.sha256);
  assert.equal(sum.end, "closed");
});

test("cells run in the session's interpreter and chain with its other calls", { skip }, async () => {
  const s = await sessions.openSession();
  await s.runJavaScript("1");
  const a = await s.runCell({ language: "python", code: "x = 1" });
  const b = await s.runCell({ language: "python", code: "x + 1", files: [{ path: "in/a.csv", content: "a" }] });
  // The fake answers a cell with its language, its count of cells and its code,
  // and lists its files on stderr.
  assert.equal(a.stdout, "python 1: x = 1");
  assert.equal(a.interpreterStarted, true);
  assert.equal(b.stdout, "python 2: x + 1");
  assert.equal(b.stderr, "in/a.csv\n");
  assert.equal(b.interpreterStarted, false);
  assert.equal(b.record.sequence, 3n);
  assert.equal(b.record.previousSha256, a.record.sha256);
  await assert.rejects(s.runCell({ language: "ruby" as never, code: "1" }), { notDispatched: "request" });
  assert.equal((await s.close()).calls, 3n);
});

test("a language hint is sent and checked", { skip }, async () => {
  // The daemon parses the field (an unknown one would fail the open); the fake states
  // no languages, so only the client's check refuses.
  const s = await sessions.openSession({ languages: ["python", "javascript", "python"] });
  assert.equal((await s.runCell({ language: "python", code: "1" })).stdout, "python 1: 1");
  await s.close();
  await assert.rejects(sessions.openSession({ languages: ["cobol" as never] }), { code: "invalid_argument", notDispatched: "request" });
});

// An owner read from an optional field arrives as "" for a request without one; sent as
// no owner, it would escape the daemon's per-owner cap.
test("an empty owner is refused before anything is sent; an owner is sent as its digest", { skip }, async () => {
  const bodies: string[] = [];
  const c = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: (input, init) => {
      bodies.push(String(init?.body));
      return fetch(input, init);
    },
  });
  await assert.rejects(c.openSession({ owner: "" }), { code: "invalid_argument", notDispatched: "request" });
  await assert.rejects(c.openSession({ owner: 7 as never }), { code: "invalid_argument", notDispatched: "request" });
  assert.equal(bodies.length, 0, "nothing was sent");
  const s = await c.openSession({ owner: "alice" });
  await s.close();
  assert.match(JSON.parse(bodies[0]!).owner, /^[0-9a-f]{64}$/);
});

test("concurrent calls on one session are serialized and keep the chain", { skip }, async () => {
  const s = await sessions.openSession();
  const results = await Promise.all([1, 2, 3, 4].map((n) => s.runJavaScript(String(n))));
  assert.deepEqual(results.map((r) => r.record.sequence), [1n, 2n, 3n, 4n]);
  assert.equal((await s.close()).calls, 4n);
});

test("a call on an ended session is refused, marked not dispatched", { skip }, async () => {
  const s = await sessions.openSession();
  await s.runJavaScript("1");
  await fetch(`${sessionsUrl}/test/end-sessions`, { method: "POST" });
  await assert.rejects(s.runJavaScript("2"), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.ok(e.notDispatched, "an ended session ran nothing");
    assert.equal(e.sessionEnded?.reason, "expired");
    return true;
  });
  assert.equal(s.ended?.reason, "expired");
  await s.close();
});

// A daemon one enum value newer than this client can end a session for a reason the
// client has no name for: that still says the session ended.
test("a session end this client has no name for is an end, never open", { skip }, async () => {
  assert.equal(sessionEndFromWire(undefined), "open");
  assert.equal(sessionEndFromWire(0), "open");
  assert.equal(sessionEndFromWire("SESSION_END_UNSPECIFIED"), "open");
  assert.equal(sessionEndFromWire("SESSION_END_REPLACED"), "replaced");
  assert.equal(sessionEndFromWire(8), "replaced");
  assert.equal(sessionEndFromWire(9), "not_found");
  assert.equal(sessionEndFromWire("SESSION_END_NOT_FOUND"), "not_found");
  for (const v of [10, 99, -1, "SESSION_END_HOST_LOST", "SESSION_END_OPEN", "SESSION_END_UNKNOWN", "bogus"]) {
    assert.equal(sessionEndFromWire(v), "unknown", String(v));
  }
  // A SessionEnded detail says the session ended, whatever reason it names.
  const detail = (reason: number) => ({ type: "plimsoll.v1.SessionEnded", value: Buffer.from(reason ? [8, reason] : []).toString("base64") });
  assert.equal(errorFromWire(412, { code: "failed_precondition", details: [detail(0)] }).sessionEnded?.reason, "unknown");
  assert.equal(errorFromWire(412, { code: "failed_precondition", details: [detail(42)] }).sessionEnded?.reason, "unknown");
  assert.equal(errorFromWire(412, { code: "failed_precondition", details: [detail(2)] }).sessionEnded?.reason, "expired");

  const c = tampering(sessionsUrl!, (b) => {
    if (b.run) b.ended = "SESSION_END_HOST_LOST";
  });
  const s = await c.openSession();
  await s.runJavaScript("1");
  assert.equal(s.ended?.reason, "unknown", "the answer said the session ended");
});

test("a session call whose record skips a call is data loss", { skip }, async () => {
  const c = tampering(sessionsUrl!, (b) => {
    if (b.run?.record) b.run.record.sequence = "5";
  });
  const s = await c.openSession();
  await assert.rejects(s.runJavaScript("1"), { code: "data_loss" });
});

test("a wasm daemon has no sessions", { skip }, async () => {
  await assert.rejects(wasm.openSession(), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.code, "unimplemented");
    assert.equal(e.notDispatched, "unsupported");
    return true;
  });
});

// A session call whose answer is lost after the daemon ran it leaves the client's
// chain behind the daemon's. The session refuses every later call itself, marked
// not dispatched, instead of sending calls that would run and then fail the check.
test("a session sends nothing after a call that ended without an answer", { skip }, async () => {
  let runs = 0;
  let drop = false;
  const lossy = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: async (input, init) => {
      const res = await fetch(input, init);
      if (String(input).endsWith("/SessionRun")) {
        runs++;
        if (drop) throw new TypeError("the connection dropped after the daemon answered");
      }
      return res;
    },
  });
  const s = await lossy.openSession();
  await s.runCell({ language: "python", code: "x = 1" });
  drop = true;
  await assert.rejects(s.runCell({ language: "python", code: "x" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === undefined);
  drop = false;
  await assert.rejects(s.runCell({ language: "python", code: "x" }), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.code, "failed_precondition");
    assert.equal(e.notDispatched, "request");
    return true;
  });
  assert.equal(runs, 2, "the refused call reached the daemon");
  await s.close().catch(() => undefined); // its count is ahead of this client's
});

// A session call that may have run but ended in an error comes with its record: the
// session keeps it in its chain and goes on, and the close's count agrees.
test("an unanswered session call is in the chain and the session goes on", { skip: process.env.PLIMSOLL_BREAKING_URL ? false : "run through `go test ./clients/typescript`" }, async () => {
  const c = new PlimsollClient({ baseUrl: process.env.PLIMSOLL_BREAKING_URL! });
  const s = await c.openSession();
  await s.runJavaScript("1");
  await assert.rejects(s.runJavaScript("2"), (e: unknown) => {
    assert.ok(e instanceof PlimsollError);
    assert.equal(e.notDispatched, undefined, "a call that may have run is never marked not dispatched");
    assert.equal(e.unanswered?.version, 3);
    return true;
  });
  const r = await s.runJavaScript("3");
  assert.equal(r.record.sequence, 3n);
  const sum = await s.close();
  assert.equal(sum.calls, 3n);
});

// Every holder of a session can close it; the daemon forgets it at the first close and
// answers a second NotFound, which would read as a failed close.
test("a session closes once, however many holders close it", { skip }, async () => {
  const procedures: string[] = [];
  const c = new PlimsollClient({
    baseUrl: sessionsUrl!,
    fetch: (input, init) => {
      procedures.push(String(input).split("/").pop()!);
      return fetch(input, init);
    },
  });
  const s = await c.openSession();
  await s.runJavaScript("1");
  const [a, b] = await Promise.all([s.close(), s.close()]);
  assert.equal(a, b, "the second close is the first one's answer");
  assert.equal(a.calls, 1n);
  assert.equal(await s.close(), a, "and so is a later one");
  assert.equal(procedures.filter((p) => p === "CloseSession").length, 1);
  // A close refused before it was sent closed nothing, so a later close tries again.
  const t = await c.openSession();
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(t.close(aborted.signal), { code: "canceled", notDispatched: "request" });
  assert.equal((await t.close()).calls, 0n);
  assert.equal(procedures.filter((p) => p === "CloseSession").length, 2);
});

// An unanswered call's record must meet the session's floor, which every call carries,
// and repeat what the session stated at open; otherwise it is data loss and the session
// sends nothing more (v0.15.0 review, M5.3 and L24).
test("an unanswered record must state the session's evidence", { skip: !process.env.PLIMSOLL_LIAR_URL && "run through `go test ./clients/typescript`" }, async () => {
  const c = new PlimsollClient({ baseUrl: process.env.PLIMSOLL_LIAR_URL! });
  const s = await c.openSession({ minimumIsolation: "container" });
  await assert.rejects(s.runJavaScript("weaker"), (e: unknown) => e instanceof PlimsollError && e.code === "data_loss" && /below the call's minimum container/.test(e.message));
  await assert.rejects(s.runJavaScript("next"), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request");
  const other = await c.openSession();
  await assert.rejects(other.runJavaScript("other-provider"), (e: unknown) => e instanceof PlimsollError && e.code === "data_loss" && /the session opened as liar/.test(e.message));
});

// A session call aborted while it waits its turn was never sent: a refusal, and the
// session stays usable (v0.15.0 review, L21). A floor outside the four tiers meets
// nothing (L24).
test("a queued call aborted before it is sent leaves the session usable", { skip }, async () => {
  const s = await sessions.openSession();
  const ac = new AbortController();
  const a = s.runJavaScript("1");
  const b = s.runJavaScript("2", { signal: ac.signal });
  ac.abort();
  await a;
  await assert.rejects(b, (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request");
  assert.equal(s.stopped, undefined);
  await s.runJavaScript("3");
  await s.close();
  assert.equal(meets("vm", "bogus" as never), false);
});

// JSON can carry a lone surrogate as an escape, but no protobuf string can hold one, so
// the daemon would refuse the request after it arrived, with no not-dispatched mark. The
// client refuses it before anything is sent, marked, on every path.
const refusedAsText = (e: unknown) => e instanceof PlimsollError && e.code === "invalid_argument" && e.notDispatched === "request";

test("text that is not well-formed is refused before anything is sent", async () => {
  const lone = String.fromCharCode(0xd800);
  let sent = 0;
  const c = new PlimsollClient({
    baseUrl: "http://127.0.0.1:9",
    fetch: async () => {
      sent++;
      return new Response("{}", { status: 500 });
    },
  });
  await assert.rejects(c.runJavaScript("x" + lone), refusedAsText);
  await assert.rejects(c.runProject({ files: [{ path: "a.js", content: lone }], steps: ["node a.js"] }), refusedAsText);
  await assert.rejects(c.runProject({ files: [], steps: [lone] }), refusedAsText);
  await assert.rejects(c.runJavaScript("1", { traceId: lone }), refusedAsText);
  assert.equal(sent, 0);
});

test("a session refuses text that is not well-formed and goes on", { skip }, async () => {
  const lone = String.fromCharCode(0xdfff);
  const s = await sessions.openSession();
  await assert.rejects(s.runJavaScript(lone), refusedAsText);
  await assert.rejects(s.runCell({ language: "python", code: "1", files: [{ path: lone, content: "" }] }), refusedAsText);
  assert.equal(s.stopped, undefined);
  await s.runJavaScript("1");
  assert.equal(s.chain.calls, 1n);
  await s.close();
});
