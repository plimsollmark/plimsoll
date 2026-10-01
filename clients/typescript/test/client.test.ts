// The client against a real daemon handler, served by client_test.go: wasm for
// single runs, the in-memory session provider for sessions.

import assert from "node:assert/strict";
import { before, test } from "node:test";

import { PlimsollClient, PlimsollError, PROTOCOL } from "../src/index.ts";

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
