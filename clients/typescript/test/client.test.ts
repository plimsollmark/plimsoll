// The client against a real daemon handler, served by client_test.go: wasm for
// single runs, the in-memory session provider for sessions.

import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { before, test } from "node:test";

import { PlimsollClient, PlimsollError, PROTOCOL } from "../src/index.ts";
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
