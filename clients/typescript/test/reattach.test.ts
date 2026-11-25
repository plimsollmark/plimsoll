// Session reattach in the TypeScript client (step R4 of the sessions builds plan): the
// checkpoint and attach, against the shared daemons and vectors of internal/clientsuite
// (reattach.go), which the Go and Python clients are held to too. The reattach daemon is
// the in-memory session provider behind a token: a session call with trace ID drop-answer
// runs and its answer is cut, GET /test/calls counts the calls the provider ran and GET
// /test/checkpoint-vectors serves the vectors. The attach liar answers an attach with trace
// ID forge-<name> with the honest answer with one thing forged, counts each session's
// closes and calls, and sends a call with trace ID head-mismatch on with its head's count
// raised, so the daemon refuses it as a head mismatch.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CheckpointMismatchError,
  checkpointToJSON,
  HeadMismatchError,
  parseCheckpoint,
  PlimsollClient,
  PlimsollError,
  RecoveringError,
  StaleOwnerError,
  type SessionCheckpoint,
} from "../src/index.ts";
import { errorFromWire } from "../src/errors.ts";
import { CHECKPOINT_MISMATCH_TEXT, RECOVERING_TEXT, STALE_OWNER_TEXT } from "../src/tables.gen.ts";
import { saysOf, verdict } from "./cases.ts";

const reattachUrl = process.env.PLIMSOLL_REATTACH_URL;
const token = process.env.PLIMSOLL_REATTACH_TOKEN;
const liarUrl = process.env.PLIMSOLL_ATTACH_LIAR_URL;
const echoLiarUrl = process.env.PLIMSOLL_LIAR_URL;
const skip = !reattachUrl || !token || !liarUrl || !echoLiarUrl ? "run through `go test ./clients/typescript`" : false;

const DAEMON = "suite-daemon";

function client(url = reattachUrl!, opts: { daemonName?: string; fetch?: typeof fetch } = { daemonName: DAEMON }): PlimsollClient {
  return new PlimsollClient({ baseUrl: url, token, ...opts });
}

async function getJSON(url: string): Promise<any> {
  const res = await fetch(url);
  assert.equal(res.status, 200, url);
  return res.json();
}

// The error an attach ends with, or undefined when it was taken.
async function attachError(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return e;
  }
}

const providerCalls = async (): Promise<number> => (await getJSON(`${reattachUrl}/test/calls`)).calls;

// The ownership refusals by code, reason and text: reason permission is a stale worker,
// reason request with the daemon's constant text a mismatch, and any other text with that
// reason neither.
test("the stale and mismatch refusals map to their errors, and only they", () => {
  const detail = (reason: number) => ({ type: "plimsoll.v1.NotDispatched", value: Buffer.from([0x08, reason]).toString("base64") });
  const refusal = (reason: number, message: string) => errorFromWire(400, { code: "failed_precondition", message, details: [detail(reason)] }, { bound: true });
  assert.ok(refusal(2, STALE_OWNER_TEXT) instanceof StaleOwnerError);
  assert.equal(refusal(2, STALE_OWNER_TEXT).notDispatched, "permission");
  const mismatch = refusal(1, CHECKPOINT_MISMATCH_TEXT);
  assert.ok(mismatch instanceof CheckpointMismatchError && !(mismatch instanceof StaleOwnerError));
  assert.equal(mismatch.notDispatched, "request");
  const other = refusal(1, "some other refusal with reason request");
  assert.ok(!(other instanceof CheckpointMismatchError) && !(other instanceof StaleOwnerError) && other.notDispatched === "request");
});

// A call's head mismatch (protocol 8) is the attach mismatch's code, reason and text with the
// daemon's head as a SessionHeadMismatch detail; the detail is decoded by hand.
test("a head mismatch refusal carries the daemon's head, and only with its detail", () => {
  const nd = { type: "plimsoll.v1.NotDispatched", value: Buffer.from([0x08, 1]).toString("base64") };
  const head = (bytes: number[]) => ({ type: "plimsoll.v1.SessionHeadMismatch", value: Buffer.from(bytes).toString("base64") });
  const refusal = (...details: { type: string; value: string }[]) =>
    errorFromWire(400, { code: "failed_precondition", message: CHECKPOINT_MISMATCH_TEXT, details: [nd, ...details] }, { bound: true });
  // head { generation: 3, calls: 300, last_record_sha256: "ab" }, then a field this client does not know.
  const cp = [0x08, 0x03, 0x10, 0xac, 0x02, 0x1a, 0x02, 0x61, 0x62, 0x20, 0x07];
  const got = refusal(head([0x0a, cp.length, ...cp, 0x15, 1, 2, 3, 4]));
  assert.ok(got instanceof HeadMismatchError && !(got instanceof CheckpointMismatchError), String(got));
  assert.deepEqual(got.head, { generation: 3n, calls: 300n, lastRecordSha256: "ab" });
  assert.equal(got.notDispatched, "request");
  // No head in the detail, a varint past 64 bits, or a cut length: an attach's mismatch, as without the detail.
  for (const bytes of [[0x20, 0x01], [0x0a, 11, 0x08, ...Array(9).fill(0xff), 0x7f], [0x0a, 0x05, 0x08]]) {
    const e = refusal(head(bytes));
    assert.ok(e instanceof CheckpointMismatchError && !(e instanceof HeadMismatchError), JSON.stringify(bytes));
  }
  assert.ok(refusal() instanceof CheckpointMismatchError && !(refusal() instanceof HeadMismatchError));
});

test("every client reads the shared checkpoint vectors", { skip }, async () => {
  const v = await getJSON(`${reattachUrl}/test/checkpoint-vectors`);
  for (const c of v.valid) {
    const cp = parseCheckpoint(c.json);
    verdict(`checkpoint/valid/${c.name}`, "checkpoint", "parsed");
    assert.deepEqual(parseCheckpoint(checkpointToJSON(cp)), cp, c.name);
  }
  for (const c of v.invalid) {
    let err: unknown;
    try {
      parseCheckpoint(c.json);
    } catch (e) {
      err = e;
    }
    verdict(`checkpoint/invalid/${c.name}`, "checkpoint", err === undefined ? "parsed" : "refused");
    assert.ok(err instanceof PlimsollError && err.code === "invalid_argument", c.name);
  }
});

test("a checkpoint round trips and holds no secret", { skip }, async () => {
  const s = await client().openSession({ minimumIsolation: "container" });
  await s.runCell({ language: "python", code: "x = 1" });
  const cp = await s.checkpoint();
  assert.equal(cp.daemon, DAEMON);
  assert.equal(cp.session, s.fingerprint);
  assert.deepEqual([cp.generation, cp.calls, cp.openFloor, cp.isolation, cp.provider], [1n, 1n, "container", "container", "fake-sessions"]);
  assert.equal(cp.lastRecordSha256, s.chain.lastRecordSha256);
  const text = checkpointToJSON(cp);
  assert.deepEqual(parseCheckpoint(text), cp);
  assert.ok(!text.includes(token!), "the checkpoint carries the token");
  await s.close();
});

test("no checkpoint without a daemon name, or from a stopped, closed or ended session", { skip }, async () => {
  const unnamed = await client(reattachUrl, {}).openSession();
  await assert.rejects(unnamed.checkpoint(), /daemonName/);
  await unnamed.close();
  const closed = await client().openSession();
  await closed.close();
  await assert.rejects(closed.checkpoint(), /closed/);
  const stopped = await client().openSession();
  await assert.rejects(stopped.runCell({ language: "python", code: "1" }, { traceId: "drop-answer" }), (e: unknown) => e instanceof PlimsollError && !e.notDispatched);
  await assert.rejects(stopped.checkpoint(), /stopped/);
});

test("a daemon name is never a URL", { skip }, () => {
  assert.throws(() => new PlimsollClient({ baseUrl: reattachUrl!, daemonName: "https://plimsoll.example" }), /daemonName/);
});

test("an open answer must echo the floor and rule the open sent", { skip }, async () => {
  for (const traceId of ["bad-floor", "bad-rule"]) {
    await assert.rejects(new PlimsollClient({ baseUrl: echoLiarUrl! }).openSession({ minimumIsolation: "process", traceId }), (e: unknown) => e instanceof PlimsollError && e.code === "data_loss", traceId);
  }
});

test("an attach carries the chain on, in the same sandbox", { skip }, async () => {
  const a = await client().openSession();
  await a.runCell({ language: "python", code: "x = 1" });
  await a.runCell({ language: "python", code: "y = 2" });
  const cp = await a.checkpoint();
  const b = await client().attachSession(cp);
  const r = await b.runCell({ language: "python", code: "z = 3" });
  assert.equal(r.stdout, "python 3: z = 3", "the same interpreter, now behind the second worker");
  assert.deepEqual([r.record.sequence, r.record.previousSha256], [cp.calls + 1n, cp.lastRecordSha256]);
  const next = await b.checkpoint();
  assert.deepEqual([next.generation, next.calls, next.lastRecordSha256], [cp.generation + 1n, 3n, r.record.sha256]);
  assert.equal((await b.close()).calls, 3n);
});

test("a stale worker is refused before dispatch, and sends nothing more", { skip }, async () => {
  const a = await client().openSession();
  const b = await client().attachSession(await a.checkpoint());
  const calls = await providerCalls();
  await assert.rejects(a.runCell({ language: "python", code: "1" }), (e: unknown) => e instanceof StaleOwnerError && e.notDispatched === "permission");
  assert.equal(await providerCalls(), calls, "the provider ran the stale worker's call");
  assert.ok(a.stopped);
  await assert.rejects(a.runCell({ language: "python", code: "1" }), (e: unknown) => e instanceof StaleOwnerError && e.notDispatched === "request");
  await assert.rejects(a.checkpoint(), /stopped/);
  await b.close();
});

test("a stale worker cannot close", { skip }, async () => {
  const a = await client().openSession();
  const b = await client().attachSession(await a.checkpoint());
  await assert.rejects(a.close(), (e: unknown) => e instanceof StaleOwnerError);
  assert.ok(a.stopped);
  await b.runCell({ language: "python", code: "still open" });
  await b.close();
});

test("an attach refuses locally, sending nothing", { skip }, async () => {
  const s = await client().openSession();
  const cp = await s.checkpoint();
  const silent: typeof fetch = async () => assert.fail("a request was sent");
  const cases: [string, PlimsollClient, SessionCheckpoint][] = [
    ["an invalid checkpoint", client(reattachUrl, { daemonName: DAEMON, fetch: silent }), { ...cp, generation: 0n }],
    ["another daemon's checkpoint", client(reattachUrl, { daemonName: DAEMON, fetch: silent }), { ...cp, daemon: "another-daemon" }],
    ["a client with no name", client(reattachUrl, { fetch: silent }), cp],
  ];
  for (const [name, c, bad] of cases) {
    await assert.rejects(c.attachSession(bad), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request", name);
  }
  await (await client().attachSession(cp)).close();
});

test("each forged attach answer is refused, and nothing is closed", { skip }, async () => {
  const s = await client(liarUrl).openSession({ minimumIsolation: "container" });
  await s.runCell({ language: "python", code: "1" });
  const cp = await s.checkpoint();
  const b = client(liarUrl);
  for (const name of await getJSON(`${liarUrl}/test/forgeries`)) {
    const err = await attachError(b.attachSession(cp, { traceId: `forge-${name}` }));
    verdict(`attach/forgeries/${name}`, "attach-live", saysOf(err));
    assert.ok(err instanceof PlimsollError && err.code === "data_loss", `${name}: ${String(err)}`);
  }
  assert.equal((await getJSON(`${liarUrl}/test/closes?session=${s.fingerprint}`)).closes, 0);
  await b.attachSession(cp, { traceId: "forge-none" }); // the honest answer
  verdict("attach/forgeries/none", "attach-live", "accept");
});

test("two attaches from one checkpoint: exactly one gets the session", { skip }, async () => {
  const s = await client().openSession();
  const cp = await s.checkpoint();
  const got = await Promise.allSettled([client().attachSession(cp), client().attachSession(cp)]);
  const ok = got.filter((g) => g.status === "fulfilled");
  const stale = got.filter((g) => g.status === "rejected" && g.reason instanceof StaleOwnerError);
  assert.deepEqual([ok.length, stale.length], [1, 1], String(got.map((g) => (g.status === "rejected" ? g.reason : "ok"))));
  await (ok[0] as PromiseFulfilledResult<Awaited<ReturnType<PlimsollClient["attachSession"]>>>).value.close();
});

test("a lost answer prevents the attach", { skip }, async () => {
  const a = await client().openSession();
  const cp = await a.checkpoint();
  const calls = await providerCalls();
  await assert.rejects(a.runCell({ language: "python", code: "lost" }, { traceId: "drop-answer" }), (e: unknown) => e instanceof PlimsollError && !e.notDispatched);
  assert.equal(await providerCalls(), calls + 1, "the call ran");
  await assert.rejects(client().attachSession(cp), (e: unknown) => e instanceof CheckpointMismatchError && e.notDispatched === "request" && !(e instanceof StaleOwnerError));
});

test("an attach whose answer is lost is never retried", { skip }, async () => {
  const s = await client().openSession();
  const cp = await s.checkpoint();
  let sent = 0;
  const lossy: typeof fetch = async (input, init) => {
    const res = await fetch(input, init);
    if (String(input).endsWith("/AttachSession")) {
      sent++;
      await res.body?.cancel();
      throw new Error("the connection dropped after the daemon answered");
    }
    return res;
  };
  await assert.rejects(client(reattachUrl, { daemonName: DAEMON, fetch: lossy }).attachSession(cp), (e: unknown) => e instanceof PlimsollError && !e.notDispatched);
  assert.equal(sent, 1);
  await assert.rejects(client().attachSession(cp), (e: unknown) => e instanceof StaleOwnerError, "the lost attach moved ownership");
});

// The explained gap (option A of the PydanticAI design's section 3.3, option 3 of the lost
// call design): naming the call that ran with its answer lost takes the session over across
// the gap, once, with its record and, when the daemon kept it, its answer; the attached
// session is then recovering and sends nothing until the application resolves the lost call.

async function lostCall(url = reattachUrl!, opts: { minimumIsolation?: "container"; keepNoAnswer?: boolean } = {}) {
  const a = await client(url).openSession(opts);
  await a.runCell({ language: "python", code: "x = 1" });
  const cp = await a.checkpoint();
  await assert.rejects(a.runCell({ language: "python", code: "y = 2" }, { traceId: "drop-answer" }), (e: unknown) => e instanceof PlimsollError && !e.notDispatched);
  assert.match(a.lostRequestSha256, /^[0-9a-f]{64}$/);
  return { a, cp, lost: a.lostRequestSha256 };
}

const recovering = (e: unknown) =>
  e instanceof RecoveringError && e.notDispatched === "request" && e.code === "failed_precondition" && e.message === `plimsoll: ${RECOVERING_TEXT}; nothing was sent`;

test("naming the lost call carries the chain on across the gap, with its record and its kept answer", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  const lc = b.lostCall;
  assert.equal(lc?.requestSha256, lost);
  assert.equal(lc?.record?.requestSha256, lost);
  assert.equal(lc?.record?.sequence, cp.calls + 1n);
  // The daemon kept the answer the drop cut, and the attach returned it, checked against the record.
  assert.equal(lc?.answer?.kind, "cell");
  assert.equal(lc?.answer?.result.stdout, "python 2: y = 2");
  assert.equal(lc?.answer?.result.record.sha256, lc?.record?.sha256);
  assert.deepEqual(b.chain, { calls: cp.calls + 1n, lastRecordSha256: lc?.record?.sha256 });
  b.resolveLostCall();
  assert.equal(b.lostCall, undefined);
  const r = await b.runCell({ language: "python", code: "z = 3" });
  assert.equal(r.stdout, "python 3: z = 3");
  assert.deepEqual([r.record.sequence, r.record.previousSha256], [cp.calls + 2n, lc?.record?.sha256]);
  assert.equal((await b.close()).calls, 3n);
});

test("a recovering session refuses every call before it is sent, the lost one and any other, until it is resolved", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  const calls = await providerCalls();
  await assert.rejects(b.runCell({ language: "python", code: "y = 2" }), recovering, "the lost call repeated");
  await assert.rejects(b.runCell({ language: "python", code: "w = 0" }), recovering, "another call");
  await assert.rejects(b.runJavaScript("1"), recovering, "a snippet");
  await assert.rejects(b.runProject({ files: [], steps: ["true"] }), recovering, "a project");
  // A refusal does not resolve it, and does not stop the session.
  await assert.rejects(b.runCell({ language: "python", code: "w = 0" }), recovering, "after a refusal");
  assert.equal(await providerCalls(), calls, "a call reached the provider");
  assert.equal(b.stopped, undefined);
  assert.equal(b.lostCall?.requestSha256, lost);
  b.resolveLostCall();
  b.resolveLostCall(); // resolving a session that is not recovering does nothing
  await b.runCell({ language: "python", code: "w = 0" });
  assert.equal(await providerCalls(), calls + 1);
  await b.close();
});

test("a checkpoint saved while recovering carries the state to the next worker, which knows the digest alone", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  const cp2 = await b.checkpoint();
  assert.equal(cp2.version, 2);
  assert.equal(cp2.recoveringRequestSha256, lost);
  const text = checkpointToJSON(cp2);
  assert.equal(JSON.parse(text).recovering_request_sha256, lost);
  assert.ok(!("lost_call_sha256" in JSON.parse(text)));
  assert.deepEqual(parseCheckpoint(text), cp2);
  const c = await client().attachSession(cp2);
  assert.deepEqual(c.lostCall, { requestSha256: lost });
  const calls = await providerCalls();
  await assert.rejects(c.runCell({ language: "python", code: "w = 0" }), recovering);
  assert.equal(await providerCalls(), calls);
  assert.equal((await c.checkpoint()).recoveringRequestSha256, lost, "only resolving clears it");
  c.resolveLostCall();
  assert.equal((await c.checkpoint()).recoveringRequestSha256, "");
  await c.runCell({ language: "python", code: "w = 0" });
  await c.close();
});

test("a session opened with keepNoAnswer gives the lost call back without its answer", { skip }, async () => {
  const opens: unknown[] = [];
  const spy: typeof fetch = async (input, init) => {
    if (String(input).endsWith("/OpenSession")) opens.push(JSON.parse(String(init?.body)).keepNoAnswer);
    return fetch(input, init);
  };
  const a = await client(reattachUrl, { daemonName: DAEMON, fetch: spy }).openSession({ keepNoAnswer: true });
  assert.deepEqual(opens, [true]);
  await a.runCell({ language: "python", code: "x = 1" });
  const cp = await a.checkpoint();
  await assert.rejects(a.runCell({ language: "python", code: "y = 2" }, { traceId: "drop-answer" }), (e: unknown) => e instanceof PlimsollError && !e.notDispatched);
  const b = await client().attachSession(cp, { lostRequestSha256: a.lostRequestSha256 });
  assert.equal(b.lostCall?.record?.requestSha256, a.lostRequestSha256);
  assert.equal(b.lostCall?.answer, undefined, "the daemon kept an answer it was asked to keep none of");
  await b.close();
  const silent: typeof fetch = async () => assert.fail("an open with a keepNoAnswer that is not a boolean was sent");
  await assert.rejects(
    client(reattachUrl, { daemonName: DAEMON, fetch: silent }).openSession({ keepNoAnswer: "yes" as unknown as boolean }),
    (e: unknown) => e instanceof PlimsollError && e.code === "invalid_argument" && e.notDispatched === "request",
  );
});

test("every call states the head the call before it left; a close states the generation alone", { skip }, async () => {
  const sent: { method: string; body: any }[] = [];
  const spy: typeof fetch = async (input, init) => {
    sent.push({ method: String(input).split("/").pop()!, body: JSON.parse(String(init?.body)) });
    return fetch(input, init);
  };
  const c = client(reattachUrl, { daemonName: DAEMON, fetch: spy });
  const a = await c.openSession();
  const r1 = await a.runCell({ language: "python", code: "x = 1" });
  // Two calls at once: the second's head is the one the first left, as the queue sends them in turn.
  const [r2] = await Promise.all([a.runCell({ language: "python", code: "y = 2" }), a.runCell({ language: "python", code: "z = 3" })]);
  const b = await c.attachSession(await a.checkpoint());
  const r4 = await b.runCell({ language: "python", code: "w = 4" });
  await b.close();
  const runs = sent.filter((s) => s.method === "SessionRun").map((s) => s.body);
  assert.ok(runs.every((body) => !("generation" in body)), "a call still states the generation alone");
  assert.deepEqual(runs.map((body) => body.head), [
    { generation: "1", calls: "0", lastRecordSha256: "" },
    { generation: "1", calls: "1", lastRecordSha256: r1.record.sha256 },
    { generation: "1", calls: "2", lastRecordSha256: r2.record.sha256 },
    { generation: "2", calls: "3", lastRecordSha256: r4.record.previousSha256 },
  ]);
  const close = sent.find((s) => s.method === "CloseSession")!.body;
  assert.deepEqual(Object.keys(close).sort(), ["generation", "protocol", "sessionId"]);
  assert.equal(close.generation, "2");
});

// The integers a session's answers state in strings (the generation, the count of calls, the
// expiry) are whole decimals, as in a record: " 2" and "0x2" are not 2 (finding release-90).
test("a session answer's integer strings are whole decimals", { skip }, async () => {
  const rewriting = (method: string, edit: (body: any) => void): typeof fetch => async (input, init) => {
    const res = await fetch(input, init);
    if (!String(input).endsWith(`/${method}`)) return res;
    const body = await res.json();
    edit(body);
    const headers = new Headers(res.headers);
    headers.delete("content-length");
    return new Response(JSON.stringify(body), { status: res.status, headers });
  };
  const a = await client().openSession();
  await a.runCell({ language: "python", code: "x = 1" });
  const cp = await a.checkpoint();
  for (const [name, edit] of [
    ["a generation with a space before it", (b: any) => (b.checkpoint.generation = ` ${b.checkpoint.generation}`)],
    ["a generation in hex", (b: any) => (b.sessionInfo.generation = `0x${Number(b.sessionInfo.generation).toString(16)}`)],
    ["a count with a leading zero", (b: any) => (b.checkpoint.calls = `0${b.checkpoint.calls}`)],
    ["an expiry with a decimal point", (b: any) => (b.sessionInfo.expiresUnixMs = `${b.sessionInfo.expiresUnixMs}.0`)],
  ] as const) {
    const err = await attachError(client(reattachUrl, { daemonName: DAEMON, fetch: rewriting("AttachSession", edit) }).attachSession(cp));
    assert.ok(err instanceof PlimsollError && err.code === "data_loss", `${name}: ${String(err)}`);
    // The refused attach raised the generation all the same: carry on from the daemon's head.
    cp.generation += 1n;
  }
  const s = await client(reattachUrl, { daemonName: DAEMON, fetch: rewriting("CloseSession", (b) => (b.calls = `${b.calls} `)) }).attachSession(cp);
  await assert.rejects(s.close(), (e: unknown) => e instanceof PlimsollError && e.code === "data_loss" && /whole decimal/.test(e.message));
  await assert.rejects(
    client(reattachUrl, { daemonName: DAEMON, fetch: rewriting("OpenSession", (b) => (b.expiresUnixMs = `${b.expiresUnixMs}e0`)) }).openSession(),
    (e: unknown) => e instanceof PlimsollError && e.code === "data_loss" && /whole decimal/.test(e.message),
  );
});

// A call whose head the daemon refuses (the attach liar raises the head's count on a call
// with trace ID head-mismatch) stops the session: nothing ran, and the call after it is
// refused before it is sent (internal/clientcases, session/head-mismatch).
test("a head mismatch stops the session, and the next call is never sent", { skip }, async () => {
  const s = await client(liarUrl).openSession({ minimumIsolation: "container" });
  const sent = async () => (await getJSON(`${liarUrl}/test/session-calls?session=${s.fingerprint}`)).calls;
  let callErr: unknown;
  try {
    await s.runCell({ language: "python", code: "1" }, { traceId: "head-mismatch" });
  } catch (e) {
    callErr = e;
  }
  assert.ok(callErr instanceof HeadMismatchError && callErr.notDispatched === "request", String(callErr));
  // The daemon's head, from the refusal's detail: the session's real one, which this client holds.
  assert.deepEqual(callErr.head, { generation: 1n, calls: 0n, lastRecordSha256: "" });
  assert.match(s.stopped ?? "", /head on the daemon is not this client's/);
  assert.equal(s.lostRequestSha256, "", "a call that did not run is no lost call");
  const before = await sent();
  let nextErr: unknown;
  try {
    await s.runCell({ language: "python", code: "1" });
  } catch (e) {
    nextErr = e;
  }
  const nextSent = (await sent()) !== before;
  verdict("session/head-mismatch", "session-head", { call: saysOf(callErr), next: saysOf(nextErr), nextSent });
  assert.ok(nextErr instanceof PlimsollError && nextErr.notDispatched === "request", String(nextErr));
  assert.equal(nextSent, false, "the call after a head mismatch was sent");
  await assert.rejects(s.checkpoint(), /stopped/);
});

test("a wrong lost digest is the plain mismatch, and moves nothing", { skip }, async () => {
  const { cp, lost } = await lostCall();
  await assert.rejects(client().attachSession(cp, { lostRequestSha256: "0".repeat(64) }), (e: unknown) => e instanceof CheckpointMismatchError);
  const silent: typeof fetch = async () => assert.fail("a malformed digest was sent");
  await assert.rejects(client(reattachUrl, { daemonName: DAEMON, fetch: silent }).attachSession(cp, { lostRequestSha256: "ABC" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request");
  await (await client().attachSession(cp, { lostRequestSha256: lost })).close();
});

test("each forged explained-gap answer is refused, and nothing is closed", { skip }, async () => {
  const { a, cp, lost } = await lostCall(liarUrl, { minimumIsolation: "container" });
  const b = client(liarUrl);
  for (const name of await getJSON(`${liarUrl}/test/lost-forgeries`)) {
    const err = await attachError(b.attachSession(cp, { traceId: `forge-${name}`, lostRequestSha256: lost }));
    verdict(`attach/lost-forgeries/${name}`, "attach-live", saysOf(err));
    assert.ok(err instanceof PlimsollError && err.code === "data_loss", `${name}: ${String(err)}`);
  }
  assert.equal((await getJSON(`${liarUrl}/test/closes?session=${a.fingerprint}`)).closes, 0);
  const s = await b.attachSession(cp, { traceId: "forge-lost-none", lostRequestSha256: lost });
  // The honest answer carries the lost call's kept answer beside its record (the liar keeps it).
  assert.ok(s.lostCall?.record && s.lostCall.answer?.kind === "cell", JSON.stringify(s.lostCall?.answer?.kind));
  verdict("attach/lost-forgeries/lost-none", "attach-live", "accept");
});
