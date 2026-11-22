// Session reattach in the TypeScript client (step R4 of the sessions builds plan): the
// checkpoint and attach, against the shared daemons and vectors of internal/clientsuite
// (reattach.go), which the Go and Python clients are held to too. The reattach daemon is
// the in-memory session provider behind a token: a session call with trace ID drop-answer
// runs and its answer is cut, GET /test/calls counts the calls the provider ran and GET
// /test/checkpoint-vectors serves the vectors. The attach liar answers an attach with trace
// ID forge-<name> with the honest answer with one thing forged, and counts each session's
// closes.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CallAlreadySentError,
  CheckpointMismatchError,
  checkpointToJSON,
  parseCheckpoint,
  PlimsollClient,
  PlimsollError,
  StaleOwnerError,
  type SessionCheckpoint,
} from "../src/index.ts";
import { errorFromWire } from "../src/errors.ts";
import { CALL_ALREADY_SENT_TEXT, CHECKPOINT_MISMATCH_TEXT, STALE_OWNER_TEXT } from "../src/tables.gen.ts";
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

// The explained gap (option A of the PydanticAI design's section 3.3): naming the call that
// ran with its answer lost takes the session over across the gap, once, with its record;
// the first call after may not repeat it.

async function lostCall(url = reattachUrl!, minimumIsolation?: "container") {
  const a = await client(url).openSession({ minimumIsolation });
  await a.runCell({ language: "python", code: "x = 1" });
  const cp = await a.checkpoint();
  await assert.rejects(a.runCell({ language: "python", code: "y = 2" }, { traceId: "drop-answer" }), (e: unknown) => e instanceof PlimsollError && !e.notDispatched);
  assert.match(a.lostRequestSha256, /^[0-9a-f]{64}$/);
  return { a, cp, lost: a.lostRequestSha256 };
}

test("naming the lost call carries the chain on across the gap", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  assert.equal(b.lostCall?.requestSha256, lost);
  assert.equal(b.lostCall?.sequence, cp.calls + 1n);
  const r = await b.runCell({ language: "python", code: "z = 3" });
  assert.equal(r.stdout, "python 3: z = 3");
  assert.deepEqual([r.record.sequence, r.record.previousSha256], [cp.calls + 2n, b.lostCall?.sha256]);
  assert.equal((await b.close()).calls, 3n);
});

test("the first call may not repeat the lost call; the note is then spent", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  const calls = await providerCalls();
  // What the client knows, in the Go client's words (client.CallAlreadySentText, copied into
  // tables.gen.ts by internal/wiretables): the call was sent once. The lost call's record
  // says whether it finished.
  await assert.rejects(b.runCell({ language: "python", code: "y = 2" }), (e: unknown) =>
    e instanceof CallAlreadySentError && e.notDispatched === "request" &&
    e.message === `plimsoll: ${CALL_ALREADY_SENT_TEXT}; nothing was sent` && !e.message.includes("ran once"));
  assert.equal(await providerCalls(), calls, "the repeat ran");
  assert.equal(b.stopped, undefined);
  await b.runCell({ language: "python", code: "y = 2" });
  await b.close();
});

test("a checkpoint carries the note to the next worker until the first call", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  const cp2 = await b.checkpoint();
  assert.equal(cp2.lostCallSha256, lost);
  assert.deepEqual(parseCheckpoint(checkpointToJSON(cp2)), cp2);
  const c = await client().attachSession(cp2);
  await assert.rejects(c.runCell({ language: "python", code: "y = 2" }), (e: unknown) => e instanceof CallAlreadySentError);
  assert.equal((await c.checkpoint()).lostCallSha256, "");
  await c.close();
});

test("a first call the daemon refuses leaves the note", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  const calls = await providerCalls();
  // A floor above the session's tier: refused with the not-dispatched mark, so nothing ran.
  await assert.rejects(b.runCell({ language: "python", code: "w = 0" }, { minimumIsolation: "vm" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "isolation");
  assert.equal((await b.checkpoint()).lostCallSha256, lost);
  await assert.rejects(b.runCell({ language: "python", code: "y = 2" }), (e: unknown) => e instanceof CallAlreadySentError);
  assert.equal(await providerCalls(), calls, "a call ran");
  await b.close();
});

test("a different first call runs and spends the note", { skip }, async () => {
  const { cp, lost } = await lostCall();
  const b = await client().attachSession(cp, { lostRequestSha256: lost });
  await b.runCell({ language: "python", code: "w = 0" });
  await b.runCell({ language: "python", code: "y = 2" });
  await b.close();
});

test("a wrong lost digest is the plain mismatch, and moves nothing", { skip }, async () => {
  const { cp, lost } = await lostCall();
  await assert.rejects(client().attachSession(cp, { lostRequestSha256: "0".repeat(64) }), (e: unknown) => e instanceof CheckpointMismatchError);
  const silent: typeof fetch = async () => assert.fail("a malformed digest was sent");
  await assert.rejects(client(reattachUrl, { daemonName: DAEMON, fetch: silent }).attachSession(cp, { lostRequestSha256: "ABC" }), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request");
  await (await client().attachSession(cp, { lostRequestSha256: lost })).close();
});

test("each forged explained-gap answer is refused, and nothing is closed", { skip }, async () => {
  const { a, cp, lost } = await lostCall(liarUrl, "container");
  const b = client(liarUrl);
  for (const name of await getJSON(`${liarUrl}/test/lost-forgeries`)) {
    const err = await attachError(b.attachSession(cp, { traceId: `forge-${name}`, lostRequestSha256: lost }));
    verdict(`attach/lost-forgeries/${name}`, "attach-live", saysOf(err));
    assert.ok(err instanceof PlimsollError && err.code === "data_loss", `${name}: ${String(err)}`);
  }
  assert.equal((await getJSON(`${liarUrl}/test/closes?session=${a.fingerprint}`)).closes, 0);
  const s = await b.attachSession(cp, { traceId: "forge-lost-none", lostRequestSha256: lost });
  assert.ok(s.lostCall);
  verdict("attach/lost-forgeries/lost-none", "attach-live", "accept");
});
