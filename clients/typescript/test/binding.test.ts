// Answers bound to their request (failure-injection review, findings 1 and 3). The
// daemons are client_test.go's bindingDaemons: replaying proxies that forward each
// request (so the daemon runs it) and answer it with the first request's answer, a
// daemon that does not echo the request ID, one that refuses a body before the
// handler, and one that serves no procedure.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PlimsollClient, PlimsollError } from "../src/index.ts";

const env = (name: string) => process.env[name];
const skip = env("PLIMSOLL_REPLAY_RUNS_URL") ? false : "run through `go test ./clients/typescript`";

async function runs(): Promise<number> {
  return Number(await (await fetch(env("PLIMSOLL_REPLAY_RUNS_URL")!)).text());
}

function plimsollError(e: unknown): PlimsollError {
  assert.ok(e instanceof PlimsollError, String(e));
  return e;
}

test("a replayed refusal is not believed", { skip }, async () => {
  const c = new PlimsollClient({ baseUrl: env("PLIMSOLL_REPLAY_REFUSAL_URL")! });
  const first = plimsollError(await c.runJavaScript("1", { minimumIsolation: "vm" }).catch((e) => e));
  assert.equal(first.notDispatched, "isolation");
  const before = await runs();
  const e = plimsollError(await c.runJavaScript("console.log(42)").catch((e) => e));
  assert.equal(await runs(), before + 1, "the daemon ran the call it was given another answer for");
  assert.equal(e.notDispatched, undefined, "a replayed refusal reads as nothing ran for a call that ran");
  assert.equal(e.answerNotBound, true);
  assert.equal(e.code, "failed_precondition");
});

test("a replayed success is data loss", { skip }, async () => {
  const c = new PlimsollClient({ baseUrl: env("PLIMSOLL_REPLAY_SUCCESS_URL")! });
  assert.equal((await c.runJavaScript("console.log(42)")).stdout, "42\n");
  const before = await runs();
  const e = plimsollError(await c.runJavaScript("console.log(42)").catch((e) => e));
  assert.equal(await runs(), before + 1);
  assert.deepEqual([e.code, e.notDispatched, e.answerNotBound], ["data_loss", undefined, true]);
});

test("a daemon without the echo is believed in nothing", { skip }, async () => {
  const c = new PlimsollClient({ baseUrl: env("PLIMSOLL_UNBOUND_URL")! });
  const d = plimsollError(await c.describe().catch((e) => e));
  assert.deepEqual([d.code, d.answerNotBound], ["data_loss", true]);
  const e = plimsollError(await c.runJavaScript("1", { minimumIsolation: "vm" }).catch((e) => e));
  assert.deepEqual([e.code, e.notDispatched, e.answerNotBound], ["failed_precondition", undefined, true]);
});

test("a body refused before the handler is marked", { skip }, async () => {
  const c = new PlimsollClient({ baseUrl: env("PLIMSOLL_EARLY_REFUSAL_URL")! });
  const e = plimsollError(await c.runJavaScript(`console.log('${"x".repeat(1024)}')`).catch((e) => e));
  assert.deepEqual([e.code, e.notDispatched, e.answerNotBound], ["resource_exhausted", "request", false]);
});

test("a procedure the daemon lacks is marked unsupported", { skip }, async () => {
  const c = new PlimsollClient({ baseUrl: env("PLIMSOLL_NO_PROCEDURE_URL")! });
  const e = plimsollError(await c.describe().catch((e) => e));
  assert.deepEqual([e.code, e.notDispatched], ["unimplemented", "unsupported"]);
});

test("every request carries a fresh ID", { skip }, async () => {
  const ids: string[] = [];
  const c = new PlimsollClient({
    baseUrl: env("PLIMSOLL_WASM_URL")!,
    fetch: (input, init) => {
      ids.push(new Headers(init?.headers).get("Plimsoll-Request-Id") ?? "");
      return fetch(input, init);
    },
  });
  for (let i = 0; i < 3; i++) await c.describe();
  assert.equal(new Set(ids).size, 3);
  for (const id of ids) assert.match(id, /^[0-9a-f]{32}$/);
});
