// The daemon answers in protocol/testdata/answers.json, which the Go and Python clients
// read too: this client must read each the way the file says (review D5, 2026-10-23: the
// accept and reject logic was ported three times, with vectors for the digests alone).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { errorFromWire } from "../src/errors.ts";
import { wireBytes, WireShapeError, type WireError } from "../src/wire.ts";
import { verdict } from "./cases.ts";

type Answer = {
  name: string;
  status: number;
  body: string;
  echo: "match" | "missing" | "other";
  mark?: string;
  expect: { code: string; notDispatched: string; sessionEnded: string; answerNotBound: boolean; capacityLimit: string };
};

const answers: Answer[] = JSON.parse(readFileSync(new URL("../../../protocol/testdata/answers.json", import.meta.url), "utf8")).answers;

test("every shared answer reads as the file says", () => {
  assert.ok(answers.length >= 10, `only ${answers.length} answers`);
  for (const a of answers) {
    let body: WireError | undefined;
    try {
      body = JSON.parse(a.body) as WireError;
    } catch {
      body = undefined; // not a Connect error body: a proxy's page
    }
    const e = errorFromWire(a.status, body, { bound: a.echo === "match", mark: a.mark ?? null });
    const got = {
      code: e.code,
      notDispatched: e.notDispatched ?? "",
      sessionEnded: e.sessionEnded?.reason ?? "",
      answerNotBound: e.answerNotBound,
      capacityLimit: e.capacityLimit ?? "",
    };
    verdict(`answers/${a.name}`, "error-answer", got);
    assert.deepEqual(got, a.expect, a.name);
  }
});

test("an error detail whose value is not base64 text states nothing and allocates nothing", () => {
  const t0 = performance.now();
  const e = errorFromWire(400, { code: "invalid_argument", message: "m", details: [{ type: "plimsoll.v1.NotDispatched", value: { length: 2_000_000_000 } }] }, { bound: true, mark: null });
  assert.equal(e.notDispatched, undefined);
  assert.ok(performance.now() - t0 < 1000);
});

// Finding hunt-quality-93: base64 is read strictly, as the Python client reads it, so a
// stray character makes a detail unreadable instead of being skipped.
test("a bytes field is base64 throughout or nothing", () => {
  for (const [text, bytes] of [["CAY", [8, 6]], ["CAY=", [8, 6]], ["", []], ["-_8", [251, 255]], ["+/8=", [251, 255]]] as const) {
    assert.deepEqual([...wireBytes(text)], bytes, text);
  }
  for (const text of ["CAY!", "CA Y", "CAY=x", "C", "CAYxC"]) {
    assert.throws(() => wireBytes(text), WireShapeError, text);
  }
});

// Finding hunt-security-35: the padding was stripped with /=+$/, which is tried again from
// every "=" of a run that does not reach the end. Measured on 2026-11-20 (node 26): 80,000
// "=" and a letter took 1.1 s, four times 40,000's, so a million would take about three
// minutes on one synchronous call, and the 32 MiB an answer may hold about two days. Counted
// from the end, a million take a few milliseconds; the bound of 500 ms is for a loaded
// machine, and still a thousandth of the old cost.
test("a long run of '=' in a bytes field is refused in one pass", () => {
  const text = "=".repeat(1_000_000) + "A";
  for (const read of [
    () => assert.throws(() => wireBytes(text), WireShapeError),
    () => assert.equal(errorFromWire(400, { code: "invalid_argument", message: "m", details: [{ type: "plimsoll.v1.NotDispatched", value: text }] }, { bound: true, mark: null }).notDispatched, undefined),
  ]) {
    const t0 = performance.now();
    read();
    const ms = performance.now() - t0;
    assert.ok(ms < 500, `took ${ms.toFixed(0)} ms`);
  }
  for (const [text, bytes] of [["CA==", [8]], ["CAY=", [8, 6]], ["CAY====", [8, 6]], ["=", []]] as const) {
    assert.deepEqual([...wireBytes(text)], bytes, text);
  }
});

// Finding release-88: the Go client panicked on a null in the details list. Every client
// reads such an answer as one it cannot read: the HTTP status's code, no mark (the
// header's included), no session end, no unanswered call's record.
test("an answer with a null detail is believed in nothing", () => {
  const nulls = answers.filter((a) => a.name.includes("null"));
  assert.ok(nulls.length >= 4, `only ${nulls.length} answers with a null`);
  for (const a of nulls) {
    const e = errorFromWire(a.status, JSON.parse(a.body) as WireError, { bound: true, mark: a.mark ?? null });
    assert.equal(e.notDispatched, undefined, a.name);
    assert.equal(e.sessionEnded, undefined, a.name);
    assert.equal(e.unanswered, undefined, a.name);
  }
  for (const first of [5, [], "x"]) {
    const body = { code: "internal", details: [first, { type: "plimsoll.v1.NotDispatched", value: "CAE" }] } as unknown as WireError;
    const e = errorFromWire(503, body, { bound: true, mark: "capacity" });
    assert.deepEqual([e.code, e.notDispatched], ["unavailable", undefined], JSON.stringify(first));
  }
});
