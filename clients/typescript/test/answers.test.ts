// The daemon answers in protocol/testdata/answers.json, which the Go and Python clients
// read too: this client must read each the way the file says (review D5, 2026-10-23: the
// accept and reject logic was ported three times, with vectors for the digests alone).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { errorFromWire } from "../src/errors.ts";
import type { WireError } from "../src/wire.ts";

type Answer = {
  name: string;
  status: number;
  body: string;
  echo: "match" | "missing" | "other";
  mark?: string;
  expect: { code: string; notDispatched: string; sessionEnded: string; answerNotBound: boolean };
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
    const got = { code: e.code, notDispatched: e.notDispatched ?? "", sessionEnded: e.sessionEnded?.reason ?? "", answerNotBound: e.answerNotBound };
    assert.deepEqual(got, a.expect, a.name);
  }
});
