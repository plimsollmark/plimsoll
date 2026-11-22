// The record cases of internal/clientcases/testdata/records.json, which the Go and Python
// clients run too, on the two paths this client has for them: the record an unanswered
// session call's error carries (checkUnanswered, which the session calls), and the lost
// call's record an attach answer returns (lostRecord, which the attach calls, refusing
// every problem it states as data_loss). Each verdict is asserted here and written down for
// the judge of the shared cases (test/cases.ts).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { parseCheckpoint } from "../src/checkpoint.ts";
import { lostRecord } from "../src/client.ts";
import { checkUnanswered } from "../src/record.ts";
import type { WireRecord } from "../src/wire.ts";
import { saysOfProblem, verdict } from "./cases.ts";

type RecordCase = {
  id: string;
  paths: string[];
  input: {
    requestSha256: string;
    floor: string;
    record: WireRecord;
    chain: { session: string; calls: string; last: string };
    checkpoint: string;
    lost: string;
  };
  expect: Record<string, string>;
};

const cases: RecordCase[] = JSON.parse(readFileSync(new URL("../../../internal/clientcases/testdata/records.json", import.meta.url), "utf8")).cases;

test("every shared record case on every path this client has", () => {
  assert.ok(cases.length > 0, "no record cases");
  for (const c of cases) {
    const inp = c.input;
    for (const path of c.paths) {
      let got: string;
      if (path === "session-unanswered") {
        const checked = checkUnanswered(inp.requestSha256, inp.floor, undefined, inp.record, inp.chain.session, BigInt(inp.chain.calls), inp.chain.last);
        got = saysOfProblem("problem" in checked ? checked.problem : undefined);
      } else if (path === "attach-lost") {
        const checked = lostRecord(parseCheckpoint(inp.checkpoint), inp.lost, inp.record);
        got = saysOfProblem("problem" in checked ? checked.problem : undefined);
      } else {
        continue; // a path this client does not have (stored is Go's)
      }
      verdict(c.id, path, got);
      // This client's verdicts state the outcome alone (test/cases.ts).
      assert.equal(got, c.expect[path]!.split("/")[0], `${c.id} on ${path}`);
    }
  }
});
