// Verdicts on the shared test cases every client must pass (internal/clientcases).
//
// A test that runs a shared case asserts the client's answer, as it always has, and also
// writes it down with verdict(): one JSON line per case and path in the file
// PLIMSOLL_CASE_VERDICTS names. Under `go test ./clients/typescript` that file is read
// after the suite by the judge, which fails a case this suite skipped or answered
// otherwise than the case's file states. Unset, as when the suite runs alone, nothing is
// written. This client's errors name no kind of rule (the rule is only in the message),
// so its verdicts state the outcome alone: "accept", "may_have_run" or
// "not_dispatched:<reason>".

import { appendFileSync } from "node:fs";

import { PlimsollError } from "../src/errors.ts";

const file = process.env.PLIMSOLL_CASE_VERDICTS ?? "";

/** Writes down what this client said about one case on one path. */
export function verdict(id: string, path: string, says: unknown): void {
  if (file) appendFileSync(file, JSON.stringify({ id, path, says }) + "\n");
}

/** The verdict on an error: "accept" for none, else the outcome a caller acts on. */
export function saysOf(e: unknown): string {
  if (e === undefined) return "accept";
  if (e instanceof PlimsollError && e.notDispatched) return `not_dispatched:${e.notDispatched}`;
  return "may_have_run";
}

/** The verdict on a check that returns the reason it fails: a problem is an error the client raises with no mark. */
export function saysOfProblem(problem: string | undefined): string {
  return problem === undefined ? "accept" : "may_have_run";
}
