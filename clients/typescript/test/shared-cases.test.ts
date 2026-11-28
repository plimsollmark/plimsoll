// The record cases of internal/clientcases/testdata/records.json, which the Go and Python
// clients run too, on the paths this client has for them: the record an unanswered
// session call's error carries (checkUnanswered, which the session calls), the lost call's
// record an attach answer returns (lostRecord, which the attach calls, refusing every
// problem it states as data_loss), an answered call's response against the request sent
// (checkRecord) and the answer an attach returns for a lost call against that call's record
// (checkLostAnswer). The file-call cases of files-calls.json run through Session.runFiles
// against the files daemon, each case a session of its own. Each verdict is asserted here
// and written down for the judge of the shared cases (test/cases.ts).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { parseCheckpoint } from "../src/checkpoint.ts";
import { lostRecord, PlimsollClient, type FilesResult } from "../src/client.ts";
import { filesOutcome, filesPayload, type FilesOperation } from "../src/files.ts";
import { checkLostAnswer, checkRecord, checkUnanswered, filesOp, recordFromWire, requestDigest } from "../src/record.ts";
import { PlimsollError } from "../src/errors.ts";
import { WireShapeError, type WireFilesRun, type WireRecord, type WireRunResponse } from "../src/wire.ts";
import { saysOf, saysOfProblem, verdict } from "./cases.ts";

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
    // An answered call's case: the request sent and the response, its record inside.
    request: { protocol: number; minimumIsolation?: string; timeoutMs?: number; files: WireFilesRun };
    response: WireRunResponse;
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
      } else if (path === "answer") {
        // The answered call's response against the request sent, as the session's call
        // checks it (checkRecord, with the request's operation).
        const req = inp.request;
        const digest = requestDigest({ protocol: req.protocol, minimumIsolation: req.minimumIsolation ?? "", timeoutMs: req.timeoutMs ?? 0, softwareRule: undefined, payload: { kind: "files", files: req.files } });
        const checked = checkRecord(digest, "files", undefined, inp.response, filesOp(req.files));
        got = saysOfProblem("problem" in checked ? checked.problem : undefined);
      } else if (path === "lost-answer") {
        // The same response as an attach's lost answer, against its own record.
        const checked = checkLostAnswer(inp.response, recordFromWire(inp.response.record!));
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

// session-files-20: what a client returns of a file call's answer is what its record's digest
// covered, decoded once. An integer in the other form proto3 JSON allows (mode "420", a size as a
// number) reaches the caller as the number the digest covered, never as the string; each answer
// whose flag is not a boolean or whose number is not an integer is refused, as the record check
// refuses it (the cases above), before any value of it reaches a caller.
test("a file call's answer hands its caller the values its digest covers", () => {
  const files = (id: string) => {
    const c = cases.find((x) => x.id === id);
    assert.ok(c, `no case ${id}`);
    return c.input.response.files!;
  };
  assert.deepEqual(filesOutcome(files("files-answer/accepted-integers-as-strings")).answer, { op: "stat", type: "file", size: 1234n, mode: 420 });
  assert.deepEqual(filesOutcome(files("files-answer/accepted")).answer, { op: "stat", type: "file", size: 1234n, mode: 420 });
  for (const id of ["files-answer/list-more-a-string", "files-answer/read-many-more-a-number", "files-answer/mode-a-fraction", "files-answer/size-a-boolean"]) {
    assert.throws(() => filesOutcome(files(id)), WireShapeError, id);
  }
  const page = filesOutcome({ outcome: "PROJECT_OUTCOME_COMPLETED", list: { entries: [], more: true } }).answer;
  assert.ok(page?.op === "list" && page.more === true);
});

// A scope or a write mode that is an inherited key of the client's own tables names none: refused
// before anything is sent, as any other unknown word is, never sent as the table's function.
test("a file call naming an inherited key as its scope or mode is refused before it is sent", () => {
  for (const op of [
    { op: "stat", path: "a", scope: "constructor" },
    { op: "stat", path: "a", scope: "__proto__" },
    { op: "write", path: "a", content: "x", mode: "constructor" },
    { op: "write", path: "a", content: "x", mode: "hasOwnProperty" },
  ]) {
    assert.throws(() => filesPayload(op as unknown as FilesOperation), (e: unknown) => e instanceof PlimsollError && e.notDispatched === "request", JSON.stringify(op));
  }
});

type FilesCase = { id: string; input: { calls: { call: Record<string, any>; forge?: string; rule?: boolean }[] }; expect: { "files-call": unknown } };

const filesCases: FilesCase[] = JSON.parse(readFileSync(new URL("../../../internal/clientcases/testdata/files-calls.json", import.meta.url), "utf8")).cases;
const filesUrl = process.env.PLIMSOLL_FILES_URL;

// A case's call (bytes in hex) as this client's operation.
function operation(c: Record<string, any>): FilesOperation {
  const x = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
  switch (c.op) {
    case "stat":
      return { op: "stat", path: x(c.path) };
    case "read":
      return { op: "read", path: x(c.path), offset: c.offset, maxBytes: c.max_bytes };
    case "write":
      return { op: "write", path: x(c.path), content: x(c.content), mode: c.mode, makeParents: c.make_parents };
    case "list":
      return { op: "list", path: x(c.path), recursive: c.recursive, match: x(c.match), after: x(c.after), budgetBytes: c.budget_bytes };
    case "read_many":
      return { op: "read_many", paths: (c.paths as string[]).map(x), maxBytesEach: c.max_bytes_each, budgetBytes: c.budget_bytes };
    case "make_dir":
      return { op: "make_dir", path: x(c.path), parents: c.parents };
    case "remove":
      return { op: "remove", path: x(c.path), dir: c.dir };
    case "rename":
      return { op: "rename", fromPath: x(c.from), toPath: x(c.to), replace: c.replace };
  }
  throw new Error(`a case names the operation ${c.op}`);
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// A file call's result as the shared cases state it: words, numbers, bytes in hex.
function answerSays(r: FilesResult): unknown {
  const a: Record<string, unknown> = { outcome: r.outcome, error: r.error, errno: r.errno, op: r.answer?.op ?? "" };
  const ans = r.answer;
  if (ans?.op === "stat") Object.assign(a, { type: ans.type, size: Number(ans.size), mode: ans.mode });
  else if (ans?.op === "read") Object.assign(a, { content: hex(ans.content), size_at_open: Number(ans.sizeAtOpen) });
  else if (ans?.op === "write") Object.assign(a, { written: Number(ans.written) });
  else if (ans?.op === "list") Object.assign(a, { entries: ans.entries.map((e) => ({ path: hex(e.path), type: e.type, size: Number(e.size) })), more: ans.more });
  else if (ans?.op === "read_many") {
    Object.assign(a, { items: ans.items.map((i) => ({ error: i.error, errno: i.errno, content: hex(i.content), size_at_open: Number(i.sizeAtOpen) })), more: ans.more });
  }
  return { answer: a };
}

test("every shared file-call case, through runFiles", { skip: !filesUrl ? "run through `go test ./clients/typescript`" : false }, async () => {
  assert.ok(filesCases.length > 0, "no file-call cases");
  for (const c of filesCases) {
    const s = await new PlimsollClient({ baseUrl: filesUrl! }).openSession();
    assert.deepEqual(s.fileScopes, ["work"]);
    assert.equal(s.workDir, "/work");
    const calls: unknown[] = [];
    for (const call of c.input.calls) {
      try {
        const r = await s.runFiles(operation(call.call), call.forge ? { traceId: `forge-files-${call.forge}` } : {});
        assert.ok(r.record);
        calls.push(answerSays(r));
      } catch (e) {
        // This client's errors name no kind of rule: its verdicts state the outcome alone.
        calls.push({ refused: saysOf(e) });
      }
    }
    const got = { calls };
    verdict(c.id, "files-call", got);
    const want = JSON.parse(JSON.stringify(c.expect["files-call"]), (k, v) => (k === "check" ? undefined : v));
    assert.deepEqual(got, want, c.id);
    await s.close().catch(() => undefined);
  }
});

// The thin methods over runFiles, and a string path encoded as UTF-8 beside the bytes of a
// name that is not UTF-8; a string with a lone surrogate, and an operation this client does
// not know, are refused before anything is sent.
test("the file methods over runFiles", { skip: !filesUrl ? "run through `go test ./clients/typescript`" : false }, async () => {
  const s = await new PlimsollClient({ baseUrl: filesUrl! }).openSession();
  const name = new Uint8Array([0x64, 0xff, 0x0a]); // "d", 0xff, a newline
  const file = new Uint8Array([...name, 0x2f, 0x66]); // name + "/f"
  assert.equal((await s.makeDir(name)).error, "none");
  // "dÿ" as a string is UTF-8 c3 bf, not the folder's byte ff: no folder of that name.
  assert.equal((await s.writeFile("dÿ\n/f", "x", { mode: "create_only" })).error, "not_found");
  assert.deepEqual((await s.writeFile(file, "hé")).answer, { op: "write", written: 3n });
  const l = await s.list(name);
  assert.ok(l.answer?.op === "list");
  assert.deepEqual(l.answer.entries.map((e) => [hex(e.path), e.pathText, e.type, e.size]), [["66", "f", "file", 3n]]);
  const top = await s.list();
  assert.ok(top.answer?.op === "list");
  assert.deepEqual(top.answer.entries.map((e) => [hex(e.path), e.pathText]), [["64ff0a", "d�\n"]]);
  const r = await s.readFile(file, { offset: 1, maxBytes: 2 });
  assert.ok(r.answer?.op === "read");
  assert.equal(hex(r.answer.content), "c3a9");
  assert.equal(r.answer.sizeAtOpen, 3n);
  assert.deepEqual((await s.stat(file)).answer, { op: "stat", type: "file", size: 3n, mode: 420 });
  const m = await s.readMany([file, "nothing"], { maxBytesEach: 8, budgetBytes: 8192 });
  assert.ok(m.answer?.op === "read_many");
  assert.deepEqual(m.answer.items.map((i) => [i.error, i.errno]), [["none", ""], ["not_found", "ENOENT"]]);
  assert.deepEqual((await s.rename(file, "g")).answer, { op: "rename" });
  assert.deepEqual((await s.removeFile("g")).answer, { op: "remove" });
  assert.deepEqual((await s.removeFile(name, { dir: true })).answer, { op: "remove" });
  const calls = s.chain.calls;
  await assert.rejects(s.stat("a\ud800b"), (e: any) => e.notDispatched === "request");
  await assert.rejects(s.runFiles({ op: "copy", path: "a" } as any), (e: any) => e.notDispatched === "request");
  await assert.rejects(s.readFile("a", { maxBytes: -1 }), (e: any) => e.notDispatched === "request");
  assert.equal(s.chain.calls, calls, "a refused call was sent");
  await s.close();
});
