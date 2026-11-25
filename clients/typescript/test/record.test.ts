// The golden vectors of record/testdata/golden.json, computed by this client's own
// encoder: the file the Go record package and the Python client test against too, so
// the TypeScript digests must equal theirs byte for byte. Module vectors are skipped:
// this client sends no module runs.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import {
  checkLostAnswer, checkRecord, RECORD_KINDS, recordDigest, recordFromWire, requestDigest, resultDigest, sessionFingerprint, softwareRuleId,
  statesOnlyProblem, validDaemonVersion, validQualification, type DigestPayload,
} from "../src/record.ts";
import { INT64, UINT32, UINT64, wholeInt } from "../src/wire.ts";
import { meets } from "../src/client.ts";
import { RECORD_FIELDS, RETIRED_END_BEFORE_START_TEXT } from "../src/tables.gen.ts";
import { PlimsollError } from "../src/errors.ts";
import type { WireRecord, WireRunResponse, WireSoftwareRule } from "../src/wire.ts";
import { saysOf, saysOfProblem, verdict } from "./cases.ts";

type Files = { path: string; content: string }[];
type WireRequest = {
  protocol: number;
  minimumIsolation?: string;
  timeoutMs?: number;
  softwareRule?: WireSoftwareRule;
  javascript?: { code: string; grantProfile?: string };
  project?: { files?: Files; steps?: string[]; artifacts?: string[]; grantProfile?: string };
  cell?: { language: string; code: string; files?: Files };
};
type Golden = {
  requests: { name: string; request: WireRequest; sha256: string }[];
  results: { name: string; response: WireRunResponse; sha256: string }[];
  records: { name: string; record: WireRecord; sha256: string }[];
  sessionFingerprints: { name: string; sessionId: string; sha256: string }[];
  refused: { name: string; record: WireRecord; sha256: string; why: string }[];
  malformed: { name: string; record: WireRecord; why: string }[];
  qualifications: { name: string; text: string; valid: boolean }[];
  meets: { tier: string; floor: string; meets: boolean }[];
};

const golden: Golden = JSON.parse(readFileSync(new URL("../../../record/testdata/golden.json", import.meta.url), "utf8"));

// The digest's view of a request in its wire form; undefined for a module run.
function payload(r: WireRequest): DigestPayload | undefined {
  if (r.javascript) return { kind: "javascript", code: r.javascript.code, grantProfile: r.javascript.grantProfile ?? "" };
  if (r.cell) return { kind: "cell", language: r.cell.language, code: r.cell.code, files: r.cell.files ?? [] };
  if (r.project) {
    const p = r.project;
    return { kind: "project", grantProfile: p.grantProfile ?? "", files: p.files ?? [], steps: p.steps ?? [], artifacts: p.artifacts ?? [] };
  }
  return undefined;
}

test("request digests", () => {
  let n = 0;
  for (const v of golden.requests) {
    const p = payload(v.request);
    if (!p) continue;
    const r = v.request;
    const got = requestDigest({ protocol: r.protocol, minimumIsolation: r.minimumIsolation ?? "", timeoutMs: r.timeoutMs ?? 0, softwareRule: r.softwareRule, payload: p });
    verdict(`golden/requests/${v.name}`, "digest", got);
    assert.equal(got, v.sha256, v.name);
    n++;
  }
  assert.ok(n >= 5, `only ${n} request vectors`);
});

test("result digests", () => {
  let n = 0;
  for (const v of golden.results) {
    if (v.response.module !== undefined) continue;
    const got = resultDigest(v.response);
    verdict(`golden/results/${v.name}`, "digest", got);
    assert.equal(got, v.sha256, v.name);
    n++;
  }
  assert.ok(n >= 3, `only ${n} result vectors`);
});

test("every release's own vectors still hold", () => {
  // record/testdata/published, never edited: the versions a release wrote keep their
  // digests in this client too, and every record a release wrote passes the record check,
  // as Go's record.CheckStored passes it (record/published_test.go): a check added to the
  // reader never refuses evidence an earlier release signed.
  const dir = new URL("../../../record/testdata/published/", import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith("-golden.json"));
  assert.ok(files.length >= 1, "no published vectors");
  for (const f of files) {
    const g: Golden = JSON.parse(readFileSync(new URL(f, dir), "utf8"));
    const prefix = `published/${f.replace(/-golden\.json$/, "")}/`;
    for (const v of g.requests) {
      const p = payload(v.request);
      if (!p) continue;
      const r = v.request;
      const got = requestDigest({ protocol: r.protocol, minimumIsolation: r.minimumIsolation ?? "", timeoutMs: r.timeoutMs ?? 0, softwareRule: r.softwareRule, payload: p });
      verdict(`${prefix}requests/${v.name}`, "digest", got);
      assert.equal(got, v.sha256, `${f}: ${v.name}`);
    }
    for (const v of g.results) {
      if (v.response.module !== undefined) continue;
      const got = resultDigest(v.response);
      verdict(`${prefix}results/${v.name}`, "digest", got);
      assert.equal(got, v.sha256, `${f}: ${v.name}`);
    }
    for (const v of g.records) {
      const r = recordFromWire(v.record);
      verdict(`${prefix}records/${v.name}`, "digest", recordDigest(r));
      assert.equal(recordDigest(r), v.sha256, `${f}: ${v.name}`);
      const problem = statesOnlyProblem({ ...r, sha256: v.sha256 });
      verdict(`${prefix}records/${v.name}/check`, "states-only", saysOfProblem(problem));
      assert.equal(problem, undefined, `${f}: ${v.name}`);
    }
    for (const v of g.sessionFingerprints) {
      const got = sessionFingerprint(v.sessionId);
      verdict(`${prefix}sessionFingerprints/${v.name}`, "digest", got);
      assert.equal(got, v.sha256, `${f}: ${v.name}`);
    }
  }
  for (const v of golden.records) {
    const problem = statesOnlyProblem(recordFromWire(v.record));
    verdict(`golden/records/${v.name}/check`, "states-only", saysOfProblem(problem));
    assert.equal(problem, undefined, `golden.json: ${v.name}`);
  }
});

test("record digest and session fingerprint", () => {
  for (const v of golden.records) {
    const got = recordDigest(recordFromWire(v.record));
    verdict(`golden/records/${v.name}`, "digest", got);
    assert.equal(got, v.sha256, v.name);
  }
  for (const v of golden.sessionFingerprints) {
    const got = sessionFingerprint(v.sessionId);
    verdict(`golden/sessionFingerprints/${v.name}`, "digest", got);
    assert.equal(got, v.sha256, v.name);
  }
  assert.ok(golden.records.length >= 1 && golden.sessionFingerprints.length >= 1);
});

// Written by record_v5.py from the docs; the Go record package, the Python client and
// examples/sbom/check.js check the same rows.
test("qualification and tier vectors", () => {
  assert.ok(golden.qualifications.length >= 31);
  for (const v of golden.qualifications) {
    const got = validQualification(v.text);
    verdict(`golden/qualifications/${v.name}`, "qualification", got ? "valid" : "invalid");
    assert.equal(got, v.valid, v.name);
  }
  assert.equal(golden.meets.length, 49);
  for (const v of golden.meets) {
    const got = meets(v.tier, v.floor as never);
    verdict(`golden/meets/${v.tier}|${v.floor}`, "meets", got ? "meets" : "below");
    assert.equal(got, v.meets, `${JSON.stringify(v.tier)} meets ${JSON.stringify(v.floor)}`);
  }
});

// Every version this client digests is held by a vector a release made: golden.json (its
// version 1 record is one v0.11.1 signed) or a release's frozen file.
test("every record version has a vector", () => {
  const held = new Set(golden.records.map((v) => Number(v.record.version)));
  const dir = new URL("../../../record/testdata/published/", import.meta.url);
  for (const f of readdirSync(dir).filter((f) => f.endsWith("-golden.json"))) {
    for (const v of (JSON.parse(readFileSync(new URL(f, dir), "utf8")) as Golden).records) held.add(Number(v.record.version));
  }
  assert.deepEqual([...held].sort(), Object.keys(RECORD_FIELDS).map(Number).sort());
});

const approved = {
  mode: "approved",
  identities: ["oci-manifest:linux/amd64@sha256:" + "a".repeat(64), "oci-manifest:linux/amd64@sha256:" + "b".repeat(64)],
};

test("software rule ids", () => {
  assert.equal(softwareRuleId(undefined), "");
  assert.equal(softwareRuleId({ mode: "approved", identities: ["x"] }), "exact:x");
  // Order-independent.
  assert.equal(softwareRuleId(approved), softwareRuleId({ mode: "approved", identities: [...approved.identities].reverse() }));
});

// An answered call's record that also states an unanswered code is refused (v0.15.0
// review, H1), and so is one of an earlier version or whose instance is not the response's.
test("an answered record stating an unanswered code, an old version or another instance is refused", () => {
  const resp: WireRunResponse = { sandbox: "docker", isolation: "container", instance: "k8s-pod-uid:7f3e9c2a", javascript: { stdout: "" } };
  const record: WireRecord = {
    version: 5, requestSha256: "r", resultSha256: resultDigest(resp), provider: "docker", isolation: "container",
    instance: "k8s-pod-uid:7f3e9c2a", startedUnixMs: 1, endedUnixMs: 2,
  };
  record.recordSha256 = recordDigest(recordFromWire(record));
  resp.record = record;
  assert.ok("record" in checkRecord("r", "javascript", undefined, resp));
  const refused = (r: WireRecord, why: string) => {
    resp.record = { ...r, recordSha256: recordDigest(recordFromWire(r)) };
    const got = checkRecord("r", "javascript", undefined, resp);
    assert.ok("problem" in got && got.problem.includes(why), JSON.stringify(got));
  };
  refused({ ...record, unanswered: "unknown" }, "unanswered");
  for (const version of [1, 2, 3, 4, 6]) refused({ ...record, version }, "version");
  refused({ ...record, instance: "k8s-pod-uid:other" }, "instance");
  refused({ ...record, instance: "/var/run/pod" }, "instance");
  assert.equal(resultDigest({ ...resp, instance: "k8s-pod-uid:other" }), resultDigest(resp), "the instance moved the result digest");
});


// The record check itself refuses a result of another kind than the request's, or none,
// and a record that ends before it starts, as Go's record.check does since 2026-10-26.
test("a result of another kind than the request's, or none, or a record ending before it starts, is refused", () => {
  const resp: WireRunResponse = { sandbox: "docker", isolation: "container", javascript: { stdout: "" } };
  const record: WireRecord = {
    version: 5, requestSha256: "r", resultSha256: resultDigest(resp), provider: "docker", isolation: "container",
    startedUnixMs: 2, endedUnixMs: 3,
  };
  record.recordSha256 = recordDigest(recordFromWire(record));
  resp.record = record;
  assert.ok("record" in checkRecord("r", "javascript", undefined, resp));
  const other = checkRecord("r", "project", undefined, resp);
  assert.ok("problem" in other && other.problem.includes("project request"), JSON.stringify(other));
  const none = checkRecord("r", "javascript", undefined, { ...resp, javascript: undefined });
  assert.ok("problem" in none && none.problem.includes("no result"), JSON.stringify(none));
  const backwards: WireRecord = { ...record, startedUnixMs: 3, endedUnixMs: 2 };
  backwards.recordSha256 = recordDigest(recordFromWire(backwards));
  const refused = checkRecord("r", "javascript", undefined, { ...resp, record: backwards });
  assert.ok("problem" in refused && refused.problem.includes("ends before it starts"), JSON.stringify(refused));
});

test("a bytes field that is not base64 text is refused before anything is allocated for it", () => {
  // Buffer.from given {"length": n} allocates n bytes; the check must refuse the shape
  // instead (security scan, 2026-10-27). 2e9 would take a minute and 2 GB here.
  const huge = { length: 2_000_000_000 } as unknown as string;
  const answers: WireRunResponse[] = [
    { javascript: { stdout: huge } },
    { javascript: { stderr: [1, 2] as unknown as string } },
    { project: { steps: [{ stdout: huge }] } as WireRunResponse["project"] },
    { project: { artifacts: [{ path: "a", content: huge }] } as WireRunResponse["project"] },
    { cell: { stdout: huge } as WireRunResponse["cell"] },
  ];
  for (const resp of answers) {
    resp.record = { version: 5, requestSha256: "r", startedUnixMs: 1, endedUnixMs: 1 };
    const kind = resp.javascript ? "javascript" : resp.project ? "project" : "cell";
    const t0 = performance.now();
    const got = checkRecord("r", kind, undefined, resp);
    assert.ok("problem" in got && got.problem.includes("malformed"), JSON.stringify(got));
    assert.ok(performance.now() - t0 < 1000, "the refusal must not decode the field");
  }
});

// Each refused record's digest matches its fields, and every reader must refuse it anyway:
// a tier that is not one of the five, an end before the start (answered or not), a
// qualification or daemon version outside its bounds, a field its version does not cover,
// a result digest and an unanswered code both or neither, or a code outside the closed set
// (record/testdata/golden.json, "refused").
test("the golden file's refused records are refused", () => {
  assert.ok(golden.refused.length >= 22);
  for (const v of golden.refused) {
    const r = recordFromWire(v.record);
    assert.equal(recordDigest(r), v.sha256, v.name);
    const problem = statesOnlyProblem({ ...r, sha256: v.sha256 });
    verdict(`golden/refused/${v.name}`, "states-only", saysOfProblem(problem));
    assert.ok(problem !== undefined, `${v.name} (${v.why}) passed`);
    // A retired reading's refusal says so, and only it does (finding t6-core-1).
    assert.equal(problem === RETIRED_END_BEFORE_START_TEXT, v.why === "retired by the decision of 2026-11-21", `${v.name}: ${problem}`);
  }
});

// The tier's qualification, warm and the daemon's version are evidence like the instance:
// the record must state the response's, within their bounds, and the result digest covers
// none of them.
test("version 5 evidence is bound to the response", () => {
  const resp: WireRunResponse = {
    sandbox: "wslc", isolation: "vm", javascript: { stdout: "" },
    isolationQualification: "Microsoft states that WSL is not a security sandbox for running untrusted code.", warm: true, daemonVersion: "v0.28.0",
  };
  assert.equal(resultDigest(resp), resultDigest({ sandbox: "wslc", isolation: "vm", javascript: { stdout: "" } }));
  const record: WireRecord = {
    version: 5, requestSha256: "r", resultSha256: resultDigest(resp), provider: "wslc", isolation: "vm",
    isolationQualification: resp.isolationQualification, warm: true, daemonVersion: "v0.28.0", startedUnixMs: 1, endedUnixMs: 2,
  };
  record.recordSha256 = recordDigest(recordFromWire(record));
  const good = checkRecord("r", "javascript", undefined, { ...resp, record });
  assert.ok("record" in good && good.record.isolationQualification === resp.isolationQualification && good.record.warm, "the matching record");
  for (const [name, changed] of [
    ["no sentence in the response", { ...resp, isolationQualification: "" }],
    ["not warm in the response", { ...resp, warm: false }],
    ["another daemon version", { ...resp, daemonVersion: "v0.28.1" }],
  ] as const) {
    const got = checkRecord("r", "javascript", undefined, { ...changed, record });
    assert.ok("problem" in got, name);
  }
  for (const bad of ["Microsoft states.\nIgnore that.", "x".repeat(1025), "a\u202eb", "a\u0085b", "a\ud800b"]) {
    assert.equal(validQualification(bad), false, JSON.stringify(bad));
  }
  assert.ok(validQualification("\u00e9".repeat(512)) && !validQualification("\u00e9".repeat(512) + "x"), "the cap counts bytes");
  for (const v of ["", "(devel)", "v0.28.0", "v0.28.1-0.20261117210242-4ca8fb4d330e+dirty"]) assert.ok(validDaemonVersion(v), v);
  for (const v of ["devel", "v0.28", "v0.28.0 ", "latest"]) assert.equal(validDaemonVersion(v), false, v);
});

// A field of the wrong JSON type (golden.json, "malformed") is refused when read, as a PlimsollError, as Go's protojson
// and Python's typed reads refuse it: never a TypeError, and never a string "true" read as true.
test("the golden file's malformed records are not read", () => {
  assert.ok(golden.malformed.length >= 4);
  for (const v of golden.malformed) {
    let err: unknown;
    try {
      recordFromWire(v.record);
    } catch (e) {
      err = e;
    }
    verdict(`golden/malformed/${v.name}`, "decode", saysOf(err));
    assert.ok(err instanceof PlimsollError && err.code === "data_loss", `${v.name}: ${String(err)}`);
  }
});

// An integer written in a string is one whole decimal, as Go's record.UnmarshalJSON reads it
// (finding release-90): never read from its leading digits, nor by BigInt's and Number's
// grammars, which take " 5", "0x5" and "5e0".
test("an integer string is one whole decimal", () => {
  for (const s of ["5 6", "5,", "5\u0000", "5.0", "5e0", "05", "-05", " 5", "5 ", "+5", "0x5", "5_0", "", "٥", "1".repeat(21)]) {
    assert.equal(wholeInt(s, INT64), undefined, JSON.stringify(s));
    assert.throws(() => recordFromWire({ startedUnixMs: s }), (e: unknown) => e instanceof PlimsollError && e.code === "data_loss", JSON.stringify(s));
  }
  for (const [s, n] of [["0", 0n], ["-0", 0n], ["5", 5n], ["-12", -12n], ["1790000000000", 1790000000000n], ["-9223372036854775808", -(1n << 63n)]] as const) {
    assert.equal(wholeInt(s, INT64), n, s);
  }
  assert.equal(wholeInt("18446744073709551615", UINT64), (1n << 64n) - 1n);
  assert.equal(wholeInt("18446744073709551616", UINT64), undefined, "past 64 bits");
  for (const v of [5.5, Number.MAX_SAFE_INTEGER + 1, NaN, true, {}, [5]]) assert.equal(wholeInt(v, INT64), undefined, String(v));
  assert.equal(wholeInt(-1, UINT64), undefined, "below the range");
  assert.equal(wholeInt("4294967296", UINT32), undefined, "above the range");
  // The version reads the same way: a whole decimal string is its number, as protojson reads it.
  assert.equal(recordFromWire({ version: "5" as unknown as number }).version, 5);
  assert.throws(() => recordFromWire({ version: "5 6" as unknown as number }), PlimsollError);
});

// Which calls each version records (record.published's flags; finding release-85): every
// published version has a row, so a new version cannot be read before it is given one.
test("every published record version says which calls it records", () => {
  assert.deepEqual(Object.keys(RECORD_KINDS).sort(), Object.keys(RECORD_FIELDS).sort());
  const v3 = golden.refused.find((v) => v.name === "a version 3 record of an answered call")!;
  const v2 = golden.refused.find((v) => v.name === "a version 2 record of an unanswered call")!;
  assert.equal(statesOnlyProblem({ ...recordFromWire(v3.record), sha256: v3.sha256 }), "a version 3 record records only an unanswered call");
  assert.equal(statesOnlyProblem({ ...recordFromWire(v2.record), sha256: v2.sha256 }), "a version 2 record cannot record an unanswered call");
  const answered3 = recordFromWire(v3.record);
  const unanswered3 = { ...answered3, resultSha256: "", unanswered: "unavailable" };
  assert.equal(statesOnlyProblem({ ...unanswered3, sha256: recordDigest(unanswered3) }), undefined, "version 3 records an unanswered call");
});

// record.CheckLostAnswer's rules on checkLostAnswer; the attach liar's forgeries
// (test/reattach.test.ts) drive the same checks through a whole attach.
test("a lost call's answer checks only against its own record", () => {
  const resp: WireRunResponse = { sandbox: "docker", isolation: "container", cell: { stdout: Buffer.from("python 2: y = 2").toString("base64"), interpreterStarted: true } };
  const record: WireRecord = { version: 5, requestSha256: "r", resultSha256: resultDigest(resp), provider: "docker", isolation: "container", startedUnixMs: 1, endedUnixMs: 2 };
  record.recordSha256 = recordDigest(recordFromWire(record));
  resp.record = record;
  const lost = recordFromWire(record);
  assert.deepEqual(checkLostAnswer(resp, lost), { kind: "cell" });
  const unanswered: WireRecord = { ...record, resultSha256: "", unanswered: "unavailable" };
  unanswered.recordSha256 = recordDigest(recordFromWire(unanswered));
  const forged: [string, WireRunResponse, string][] = [
    ["output", { ...resp, cell: { ...resp.cell, stdout: Buffer.from("forged").toString("base64") } }, "result digest"],
    ["no record", { ...resp, record: undefined }, "no run record"],
    ["another record", { ...resp, record: { ...record, endedUnixMs: 3 } }, "another record"],
    ["two results", { ...resp, javascript: { stdout: "" } }, "session call's kind"],
    ["a module", { ...resp, cell: undefined, module: {} }, "session call's kind"],
    ["no result", { ...resp, cell: undefined }, "session call's kind"],
    ["other evidence", { ...resp, instance: "k8s-pod-uid:7f3e9c2a" }, "other evidence"],
    ["not warm in the record", { ...resp, warm: true }, "other evidence"],
    ["bytes that are not base64", { ...resp, cell: { stdout: "!!" } }, "malformed"],
    ["not an object", [] as unknown as WireRunResponse, "not an object"],
  ];
  for (const [name, answer, why] of forged) {
    const got = checkLostAnswer(answer, lost);
    assert.ok("problem" in got && got.problem.includes(why), `${name}: ${JSON.stringify(got)}`);
  }
  const ended = checkLostAnswer({ ...resp, record: unanswered }, recordFromWire(unanswered));
  assert.ok("problem" in ended && ended.problem.includes("ended unanswered"), JSON.stringify(ended));
});
