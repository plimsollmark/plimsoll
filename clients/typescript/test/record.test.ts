// The golden vectors of record/testdata/golden.json, computed by this client's own
// encoder: the file the Go record package and the Python client test against too, so
// the TypeScript digests must equal theirs byte for byte. Module vectors are skipped:
// this client sends no module runs.

import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { checkRecord, recordDigest, recordFromWire, requestDigest, resultDigest, sessionFingerprint, softwareRuleId, type DigestPayload } from "../src/record.ts";
import type { WireRecord, WireRunResponse, WireSoftwareRule } from "../src/wire.ts";

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
    assert.equal(got, v.sha256, v.name);
    n++;
  }
  assert.ok(n >= 5, `only ${n} request vectors`);
});

test("result digests", () => {
  let n = 0;
  for (const v of golden.results) {
    if (v.response.module !== undefined) continue;
    assert.equal(resultDigest(v.response), v.sha256, v.name);
    n++;
  }
  assert.ok(n >= 3, `only ${n} result vectors`);
});

test("every release's own vectors still hold", () => {
  // record/testdata/published, never edited: the versions a release wrote keep their
  // digests in this client too.
  const dir = new URL("../../../record/testdata/published/", import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith("-golden.json"));
  assert.ok(files.length >= 1, "no published vectors");
  for (const f of files) {
    const g: Golden = JSON.parse(readFileSync(new URL(f, dir), "utf8"));
    for (const v of g.requests) {
      const p = payload(v.request);
      if (!p) continue;
      const r = v.request;
      assert.equal(requestDigest({ protocol: r.protocol, minimumIsolation: r.minimumIsolation ?? "", timeoutMs: r.timeoutMs ?? 0, softwareRule: r.softwareRule, payload: p }), v.sha256, `${f}: ${v.name}`);
    }
    for (const v of g.results) {
      if (v.response.module !== undefined) continue;
      assert.equal(resultDigest(v.response), v.sha256, `${f}: ${v.name}`);
    }
    for (const v of g.records) assert.equal(recordDigest(recordFromWire(v.record)), v.sha256, `${f}: ${v.name}`);
  }
});

test("record digest and session fingerprint", () => {
  for (const v of golden.records) assert.equal(recordDigest(recordFromWire(v.record)), v.sha256, v.name);
  for (const v of golden.sessionFingerprints) assert.equal(sessionFingerprint(v.sessionId), v.sha256, v.name);
  assert.ok(golden.records.length >= 1 && golden.sessionFingerprints.length >= 1);
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
    version: 4, requestSha256: "r", resultSha256: resultDigest(resp), provider: "docker", isolation: "container",
    instance: "k8s-pod-uid:7f3e9c2a", startedUnixMs: 1, endedUnixMs: 2,
  };
  record.recordSha256 = recordDigest(recordFromWire(record));
  resp.record = record;
  assert.ok("record" in checkRecord("r", undefined, resp));
  const refused = (r: WireRecord, why: string) => {
    resp.record = { ...r, recordSha256: recordDigest(recordFromWire(r)) };
    const got = checkRecord("r", undefined, resp);
    assert.ok("problem" in got && got.problem.includes(why), JSON.stringify(got));
  };
  refused({ ...record, unanswered: "unknown" }, "unanswered");
  for (const version of [1, 2, 3]) refused({ ...record, version }, "version");
  refused({ ...record, instance: "k8s-pod-uid:other" }, "instance");
  refused({ ...record, instance: "/var/run/pod" }, "instance");
  assert.equal(resultDigest({ ...resp, instance: "k8s-pod-uid:other" }), resultDigest(resp), "the instance moved the result digest");
});
