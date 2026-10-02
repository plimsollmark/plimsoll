// The Mastra add-on: the same client and the same per-conversation sandboxes,
// keyed by Mastra's thread. Needs the dev dependencies (npm install).

import assert from "node:assert/strict";
import { test } from "node:test";

import { PlimsollClient } from "../../src/index.ts";
import { plimsollExecuteCode } from "../../src/mastra.ts";

const url = process.env.PLIMSOLL_SESSIONS_URL;
const skip = url ? false : "run through `go test ./clients/typescript`";

test("a thread keeps one sandbox; another thread or user gets its own", { skip }, async () => {
  const { executeCode, dispose, sandboxes } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }) });
  const run = (code: string, threadId?: string, resourceId?: string) =>
    executeCode.execute!({ code, language: "python" }, { agent: threadId ? { threadId, resourceId, toolCallId: "c", messages: [], agentId: "a", suspend: async () => {} } : undefined } as any);

  assert.equal((await run("1", "t1", "alice")).stdout, "python 1: 1");
  assert.equal((await run("2", "t1", "alice")).stdout, "python 2: 2");
  assert.equal((await run("1", "t1", "bob")).stdout, "python 1: 1", "same thread id, another user");
  assert.equal((await run("1", "t2", "alice")).stdout, "python 1: 1");

  await dispose("t1", "alice");
  assert.equal((await run("3", "t1", "alice")).stdout, "python 1: 3", "disposed: a new sandbox");
  await sandboxes.disposeAll();
});

test("a call outside a thread never shares a sandbox", { skip }, async () => {
  const { executeCode } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }) });
  // The session fake refuses single runs: proof that no session was used.
  await assert.rejects(executeCode.execute!({ code: "1", language: "python" }, {} as any), { notDispatched: "unsupported" });
});

// Without a resource there is no user to scope the thread by, so the call runs fresh
// rather than in a sandbox every resource-less user with that thread id would share
// (v0.15.0 review, L24; warm-sandbox plan, item 2).
test("a call without a resource never shares a sandbox", { skip }, async () => {
  const { executeCode } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }) });
  const agent = { threadId: "t1", toolCallId: "c", messages: [], agentId: "a", suspend: async () => {} };
  // The session fake refuses single runs: proof that no session was used.
  await assert.rejects(executeCode.execute!({ code: "1", language: "python" }, { agent } as any), { notDispatched: "unsupported" });
  await assert.rejects(executeCode.execute!({ code: "1", language: "python" }, { agent: { ...agent, resourceId: "" } } as any), { notDispatched: "unsupported" });
});

test("the tool declares the shared description and schemas", () => {
  const { executeCode } = plimsollExecuteCode({ client: () => new PlimsollClient({ baseUrl: "http://127.0.0.1:1" }) });
  assert.equal(executeCode.id, "executeCode");
  assert.match(executeCode.description, /isolated sandbox with no network/);
  assert.ok(executeCode.inputSchema);
});
