// The Mastra add-on: the same client and the same per-conversation sandboxes,
// keyed by Mastra's thread. Needs the dev dependencies (npm install).

import assert from "node:assert/strict";
import { test } from "node:test";

import { PlimsollClient } from "../../src/index.ts";
import { plimsollExecuteCode } from "../../src/mastra.ts";

const url = process.env.PLIMSOLL_SESSIONS_URL;
const skip = url ? false : "run through `go test ./clients/typescript`";

test("a thread keeps one sandbox; another thread or user gets its own", { skip }, async () => {
  const { executeCode, dispose, sandboxes } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }), minimumIsolation: "container" });
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

// The key holds both IDs unambiguously: joined with a separator, a resource ending in
// it and a thread starting with it would name another user's sandbox.
test("IDs holding the key's separator do not reach another user's sandbox", { skip }, async () => {
  const { executeCode, sandboxes } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }), minimumIsolation: "container" });
  const nul = String.fromCharCode(0);
  const run = (code: string, threadId: string, resourceId: string) =>
    executeCode.execute!({ code, language: "python" }, { agent: { threadId, resourceId, toolCallId: "c", messages: [], agentId: "a", suspend: async () => {} } } as any);
  assert.equal((await run("1", "c", `a${nul}b`)).stdout, "python 1: 1");
  assert.equal((await run("2", `b${nul}c`, "a")).stdout, "python 1: 2", "another user's thread");
  await sandboxes.disposeAll();
});

test("a call outside a thread never shares a sandbox", { skip }, async () => {
  const { executeCode } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }), minimumIsolation: "container" });
  // The session fake refuses single runs: proof that no session was used.
  await assert.rejects(executeCode.execute!({ code: "1", language: "python" }, {} as any), { notDispatched: "unsupported" });
});

// Without a resource there is no user to scope the thread by, so the call runs fresh
// rather than in a sandbox every resource-less user with that thread id would share
// (v0.15.0 review, L24; warm-sandbox plan, item 2).
test("a call without a resource never shares a sandbox", { skip }, async () => {
  const { executeCode } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }), minimumIsolation: "container" });
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

test("the resource is the owner the per-user cap counts", { skip }, async () => {
  const { executeCode, sandboxes } = plimsollExecuteCode({ client: new PlimsollClient({ baseUrl: url! }), minimumIsolation: "container", maxSessionsPerOwner: 1 });
  const run = (code: string, threadId: string, resourceId: string) =>
    executeCode.execute!({ code, language: "python" }, { agent: { threadId, resourceId, toolCallId: "c", messages: [], agentId: "a", suspend: async () => {} } } as any);
  await run("1", "t1", "alice");
  await run("1", "t1", "bob");
  await run("1", "t2", "alice"); // closes alice's t1, not bob's
  assert.equal((await run("2", "t1", "bob")).stdout, "python 2: 2");
  assert.equal((await run("2", "t1", "alice")).stdout, "python 1: 2");
  await sandboxes.disposeAll();
});

test("in an agent network the app's owner, not the network name Mastra fills in, is what the cap counts", { skip }, async () => {
  // Mastra's network sets a missing resourceId to the network's name and the thread to
  // the run id, so both users arrive with resourceId "net"; the app's owner tells them apart.
  const { executeCode, dispose, sandboxes } = plimsollExecuteCode({
    client: new PlimsollClient({ baseUrl: url! }),
    minimumIsolation: "container",
    maxSessionsPerOwner: 1,
    owner: (ctx) => (ctx.requestContext?.get("user") as string | undefined) ?? undefined,
  });
  const run = (code: string, threadId: string, user: string) =>
    executeCode.execute!({ code, language: "python" }, {
      agent: { threadId, resourceId: "net", toolCallId: "c", messages: [], agentId: "a", suspend: async () => {} },
      requestContext: new Map([["user", user]]),
    } as any);
  await run("1", "run-1", "alice");
  await run("1", "run-2", "bob"); // without the owner, this would close alice's sandbox
  assert.equal((await run("2", "run-1", "alice")).stdout, "python 2: 2");
  assert.equal((await run("2", "run-2", "bob")).stdout, "python 2: 2");
  await dispose("run-1", "net", "alice");
  assert.equal((await run("3", "run-1", "alice")).freshSandbox, true, "dispose with the owner closed alice's");
  await sandboxes.disposeAll();
});

// The owner resolver is the app's code, run for each call before anything is sent: one
// that throws on a request without the context it expects ran nothing, and the model is
// told so.
test("an owner resolver that throws is refused as nothing ran", { skip }, async () => {
  const { executeCode } = plimsollExecuteCode({
    client: new PlimsollClient({ baseUrl: url! }),
    minimumIsolation: "container",
    owner: () => {
      throw new Error("no user in this request's context");
    },
  });
  await assert.rejects(
    executeCode.execute!({ code: "1", language: "python" }, { agent: { threadId: "t1", resourceId: "alice", toolCallId: "c", messages: [], agentId: "a", suspend: async () => {} } } as any),
    { notDispatched: "environment", message: "Nothing ran (environment): no user in this request's context" },
  );
});

