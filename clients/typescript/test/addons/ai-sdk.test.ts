import assert from "node:assert/strict";
import { test } from "node:test";
import { generateText, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";

import { plimsollCodeTools } from "../../src/ai-sdk.ts";
import { PlimsollClient } from "../../src/index.ts";
import { executeCodeDescription, executeCodeInput } from "../../src/tool.ts";

const sessionsURL = process.env.PLIMSOLL_SESSIONS_URL;
const echoURL = process.env.PLIMSOLL_ECHO_URL;
const skip = sessionsURL && echoURL ? false : "run through go test ./clients/typescript";
const context = { toolCallId: "offline-call", messages: [] };
const usage = { inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 0, text: 0, reasoning: 0 } };

test("the input schema reserves two file slots for a fresh runner", () => {
  const files = Array.from({ length: 200 }, (_, i) => ({ path: `input-${i}.txt`, content: "x" }));
  const schema = executeCodeInput();
  assert.equal(schema.safeParse({ code: "1", files: files.slice(0, 198) }).success, true);
  for (const count of [199, 200]) {
    const parsed = schema.safeParse({ code: "1", files: files.slice(0, count) });
    assert.equal(parsed.success, false);
    if (!parsed.success) assert.deepEqual(parsed.error.issues[0]!.path, ["files"]);
  }
});

test("fresh descriptions make no persistence claim and scoped state requires daemon sessions", () => {
  const client = () => { throw new Error("describing a tool must not connect"); };
  const tools = plimsollCodeTools({ client });
  const never = plimsollCodeTools({ client, sessions: "never" });
  const scope = { userId: "alice", conversationId: "chat" };
  for (const description of [executeCodeDescription(undefined, "fresh"), tools.executeCode.description!,
    never.forConversation(scope).description!]) {
    assert.match(description, /Every call uses a fresh sandbox/);
    assert.match(description, /stateKept and filesPersist are false/);
    assert.doesNotMatch(description, /can still be there|filesPersist is true|keeps an interpreter/);
  }
  assert.match(tools.forConversation(scope).description!, /State is kept only if the daemon keeps sessions/);
  assert.match(tools.forConversation(scope).description!, /otherwise every call runs fresh/);
});

test("real AI SDK loop executes a fresh code tool, applying its default language", { skip }, async () => {
  const tools = plimsollCodeTools({ client: new PlimsollClient({ baseUrl: echoURL! }), minimumIsolation: "container" });
  const files = [{ path: "input.csv", content: "a,b\n1,2\n" },
    ...Array.from({ length: 197 }, (_, i) => ({ path: `input-${i}.txt`, content: "x" }))];
  const model = new MockLanguageModelV3({ doGenerate: [
    { content: [{ type: "tool-call", toolCallId: "code-1", toolName: "executeCode", input: JSON.stringify({ code: "sum([1, 2, 3])", files }) }], finishReason: { unified: "tool-calls", raw: undefined }, usage, warnings: [] },
    { content: [{ type: "text", text: "done" }], finishReason: { unified: "stop", raw: undefined }, usage, warnings: [] },
  ] });
  const result = await generateText({ model, prompt: "offline adapter check", tools: { executeCode: tools.executeCode }, stopWhen: stepCountIs(2) });
  assert.equal(result.text, "done");
  assert.equal(model.doGenerateCalls.length, 2);
  const output = result.steps[0]!.toolResults[0]!.output;
  assert.equal(output.language, "python");
  assert.equal(output.stateKept, false);
  assert.equal(output.filesPersist, false);
  assert.match(output.recordSha256, /^[0-9a-f]{64}$/);
  const plan = JSON.parse(output.stdout);
  assert.ok(plan.files.includes("input.csv"));
  assert.equal(plan.files.length, 200); // 198 inputs plus the runner and code files.
  assert.equal(plan.cell, "sum([1, 2, 3])");
  assert.match(tools.executeCode.description!, /Every call uses a fresh sandbox/);
  await tools.disposeAll();
});

test("conversation identity is scoped by both user and conversation", { skip }, async () => {
  const tools = plimsollCodeTools({ client: new PlimsollClient({ baseUrl: sessionsURL! }), minimumIsolation: "container", idleCloseMs: 0 });
  try {
    const alice = { userId: "alice", conversationId: "chat" };
    const bob = { userId: "bob", conversationId: "chat" };
    const run = (scope: typeof alice, code: string) => tools.forConversation(scope).execute!({ code, language: "python" }, context);
    assert.equal((await run(alice, "1")).stdout, "python 1: 1");
    assert.equal((await run(alice, "2")).stdout, "python 2: 2");
    assert.equal((await run(bob, "1")).stdout, "python 1: 1");
    await tools.dispose(alice);
    assert.equal((await run(alice, "3")).stdout, "python 1: 3");
    const nul = String.fromCharCode(0);
    assert.equal((await run({ userId: `a${nul}b`, conversationId: "c" }, "1")).stdout, "python 1: 1");
    assert.equal((await run({ userId: "a", conversationId: `b${nul}c` }, "2")).stdout, "python 1: 2");
  } finally { await tools.disposeAll(); }
});

test("unscoped calls never borrow a retained conversation", { skip }, async () => {
  const tools = plimsollCodeTools({ client: new PlimsollClient({ baseUrl: sessionsURL! }), minimumIsolation: "container" });
  await assert.rejects(tools.executeCode.execute!({ code: "1", language: "python" }, context), { notDispatched: "unsupported" });
  await tools.disposeAll();
});

test("default kernel floor refuses a container daemon before dispatch", { skip }, async () => {
  const tools = plimsollCodeTools({ client: new PlimsollClient({ baseUrl: echoURL! }) });
  await assert.rejects(tools.executeCode.execute!({ code: "1", language: "python" }, context), { notDispatched: "isolation" });
});

test("empty identities are rejected without connecting", () => {
  const tools = plimsollCodeTools({ client: () => { throw new Error("must not construct client"); } });
  for (const scope of [{ userId: "", conversationId: "chat" }, { userId: "alice", conversationId: "" }]) {
    assert.throws(() => tools.forConversation(scope), { notDispatched: "request" });
    assert.throws(() => tools.warm(scope), { notDispatched: "request" });
  }
});

test("abort and invalid files keep their refusal semantics", { skip }, async () => {
  const tools = plimsollCodeTools({ client: new PlimsollClient({ baseUrl: echoURL! }), minimumIsolation: "container" });
  await assert.rejects(tools.executeCode.execute!({ code: "1", language: "python", files: [{ path: ".plimsoll/cell.py", content: "bad" }] }, context), { notDispatched: "request" });
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(tools.executeCode.execute!({ code: "1", language: "python" }, { ...context, abortSignal: aborted.signal }), { notDispatched: "request" });
});
