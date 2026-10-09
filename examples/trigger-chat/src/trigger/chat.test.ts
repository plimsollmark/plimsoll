// Drives the agent through real turns with Trigger.dev's offline harness and a
// scripted model, against the plimsolld that PLIMSOLL_URL names (go test
// ./clients/typescript serves one whose sessions are an in-memory fake that
// answers a cell with "<language> <n>: <code>" and lists its files on stderr).
// Run it with `npm test` after starting one.

import { mockChatAgent } from "@trigger.dev/sdk/ai/test"; // first: installs the task catalog
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { after, test } from "node:test";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";

import { codeChatAgent, type OwnerEvent } from "./chat.ts";
import { models } from "./models.ts";

const skip = process.env.PLIMSOLL_URL ? false : "needs PLIMSOLL_URL";

// Count the daemon procedures the agent calls.
const procedures: string[] = [];
const owners: (string | undefined)[] = []; // the owner each OpenSession sent
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = String(input);
  if (process.env.PLIMSOLL_URL && url.startsWith(process.env.PLIMSOLL_URL)) procedures.push(url.split("/").pop()!);
  if (url.endsWith("/OpenSession")) owners.push(JSON.parse(String(init?.body)).owner);
  return realFetch(input, init);
};
after(() => {
  globalThis.fetch = realFetch;
});

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};

type Call = { code: string; language?: "python" | "javascript"; files?: { path: string; content: string }[] };

// Each model step either calls executeCode or answers with text.
function scripted(steps: (Call | { text: string })[]) {
  let i = 0;
  return new MockLanguageModelV3({
    doStream: async () => {
      const step = steps[i++] ?? { text: "done" };
      const chunks: any[] =
        "code" in step
          ? [
              { type: "tool-call", toolCallId: `call-${i}`, toolName: "executeCode", input: JSON.stringify(step) },
              { type: "finish", finishReason: { unified: "tool-calls", raw: "tool_use" }, usage },
            ]
          : [
              { type: "text-start", id: "t" },
              { type: "text-delta", id: "t", delta: step.text },
              { type: "text-end", id: "t" },
              { type: "finish", finishReason: { unified: "stop", raw: "stop" }, usage },
            ];
      return { stream: simulateReadableStream({ chunks }) };
    },
  });
}

const user = (id: string, text: string) => ({ id, role: "user" as const, parts: [{ type: "text" as const, text }] });

const outputs = (chunks: any[]) => chunks.filter((c) => c.type === "tool-output-available").map((c) => c.output);

const count = (name: string) => procedures.filter((p) => p === name).length;

async function until(cond: () => boolean, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 100));
  }
}

// The exported agent with a 3 s idle window instead of Trigger.dev's default 30 s: the
// agent suspends only once that window passes on the harness's real clock, and 3 s
// still leaves the second turn, sent the moment the first ends, well inside it.
const quickSuspend = codeChatAgent({ id: "code-chat-quick-suspend", idleTimeoutInSeconds: 3 });

// Waits one 3 s idle window for the suspend.
test("one sandbox per run: warmed on the turn, its interpreter reused by every call and turn, closed at suspend", { skip, timeout: 120_000 }, async () => {
  // One model across both turns, so the second turn continues the script.
  const model = scripted([
    { code: "import csv\nrows = list(csv.DictReader(open('orders.csv')))", files: [{ path: "orders.csv", content: "id,total\n1,30\n2,12\n" }] },
    { code: "len(rows)" },
    { text: "first" },
    { code: "sum(float(r['total']) for r in rows)" },
    { text: "second" },
  ]);
  models.chat = () => model;
  const harness = mockChatAgent(quickSuspend, { chatId: "chat-1" });
  try {
    const first = outputs((await harness.sendMessage(user("u1", "load the orders and count them"))).chunks);
    assert.deepEqual(
      first.map((o) => [o.language, o.stdout, o.stderr, o.stateKept, o.filesPersist, o.isolation]),
      [
        ["python", "python 1: import csv\nrows = list(csv.DictReader(open('orders.csv')))", "orders.csv\n", true, true, "container"],
        ["python", "python 2: len(rows)", "", true, true, "container"],
      ],
    );
    for (const output of first) assert.match(output.recordSha256, /^[0-9a-f]{64}$/, "the tool exposes its checked record");

    // The next turn, before the idle window passes: the same interpreter (the
    // fake's cell counter continues).
    const [second] = outputs((await harness.sendMessage(user("u2", "and the total?"))).chunks);
    assert.equal(second.stdout, "python 3: sum(float(r['total']) for r in rows)");
    assert.match(second.recordSha256, /^[0-9a-f]{64}$/);
    assert.equal(count("OpenSession"), 1);
    assert.equal(count("CloseSession"), 0);

    // Idle: onChatSuspend closes the sandbox right before the run sleeps.
    await until(() => count("CloseSession") === 1, 60_000);
  } finally {
    await harness.close();
  }
});

// The owner resolver gets the turn's runId, chatId and task run context, so an app can
// read the user its server stamped on the run (here a tag), never the browser's
// clientData.
test("a run warmed with its owner opens its sandbox under that owner, sent as a digest", { skip, timeout: 60_000 }, async () => {
  models.chat = () => scripted([{ code: "1 + 1" }, { text: "two" }]);
  const opened = owners.length;
  const seen: OwnerEvent[] = [];
  const agent = codeChatAgent({
    id: "code-chat-owned",
    owner: (event) => {
      seen.push(event);
      return event.ctx.run.tags.find((t) => t.startsWith("user:"))?.slice("user:".length);
    },
  });
  const harness = mockChatAgent(agent, { chatId: "chat-2", taskContext: { ctx: { run: { tags: ["user:alice@example.com"] } } } });
  try {
    const [out] = outputs((await harness.sendMessage(user("u1", "add"))).chunks);
    assert.equal(out.stdout, "python 1: 1 + 1");
    assert.equal(seen.length, 1);
    assert.equal(seen[0]!.chatId, "chat-2");
    assert.equal(seen[0]!.runId, seen[0]!.ctx.run.id, "the run id and the run context are the same run's");
    assert.ok(!("clientData" in seen[0]!), "the browser's clientData is not offered");
    const sent = owners.slice(opened);
    assert.equal(sent.length, 1);
    // The digest every official client sends: HMAC-SHA256 keyed by a key derived from
    // the caller token (none here) over the owner, so the daemon never gets the name.
    const key = createHash("sha256").update("plimsoll session owner key v2\n" + (process.env.PLIMSOLL_TOKEN ?? ""), "utf8").digest();
    const digest = createHmac("sha256", key).update("plimsoll session owner v2\nalice@example.com", "utf8").digest("hex");
    assert.equal(sent[0], digest, "the owner is the user the tag named");
  } finally {
    await harness.close();
  }
});
