// Drives the agent through real turns with Trigger.dev's offline harness and a
// scripted model, against the plimsolld that PLIMSOLL_URL names (go test
// ./clients/typescript serves one whose sessions are an in-memory fake that
// answers a cell with "<language> <n>: <code>" and lists its files on stderr).
// Run it with `npm test` after starting one.

import { mockChatAgent } from "@trigger.dev/sdk/ai/test"; // first: installs the task catalog
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";

import { codeChat } from "./chat.ts";
import { models } from "./models.ts";

const skip = process.env.PLIMSOLL_URL ? false : "needs PLIMSOLL_URL";

// Count the daemon procedures the agent calls.
const procedures: string[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = String(input);
  if (process.env.PLIMSOLL_URL && url.startsWith(process.env.PLIMSOLL_URL)) procedures.push(url.split("/").pop()!);
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

// Takes about 30 s: the agent suspends only after its idle window, which is
// Trigger.dev's default and the harness's real clock.
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
  const harness = mockChatAgent(codeChat, { chatId: "chat-1" });
  try {
    const first = outputs((await harness.sendMessage(user("u1", "load the orders and count them"))).chunks);
    assert.deepEqual(
      first.map((o) => [o.language, o.stdout, o.stderr, o.stateKept, o.filesPersist, o.isolation]),
      [
        ["python", "python 1: import csv\nrows = list(csv.DictReader(open('orders.csv')))", "orders.csv\n", true, true, "container"],
        ["python", "python 2: len(rows)", "", true, true, "container"],
      ],
    );

    // The next turn, before the idle window passes: the same interpreter (the
    // fake's cell counter continues).
    const [second] = outputs((await harness.sendMessage(user("u2", "and the total?"))).chunks);
    assert.equal(second.stdout, "python 3: sum(float(r['total']) for r in rows)");
    assert.equal(count("OpenSession"), 1);
    assert.equal(count("CloseSession"), 0);

    // Idle: onChatSuspend closes the sandbox right before the run sleeps.
    await until(() => count("CloseSession") === 1, 60_000);
  } finally {
    await harness.close();
  }
});
