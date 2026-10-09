// Deterministic SDK loop against local Docker only. No hosted model or sandbox.
import assert from "node:assert/strict";
import { generateText, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { PlimsollClient } from "@plimsollmark/client";
import { plimsollCodeTools } from "@plimsollmark/client/ai-sdk";

const baseUrl = process.env.PLIMSOLL_URL;
if (!baseUrl) throw new Error("Set PLIMSOLL_URL to a local Docker-backed plimsolld.");
if (!["localhost", "127.0.0.1", "[::1]"].includes(new URL(baseUrl).hostname)) throw new Error("This no-spend smoke check requires a loopback daemon.");
const client = new PlimsollClient({ baseUrl, token: process.env.PLIMSOLL_TOKEN });
const info = await client.describe();
if (info.sandbox !== "docker") throw new Error("This no-spend smoke check requires the Docker provider.");
const tools = plimsollCodeTools({ client });
const usage = { inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 0, text: 0, reasoning: 0 } };
const model = new MockLanguageModelV3({ doGenerate: [
  { content: [
    { type: "tool-call", toolCallId: "python", toolName: "executeCode", input: JSON.stringify({ language: "python", code: "import csv\nrows = csv.DictReader(open('values.csv'))\nsum(int(row['value']) for row in rows)", files: [{ path: "values.csv", content: "value\n20\n22\n" }] }) },
    { type: "tool-call", toolCallId: "javascript", toolName: "executeCode", input: JSON.stringify({ language: "javascript", code: "40 + 2" }) },
  ], finishReason: { unified: "tool-calls", raw: undefined }, usage, warnings: [] },
  { content: [{ type: "text", text: "Local code execution checked." }], finishReason: { unified: "stop", raw: undefined }, usage, warnings: [] },
] });
try {
  const result = await generateText({ model, prompt: "Run the two fixed local checks.", tools: { executeCode: tools.executeCode }, stopWhen: stepCountIs(2) });
  const outputs = result.steps[0]!.toolResults.map(call => call.output);
  assert.equal(outputs.length, 2);
  for (const output of outputs) {
    assert.equal(output.stdout.trim(), "42");
    assert.equal(output.exitCode, 0);
    assert.equal(output.stateKept, false);
    assert.match(output.recordSha256, /^[0-9a-f]{64}$/);
  }
  console.log(JSON.stringify({ sdk: "Vercel AI SDK", model: "scripted, no inference", results: outputs }, null, 2));
} finally { await tools.disposeAll(); }
