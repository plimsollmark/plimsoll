// The granted executeCode tools (plimsollGrantedCodeTool, plimsollGrantedExecuteCode)
// against the grant-echo daemons: the tool-echo provider stating project grants, named
// docker (a provider whose Python steps reach the broker) or e2b (one whose do not),
// behind a bearer token, serving one grant profile, echo-api, whose routes a granted
// project's plan names (internal/clientsuite/grantecho.go).

import assert from "node:assert/strict";
import { test } from "node:test";
import { generateText, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";

import { plimsollCodeTools, plimsollGrantedCodeTool } from "../../src/ai-sdk.ts";
import { GRANTED_CELL, HOST_MODULE_PATH, HOST_MODULE_SOURCE } from "../../src/granted.gen.ts";
import { PlimsollClient, PlimsollError } from "../../src/index.ts";
import { plimsollExecuteCode, plimsollGrantedExecuteCode } from "../../src/mastra.ts";
import { GRANT_PERMISSION_NOTE, GRANTED_MAY_HAVE_RUN } from "../../src/sandboxes.ts";

const grantURL = process.env.PLIMSOLL_GRANT_ECHO_URL;
const grantToken = process.env.PLIMSOLL_GRANT_ECHO_TOKEN;
const guardURL = process.env.PLIMSOLL_GRANT_ECHO_GUARD_URL;
const guardToken = process.env.PLIMSOLL_GRANT_ECHO_GUARD_TOKEN;
const toolEchoURL = process.env.PLIMSOLL_TOOL_ECHO_URL;
const wasmURL = process.env.PLIMSOLL_WASM_URL;
const skip = grantURL && grantToken && guardURL && guardToken && toolEchoURL && wasmURL ? false : "run through go test ./clients/typescript";
const context = { toolCallId: "offline-call", messages: [] };
const usage = { inputTokens: { total: 0, noCache: 0, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 0, text: 0, reasoning: 0 } };

// An API description in plimsoll-specgen's shape.
const API = "Echo lights (v1).\n  host.getLight(id)  ->  GET /v1/lights/*\n";
const ROUTES = ["GET /v1/lights/*", "POST /v1/lights/*/on"];
const docker = () => new PlimsollClient({ baseUrl: grantURL!, token: grantToken! });
const guard = () => new PlimsollClient({ baseUrl: guardURL!, token: guardToken! });
const grant = { profile: "echo-api", apiDescription: API };

async function call(tool: { execute?: unknown }, input: Record<string, unknown>): Promise<any> {
  return (tool.execute as (i: unknown, c: unknown) => Promise<unknown>)(input, context);
}

test("a granted tool tells the model what its code can call, and that kept state is not available", { skip }, async () => {
  const { executeCode } = await plimsollGrantedCodeTool({ client: docker(), minimumIsolation: "container", grant });
  const text = executeCode.description!;
  assert.ok(text.includes(API.trim()));
  assert.match(text, /no network access except the one web API described below/);
  assert.match(text, /kept state between calls is not available to this tool/);
  assert.match(text, /import plimsoll_host/);
  assert.match(text, /adds the API's key outside the sandbox/);
  // The model's arguments name no profile: the application chose it.
  const shape = (executeCode.inputSchema as { shape: Record<string, unknown> }).shape;
  assert.deepEqual(Object.keys(shape).sort(), ["code", "files", "language"]);
  // The tools that keep state say nothing of an API, and take no grant.
  const plain = plimsollCodeTools({ client: docker() });
  assert.doesNotMatch(plain.executeCode.description!, /web API|plimsoll_host/);
  assert.throws(() => plimsollCodeTools({ client: docker(), grant } as never), /build a granted tool with plimsollGrantedCodeTool/);
  assert.throws(() => plimsollExecuteCode({ client: docker(), grant } as never), /plimsollGrantedExecuteCode/);
  // Kept state asked for with a grant is refused when the tool is built.
  await assert.rejects(plimsollGrantedCodeTool({ client: docker(), grant, sessions: "always" }), (e: PlimsollError) => e.notDispatched === "request");
});

test("a granted call runs fresh as the cell's form in a granted project, through the AI SDK's own loop", { skip }, async () => {
  const { executeCode } = await plimsollGrantedCodeTool({ client: docker(), minimumIsolation: "container", grant, languages: ["javascript", "python"] });
  const model = new MockLanguageModelV3({ doGenerate: [
    { content: [{ type: "tool-call", toolCallId: "c1", toolName: "executeCode", input: JSON.stringify({ code: "await host.getLight('hall')" }) }], finishReason: { unified: "tool-calls", raw: undefined }, usage, warnings: [] },
    { content: [{ type: "text", text: "done" }], finishReason: { unified: "stop", raw: undefined }, usage, warnings: [] },
  ] });
  const result = await generateText({ model, prompt: "granted check", tools: { executeCode }, stopWhen: stepCountIs(2) });
  const output = result.steps[0]!.toolResults[0]!.output;
  assert.equal(output.language, "javascript");
  assert.equal(output.stateKept, false);
  assert.equal(output.filesPersist, false);
  const plan = JSON.parse(output.stdout);
  assert.deepEqual(plan.grant.allow, ROUTES);
  assert.equal(plan.files[GRANTED_CELL.javascript.codePath], "await host.getLight('hall')");
  assert.deepEqual(plan.steps, [GRANTED_CELL.javascript.step]);
  // Python carries plimsoll_host and runs with its directory on the path.
  const py = JSON.parse((await call(executeCode, { code: "import plimsoll_host", language: "python" })).stdout);
  assert.deepEqual(py.grant.allow, ROUTES);
  assert.equal(py.files[HOST_MODULE_PATH], HOST_MODULE_SOURCE);
  assert.deepEqual(py.steps, [GRANTED_CELL.python.step]);
  // Mastra's granted tool, the same.
  const mastra = await plimsollGrantedExecuteCode({ client: docker(), minimumIsolation: "container", grant, id: "callLights" });
  assert.equal(mastra.executeCode.id, "callLights");
  const m = JSON.parse((await call(mastra.executeCode, { code: "1", language: "javascript" })).stdout);
  assert.deepEqual(m.grant.allow, ROUTES);
});

test("Python where its steps cannot reach the broker is not offered, and is refused before anything runs", { skip }, async () => {
  const { executeCode, sandboxes } = await plimsollGrantedCodeTool({ client: guard(), minimumIsolation: "container", grant });
  const schema = executeCode.inputSchema as { safeParse: (v: unknown) => { success: boolean } };
  assert.equal(schema.safeParse({ code: "1", language: "python" }).success, false, "Python is not in the language enum");
  assert.equal(schema.safeParse({ code: "1", language: "javascript" }).success, true);
  assert.match(executeCode.description!, /Python code cannot call the API on this sandbox/);
  assert.doesNotMatch(executeCode.description!, /import plimsoll_host/);
  await assert.rejects(sandboxes.run(undefined, { code: "print(1)", language: "python" }), (e: PlimsollError) =>
    e.notDispatched === "unsupported" && /Write the program in JavaScript/.test(e.message) && /Nothing ran/.test(e.message));
  // A tool left with no language is the application's mistake, said when it is built.
  await assert.rejects(plimsollGrantedCodeTool({ client: guard(), minimumIsolation: "container", grant, languages: ["python"] }),
    (e: PlimsollError) => e.notDispatched === "request");
});

test("an unknown profile is refused as the operator's to fix, and a call that may have run says the API may have been called", { skip }, async () => {
  const { sandboxes } = await plimsollGrantedCodeTool({ client: docker(), minimumIsolation: "container", grant: { profile: "no-such-api", apiDescription: API } });
  await assert.rejects(sandboxes.run(undefined, { code: "1", language: "javascript" }), (e: PlimsollError) =>
    e.notDispatched === "permission" && e.message.includes(GRANT_PERMISSION_NOTE));
  const ok = await plimsollGrantedCodeTool({ client: docker(), minimumIsolation: "container", grant });
  await assert.rejects(ok.sandboxes.run(undefined, { code: "ECHO:LOST", language: "javascript" }), (e: PlimsollError) =>
    e.notDispatched === undefined && e.message.includes(GRANTED_MAY_HAVE_RUN));
});

test("Describe is read once, when the tool is built, and its calls reuse that answer", { skip }, async () => {
  let describes = 0;
  const counting: typeof fetch = (input, init) => {
    if (String(input).endsWith("/Describe")) describes++;
    return fetch(input, init);
  };
  const { executeCode } = await plimsollGrantedCodeTool({
    client: new PlimsollClient({ baseUrl: grantURL!, token: grantToken!, fetch: counting }), minimumIsolation: "container", grant,
  });
  assert.equal(describes, 1);
  for (const language of ["javascript", "python"]) await call(executeCode, { code: "1", language });
  assert.equal(describes, 1, "a call read Describe again: the docs say the tool reads it once");
});

test("a daemon that cannot carry a grant refuses the tool when it is built", { skip }, async () => {
  for (const baseUrl of [toolEchoURL!]) {
    await assert.rejects(plimsollGrantedCodeTool({ client: new PlimsollClient({ baseUrl }), minimumIsolation: "container", grant }),
      (e: PlimsollError) => e.notDispatched === "unsupported");
  }
  // A daemon that runs snippets only and grants them (wasm): JavaScript, as a snippet.
  const wasm = await plimsollGrantedCodeTool({ client: new PlimsollClient({ baseUrl: wasmURL! }), minimumIsolation: "process", grant });
  assert.match(wasm.executeCode.description!, /Run JavaScript \(Node\.js\) in an isolated sandbox/);
  assert.equal((await wasm.sandboxes.grantPlan()).snippets, true);
  // A snippet is evaluated as a script, where top-level await fails
  // (sandbox's TestGrantedSnippetCellNeedsAnAsyncFunction): the description says so, and
  // names the form that works; a granted project's cell form says to await.
  assert.match(wasm.executeCode.description!, /Top-level await does not work in this sandbox/);
  assert.doesNotMatch(wasm.executeCode.description!, /so await it/);
  const project = await plimsollGrantedCodeTool({ client: docker(), minimumIsolation: "container", grant });
  assert.match(project.executeCode.description!, /so await it/);
  assert.doesNotMatch(project.executeCode.description!, /Top-level await does not work/);
  // The wasm daemon serves no profile, so the granted snippet is the daemon's permission refusal.
  await assert.rejects(wasm.sandboxes.run(undefined, { code: "1 + 1", language: "javascript" }), (e: PlimsollError) => e.notDispatched === "permission");
  await assert.rejects(plimsollGrantedCodeTool({ client: docker(), grant: { profile: "", apiDescription: API } }), (e: PlimsollError) => e.notDispatched === "request");
});
