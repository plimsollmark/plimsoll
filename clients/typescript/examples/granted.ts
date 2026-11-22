// The TypeScript executeCode path with a grant: CodeSandboxes, the core every executeCode
// tool shares (the AI SDK's plimsollGrantedCodeTool and Mastra's plimsollGrantedExecuteCode
// are this, wrapped in their framework's tool), built with a grant the application chose:
// the profile the operator configured on the daemon, and the description plimsoll-specgen
// wrote for it. Each call runs in a sandbox of its own and can call the API's routes,
// through plimsoll's broker outside the sandbox, which adds the API's key. It imports the
// client's source, so it runs from a checkout with node alone (node >= 22.18):
//
//   PLIMSOLL_URL=... PLIMSOLL_TOKEN=... PLIMSOLL_GRANT_DESCRIPTION_FILE=description.txt node examples/granted.ts
//
// Checked: clients/python/examples_docker_test.go runs it against a real docker daemon
// and a stand-in for the API.

import { readFileSync } from "node:fs";

import { PlimsollClient } from "../src/client.ts";
import { CodeSandboxes } from "../src/sandboxes.ts";

const client = new PlimsollClient({ baseUrl: process.env.PLIMSOLL_URL ?? "http://127.0.0.1:8746", token: process.env.PLIMSOLL_TOKEN });
const grant = { profile: process.env.PLIMSOLL_GRANT_PROFILE ?? "lights", apiDescription: readFileSync(process.env.PLIMSOLL_GRANT_DESCRIPTION_FILE!, "utf8") };
const minimumIsolation = (process.env.PLIMSOLL_MIN_ISOLATION ?? "kernel") as "kernel";
const sandboxes = new CodeSandboxes({ client, grant, minimumIsolation, languages: ["javascript", "python"] });
const plan = await sandboxes.grantPlan();
console.log("languages that can call the API here:", plan.languages.join(", "));

// The cell's form: the value of the last expression is printed, as in a notebook.
const js = await sandboxes.run(undefined, {
  language: "javascript",
  code: 'const light = await host.get("/v1/lights/kitchen");\nawait host.post("/v1/lights/kitchen/on", { level: 40 });\nawait host.post("/v1/lights/kitchen/on", { level: 50 }).catch((e) => console.log("second POST", e.status));\n({ was: light, now: "on" })',
});
console.log("javascript ->", JSON.stringify(js));
const py = await sandboxes.run(undefined, { language: "python", code: 'import plimsoll_host\nplimsoll_host.get("/v1/lights/hall")' });
console.log("python ->", JSON.stringify(py));
