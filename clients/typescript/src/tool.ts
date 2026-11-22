// The executeCode tool's model-facing surface, shared by the add-ons so the
// tools describe the same thing in the same words, with explicit fresh-call scope.

import { z } from "zod";

import type { Language } from "./client.ts";
import { DEFAULT_LANGUAGES, type GrantPlan, type ToolLanguages } from "./sandboxes.ts";
import { MAX_PROJECT_FILES } from "./tables.gen.ts";

const NAMES: Record<Language, string> = { python: "Python", javascript: "JavaScript (Node.js)" };
// The daemon accepts MAX_PROJECT_FILES project files. A fresh call adds its runner and
// code files, so the shared tool schema leaves those two slots available; a granted
// tool one more, for the plimsoll_host module a granted Python call carries.
const MAX_INPUT_FILES = MAX_PROJECT_FILES - 2;

// How JavaScript calls the API: in a granted project's cell form, top-level await works; in
// the snippet form a daemon that runs snippets only gets (sandbox.SnippetCell, evaluated as a
// script), it does not, and a final promise is printed once it settles.
const CELL_JS = "In JavaScript, call it through the global client the description names, as it shows; each call returns a promise, so await it.";
const SNIPPET_JS =
  "In JavaScript, call it through the global client the description names, as it shows; each call returns a promise. " +
  "Top-level await does not work in this sandbox: put the calls in an async function and end the code with its call, " +
  "(async () => { ... return value; })(), whose value is printed once it settles.";

/**
 * What a granted tool tells its model about the API, in the same words as the Python
 * kits' (plimsoll_client._code_tool.api_text): the routes are the only requests sent, the
 * credential is added outside, the budget, what a call that changes data means, and how
 * each offered language calls it; then the API's description as the application gave it.
 */
export function apiText(languages: readonly Language[], plan: GrantPlan): string {
  const lines = [
    "This tool's code can call one web API, described below, from inside the sandbox. Only its routes listed below " +
      "(each a method and a path) are sent to it: any other request is refused before it leaves, and so is a call " +
      "past the run's call budget (status 429). plimsoll adds the API's key outside the sandbox; the code never needs " +
      "one. A call that changes data takes effect even if the program fails afterwards, and a run is never retried.",
  ];
  if (languages.includes("javascript")) {
    lines.push(plan.snippets ? SNIPPET_JS : CELL_JS);
  }
  if (languages.includes("python")) {
    lines.push(
      "In Python, import plimsoll_host and call plimsoll_host.get(path), post(path, body), put(path, body), " +
        "patch(path, body), delete(path) or call(method, path, body) with a route's method and path from the " +
        "list below; each returns the answer's parsed JSON and raises plimsoll_host.HostAPIError, which has " +
        ".status and .body, for any other status.",
    );
  } else if (!plan.languages.includes("python")) {
    lines.push(`Python code cannot call the API on this sandbox (its provider, ${plan.provider}, gives a Python step no way to reach it).`);
  }
  lines.push("The API:\n" + plan.apiDescription);
  return lines.join("\n");
}

/** The tool's description for the languages it offers, and with a grant plan what its code can call. */
export function executeCodeDescription(languages: ToolLanguages = DEFAULT_LANGUAGES, scope: "fresh" | "conversation" = "conversation", plan?: GrantPlan): string {
  if (plan) {
    const names = languages.map((l) => NAMES[l]).join(" or ");
    return (
      `Run ${names} in an isolated sandbox with no network access except the one web API described below, and return its exit code, stdout and stderr. ` +
      "The value of the code's last expression is printed, as in a notebook, so the last line can simply name what you want to see. " +
      "Every call uses a fresh sandbox and interpreter: no earlier variable, import or file is retained, because a call that can reach the API never runs in a kept sandbox, so kept state between calls is not available to this tool. stateKept and filesPersist are false. " +
      "To give the code data, such as another tool's output, pass it in files rather than pasting it into the code; the code reads each file by its relative path. " +
      "The result also reports the isolation tier, the sentence its provider requires beside that tier when it states one (isolationQualification), and the SHA-256 of the run record the client checked." +
      "\n\n" +
      apiText(languages, plan)
    );
  }
  const names = languages.map((l) => NAMES[l]).join(" or ");
  const state = scope === "fresh"
    ? "Every call uses a fresh sandbox and interpreter: no earlier variable, import or file is retained. stateKept and filesPersist are false. "
    : "Within one conversation the sandbox usually keeps an interpreter per language between calls, so variables, functions, imports and loaded data " +
      "from earlier calls are still defined: the result's stateKept says whether this call's interpreter was still running when it answered, so what it defined can still be there " +
      "for the next call (false when its deadline ended the interpreter, or the sandbox ended). freshInterpreter means " +
      "this call's interpreter had just started, so nothing earlier calls defined exists and has to be rebuilt; freshSandbox means no file from " +
      "earlier calls is there either. " +
      "Files written to the working directory can still be there on the next call when filesPersist is true; freshSandbox on that call says they are not. ";
  return (
    `Run ${names} in an isolated sandbox with no network access and return its exit code, stdout and stderr. ` +
    "The value of the code's last expression is printed, as in a notebook, so the last line can simply name what you want to see. " +
    state +
    "To give the code data, such as another tool's output, pass it in files rather than pasting it into the code; the code reads each file by its relative path. " +
    "The result also reports the isolation tier, the sentence its provider requires beside that tier when it states one (isolationQualification), and the SHA-256 of the run record the client checked."
  );
}

/** The tool's input schema for the languages it offers. */
export function executeCodeInput(languages: ToolLanguages = DEFAULT_LANGUAGES, granted = false) {
  return z.object({
    code: z.string().min(1).describe("The source code to run. Print what you need, or end with an expression to show its value."),
    language: z
      .enum(languages)
      .default(languages[0])
      .describe(`The language of code: ${languages.map((l) => `"${l}"`).join(" or ")}. Default "${languages[0]}".`),
    files: z
      .array(
        z.object({
          path: z.string().min(1).describe("A relative path, such as data/orders.csv."),
          content: z.string().describe("The file's text."),
        }),
      )
      .max(granted ? MAX_INPUT_FILES - 1 : MAX_INPUT_FILES)
      .optional()
      .describe("Text files written into the working directory before the code runs, for data the code should read."),
  });
}

/** The tool's input after the schema applied its default language. */
export type ExecuteCodeToolInput = z.output<ReturnType<typeof executeCodeInput>>;

export const executeCodeOutput = z.object({
  language: z.string(),
  exitCode: z.number(),
  timedOut: z.boolean(),
  stdout: z.string(),
  stderr: z.string(),
  truncated: z.boolean(),
  stateKept: z.boolean(),
  freshInterpreter: z.literal(true).optional(),
  filesPersist: z.boolean(),
  freshSandbox: z.literal(true).optional(),
  isolation: z.string(),
  isolationQualification: z.string().optional(),
  recordSha256: z.string().regex(/^[0-9a-f]{64}$/),
});
