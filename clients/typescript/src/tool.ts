// The executeCode tool's model-facing surface, shared by the add-ons so the
// Trigger.dev and Mastra tools describe the same thing in the same words.

import { z } from "zod";

import type { Language } from "./client.ts";
import { DEFAULT_LANGUAGES, type ToolLanguages } from "./sandboxes.ts";

const NAMES: Record<Language, string> = { python: "Python", javascript: "JavaScript (Node.js)" };

/** The tool's description for the languages it offers. */
export function executeCodeDescription(languages: ToolLanguages = DEFAULT_LANGUAGES): string {
  const names = languages.map((l) => NAMES[l]).join(" or ");
  return (
    `Run ${names} in an isolated sandbox with no network access (beyond any API the operator granted it) and return its exit code, stdout and stderr. ` +
    "The value of the code's last expression is printed, as in a notebook, so the last line can simply name what you want to see. " +
    "Within one conversation the sandbox usually keeps an interpreter per language between calls, so variables, functions, imports and loaded data " +
    "from earlier calls are still defined: the result's stateKept says whether this call's interpreter was still running when it answered, so what it defined can still be there " +
    "for the next call (false when its deadline ended the interpreter, or the sandbox ended). freshInterpreter means " +
    "this call's interpreter had just started, so nothing earlier calls defined exists and has to be rebuilt; freshSandbox means no file from " +
    "earlier calls is there either. " +
    "To give the code data, such as another tool's output, pass it in files rather than pasting it into the code; the code reads each file by its relative path. " +
    "Files written to the working directory can still be there on the next call when filesPersist is true; freshSandbox on that call says they are not."
  );
}

/** The tool's input schema for the languages it offers. */
export function executeCodeInput(languages: ToolLanguages = DEFAULT_LANGUAGES) {
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
      .max(200)
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
});
