// Mastra add-on: the same executeCode tool on the same client, for a Mastra agent.
// Mastra has no hook for "the conversation is going to sleep", so a thread's
// sandbox closes when you call dispose(threadId), or after idleCloseMs without a
// call, whichever comes first.

import { createTool } from "@mastra/core/tools";

import { CodeSandboxes, type CodeSandboxesOptions } from "./sandboxes.ts";
import { executeCodeDescription, executeCodeInput, executeCodeOutput } from "./tool.ts";

export type PlimsollExecuteCodeOptions = CodeSandboxesOptions;

// A thread id is unique only within its resource (the user), so the key is both, and a
// call without either has no key and runs fresh. An empty resource would put every user
// without one whose thread id collided into one sandbox, with each other's files and
// variables. The pair is encoded as JSON, not joined with a separator: a resource ending
// in the separator and a thread starting with it would name another user's key.
const threadKey = (threadId: string | undefined, resourceId: string | undefined) =>
  threadId && resourceId ? JSON.stringify([resourceId, threadId]) : undefined;

export function plimsollExecuteCode(opts: PlimsollExecuteCodeOptions) {
  const sandboxes = new CodeSandboxes(opts);

  const executeCode = createTool({
    id: "executeCode",
    description: executeCodeDescription(sandboxes.languages),
    inputSchema: executeCodeInput(sandboxes.languages),
    outputSchema: executeCodeOutput,
    // The user's thread scopes the sandbox. A call outside a thread, or without a
    // resource, runs fresh: one sandbox shared across conversations would show one user
    // another's files.
    execute: async (input, ctx) => sandboxes.run(threadKey(ctx?.agent?.threadId, ctx?.agent?.resourceId), input, ctx?.abortSignal),
  });

  return {
    executeCode,
    /** Closes a user's thread's sandbox, e.g. when the conversation ends. */
    dispose: async (threadId: string, resourceId: string) => {
      const key = threadKey(threadId, resourceId);
      if (key !== undefined) await sandboxes.dispose(key);
    },
    sandboxes,
  };
}
