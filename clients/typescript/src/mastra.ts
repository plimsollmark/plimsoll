// Mastra add-on: the same executeCode tool on the same client, for a Mastra agent.
// Mastra has no hook for "the conversation is going to sleep", so a thread's
// sandbox closes when you call dispose(threadId), or after idleCloseMs without a
// call, whichever comes first.

import { createTool } from "@mastra/core/tools";

import { CodeSandboxes, type CodeSandboxesOptions } from "./sandboxes.ts";
import { executeCodeDescription, executeCodeInput, executeCodeOutput } from "./tool.ts";

export type PlimsollExecuteCodeOptions = CodeSandboxesOptions;

// A thread id is unique only within its resource (the user), so the key is both.
const threadKey = (threadId: string, resourceId = "") => `${resourceId}\u0000${threadId}`;

export function plimsollExecuteCode(opts: PlimsollExecuteCodeOptions) {
  const sandboxes = new CodeSandboxes(opts);

  const executeCode = createTool({
    id: "executeCode",
    description: executeCodeDescription(sandboxes.languages),
    inputSchema: executeCodeInput(sandboxes.languages),
    outputSchema: executeCodeOutput,
    // The thread scopes the sandbox. A call outside a thread runs fresh: one
    // sandbox shared across conversations would show one user another's files.
    execute: async (input, ctx) => {
      const thread = ctx?.agent?.threadId;
      return sandboxes.run(thread ? threadKey(thread, ctx?.agent?.resourceId) : undefined, input, ctx?.abortSignal);
    },
  });

  return {
    executeCode,
    /** Closes a thread's sandbox, e.g. when the conversation ends. */
    dispose: (threadId: string, resourceId?: string) => sandboxes.dispose(threadKey(threadId, resourceId)),
    sandboxes,
  };
}
