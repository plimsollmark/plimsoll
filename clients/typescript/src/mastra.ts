// Mastra add-on: the same executeCode tool on the same client, for a Mastra agent.
// Mastra has no hook for "the conversation is going to sleep", so a thread's
// sandbox closes when you call dispose(threadId), or after idleCloseMs without a
// call, whichever comes first.

import { createTool, type ToolExecutionContext } from "@mastra/core/tools";

import { CodeSandboxes, type CodeSandboxesOptions, type SandboxKey } from "./sandboxes.ts";
import { executeCodeDescription, executeCodeInput, executeCodeOutput } from "./tool.ts";

export type PlimsollExecuteCodeOptions = CodeSandboxesOptions & {
  /**
   * The user a call belongs to, from your app's own authentication (a value your server
   * put in Mastra's requestContext, say). Default: the call's resourceId. Set it for an
   * agent network: Mastra fills a missing resourceId with the network's name, so every
   * user of the network would count as one owner under maxSessionsPerOwner and the
   * daemon's SANDBOX_MAX_SESSIONS_PER_OWNER, and close each other's sandboxes. Pass the
   * same owner to dispose.
   */
  owner?: (ctx: ToolExecutionContext) => string | undefined;
};

// A thread id is unique only within its resource (the user), so the key is both, the
// resource as the owner the per-user cap counts, and a call without either has no key
// and runs fresh. An empty resource would put every user without one whose thread id
// collided into one sandbox, with each other's files and variables. An owner of the
// app's own replaces the resource as what the caps count, and the conversation keeps
// both IDs, so the sandbox is still the resource's thread's.
const threadKey = (threadId: string | undefined, resourceId: string | undefined, owner?: string): SandboxKey | undefined =>
  !threadId || !resourceId
    ? undefined
    : owner === undefined
      ? { owner: resourceId, conversation: threadId }
      : { owner, conversation: JSON.stringify([resourceId, threadId]) };

export function plimsollExecuteCode(opts: PlimsollExecuteCodeOptions) {
  const sandboxes = new CodeSandboxes(opts);

  const executeCode = createTool({
    id: "executeCode",
    description: executeCodeDescription(sandboxes.languages),
    inputSchema: executeCodeInput(sandboxes.languages),
    outputSchema: executeCodeOutput,
    // The user's thread scopes the sandbox. A call outside a thread, or without a
    // resource, runs fresh: one sandbox shared across conversations would show one user
    // another's files. The key is read inside run, so an owner resolver that throws is
    // refused as nothing ran.
    execute: async (input, ctx) =>
      sandboxes.run(() => threadKey(ctx?.agent?.threadId, ctx?.agent?.resourceId, ctx && opts.owner ? opts.owner(ctx) : undefined), input, ctx?.abortSignal),
  });

  return {
    executeCode,
    /** Closes a user's thread's sandbox, e.g. when the conversation ends; owner is the one the option gave. */
    dispose: async (threadId: string, resourceId: string, owner?: string) => {
      const key = threadKey(threadId, resourceId, owner);
      if (key !== undefined) await sandboxes.dispose(key);
    },
    sandboxes,
  };
}
