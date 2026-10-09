// Trigger.dev add-on: the code-sandbox recipe from Trigger.dev's own docs
// (https://trigger.dev/docs/ai-chat/patterns/code-sandbox) with plimsoll as the
// sandbox. Warm in onTurnStart without blocking, reuse for every executeCode call,
// dispose in onChatSuspend (right before the run sleeps) and in onComplete.
//
// The sandboxes live in this module's memory, keyed by run id (and the run's owner,
// when warm names one); chat.local holds only the run id, because Trigger.dev
// serializes chat.local into subtask metadata, a session ID is a capability that must
// stay in this process, and the owner is a user's identity.

import { chat } from "@trigger.dev/sdk/ai";
import { tool, type Tool } from "ai";

import { CodeSandboxes, type CodeSandboxesOptions, type ExecuteCodeOutput, type SandboxKey } from "./sandboxes.ts";
import { executeCodeDescription, executeCodeInput, type ExecuteCodeToolInput } from "./tool.ts";

export type PlimsollCodeSandboxOptions = CodeSandboxesOptions & {
  /** The chat.local id; unique across your project's chat.local() calls. */
  localId?: string;
};

export type PlimsollCodeSandbox = {
  /** The AI SDK tool to pass to streamText's tools. */
  executeCode: Tool<ExecuteCodeToolInput, ExecuteCodeOutput>;
  /**
   * Call from onTurnStart: records the run id for the tool and starts the sandbox
   * without waiting. owner is the user the chat belongs to, as your server
   * authenticated it (never clientData, which the browser sets: a user who could
   * choose it could close another user's sandboxes). With it, maxSessionsPerOwner
   * counts this worker's sandboxes per user, and a daemon with
   * SANDBOX_MAX_SESSIONS_PER_OWNER counts them across every worker.
   */
  warm(runId: string, owner?: string): void;
  /** Call from onChatSuspend and onComplete. */
  dispose(runId: string): Promise<void>;
  sandboxes: CodeSandboxes;
};

export function plimsollCodeSandbox(opts: PlimsollCodeSandboxOptions): PlimsollCodeSandbox {
  const sandboxes = new CodeSandboxes(opts);
  const current = chat.local<{ runId: string }>({ id: opts.localId ?? "plimsollCodeSandbox" });
  // The owner warm named for each run, in this module's memory only.
  const owners = new Map<string, string>();
  const keyOf = (runId: string): SandboxKey => {
    const owner = owners.get(runId);
    return owner === undefined ? runId : { owner, conversation: runId };
  };

  function warm(runId: string, owner?: string): void {
    current.init({ runId });
    if (owner !== undefined) owners.set(runId, owner);
    sandboxes.warm(keyOf(runId));
  }

  async function dispose(runId: string): Promise<void> {
    const key = keyOf(runId);
    owners.delete(runId);
    await sandboxes.dispose(key);
  }

  const executeCode = tool({
    description: executeCodeDescription(sandboxes.languages),
    inputSchema: executeCodeInput(sandboxes.languages),
    // The key is read inside run, so a turn whose onTurnStart never warmed (chat.local
    // then has no run id) is refused as nothing ran, with the lead the model needs.
    execute: async (input, { abortSignal }) => sandboxes.run(() => keyOf(current.get().runId), input, abortSignal),
  });

  return { executeCode, warm, dispose, sandboxes };
}
