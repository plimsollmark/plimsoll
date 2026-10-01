// Trigger.dev add-on: the code-sandbox recipe from Trigger.dev's own docs
// (https://trigger.dev/docs/ai-chat/patterns/code-sandbox) with plimsoll as the
// sandbox. Warm in onTurnStart without blocking, reuse for every executeCode call,
// dispose in onChatSuspend (right before the run sleeps) and in onComplete.
//
// The sandboxes live in this module's memory, keyed by run id; chat.local holds
// only the run id, because Trigger.dev serializes chat.local into subtask
// metadata and a session ID is a capability that must stay in this process.

import { chat } from "@trigger.dev/sdk/ai";
import { tool, type Tool } from "ai";

import { CodeSandboxes, type CodeSandboxesOptions, type ExecuteCodeOutput } from "./sandboxes.ts";
import { executeCodeDescription, executeCodeInput, type ExecuteCodeToolInput } from "./tool.ts";

export type PlimsollCodeSandboxOptions = CodeSandboxesOptions & {
  /** The chat.local id; unique across your project's chat.local() calls. */
  localId?: string;
};

export type PlimsollCodeSandbox = {
  /** The AI SDK tool to pass to streamText's tools. */
  executeCode: Tool<ExecuteCodeToolInput, ExecuteCodeOutput>;
  /** Call from onTurnStart: records the run id for the tool and starts the sandbox without waiting. */
  warm(runId: string): void;
  /** Call from onChatSuspend and onComplete. */
  dispose(runId: string): Promise<void>;
  sandboxes: CodeSandboxes;
};

export function plimsollCodeSandbox(opts: PlimsollCodeSandboxOptions): PlimsollCodeSandbox {
  const sandboxes = new CodeSandboxes(opts);
  const current = chat.local<{ runId: string }>({ id: opts.localId ?? "plimsollCodeSandbox" });

  function warm(runId: string): void {
    current.init({ runId });
    sandboxes.warm(runId);
  }

  function dispose(runId: string): Promise<void> {
    return sandboxes.dispose(runId);
  }

  const executeCode = tool({
    description: executeCodeDescription(sandboxes.languages),
    inputSchema: executeCodeInput(sandboxes.languages),
    execute: async (input, { abortSignal }) => sandboxes.run(current.get().runId, input, abortSignal),
  });

  return { executeCode, warm, dispose, sandboxes };
}
