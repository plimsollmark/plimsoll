// Vercel AI SDK tools over the shared checked client and sandbox manager.
// Only this optional entry point imports AI SDK and its schema dependency.

import { tool, type Tool } from "ai";

import { PlimsollError } from "./errors.ts";
import { CodeSandboxes, type CodeSandboxesOptions, type ExecuteCodeOutput, type SandboxKey } from "./sandboxes.ts";
import { executeCodeDescription, executeCodeInput, type ExecuteCodeToolInput } from "./tool.ts";

/** Application-owned identity, never fields of a model-generated tool call. */
export type ConversationScope = { userId: string; conversationId: string };
export type PlimsollCodeTool = Tool<ExecuteCodeToolInput, ExecuteCodeOutput>;
export type PlimsollCodeTools = {
  executeCode: PlimsollCodeTool;
  forConversation: (scope: ConversationScope) => PlimsollCodeTool;
  warm: (scope: ConversationScope) => void;
  dispose: (scope: ConversationScope) => Promise<void>;
  disposeAll: () => Promise<void>;
  sandboxes: CodeSandboxes;
};

function scopeKey(scope: ConversationScope): SandboxKey {
  if (!scope || typeof scope.userId !== "string" || !scope.userId || typeof scope.conversationId !== "string" || !scope.conversationId) {
    throw new PlimsollError("invalid_argument", "plimsoll: a conversation requires nonempty userId and conversationId from the application", {
      notDispatched: "request",
    });
  }
  // The user is the owner the sandboxes' per-user cap counts.
  return { owner: scope.userId, conversation: scope.conversationId };
}

/**
 * Create once per process and bind tools to authenticated conversation identities.
 * The unscoped executeCode always runs fresh. A scoped tool keeps interpreter state
 * only when the daemon supports sessions, and reports that capability in each result.
 * Default floor: verified kernel isolation, or a stronger VM boundary.
 */
export function plimsollCodeTools(opts: CodeSandboxesOptions): PlimsollCodeTools {
  const sandboxes = new CodeSandboxes(opts);
  const makeTool = (key?: SandboxKey): PlimsollCodeTool => {
    const scope = key === undefined || opts.sessions === "never" ? "fresh" : "conversation";
    return tool({
      description: (scope === "conversation"
        ? "State is kept only if the daemon keeps sessions; otherwise every call runs fresh. "
        : "") + executeCodeDescription(sandboxes.languages, scope),
      inputSchema: executeCodeInput(sandboxes.languages),
      execute: async (input, { abortSignal }) => sandboxes.run(key, input, abortSignal),
    });
  };

  return {
    /** No conversation identity: no retained files or interpreter between calls. */
    executeCode: makeTool(),
    /** Bind to IDs read by the application from its authenticated request or session. */
    forConversation: (scope: ConversationScope) => makeTool(scopeKey(scope)),
    /** Begin opening a supported session; subsequent execution waits for readiness. */
    warm: (scope: ConversationScope) => sandboxes.warm(scopeKey(scope)),
    /** Close the conversation's sandbox when the application ends it. */
    dispose: (scope: ConversationScope) => sandboxes.dispose(scopeKey(scope)),
    /** Close every held sandbox, for example during application shutdown. */
    disposeAll: () => sandboxes.disposeAll(),
    sandboxes,
  };
}
