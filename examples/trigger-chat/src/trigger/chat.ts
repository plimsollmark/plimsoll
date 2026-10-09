// A chat agent with an executeCode tool, written on Trigger.dev's own
// code-sandbox recipe (https://trigger.dev/docs/ai-chat/patterns/code-sandbox),
// with plimsoll as the sandbox:
//
//   onTurnStart    warm the sandbox without blocking the turn
//   executeCode    every call in the turn (and later turns of the run) reuses it
//   onChatSuspend  dispose it right before the run sleeps for the next message
//   onComplete     dispose it if the run ends instead
//
// On a daemon that keeps sessions (docker with a project image, or openshell) the
// run gets one sandbox, created once, with a Python and a JavaScript interpreter
// that stay alive between calls: a variable or a loaded table from one call is
// still there in the next, and the files a call is handed (another tool's output,
// say) stay in its working directory. On any other provider each call starts a
// fresh sandbox and the tool's output says nothing was kept. The client checks
// every answer's run record and isolation evidence.

import { chat, type TurnStartEvent } from "@trigger.dev/sdk/ai";
import { stepCountIs } from "ai";
import { PlimsollClient } from "@plimsollmark/client";
import { plimsollCodeSandbox } from "@plimsollmark/client/trigger";

import { models } from "./models.ts";

/** What owner is given: the parts of onTurnStart's event that can name the run's user. */
export type OwnerEvent = Pick<TurnStartEvent, "runId" | "chatId" | "ctx">;

// codeChatAgent builds the agent. idleTimeoutInSeconds is how long a run waits for the
// next message before it suspends, which is when onChatSuspend closes the sandbox;
// unset, it is Trigger.dev's default of 30. The test builds one with a few seconds,
// so its check of the suspend does not wait half a minute of real time.
//
// owner, when given, names the user each run belongs to, as your server authenticated
// it. It gets the turn's runId, chatId and ctx, the task run context. Look the chat's
// user up in your own database by chatId, or read a tag of ctx.run.tags that your
// server set itself when it started the session: chat.createStartSessionAction's
// helper shallow-merges a per-call triggerConfig over its default, so call it from
// your own server action with the authenticated user's tag, never with a
// triggerConfig the browser sent, or the browser chooses the tag. Never use
// clientData, which the browser sets: it is left out of the event on purpose. The
// owner caps that user's sandboxes: 3 per worker by default, and across every worker
// when the daemon sets SANDBOX_MAX_SESSIONS_PER_OWNER. Without it the run id is the
// only key, and no per-user cap applies.
export function codeChatAgent(options: { id?: string; idleTimeoutInSeconds?: number; owner?: (event: OwnerEvent) => string | undefined } = {}) {
  const sandbox = plimsollCodeSandbox({
    // Built on first use, so indexing the task at deploy time needs no secrets.
    client: () =>
      new PlimsollClient({
        baseUrl: process.env.PLIMSOLL_URL ?? "",
        token: process.env.PLIMSOLL_TOKEN,
      }),
    // For local development only, so the example runs on an ordinary docker daemon
    // (runc, the container tier). Production must delete this line and keep the
    // add-on's default, kernel (a verified gVisor runtime), the weakest tier this
    // project treats as fit for code a model wrote, or set "vm". A daemon below the
    // floor is refused before anything runs.
    minimumIsolation: "container",
    timeoutMs: 30_000,
  });

  return chat.agent({
    id: options.id ?? "code-chat",
    idleTimeoutInSeconds: options.idleTimeoutInSeconds,
    tools: { executeCode: sandbox.executeCode },
    onTurnStart: async ({ runId, chatId, ctx }) => {
      sandbox.warm(runId, options.owner?.({ runId, chatId, ctx }));
    },
    onChatSuspend: async ({ runId }) => {
      await sandbox.dispose(runId);
    },
    onComplete: async ({ ctx }) => {
      await sandbox.dispose(ctx.run.id);
    },
    run: async ({ messages, tools, signal, streamText }) =>
      streamText({
        model: models.chat(),
        system:
          "You are a careful analyst. When a question needs arithmetic, parsing or data analysis, " +
          "write Python and run it with executeCode instead of computing in your head. Load data once: " +
          "variables you define stay defined in later calls while stateKept is true, until a result says " +
          "freshInterpreter (rebuild them) or freshSandbox (earlier files are gone too).",
        messages,
        tools,
        stopWhen: stepCountIs(10),
        abortSignal: signal,
      }),
  });
}

export const codeChat = codeChatAgent();
