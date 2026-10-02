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

import { chat } from "@trigger.dev/sdk/ai";
import { stepCountIs } from "ai";
import { PlimsollClient } from "@plimsollmark/client";
import { plimsollCodeSandbox } from "@plimsollmark/client/trigger";

import { models } from "./models.ts";

const sandbox = plimsollCodeSandbox({
  // Built on first use, so indexing the task at deploy time needs no secrets.
  client: () =>
    new PlimsollClient({
      baseUrl: process.env.PLIMSOLL_URL ?? "",
      token: process.env.PLIMSOLL_TOKEN,
    }),
  // Refused before dispatch on a daemon whose provider reports less.
  minimumIsolation: "container",
  timeoutMs: 30_000,
});

export const codeChat = chat.agent({
  id: "code-chat",
  tools: { executeCode: sandbox.executeCode },
  onTurnStart: async ({ runId }) => {
    sandbox.warm(runId);
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
