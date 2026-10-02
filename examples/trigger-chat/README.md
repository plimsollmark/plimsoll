# A Trigger.dev chat agent with an executeCode tool

[`src/trigger/chat.ts`](src/trigger/chat.ts) is a `chat.agent` written on Trigger.dev's
own [code-sandbox recipe](https://trigger.dev/docs/ai-chat/patterns/code-sandbox), with
plimsoll as the sandbox instead of a hosted one:

| Hook | What happens |
|---|---|
| `onTurnStart` | the run's sandbox is warmed without blocking the turn |
| `executeCode` | every call in the turn, and in later turns of the same run, reuses it and its interpreter |
| `onChatSuspend` | it is closed right before the run sleeps waiting for the next message |
| `onComplete` | it is closed if the run ends instead |

The tool comes from [`@plimsollmark/client/trigger`](../../clients/typescript/), which sits on
the same client and per-conversation layer as the Mastra add-on.

## What the tool gives the model

`executeCode` takes Python (the default) or JavaScript, and optional files: the model
hands the code another tool's output as a file it reads by path, instead of pasting it
into the source. The value of the last expression is printed, as in a notebook.

The recipe keeps one sandbox per run. plimsoll does that with a **session**
([sessions.md](../../docs/sessions.md)), which the `docker` provider (with a project image)
and the `openshell` provider keep. In a session every call is a **cell**: it runs in a
Python or Node.js interpreter that stays alive between calls, so a table the model loaded
in one call is still in memory in the next, as it would be in a notebook, and files stay
in the working directory. The tool's output says so (`stateKept`, `filesPersist`), and says
when a call starts from nothing (`freshInterpreter`, `freshSandbox`): the recipe disposes
the sandbox when the chat suspends, so the first call of a resumed turn reports both.

On a provider without sessions (`e2b`, `dockercloud`) the agent still works, and each call
starts a fresh sandbox; the tool's `stateKept: false` and `filesPersist: false` tell the
model nothing carried over. `docker` under gVisor (`SANDBOX_DOCKER_RUNTIME=runsc`) keeps
sessions at the `kernel` tier.

## Run it

1. A plimsolld with sessions on, for example docker under gVisor with the Python image
   (`make docker-images` builds it):

   ```sh
   SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc \
   SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest SANDBOX_MAX_SESSIONS=32 \
   PLIMSOLL_CLIENTS_FILE=clients.json go run ./cmd/plimsolld
   ```

   or the openshell provider ([openshell.md](../../docs/openshell.md) for the gateway
   settings).

2. In this directory, `npm install` (the `.npmrc` installs the client as a copy, so it
   shares the example's `ai` and Trigger.dev packages), then set on the Trigger.dev
   environment: `PLIMSOLL_URL`, `PLIMSOLL_TOKEN` (a caller with `code:run`) and
   `ANTHROPIC_API_KEY`, plus `TRIGGER_PROJECT_REF` for `trigger.config.ts`.
3. `npm run dev`, and connect a frontend with Trigger.dev's chat transport
   ([frontend docs](https://trigger.dev/docs/ai-chat/frontend)).

The `minimumIsolation: "container"` in `chat.ts` makes the daemon refuse, before running
anything, if its provider reports less (the `wasm` provider is `process`). Raise it to
`kernel` or `vm` to require those, at the cost of sessions.

## Test

`go test ./clients/typescript/` (from the repository root) serves a daemon whose sessions
are an in-memory fake and runs [`chat.test.ts`](src/trigger/chat.test.ts): Trigger.dev's
`mockChatAgent` drives two turns with a scripted model that calls `executeCode` three
times, the first with a CSV file. It checks that one interpreter served all three calls
across both turns, that the file reached it, and, after Trigger.dev's 30-second idle
window, that `onChatSuspend` closed the sandbox. The harness does not
run task-level `onComplete`, so that hook is not exercised.
