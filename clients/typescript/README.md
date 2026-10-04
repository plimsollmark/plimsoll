# @plimsollmark/client

A TypeScript client for `plimsolld`, plus two add-ons that give a chat agent an
`executeCode` tool backed by plimsoll: one for [Trigger.dev](https://trigger.dev) chat
agents and one for [Mastra](https://mastra.ai) agents. Both add-ons sit on the same
client and the same per-conversation sandbox layer, so they behave the same way.

The client has no runtime dependencies (Node >= 22.18). It speaks Connect's JSON
protocol over `fetch` and keeps the promises the Go client keeps:

- it states the protocol number on every request;
- it checks every answer's **run record**: it recomputes the request and result digests
  from what it sent and received ([run-records.md](https://github.com/plimsollmark/plimsoll/blob/main/docs/run-records.md)), and an
  answer that does not check, or has no record, is a `data_loss` error with the result
  attached, because the code may have run;
- it checks the reported isolation tier against the caller's floor the same way;
- in a **session** it tracks the chain of records, so a call made by anyone else who holds
  the session ID is caught at the next call, and at close;
- an error says whether anything ran: `notDispatched` is set only when the daemon stated
  that nothing did, and only then is a retry safe.

The tier it reports is configuration and provider evidence, never runtime attestation
(the README's provider table says what each tier means).

## Install

```sh
npm install @plimsollmark/client
```

The package's version is the plimsoll release it ships in: version X.Y.Z was built and
tested against plimsolld vX.Y.Z. The add-ons need their framework installed beside it:
`@trigger.dev/sdk`, `ai` and `zod` for `/trigger`, `@mastra/core` and `zod` for `/mastra`.

## The client

```ts
import { PlimsollClient } from "@plimsollmark/client";

const plimsoll = new PlimsollClient({ baseUrl: "https://plimsoll.internal:8443", token: process.env.PLIMSOLL_TOKEN });

const info = await plimsoll.describe(); // provider, tier, supportsSessions, ...
const r = await plimsoll.runJavaScript("console.log(6 * 7)", { minimumIsolation: "container", timeoutMs: 10_000 });
r.stdout; // "42\n"; a non-zero r.exitCode is a normal result, not an error

const s = await plimsoll.openSession({ minimumIsolation: "container" }); // docker or openshell
await s.runProject({ files: [{ path: "a.js", content: "console.log(1)" }], steps: ["node a.js"] });
await s.runJavaScript("console.log(require('fs').readdirSync('.'))");
// A cell runs in an interpreter the session keeps alive: what it defines is there next time.
await s.runCell({ language: "python", code: "import csv\nrows = list(csv.reader(open('t.csv')))", files: [{ path: "t.csv", content: "a,b\n1,2\n" }] });
(await s.runCell({ language: "python", code: "len(rows)" })).stdout; // "2\n": the last expression is printed
await s.close(); // checks the daemon's call count against the chain this client saw
```

A cell's `files` are written into the session's work directory, the interpreter's working
directory, before the code runs. Its result adds `interpreterStarted` (this call began with
a fresh interpreter, so nothing defined earlier exists) and `interpreterEnded`; its exit code
is 0 when the code ran, 1 when it raised and 124 at the deadline. Python needs `python3` in
the daemon's image (`plimsoll/sandbox-python` has it, with NumPy and SciPy);
`describe()` lists the languages the daemon proved on `environments.project.languages`.

Cleartext HTTP is accepted only to a loopback address unless you pass `insecureHttp: true`.

## `executeCode` for an agent: `CodeSandboxes`

The `executeCode` tool takes `code`, a `language` (`"python"` or `"javascript"`; the
`languages` option sets which the tool offers and the default, Python first unless you
say otherwise) and optional `files`: text files written into the working directory before
the code runs, so the model can hand the code another tool's output by path instead of
pasting it into the source. The value of the code's last expression is printed, as in a
notebook.

Every call of a conversation runs in the same sandbox, so code one call ran can change what
later calls see: a call's output is only as trustworthy as the calls before it in that
conversation
([what a session gives up](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#what-a-session-gives-up)).
The tool's calls are cells, which carry no grant, so no API access is shared between them.

**The key decides who shares a sandbox, so derive it from identities you verified.** A
sandbox holds one trust domain: everything one call leaves there, later calls with the same
key see. plimsoll ties a session to the credential that opened it, not to the users behind
that credential, so if your service runs many users' code through one plimsoll credential,
two users with the same key share one sandbox, files and variables included. Build the key
from your own authenticated user and conversation (or job) IDs, never from a string a user
or the model supplies, or give each customer a plimsoll credential of their own
([who may share a session](https://github.com/plimsollmark/plimsoll/blob/main/docs/sessions.md#who-may-share-a-session)).

`CodeSandboxes` keeps one sandbox per conversation key. With `sessions: "auto"` (the
default) it asks the daemon once whether it keeps sessions:

- **It does** (`docker` with a project image, or `openshell`, with `SANDBOX_MAX_SESSIONS`
  set): a key holds one plimsoll session, and every call is a cell in that session's
  interpreter. Variables, imports and loaded data from earlier calls are still defined, and
  files stay in the working directory. On one laptop on 2026-10-01, a call that used an
  80 MB array an earlier call had loaded took 10 ms on OpenShell and 23 ms on docker
  under gVisor (medians), against 939 ms and 714 ms for a fresh sandbox that rebuilt it.
- **It does not** (`e2b`, `dockercloud`, `wasm`, or `sessions: "never"`): every call runs in
  a fresh sandbox, as a small project whose runner prints the last expression the same way,
  and nothing persists. `wasm` runs no projects, so there a call is a JavaScript snippet
  printing its last value; Python and files are refused before anything is sent.

The tool's output says which: `stateKept` (this call's interpreter was still running when
it answered, so what it defined can be there for the next call; false when no interpreter is
kept, and when the call's deadline or the sandbox's end ended it) and `filesPersist` (the same
for its sandbox and files). Neither promises the next call anything: the sandbox can still end
between calls, at the end of its lifetime or when the disk check after a call finds it over
its limit. So the output also says what is new, rather than what was lost, because
only the sandbox knows: `freshInterpreter` whenever the call's interpreter had just started
(the first call in a language, a deadline, a crash), so nothing earlier calls defined
exists, and `freshSandbox` whenever the call is the first answered one in a newly opened
sandbox, so no earlier file is there either. That covers a sandbox that `dispose` or the
idle close let go, one that ended by itself (its lifetime, its disk budget), and a
conversation resumed in another process, which this instance cannot tell from a first
call. A call without a key (no thread, no run) always runs fresh: one sandbox shared
across conversations would show one user another's files. A language the daemon's image
cannot run is refused before anything is sent.

Each tool answer also includes `isolation` and `recordSha256`. The client checks
the run record before returning, then gives the tool the checked record's SHA-256.
The digest names that record; it is not a signature or a proof that the guest
computed honestly. See the [Trigger.dev feature and deployment guide](https://github.com/plimsollmark/plimsoll/blob/main/docs/trigger-dev.md)
for the three properties together.

Closing a sandbox checks the daemon's count of calls against the chain the client saw; a
mismatch means the daemon counted a call the client has no answer for (one that ended in an
abort, a timeout, a dropped connection or a proxy's error), or, if none did, that someone
else held the session ID. It goes to `onCloseError` (by default a warning) rather than being
dropped at teardown. A call that may have run but ended in an error comes with its record
(`PlimsollError.unanswered`, a version 3 record); the session checks it, hands it back as
`PlimsollError.record`, keeps it in its chain and goes on, and so does the conversation's
sandbox. A call whose answer never arrived carries none, so the client sends nothing more
on that session (`Session.stopped` says why), and the conversation's next call opens a new
sandbox and reports `freshSandbox: true`. A session call aborted while it waits its turn
was never sent: it is refused, marked not dispatched, and the session goes on. The
`.plimsoll/` directory is the runner's: a file under it is refused before anything is
sent.

The session ID is a capability. It lives in the client's memory and nowhere else: not in
a log line, not in a record, not in Trigger.dev's `chat.local` (which is serialized into
subtask metadata). Records carry its SHA-256.

## Trigger.dev

The add-on follows Trigger.dev's own
[code-sandbox recipe](https://trigger.dev/docs/ai-chat/patterns/code-sandbox): warm in
`onTurnStart`, reuse in `executeCode`, dispose in `onChatSuspend` (right before the run
sleeps) and in `onComplete`.

```ts
import { chat } from "@trigger.dev/sdk/ai";
import { PlimsollClient } from "@plimsollmark/client";
import { plimsollCodeSandbox } from "@plimsollmark/client/trigger";

const sandbox = plimsollCodeSandbox({
  client: () => new PlimsollClient({ baseUrl: process.env.PLIMSOLL_URL!, token: process.env.PLIMSOLL_TOKEN }),
  minimumIsolation: "kernel",
});

export const codeChat = chat.agent({
  id: "code-chat",
  tools: { executeCode: sandbox.executeCode },
  onTurnStart: async ({ runId }) => sandbox.warm(runId),
  onChatSuspend: async ({ runId }) => sandbox.dispose(runId),
  onComplete: async ({ ctx }) => sandbox.dispose(ctx.run.id),
  run: async ({ messages, tools, signal, streamText }) => streamText({ model, messages, tools, abortSignal: signal }),
});
```

The full example, with a test that drives real turns through Trigger.dev's `mockChatAgent`:
[examples/trigger-chat](https://github.com/plimsollmark/plimsoll/tree/main/examples/trigger-chat/).
Its source uses a `container` floor for local development. The
[deployable sister starter](https://github.com/plimsollmark/plimsoll-trigger-starter)
uses `kernel` by default. Hostile production code needs the verified kernel or
VM tier; choose `vm` when the threat model requires a VM boundary, accepting
that current VM providers cannot keep cells.

What the hooks cannot cover: a run that dies without reaching `onChatSuspend` or
`onComplete` (its process killed, a crash) leaves its sandbox open until the add-on's idle
close (`idleCloseMs`, default 10 minutes) or, if the process is gone too, the daemon's own
idle suspend and session lifetime (`SANDBOX_SESSION_IDLE`, `SANDBOX_SESSION_LIFETIME`). A
worker shutting down can close every sandbox it holds with `sandbox.sandboxes.disposeAll()`.

## Mastra

```ts
import { Agent } from "@mastra/core/agent";
import { PlimsollClient } from "@plimsollmark/client";
import { plimsollExecuteCode } from "@plimsollmark/client/mastra";

const { executeCode, dispose } = plimsollExecuteCode({
  client: new PlimsollClient({ baseUrl: process.env.PLIMSOLL_URL!, token: process.env.PLIMSOLL_TOKEN }),
});

export const analyst = new Agent({ id: "analyst", name: "analyst", instructions: "...", model, tools: { executeCode } });
// When a conversation ends: await dispose(threadId, resourceId);
```

The sandbox is keyed by Mastra's thread and resource (a thread ID is unique only within
its user). A call without a `resourceId` runs in a fresh sandbox every time: under an empty
resource, every user without one would share a sandbox with anyone whose thread ID
collided. Set the resource from your authenticated user, not from anything the user
typed. Mastra has no hook for "this conversation is going to sleep", so a thread's
sandbox closes on `dispose(threadId, resourceId)`, or after `idleCloseMs` (default 10
minutes) without a call.

## Tests

`go test ./clients/typescript/` serves the real RPC handler (the wasm provider for single
runs, an in-memory session provider for sessions and cells, and a provider that answers a
project with the plan it received, for the project a fresh call sends) and runs three
suites against them: the
client's (needs only node), the add-ons' (needs `npm install` here), and the Trigger.dev
example's (needs `npm install` in `examples/trigger-chat`; it waits out Trigger.dev's
30-second idle window to prove the suspend closes the sandbox). An ordinary Go test
skips a suite whose runtime or dependencies are absent. CI runs `make clients-suite`,
which installs both npm lockfiles and sets `PLIMSOLL_REQUIRE_CLIENTS=1`, so a missing
prerequisite or skipped Go test fails. The client's digests are also checked against the
golden vectors of `record/record_test.go`, and the fresh-run runners are run on this
machine's `node` and `python3` to check they print the last expression.
