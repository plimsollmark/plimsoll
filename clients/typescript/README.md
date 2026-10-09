# @plimsollmark/client

A TypeScript client for `plimsolld`, plus three add-ons that give an agent an
`executeCode` tool backed by plimsoll: one for the [Vercel AI SDK](https://ai-sdk.dev),
one for [Trigger.dev](https://trigger.dev) chat agents and one for
[Mastra](https://mastra.ai) agents. All three sit on the same client and the same
per-conversation sandbox layer, so they behave the same way.

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
`ai` and `zod` for `/ai-sdk`, `@trigger.dev/sdk`, `ai` and `zod` for `/trigger`, `@mastra/core` and `zod` for `/mastra`.

This package has no dependencies, so it brings nothing into your installation; the
frameworks do. One worth knowing about: `@trigger.dev/sdk` 4.7 pins `socket.io-client`
4.7.5, whose `engine.io-client` resolves a `ws` affected by two advisories fixed in 8.21.0
([GHSA-58qx-3vcg-4xpx and GHSA-96hv-2xvq-fx4p, EXTERNAL · advisory ↗](https://github.com/advisories/GHSA-96hv-2xvq-fx4p)).
npm applies `overrides` only from your application's own `package.json`, so this
package's override cannot reach your installation. Until Trigger.dev moves, add one
there, as this repository's tests do:

```json
"overrides": { "engine.io-client": "^6.6.7" }
```

## The client

```ts
import { PlimsollClient } from "@plimsollmark/client";

const plimsoll = new PlimsollClient({ baseUrl: "https://plimsoll.internal:8443", token: process.env.PLIMSOLL_TOKEN });

const info = await plimsoll.describe(); // provider, tier, supportsSessions, ...
const r = await plimsoll.runJavaScript("console.log(6 * 7)", { minimumIsolation: "container", timeoutMs: 10_000 });
r.stdout; // "42\n"; a non-zero r.exitCode is a normal result, not an error

const s = await plimsoll.openSession({ minimumIsolation: "container" }); // docker, openshell or e2b
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

`close()` sends one `CloseSession` however many times it is called, and every later call
gets the first one's summary or error: the daemon forgets a session at its first close and
would answer a second with NotFound. A close refused not dispatched (aborted before it was
sent, say) closed nothing, so a later `close()` tries again.

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

A key is a `SandboxKey`: either a string (the Trigger.dev add-on passes its run ID) or
`{ owner, conversation }`, the user a conversation belongs to and the conversation's ID
(the AI SDK add-on passes `{ owner: userId, conversation: conversationId }`, the Mastra
add-on `{ owner: resourceId, conversation: threadId }`). The parts are encoded as a JSON
array, never joined with a separator, so no user's IDs can spell another user's key or a
string key. The owner is what `maxSessionsPerOwner` counts (below).

**The floor defaults to `kernel`.** `minimumIsolation` is the weakest isolation tier a call
accepts: the daemon refuses, before anything runs, a call whose floor its tier does not meet,
and the client checks the tier stated on the answer. `CodeSandboxes`, and so every add-on
on it, defaults to `kernel` (docker running gVisor's `runsc` runtime, which the daemon's
startup checks verified; the stronger `vm` tier also meets it) because it is the weakest
tier this project treats as fit for code you did not write. An ordinary docker daemon (runc) is the `container` tier and refuses every
call under the default: set `minimumIsolation: "container"` for local development on your
own code. Set `"vm"` when the threat model needs a virtual-machine boundary; of today's VM
providers `e2b` keeps sessions (a suspend ends its interpreters, so the next call reports
`freshInterpreter`) and `dockercloud` keeps none, so every call there runs fresh.

`CodeSandboxes` keeps one sandbox per conversation key. With `sessions: "auto"` (the
default) it asks the daemon whether it keeps sessions (`describe()`), keeps the answer, and
asks again after a call refused for a reason that says the daemon may have changed since
(`notDispatched` `unsupported`, `environment`, `protocol` or `isolation`: a restart with
sessions turned on or off, another image or tier), never after a `capacity` or `request`
refusal:

- **It does** (`docker` with a project image, `openshell` or `e2b`, with
  `SANDBOX_MAX_SESSIONS` set; on `e2b` a suspend ends the interpreters, so the next call
  reports `freshInterpreter`): a key holds one plimsoll session, and every call is a cell in that session's
  interpreter. Variables, imports and loaded data from earlier calls are still defined, and
  files stay in the working directory. On one laptop on 2026-10-01, a call that used an
  80 MB array an earlier call had loaded took 10 ms on OpenShell and 23 ms on docker
  under gVisor (medians), against 939 ms and 714 ms for a fresh sandbox that rebuilt it.
- **It does not** (`dockercloud`, `wasm`, a daemon with sessions off, or `sessions: "never"`): every call runs in
  a fresh sandbox, as a small project whose runner prints the last expression the same way,
  and nothing persists. `wasm` runs no projects, so there a call is a JavaScript snippet
  printing its last value; Python and files are refused before anything is sent.

A fresh project run (every call on a daemon without sessions, and a call without a key on
any daemon) whose result has no step report has no exit code to give: its outcome, such as
`timed_out` or `protocol_error`, says what ended the run but not whether the code had
started. So the tool throws instead of inventing an exit code: a `PlimsollError` (code
`unknown`) with no `notDispatched` mark, because the code may have run, and the checked
result on `PlimsollError.result`. Nothing retries it, since running it again could repeat
what it did.

A framework hands its model only an error's message, so every error the tool throws is a
`PlimsollError` whose message starts with whether the code ran: `Nothing ran (<reason>): `
when it carries a `notDispatched` mark (a refusal, a cap, a cancel before sending), and `The
code may have run, and there is no checked answer for it: ` otherwise. Where the call
failed decides the mark, not who raised the error: everything before the code is sent
(reading the key, building the client, the Describe, opening the sandbox) runs nothing, so
a failure there is marked even when the daemon could not mark it (unreachable, a proxy's
503, a dropped connection, the client's own check of the session it opened), with reason
`environment` unless the daemon gave one. An error of another class there (a key or owner
resolver of the app's that throws) is wrapped the same way. From the moment the code may
have been sent, an unmarked error stays unmarked.

The tool's output says which: `stateKept` (this call's interpreter was still running when
it answered, so what it defined can be there for the next call; false when no interpreter is
kept, and when the call's deadline or the sandbox's end ended it) and `filesPersist` (the same
for its sandbox and files). Neither promises the next call anything: the sandbox can still end
between calls, at the end of its lifetime or when the disk check after a call finds it over
its limit. So the output also says what is new, rather than what was lost, because
only the sandbox knows: `freshInterpreter` whenever the call's interpreter had just started
(the first call in a language, a deadline, a crash), so nothing earlier calls defined
exists, and `freshSandbox` whenever the call is the first answered one in a newly opened
sandbox, so no earlier file is there either. That covers a sandbox that `dispose`, the
idle close or a session cap (below) let go, one that ended by itself (its lifetime, its disk
budget), and a conversation resumed in another process, which this instance cannot tell
from a first call. A call without a key (no thread, no run) always runs fresh: one sandbox
shared across conversations would show one user another's files. A language the daemon's
image cannot run is refused before anything is sent. Output past `maxOutputChars` (each of
stdout and stderr) is cut and marked truncated, and a cut never ends on the first half of a
surrogate pair (the two UTF-16 code units that encode one character such as an emoji): a
lone half is not valid Unicode, and a strict model provider can refuse the request that
carries it back.

**Every kept sandbox holds one of the daemon's session slots** (`SANDBOX_MAX_SESSIONS`), and
every user of an app that shares one plimsoll token draws on the same slots. Two caps keep
one user, or one app, from holding them all:

- `maxSessionsPerOwner` (default 3; 0 for no cap): the sandboxes one owner may hold in this
  instance. When the owner already holds that many, opening another of the owner's
  conversations first closes the owner's least recently used sandbox with no call in flight (least recently used: the one whose last call
  started or ended longest ago), and that conversation's next call opens a new sandbox and
  reports `freshSandbox: true`. Three, because a person rarely works in more than a few
  conversations at once, and the closed conversation loses its variables and files, never
  an answer. If every one of the owner's sandboxes has a call in flight, the new
  conversation's call is refused before anything opens (`PlimsollError` code
  `resource_exhausted`, `notDispatched: "capacity"`). A string key names no owner and is not
  counted here.
- `maxSessions` (default 0, no cap of its own): the same across all owners and string keys.
  Set it to this app's share of the daemon's `SANDBOX_MAX_SESSIONS`, a number only the
  daemon's operator knows.

A `warm` is a guess (Trigger.dev's recipe warms in every new run's `onTurnStart`, a chat the
user opened and never typed in included), so it never closes a sandbox to make room: when
either cap is reached it does nothing, and the conversation's first call opens its sandbox,
closing the least recently used idle one as any call does.

Both caps count what one process holds. A host that runs many processes (serverless
functions, several Trigger.dev workers) keeps one count per process, so set the daemon's
`SANDBOX_MAX_SESSIONS_PER_OWNER`, which counts them all: every open names the key's owner
to the daemon (`openSession({ owner })`, sent as a hex HMAC-SHA256 of the owner under a key derived from
the client's token (SHA-256 of a fixed prefix and the token), so the ID itself never leaves the process and the daemon, which stores
only the token's SHA-256, cannot test a guessed one). Omit `owner` for none: an empty
string is refused before anything is sent (`invalid_argument`, `notDispatched:
"request"`), because sent as no owner it would escape the cap. At that cap the daemon closes the
owner's least recently used session with no call in progress; its next call is refused as
`replaced` (not dispatched), and `CodeSandboxes` runs it once more in a new sandbox, saying
`freshSandbox: true`. The daemon cannot tell a warm from a call's open, so a warm that opens
counts there like any open, and at that cap closes the user's least recently used session,
which may be a conversation in use in another process. `SANDBOX_MAX_SESSIONS` and `SANDBOX_MAX_SESSIONS_PER_CALLER` still
bound the daemon and each caller token. A daemon at either of those refuses the
open (not dispatched, reason `capacity`), and the client does not close sandboxes in
response, because the daemon gives the same refusal for a caller over its rate limit, which
a close would not help.

Each tool answer also includes `isolation` and `recordSha256`. The client checks
the run record before returning, then gives the tool the checked record's SHA-256.
The digest names that record; it is not a signature or a proof that the guest
computed honestly. See the [Trigger.dev feature and deployment guide](https://github.com/plimsollmark/plimsoll/blob/main/docs/trigger-dev.md)
for the three properties together.

Closing a sandbox checks the daemon's count of calls against the chain the client saw; a
mismatch means the daemon counted a call the client has no answer for (one that ended in an
abort, a timeout, a dropped connection or a proxy's error), or, if none did, that someone
else held the session ID. It goes to `onCloseError(key, err)` rather than being dropped at
teardown; `key` is the `SandboxKey` as the add-on passed it (the `{ owner, conversation }`
object for a pair). Without `onCloseError`, a `console.warn` names the key only by the first
12 hex digits of its SHA-256 fingerprint, enough to tell one conversation's lines from
another's, never by its IDs, because a key can hold a user's ID (an email address, in some
apps). An `onCloseError` that throws, or returns a promise that rejects, is logged the same
way: an app's reporting never stops a close, or the open that waited for one to make room. A call that may have run but ended in an error comes with its record
(`PlimsollError.unanswered`, a version 3 record); the session checks it, hands it back as
`PlimsollError.record`, keeps it in its chain and goes on, and so does the conversation's
sandbox. A call whose answer never arrived carries none, so the client sends nothing more
on that session (`Session.stopped` says why), and the conversation's next call opens a new
sandbox and reports `freshSandbox: true`. A session call aborted while it waits its turn
was never sent: it is refused, marked not dispatched, and the session goes on. A call
aborted before or while its sandbox opens sends nothing either (`PlimsollError` code
`canceled`, `notDispatched: "request"`), and a sandbox it was opening that no other call is
using or has used is closed as soon as it opens. The
`.plimsoll/` directory is the runner's: a file under it is refused before anything is
sent.

The session ID is a capability. It lives in the client's memory and nowhere else: not in
a log line, not in a record, not in Trigger.dev's `chat.local` (which is serialized into
subtask metadata). Records carry its SHA-256.

## Vercel AI SDK

`@plimsollmark/client/ai-sdk` exports `plimsollCodeTools`. Its `executeCode` tool
runs fresh; `forConversation({userId, conversationId})` binds a tool to
application-owned identity and the shared sandbox manager, with the user as the key's
owner. It accepts Python or JavaScript plus text files and returns checked results. The
default minimum isolation is kernel, as for every add-on on `CodeSandboxes`; use a
verified gVisor or VM daemon for hostile code.

See [usage, lifecycle and the no-spend local smoke check, EXTERNAL · official docs ↗](https://github.com/plimsollmark/plimsoll/blob/main/docs/ai-sdk.md).
This source add-on needs the optional `ai` and `zod` peer packages.

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
Its source sets a `container` floor for local development. The
[deployable sister starter](https://github.com/plimsollmark/plimsoll-trigger-starter)
uses `kernel`, the add-on's default (the snippet above writes it out). Hostile
production code needs the verified kernel or VM tier; choose `vm` when the threat
model requires a VM boundary: `e2b` keeps cells until a suspend, and `dockercloud` runs
every call fresh.

The key is the run ID. To cap each user's sandboxes, name the run's user in the warm,
as your server authenticated it: `sandbox.warm(runId, userId)`. Never take it from
`clientData`, which the browser sets: a user who could choose it could close another
user's sandboxes. The key is then the user and the run, `maxSessionsPerOwner` counts
the worker's sandboxes per user, and a daemon with `SANDBOX_MAX_SESSIONS_PER_OWNER`
counts them across every worker of the deployment. The user stays in the worker's
memory, never in `chat.local`. Without it no per-user cap applies; `maxSessions`, when
set, caps the sandboxes one worker holds.

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

No floor is set here, so the tool requires `kernel`; for local development against an
ordinary docker daemon, pass `minimumIsolation: "container"`.

Recorded calls through this tool, two users and a disposed thread included, replay on its
integration page: [see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/mastra/index.html).

The sandbox is keyed by Mastra's thread and resource, `{ owner: resourceId, conversation:
threadId }` (a thread ID is unique only within its user). A call without a `resourceId`
runs in a fresh sandbox every time: under an empty resource, every user without one would
share a sandbox with anyone whose thread ID collided. Set the resource from your
authenticated user, not from anything the user typed. Mastra has no hook for "this
conversation is going to sleep", so a thread's sandbox closes on
`dispose(threadId, resourceId)`, after `idleCloseMs` (default 10 minutes) without a call,
or when the same user opens a thread past `maxSessionsPerOwner` (default 3) and this
thread's sandbox is that user's least recently used one with no call in flight.

In an agent network, Mastra fills a missing `resourceId` with the network's name (and the
thread with the run ID), so every user of the network would count as one owner and close
each other's sandboxes. Pass `owner`, the user from your own authentication (for example a
value your server put in Mastra's `requestContext`):
`plimsollExecuteCode({ ..., owner: (ctx) => ctx.requestContext?.get("userId") })`, and the
same owner to `dispose(threadId, resourceId, owner)`. The caps then count that owner.

## Tests

`go test ./clients/typescript/` serves the real RPC handler (the wasm provider for single
runs, an in-memory session provider for sessions and cells, and a provider that answers a
project with the plan it received, for the project a fresh call sends) and runs three
suites against them: the
client's (needs only node), the add-ons' (needs `npm install` here), and the Trigger.dev
example's (needs `npm install` in `examples/trigger-chat`; it waits out the example's
3-second idle window, Trigger.dev's default being 30 seconds, to prove the suspend closes
the sandbox). An ordinary Go test
skips a suite whose runtime or dependencies are absent. CI runs `make clients-suite`,
which installs both npm lockfiles and sets `PLIMSOLL_REQUIRE_CLIENTS=1`, so a missing
prerequisite or skipped Go test fails. The client's digests are also checked against the
golden vectors of `record/record_test.go`, and the fresh-run runners are run on this
machine's `node` and `python3` to check they print the last expression.
