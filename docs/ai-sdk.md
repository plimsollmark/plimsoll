# Vercel AI SDK code execution

Vercel's AI SDK (software development kit) can call plimsoll as an ordinary
`executeCode` tool. It executes Python or JavaScript on the configured daemon,
checks the execution record and isolation evidence, and reports whether interpreter
state and files can persist. It needs no Trigger.dev or Mastra runtime.

Recorded calls through this tool, from a fresh run to a refused floor, replay on its
integration page: [see a run, INTERNAL · plimsoll site →](https://plimsollmark.github.io/plimsoll/integrations/vercel-ai-sdk/index.html).

This add-on ships in `@plimsollmark/client` 0.20.0 and later (0.19.0 does not have it). Its optional dependencies are `ai` and `zod`. The base TypeScript client does not
import either framework. Tested with AI SDK 7.0.126.

```ts
import { PlimsollClient } from "@plimsollmark/client";
import { plimsollCodeTools } from "@plimsollmark/client/ai-sdk";

const codeTools = plimsollCodeTools({
  client: () => new PlimsollClient({
    baseUrl: process.env.PLIMSOLL_URL!,
    token: process.env.PLIMSOLL_TOKEN,
  }),
});

// IDs come from the authenticated request, never model-generated tool arguments.
const scope = { userId: authenticatedUser.id, conversationId: authorizedConversation.id };
const executeCode = codeTools.forConversation(scope);
// Pass { executeCode } to your existing AI SDK agent or generateText call.
// When the application ends this conversation:
await codeTools.dispose(scope);
```

Create the manager once per application process so consecutive requests can find
the same session. The key includes both IDs without separator collisions. A new
process has a new manager; it does not restore an old interpreter. The application
must authorize access to the conversation before binding its tool.

`codeTools.executeCode` has no identity and always runs fresh. `forConversation`
retains a session only when the daemon advertises support. `sessions: "always"`
requires it; `sessions: "never"` requests fresh execution. Results' `freshSandbox`,
`freshInterpreter`, `stateKept` and `filesPersist` say what was new and what survived.
A sandbox can expire before the next call. Current plimsoll Docker, OpenShell and E2B
adapters support sessions (an E2B suspend ends the session's interpreters, so the next
call reports `freshInterpreter`); its Docker Cloud adapter uses fresh executions.

`warm(scope)` begins opening a supported session, unless the user (or the manager) is
at its cap below: a warm never closes another session to make room, so then it does
nothing and the conversation's first call opens one. `dispose(scope)` closes it, and
`disposeAll()` closes every held session during shutdown. The manager also closes
idle sessions by default (`idleCloseMs`, 10 minutes). The user ID is the session's
owner: the manager holds at most `maxSessionsPerOwner` sessions per user (default 3,
since a person rarely works in more than a few conversations at once), and opening
one more first closes that user's least recently used session with no call in flight.
That conversation's next call reports `freshSandbox: true`: it loses variables and
files, never an answer. These caps count one process's sessions. Across processes
(serverless functions, several servers), set the daemon's
`SANDBOX_MAX_SESSIONS_PER_OWNER`: every open names its user to the daemon as a digest
under a key derived from the caller token (never the ID itself), and the daemon applies the same rule
to every process of the app. A sandbox it closes refuses its next call as `replaced`,
and the manager runs that call once more in a new sandbox, saying `freshSandbox: true`.
`SANDBOX_MAX_SESSIONS` and `SANDBOX_MAX_SESSIONS_PER_CALLER` still bound the daemon and
each caller token. See [options and lifecycle, INTERNAL · TypeScript client guide →](../clients/typescript/README.md).

The default isolation floor is `kernel`, accepting verified gVisor or a stronger
VM (virtual machine) boundary. Ordinary Docker containers require an explicit
`minimumIsolation: "container"` for controlled development. Use kernel or VM tier
for hostile production code. The project image must contain the interpreter and
dependencies. Runtime package installation, arbitrary internet access and public
web servers are not provided by this tool.

Input contains code, language and text files. Output contains stdout, stderr, exit
status, timeout/truncation flags, persistence flags, isolation tier and the checked
record's SHA-256 digest. A digest checks the stated request/result, not computation
correctness or an unbreached boundary. Guest failures remain results. Infrastructure
exceptions can follow execution and are not replayed automatically; a fresh run that
ends without a step report is one of them, thrown with its checked result rather
than given an invented exit code. AI SDK's abort signal reaches the client. An
aborted call is proof that nothing ran only when its error carries `notDispatched`,
as a call aborted before or while its session opens does (reason `request`). A
failure before the code is sent (the daemon unreachable, a proxy's 503 on Describe or
on the session's open, a client that cannot be built) also carries it, reason
`environment`; the error's message, which is all the model sees, starts `Nothing ran`
or `The code may have run` accordingly.

## Verify locally without a paid model

Start a local plimsolld using Docker/gVisor and `plimsoll/sandbox-python` as its
project image (after `make docker-images`, with gVisor installed):

```sh
SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc \
SANDBOX_DOCKER_PROJECT_IMAGE=plimsoll/sandbox-python:latest SANDBOX_MAX_SESSIONS=4 \
PLIMSOLL_ADDR=127.0.0.1:8746 PLIMSOLL_INSECURE=1 go run ./cmd/plimsolld
```

Then build the client and run the example below. It uses a scripted AI
SDK test model and refuses nonlocal or non-Docker daemons before dispatch.

```sh
cd clients/typescript
npm ci --userconfig=/dev/null
PLIMSOLL_URL=http://127.0.0.1:8746 node examples/ai-sdk-smoke.ts
```

Use your actual daemon URL, with `PLIMSOLL_TOKEN` in the process environment if
auth is enabled. Expect Python and JavaScript results of `42`, checked record
digests and the isolation tier. Connection failure means the daemon is unreachable;
isolation refusal means its tier is below the required floor. A missing interpreter
requires a suitable project image, never fallback execution on the host.

Real-RPC adapter tests also run through the existing TypeScript suite:

```sh
env -u E2B_API_KEY -u DOCKER_SBX_TOKEN go test ./clients/typescript -count=1
```

See [tool calling, EXTERNAL · official docs ↗](https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling)
and [tool registry, EXTERNAL · official docs ↗](https://ai-sdk.dev/resources/tools).
Registry submission and package publication are separate actions.
