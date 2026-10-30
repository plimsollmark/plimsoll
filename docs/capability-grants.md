# Capability grants

How agent-written code calls your API without ever receiving the credential, the base URL, or general network access; how the policy and the model-facing <dfn>*tool*</dfn> description (a tool is one named action an AI application offers its model, and its description is what the model reads about it) are generated from one source; and how plimsoll protects the API from the agent.

Part of the [plimsoll README](../README.md).

A <dfn>*grant*</dfn> is permission, attached to one run, for the run's code to call listed
routes of one HTTP API. Without a grant, a run has **no network at all**. A grant is
opt-in twice over: no grant (nil) reaches nothing, and a grant with an empty allow list
also reaches nothing.

A grant belongs to one run, not to the <dfn>*provider*</dfn> (the backend that runs the
code), so each run's permission is chosen separately. It is not tied to any kind of API:
it lets <dfn>*guest*</dfn> code, the code running in the sandbox, call the allowed routes
through a generic client that plimsoll places in the sandbox
(`host.get/put/post/del/call`).

**The credential is supplied per run and never placed in guest code.** A grant carries a
`TokenMinter`, which plimsoll calls to <dfn>*mint*</dfn> the run's credential, that is, to
create it fresh for that run. With the `jwt` token type it issues fresh, expiring tokens
with the caller's identity and any declared scopes; with the `static` type it reuses one
configured bearer token. See the
[INTERNAL · credential-minting diagram and enhancement notes →](architecture/credential-minting.md).

The checks happen in the <dfn>*broker*</dfn>, the part of plimsoll outside the sandbox
that makes each API call for the guest; every provider uses the same broker code. Docker
runs keep `--network none` (no network inside the container) and send calls over a
per-run Unix socket. Under `wasm`, a JavaScript engine compiled to
<dfn>*WebAssembly*</dfn> (a portable bytecode format) runs inside plimsoll's own process,
and the guest calls a function plimsoll provides directly through <dfn>*wazero*</dfn>,
plimsoll's Go WebAssembly runtime; only `{method, path, body}` and a size-limited
response cross into the engine's memory. In both cases the token stays in Go.

The broker accepts a path only if it is already decoded and in its simplest form (no
doubled slashes or dot segments), and byte-identical to an approved route. Queries,
traversal (`..` segments that climb out of a route), and percent-encoding tricks are
refused before anything is sent to the API, and so are `;` parameters inside a path
segment and segments made only of dots, because some servers reinterpret them after the
match: Tomcat and Spring read `/orgs/..;/repos/x` as `/repos/x`. A `*` matches only a
segment made of letters, digits, `-`, `.`, `_` and `~`, the characters
[RFC 3986 calls unreserved (EXTERNAL · official docs ↗)](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3),
because servers give other characters meanings of their own. On APIs that follow Google's
[custom-method convention (EXTERNAL · official docs ↗)](https://google.aip.dev/136) and on
gRPC-JSON transcoders, `POST /v1/items/a:setIamPolicy` is a different operation on item
`a`. On an OData service, `POST /odata/$batch` carries a
[batch of other requests (EXTERNAL · official docs ↗)](https://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part1-protocol.html#sec_BatchRequests),
and `/odata/Products/$each` acts on every product. A grant of `POST /v1/items/*` or
`DELETE /odata/Products/*` reaches none of them. An ID that contains another character (a
timestamp with a colon, an address with `@`, a `+`) cannot be passed through a wildcard;
grant that segment as a literal route instead.

Over RPC, a caller selects a <dfn>*grant profile*</dfn>, a grant stored on the server
under a name, by that name. Raw grants supplied by the caller are intentionally not
accepted over the network, so the base URL, the routes and the credential all stay on the
server. Every profile carries an `allowed_callers` list: the IDs of the
<dfn>*principals*</dfn>, the authenticated callers, that may use it. The single entry
`"*"` opens a profile to every authenticated caller holding the `code:run` scope, so the
list then permits nothing beyond that scope; it is meant for a profile shared on purpose,
never as a placeholder, and the daemon logs a warning naming each such profile at
startup. No caller can present `*` as its own ID: the daemon's caller check refuses that
ID.

A profile is off limits to calls inside a
[session (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#session),
one sandbox kept for many calls, unless it sets `"allow_in_sessions":
true`. In a session, code an earlier call left running can use the grant while a later
call that selected it runs, so a session refuses such a call before anything runs
([sessions.md](sessions.md#what-a-session-gives-up)). Set it only for an API whose access
may be shared with every call of a session.

### The policy and the tool description are generated from one source

Three things describe the same set of API routes, and in every setup where they are kept
up by hand, they drift apart:

- the **allow list**, which is what the broker enforces,
- the **preamble**, the JavaScript client the agent actually calls,
- the **tool description**, the text a gateway (the service between the model and
  plimsoll) shows the model so it knows what exists.

When they disagree the failure is quiet and specific: the model is told about a route
the broker will refuse, or the client offers a method the policy never approved. You
find out at runtime, in an agent transcript.

[`plimsoll-specgen`](../cmd/plimsoll-specgen) builds **all three from one OpenAPI 3.x
document** (the standard machine-readable description of an HTTP API), so they cannot
disagree. Path parameters such as `{id}` become `*` routes, where `*` stands for one
whole segment; operations become typed methods on a global object; and summaries become
the description. The same document always gives the same output, and the tool runs fully
offline: no server is contacted and no credential is needed. It <dfn>*fails
closed*</dfn> on ambiguous input, refusing rather than guessing, and it **reports rather
than silently drops** what it cannot express, so an HTTP method the broker cannot enforce
(`HEAD`, `OPTIONS`, `TRACE`) is a warning rather than a gap you discover later.

```sh
plimsoll-specgen -outdir ./generated api.openapi.json  # every artifact, as files
plimsoll-specgen -emit catalog       api.openapi.json  # every route, for operator advice
plimsoll-specgen -emit health        api.openapi.json  # the recovery probe, if marked
```

**It handles part of OpenAPI, and says so when your document goes beyond that part.** A
grant permits literal path templates only, so an operation that *requires* a query,
header, or cookie parameter cannot be called through the broker at all: it is skipped
with its reason, rather than granted as a route the agent can never use. An operation
with optional ones is generated with a warning that the method always calls the bare
route. A `$ref` path item or parameter (a pointer to a definition elsewhere in the
document) is an error, not a silent omission. The project's own tests run the generated
client library in <dfn>*QuickJS*</dfn>, the small JavaScript engine plimsoll embeds, so a
generated method that cannot parse or throws on its first call fails the build rather
than the agent.

**One decision the generator cannot make for you.** The `allow` list it emits is
*every* operation in the document, because a spec describes what an API has, not what
an agent should be able to reach. Pasting it unedited into a profile grants the agent
the whole API. Trim it to the routes you actually want reachable, and keep the
untrimmed list in the profile's `catalog` field. The gap between the two is what lets
the [efficiency advisor](efficiency-advisor.md), which reads each run's call log and
suggests cheaper call patterns, name the specific missing route to add, instead of
reporting a vague shortfall you still have to diagnose.

Worked example, with the input document and every generated artifact side by side:
[docs/examples/specgen](examples/specgen).

### The broker also protects the API from the agent

A sandbox usually protects your infrastructure from the agent's code. This one also
protects your API from the agent's behaviour, which is a different failure: **an agent
loop that reacts to a 429 by trying again, faster.**

Nothing in a model's training makes it back off, so the broker backs off for it, outside
the sandbox. When your API returns 429 (too many requests) or 503 (unavailable), a
per-run <dfn>*circuit breaker*</dfn> opens: for a cooldown that honours `Retry-After`
(capped at 30s), the broker stops forwarding calls. Further permitted calls are
<dfn>*shed*</dfn>, refused at once with a fast 503, rather than piled onto an API that
has already asked for room.

Recovery depends on which of the two your API sent, because they answer different
questions. A **503** means the service is degraded, and the grant's declared
`health_check` route can speak to that: while shedding, once a second one waiting call is
picked to request that route, and a 2xx closes the breaker early, so recovery does not
wait out the full cooldown or spend an expensive call to discover it. A **429** means
*this caller* has used up its allowance, which a healthy service says nothing about, so
that window is never probed and is simply waited out. Reopening it on a cheerful 200
would push the run's traffic straight back into the rate limiter that just asked it to
stop. For the same reason, the generator will not pick a probe because an endpoint is
*named* `/status` or `/healthz`; you mark the one that answers "can this API take traffic
again" with `x-plimsoll-health-check`.

The probe uses the run's credential but is neither recorded in the call trace nor
counted against the call budget. Sheds are counted separately from calls refused by
policy (`CallTrace.Shed` versus `Denied`) and appear on the audit line as
`host_calls_shed`, so "the agent was throttled" and "the agent tried something it was not
allowed to" never look alike.

**The call budget is per profile, with a default and a ceiling.** A run gets 256 calls
through the broker unless its profile sets `max_calls`, and no profile may ask for more
than 100,000. The reason to raise it is a workload that is a loop by design, such as a
<dfn>*controller*</dfn>, a program that steers a simulated machine and calls the API once
per <dfn>*tick*</dfn> (one fixed time step of the simulation); there, 256 calls is a few
seconds of simulated time. The reason there is still a ceiling is that a grant must never
allow an unlimited number of requests to your API. The call trace (the broker's
metadata-only log of the run's calls) stays capped at 256 rows whichever budget applies:
it is limited evidence, not a complete ledger, and the calls past the cap are counted as
`Dropped`, so a finding says "at least" rather than reporting a number it cannot support.

**The scope is one run.** This does not protect your API from overload across all runs,
and runs happening at the same time do not coordinate; it stops a single agent loop from
hammering an endpoint that is already struggling. In a
[session](sessions.md), a run is one call: each granted call gets the full call budget.

**A route whose call spends gets a cap of its own.** `max_calls` bounds all of a run's
routes together. On an API where one route costs money, such as a GPU job service whose
submit route starts a paid job while its status route can be polled for free, a run
allowed to poll 200 times could also start 200 jobs. `route_max_calls` caps one `allow`
entry, written as it is in `allow`; past the cap the broker answers 429 and the call never
reaches the API. A call counts against every capped entry it matches, in whichever order
they are written, so a capped `POST /v2/*/run` also charges the calls an exact
`POST /v2/abc123/run` beside it allows. The reverse is refused when the profile loads: a
`POST /v2/*/run`, capped or not, beside a capped `POST /v2/abc123/run`. The broker compares
path segments as written, while a server may serve `abc123.json` (Rails reads `.json` as a
response format), `abc123.` or, for a numeric ID, `0123` for `123` as the capped route, so
a call only the wildcard matched would reach it uncounted. Move the cap to the wider route,
or list the routes it should reach in place of the `*`. The run's trace, and the advice and
metrics built from it, name each call by the first `allow` entry it matches; list the
capped route first to see it by name. A capped route is compared without regard to letter
case, so a call to `/v2/ABC123/run`, allowed by an entry spelled that way, also counts
against the cap on `/v2/abc123/run`, since many APIs route both to the same place. In a
[session](sessions.md) the cap spans the whole session, not each call: code a session
keeps can run between its calls and use each call's grant, so a cap that started over with
every call would bound nothing. Two profiles that cap the same route of the same API share
that count within a session. A profile for a RunPod serverless endpoint, two jobs a run
(or a session):

```json
"gpu-jobs": {
  "base_url": "https://api.runpod.ai",
  "allow": ["POST /v2/abc123/run", "GET /v2/abc123/status/*", "POST /v2/abc123/cancel/*"],
  "route_max_calls": {"POST /v2/abc123/run": 2},
  "allowed_callers": ["agent-a"],
  "token": {"type": "static", "env": "RUNPOD_API_KEY"}
}
```

The endpoint ID is written into each route, so the run reaches that one endpoint, and the
account's API key stays in the daemon. What the cap cannot bound, the service must: a job
keeps running after the run that started it ends, and the broker never reads a request
body, so an API whose body chooses the machine and its running time can only be bounded
on the service's side. A RunPod endpoint fixes its GPU type, its worker count and a job's
execution timeout (10 minutes unless changed) in the endpoint's settings, outside the
run's reach. This profile is tested against a stand-in shaped like RunPod's API
(`TestGrantGPUJobRouteCap`); against RunPod itself (2026-10-08), code in a docker sandbox started one job through the broker, its
second submission in the same run was refused by the cap before it reached RunPod (RunPod counted one
job), and the job's status was polled to completion.

### Standard client libraries, in any language

The injected `host.*` client is JavaScript. A granted run on the docker provider also gets a
**local web address** that any HTTP client can use: inside the sandbox, a process of
plimsoll's own listens on `127.0.0.1:8471` and passes each connection, byte for byte, to the
broker's Unix socket. For a project run that process is the container's command itself,
delivered with the daemon (it starts the runner as its child, so the image needs no change);
for a snippet it is a listener the injected client opens in the guest's own node process. The
container still has no network (`--network none` leaves only the loopback interface), the
forwarder checks nothing and adds nothing, and every request on it is checked by the same
broker as before: the route, the budgets, the credential it adds. A Python step that calls
`urllib`, `httpx` or the OpenAI and Anthropic client libraries works unchanged, because both
libraries read their base URL and key from the environment (`OPENAI_BASE_URL` and
`OPENAI_API_KEY`; `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`; checked against both
libraries' sources, 2026-10-28), and a profile's `sdk_env` puts those variables into the
guest's environment. `{origin}` in a value stands for the local address.

```json
"openai": {
  "base_url": "https://api.openai.com",
  "allow": ["POST /v1/chat/completions", "POST /v1/responses"],
  "sdk_env": {"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": "plimsoll-grant"},
  "allowed_callers": ["agent-a"],
  "token": {"type": "static", "env": "OPENAI_API_KEY"}
}
```

**The address needs its own <dfn>*seccomp*</dfn> profile (seccomp is the kernel's
per-process list of the operations a program may ask it for).** The audited default profile
allows Unix sockets only, so under it no forwarder can listen. A second profile, which the
daemon derives from the default at startup, adds IPv4 TCP sockets and the few socket
options the forwarder and the client libraries set, and nothing else; the daemon applies
it to exactly the runs whose grant sets `sdk_env`, and the default to every other run,
chosen per run from the grant. Ask for it beside `SANDBOX_DOCKER_SECCOMP`:

```sh
SANDBOX_DOCKER_SECCOMP=/etc/plimsoll/seccomp.json \
SANDBOX_DOCKER_SECCOMP_SDK=derived
```

An operator's own profile is never replaced: with a profile file configured and no variant
beside it, a run whose grant sets `sdk_env` is refused before anything starts (marked as a
run in which nothing ran, reason `environment`), and a plain grant keeps the default and
gets no forwarder at all. What the variant adds to a run, and why it is a profile of its own, is in
[docs/seccomp.md](seccomp.md#the-second-profile-runs-whose-grant-sets-sdk_env); setting
`sdk_env` on a profile is the operator's authorization of that exposure for the runs that
select it. Each run's record names the profile it applied (`seccomp:sha256:...`). Under
<dfn>*gVisor*</dfn> (`runsc`, the user-space kernel the docker provider can run containers
on) no host profile is applied to any run and the record says `seccomp:skipped:runsc`. If the
forwarder cannot listen, the run fails before any guest code starts: a snippet exits 126
with the forwarder's message on stderr and no output of its own, and a project runs no step
(`TestDockerForwarderThatCannotListenFailsBeforeGuestCode`).

The key in `sdk_env` is a placeholder: both libraries refuse to construct a client without
one, and the broker replaces whatever the guest sends with the credential it minted. Never
put the real key there; the `token` field is where it lives, in the daemon. A variable name
plimsoll itself sets in the guest environment or the dynamic loader reads (`PATH`, `HOME`,
`HOSTNAME`, `NODE_OPTIONS`, `HOST_API_SOCKET`, `HOST_API_LISTEN`, `LD_*`, `PLIMSOLL_*`) is
refused when the profile loads, since a profile's entry would come later and win, moving the
broker's socket or the forwarder; so is a value with a control character.

What this does and does not reach, stated plainly:

- **Request and response bodies of JSON APIs**, on the routes the profile allows. A client
  library's create calls (`POST /v1/chat/completions`, `POST /v1/responses`,
  `POST /v1/messages`) send no query string and fit.
- **Not a call with a query string.** The broker refuses any target with `?` (the route it
  approves must be the bytes it sends), so list and pagination calls (`files.list`,
  `limit=`, `after=`) and `extra_query` are refused with 403, as they always were.
- **Not WebSockets** (the OpenAI Realtime API): the broker carries requests and responses.
- **Streamed answers, piece by piece.** A `stream: true` call's answer (`text/event-stream`,
  the format both chat APIs stream in) is passed through as it arrives; see the next section
  for its limits.
- **Uploads, on the routes the profile marks for them.** A route listed in
  `route_content_types` takes a body of that type (`multipart/form-data` for a Files or
  transcription route) up to its `route_max_request_bytes`, passed through as it arrives;
  every other route sends its body as `application/json`, as before. See "Large uploads"
  below.
- **Not in sessions, and not on `wasm`, <dfn>*E2B*</dfn> (a hosted service that runs each
  sandbox in a small virtual machine) or Docker Cloud yet**: the forwarder exists for a run
  on the docker provider (snippets and projects). A grant with `sdk_env` in a session is
  refused before anything runs, marked as unsupported: a session's container
  applies one seccomp profile for its life, and a later call could not change the profile of
  processes already running. The WASM guest has one function to call and no sockets, and
  on E2B and Docker Cloud the guest's base URL would have to be the <dfn>*guard*</dfn>, the
  HTTPS address outside the virtual machine that stands in for the socket there, which is
  not built.

**The guard has the same door.** On E2B and Docker Cloud the broker is reached through the
guard, an HTTPS address outside the virtual machine. Beside the JSON envelope the injected
client posts to it, the guard serves a raw route: a request to `<guard URL>/raw/<target>`
reaches the broker as a standard client's request to `<target>`, method, headers and body as
sent, so `<guard URL>/raw` is the base URL a client library on those providers would take.
The same credential (`X-Plimsoll-Guard`), the same per-run limits on requests in flight and
the same body deadline apply, the body is bounded by the matched route's request limit (1 MiB
unless the profile raised it, as "Large uploads" below describes), and the target is cut from
the request line as written, so an encoded or non-canonical target, a query string, a
doubled slash or a trailing slash is refused by the broker exactly as on the socket
(`TestEgressGuardRawRouteCarriesAStandardClientsRequest`,
`TestEgressGuardRawRouteRefusesWhatIsNotTheRoute`). The injected client names the route for
the guest: `host.raw.url` is the base URL, and `host.raw.headers` the headers a client must
add (none on E2B, whose network rule adds the guard credential outside the guest; the run's
guard credential on Docker Cloud, which that client already holds). A guest's `fetch` with
those two reaches the API as a standard client, and the live tests (`TestE2BGuardLive`,
`TestDockerCloudGuardLive`) make the three raw requests this way. Both passed against the
live services on 2026-10-29: upstream saw the broker's credential and only the passed header,
a refused request came back marked not to retry, a request carrying an expired guard
credential was refused, and a streamed answer reached the guest in pieces. What is not built:
`sdk_env` on these providers (a client library in another language would need the base URL
and, on E2B, `SSL_CERT_FILE` pointed at the guest's trust store, which E2B's proxy
certificate is added to; on Docker Cloud a loopback forwarder to add the credential, since a
client library sends no custom header unchanged).

The two tests that state this are `TestDockerProjectGrantServesAStandardClientAtLoopback`
(a Python step using the standard library, sending the exact header set the client
libraries send) and `TestDockerSnippetGrantServesAStandardClientAtLoopback` (Node's
`fetch`). Both assert that the API saw the broker's credential and the passed
`anthropic-version`, and none of the client's telemetry or its placeholder key.

### A grant to a chat API is a grant to the internet through the API's own tools

The broker checks the route and never reads the body, so **everything the body can ask the
API to do is granted along with the route**. The chat APIs run tools on their own servers at
the request's asking: on the Claude API, web fetch, web search and the <dfn>*MCP*</dfn>
connector (MCP is the Model Context Protocol, a standard by which a model calls tools
served by another program; the connector lets the API call such a server on the request's
behalf), all server-side tools named in the request's `tools` list; on OpenAI's Responses
API, the hosted tools `web_search`, `mcp` (a remote MCP server of the request's choosing),
code interpreter and the shell tool. A guest that may `POST /v1/messages` can put a URL that
carries data into a user message and ask for web fetch, and Anthropic's own documentation
says what that means: "Enabling the web fetch tool in environments where Claude processes
untrusted input alongside sensitive data poses data exfiltration risks"
([web fetch tool, EXTERNAL · official docs ↗](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool),
read 2026-10-28). OpenAI says the same of remote MCP: "A malicious server can exfiltrate
sensitive data from anything that enters the model's context"
([remote MCP, EXTERNAL · official docs ↗](https://developers.openai.com/api/docs/guides/tools-remote-mcp),
read 2026-10-28). The byte caps and call budgets bound how much; they do not close the
channel, and neither does any route list, because the tool request is inside an allowed
body.

What an operator does about it, on the API's side, since plimsoll cannot see the body:

- **Claude API:** an organization admin turns web fetch and web search off, or restricts
  their domains, on the Console's Capabilities page
  ([platform.claude.com/settings/capabilities](https://platform.claude.com/settings/capabilities));
  with a tool off, a request that includes it fails with a 400 `invalid_request_error`
  (the web fetch and web search tool pages, read 2026-10-28). Use a key from an
  organization or workspace configured that way for the grant's `token`.
- **OpenAI Responses API:** the tool guides document per-request controls only
  (`web_search` with `external_web_access: false` and `filters.allowed_domains`; `mcp` with
  `require_approval` and `allowed_tools`), which a hostile guest simply does not send. The
  shell and code interpreter guides say hosted containers have no network unless "an admin
  must configure your org allow list in the dashboard", and a request's `allowed_domains`
  must lie within it. Third-party security guides describe a **Hosted tools** tab under
  Settings, Organization, Data controls, where MCP tool usage, web search and file search
  default to "Enabled for all projects" and can be turned off per project; OpenAI's own
  documentation, as read on 2026-10-28, does not describe that tab, so check it in the
  dashboard before relying on it, and prefer a project whose hosted tools are off for the
  grant's key.
- **Either API:** keep the grant's key in a project or workspace that holds nothing else, so
  what a prompt-injected tool call can reach is that project's own data and the request's.

### Streamed answers

Chat APIs send a long answer in pieces, as server-sent events: one HTTP response
of type `text/event-stream` whose body is a series of `event:` and `data:` lines, written as
the model produces them (the OpenAI stream ends with `data: [DONE]`, the Claude stream with a
`message_stop` event, and the Anthropic client library requires streaming for a long answer
to avoid HTTP timeouts). The broker passes such an answer through **piece by piece**: the
status and content type go to the guest as soon as the API sends them, then each piece as it
arrives, over the local address, the injected client's socket, and the guard's raw route alike.
Every other content type is buffered and capped exactly as before, so a JSON API's behavior
is unchanged byte for byte.

The protections work piece by piece too. A stream is cut when it has carried **4 MiB** in all
(the same response cap as a buffered answer; a chat answer is tens of kilobytes), when
**60 seconds** pass with no piece at all (the single 60 s call limit becomes a per-gap limit,
since an answer can take minutes while never pausing that long; the Claude API sends `ping`
events while it works), or when the run's own deadline ends. The first 60 s still bound the
wait for the response headers. Because the status is already with the guest, a cut cannot be
turned into a 502: the stream simply ends without its final event, and a client library
raises. The call's row in the trace records the bytes delivered and `Delivered: false` for a
cut stream, so "the guest got a complete answer" stays a question the trace can answer. Memory
per streamed call is one 32 KiB piece, never the answer
(`TestBrokerStreamsEventStreamPieceByPiece`, `TestBrokerStreamIsCutAtTheByteCap`,
`TestBrokerStreamIsCutWhenIdle`, `TestEgressGuardStreamsEventStream`). The `wasm` provider's
host function returns one answer, so there a stream is buffered whole within the cap, as it was.

### Large uploads

A chat API's Files route takes a video or a document as `multipart/form-data`, and a
transcription route takes audio the same way; the OpenAI client library's `files.create` and
an `httpx.post(files=...)` send such a body in one request with its length declared. Three
profile fields let a route take one, and each is a number the operator chose:

```json
"checker": {
  "base_url": "https://api.example",
  "allow": ["POST /v1/files", "POST /v1/responses", "POST /v1/asr/transcribe"],
  "route_max_request_bytes": {"POST /v1/files": 16777216, "POST /v1/asr/transcribe": 8388608},
  "route_content_types": {"POST /v1/files": ["multipart/form-data"], "POST /v1/asr/transcribe": ["multipart/form-data"]},
  "max_request_bytes": 50331648,
  "sdk_env": {"OPENAI_BASE_URL": "{origin}/v1", "OPENAI_API_KEY": "plimsoll-grant"},
  "allowed_callers": ["agent-a"],
  "token": {"type": "static", "env": "MODEL_API_KEY"}
}
```

- **`route_max_request_bytes`** sets the request body limit of one `allow` entry, keyed as
  written there (raised for an upload route, or lowered for a route whose bodies are small).
  The default is 1 MiB, and the most a profile may set is 512 MiB, so the Claude Files API's
  500 MB request limit fits under it. The limit is the matched entry's: when two entries
  match the same path, the first in `allow` decides, so an entry with a raised limit goes
  first or stands alone.
- **`route_content_types`** names the media types the broker takes from the guest's
  `Content-Type` on that entry. Every route takes `application/json`. On a route that lists
  types, a body of any other type is refused with 415 before a byte is read or sent; on a
  route that lists none, every body is sent as `application/json`, as it always was, whatever
  the guest's header said. A listed type is sent with the guest's `boundary` and `charset`
  parameters alone, each checked (a boundary of 1 to 70 of the characters RFC 2046 allows, a
  charset of token characters), and every other parameter dropped. A wildcard,
  `application/json`, `multipart/byteranges` or a `message/*` type cannot be listed.
- **`max_request_bytes`** is the run's total: the request body bytes of all its calls,
  uploads and JSON alike, so what a grant lets a run send to the API is a number the
  operator wrote, not the call budget times the body limit. 256 MiB when unset, which is
  what the default call budget could send at the default limit (a profile that raised
  `max_calls` could send more before this field existed, and is now bounded here); at most
  1 GiB. A route limit above the run's total is refused when the profile loads, since no
  call could use it.

How a body moves. Within the default limit a body is read whole and then sent, as it always
was. On a route with a raised limit the body is **passed through** as it arrives: the broker
reads one piece from the guest and writes it to the API, holds one piece and never the file,
and tells the API the length the guest declared (an undeclared, chunked body is sent
chunked). A declared length over the route's limit or over what is left of the run's total is
refused with 413 and `X-Should-Retry: false` before a byte is read; an undeclared body is cut
at the limit, which the API sees as a request that broke off, and the guest gets the 413. Both
count as denied in the trace, and a passed-through call's row records the bytes that went.
Because a refused declared upload is answered before its body is read, a client still sending
it may see the connection close rather than the 413 (the OpenAI library reports a connection
error there); the API never sees it either way. The run's total is charged before a body is
sent (an undeclared body holds the route's whole limit until its call ends, then gives back what
it did not use), so two uploads in flight cannot both fit the same remainder. An API may answer
before a body is in: the call ends there, and the rest of the body never goes, so the API never
receives a byte the run was not charged for. A body on the local
address or on the guard's raw route takes as long as it needs while it moves: the read
deadline moves out at each piece (10 s between pieces on the socket, the guard's body deadline
on the raw route), so it bounds a stall and not the upload, and the run's own deadline bounds
the whole.

What this is and is not. The upload goes to the operator's API on the operator's key, on a
route the profile allows, within limits the profile states; what the body asks the API to do
with it is the matter of "A grant to a chat API is a grant to the internet through the API's
own tools" above, and the byte budget bounds how much a run can send to the API, not what.
Uploads are for a standard client at the local address or the guard's raw route: the injected
`host.*` client and the `wasm` host function carry JSON envelopes, and a body there keeps the
default limit. The tests: `TestBrokerPassesAnUploadThroughWithinTheRouteLimit` (the API has
the first half of a 3 MiB body before the guest sends the second),
`TestBrokerRefusesADeclaredUploadOverTheRouteLimit`,
`TestBrokerCutsAnUndeclaredUploadAtTheRouteLimit`, `TestBrokerRefusesABodyTypeTheRouteDoesNotTake`,
`TestBrokerChargesEveryBodyToTheRunsRequestBudget`, `TestEgressGuardRawRouteStreamsAnUpload`,
and on docker `TestDockerProjectGrantCarriesTheCheckersUploads`, in which a Python step using
the standard library sends what a video-checking program sends through the OpenAI library and
httpx (a 12 MiB clip as multipart to the Files route, a two-part transcription, a JSON call, a
streamed answer) and then a clip over the route's limit, a body of the wrong type and clips
past the run's total, none of which reaches the API.

### What a standard client's request looks like to the broker

The broker builds the request it sends from scratch: the route it matched, the body (JSON, or
on a route marked for uploads a body of a type it lists), `Accept: application/json`, and the
credential it minted. Nothing the guest put in a header
reaches the API by default, so a client library's telemetry (`User-Agent`, the
`x-stainless-*` headers the OpenAI and Anthropic libraries send), its cookies, and above all
the key it was given are dropped: a guest that sends `Authorization: Bearer sk-dummy` or
`x-api-key: dummy` has them replaced by the run's minted credential, never forwarded
(`TestBrokerCoreForwardsOnlyPassListedHeaders`).

Some APIs require a header the client sends itself: the Claude API refuses a request without
`anthropic-version`. A profile's `pass_headers` names the request headers the broker copies
through, first value only, checked as visible ASCII of at most 1024 bytes; a value with a
line break or a byte outside that range is dropped whole, never cleaned. A name the broker or
the connection owns is refused when the profile loads: `Authorization`, `Cookie`, `Host`,
`Content-Type`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Accept-Encoding`,
`Forwarded` and the `X-Forwarded-*` and `X-Plimsoll-*` families among them. So is a header
a model API reads an API key from: `x-api-key` (the Claude API still accepts a key there),
`x-goog-api-key`, `api-key` and `ocp-apim-subscription-key`. Passed through, the guest's own
key would arrive beside the run's credential, and the guest, not the profile, could choose
the account the API acts for. HTTP standardizes no credential header besides
`Authorization`, so this list is what the APIs document, the same headers an AI gateway such
as LiteLLM strips from its clients by default.

A profile's `set_headers` gives a header a value of the operator's: the broker sets it on
every request, and whatever the guest sent under that name is dropped. A header has one owner,
so a name is set or passed, never both, and the names `pass_headers` refuses are refused here
too, an API key header among them: the credential belongs in `token`, never as a value in the
grants file. A value is visible ASCII of at most 1024 bytes, not empty and not padded with
spaces.

```json
"claude": {
  "base_url": "https://api.anthropic.com",
  "allow": ["POST /v1/messages"],
  "pass_headers": ["anthropic-version"],
  "allowed_callers": ["agent-a"],
  "token": {"type": "static", "env": "ANTHROPIC_API_KEY"}
}
```

Do not pass `anthropic-beta` or `OpenAI-Beta`: a beta header is how a request switches on
server-side features, tools among them, so passing it hands the guest a lever the route
check cannot see (the next section says why that matters).

**`anthropic-workspace-id`.** The Claude API requires this header on every request made with
a key that is not scoped to a workspace, and refuses such a request without it (400
`invalid_request_error`); a key created for one workspace runs there and needs no header
([authentication, EXTERNAL · official docs ↗](https://platform.claude.com/docs/en/manage-claude/authentication#select-a-workspace),
read 2026-10-28). The handling that keeps the choice of workspace out of the guest's hands:
create the grant's key scoped to the one workspace the grant is for (the Console's API keys
page offers it) and send no header, or, with a key that reaches several workspaces, fix the
workspace in the profile with `"set_headers": {"anthropic-workspace-id": "wrkspc_..."}`.
Do not list `anthropic-workspace-id` in `pass_headers`: the guest would then name the
workspace, and the API runs the request in any workspace that key can reach. The same holds
for `OpenAI-Organization` and `OpenAI-Project`, which pick the organization and project a
request to the OpenAI API counts against
([API overview, EXTERNAL · official docs ↗](https://developers.openai.com/api/reference/overview),
read 2026-10-29): set them, never pass them.

**The broker's own answers carry `X-Should-Retry: false`.** The OpenAI and Anthropic client
libraries retry a 408, 409, 429 or 5xx twice by default and read that header to stop
(checked against both libraries' base clients, 2026-10-28). Every answer the broker makes
itself (a route refused, a body too large, a spent call budget or route cap, a shed while the
circuit breaker is open, an upstream it could not reach) carries it, so a client does not
spend the run's call budget on retries of a refusal; an answer the API gave passes through
bare, and the client's retry policy toward the API stays the client's. A request that names
its own destination, an absolute-form target such as `GET http://other.example/v1/items`, a
`CONNECT` to a host, or a doubled leading slash, is refused before anything is sent: the only
origin the broker ever dials is the profile's `base_url`.

### Prior art, and what differs here

Keeping the credential out of the guest is not a new idea, and two funded platforms
ship a version of it. Vercel Sandbox's **credentials brokering** adds the credential to
traffic leaving the sandbox, outside it, so that "the secrets never enter the sandbox, so
code running inside it cannot exfiltrate them." Cloudflare's <dfn>**Code Mode**</dfn>,
its name for letting an agent write a program that calls tools instead of calling one
tool per step, holds the access tokens in a supervisor outside the isolate (the
lightweight V8 sandbox the code runs in) and makes `fetch()` and `connect()` throw inside
it. Two teams building the same control independently is the best evidence available that
it is the right control.

Checked September 2026 against their current documentation, four things differ here:

- **Route granularity, and denial as the default.** Vercel states plainly that
  "Matchers never block traffic": access is decided per domain from the TLS SNI (the host
  name a client announces when it opens a TLS connection), and a request matching no rule
  still reaches that domain, simply without the credential attached. Restricting a domain
  to particular paths means routing it through a proxy you write and rejecting the rest
  there. plimsoll refuses anything that is not byte-identical to an approved route, and
  that refusal is built into the component rather than left for you to integrate.
- **JWT profiles mint a fresh credential per run.** Their documented examples insert a
  long-lived token from the operator's environment. A grant here carries a `TokenMinter`
  called once per run with that run's scopes and the calling principal as the subject;
  static profiles deliberately reuse their bearer token.
- **No parallel path to bypass.** Vercel documents that traffic permitted by
  `subnets.allow` "bypasses SNI filtering, credentials brokering, and requests
  proxying", and that domain fronting (announcing one host name in the SNI and asking for
  another in the request) is possible because matching reads the SNI alone. A plimsoll
  guest has no network at all outside the broker: Docker runs with `--network none`, and
  the WASM guest has one function to call and no sockets.
- **Backing off, and generation.** Neither documents a circuit breaker or backoff when
  the API answers 429 or 503. And while many tools generate a model-facing tool
  description from OpenAPI, generating the *enforced* allow list from the same document
  is not something this project has found elsewhere.

**Where theirs is broader, and it is a real trade.** Vercel's firewall governs whatever
the sandbox runs, so package installs, `git`, and Postgres clients all work with a
credential attached at the boundary. plimsoll's broker serves HTTP clients (the injected
JavaScript client, or any language through the local address above, on the docker
provider), and everything else in the guest has no network access whatsoever: the project
toolchain is built into the image precisely because a run has no network. If your agent
needs to `npm install` mid-run against a private registry, their model covers that case
and this one does not. What this one offers instead is dependencies built into the image
ahead of time, with the registry credential never present in a run:
[docs/guest-dependencies.md](guest-dependencies.md).

Vendor documentation changes; this comparison is dated for that reason. If it is wrong
or has gone stale, open an issue.
