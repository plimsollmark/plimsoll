# Capability grants

How agent-written code calls your API without ever receiving the credential, the base URL, or general network access; how the policy and the model-facing tool description are generated from one source; and how plimsoll protects the API from the agent.

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
match: Tomcat and Spring read `/orgs/..;/repos/x` as `/repos/x`. A `*` never matches a
segment containing `:` either: on APIs that follow Google's
[custom-method convention (EXTERNAL · official docs ↗)](https://google.aip.dev/136) and on
gRPC-JSON transcoders, `POST /v1/items/a:setIamPolicy` is a different operation on item
`a`, so a grant of `POST /v1/items/*` must not reach it. An ID that contains a colon (a
timestamp, say) cannot be passed through a wildcard.

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
reaches the API. A call counts against every capped entry it matches, so a wider entry such
as `POST /v2/*/run` beside a capped `POST /v2/abc123/run` does not let calls to `abc123`
around the cap, in whichever order the two are written. The run's trace, and the advice and
metrics built from it, still name each call by the first `allow` entry it matches, so there
those calls appear under `POST /v2/*/run`; list the capped route first to see it by name.
A capped route is compared without regard to letter case, so `/v2/ABC123/run` also counts
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
credential attached at the boundary. plimsoll's broker serves JavaScript runs through
the injected client, and everything else in the guest has no network access whatsoever:
the project toolchain is built into the image precisely because a run has no network. If
your agent needs to `npm install` mid-run against a private registry, their model covers
that case and this one does not. What this one offers instead is dependencies built into
the image ahead of time, with the registry credential never present in a run:
[docs/guest-dependencies.md](guest-dependencies.md).

Vendor documentation changes; this comparison is dated for that reason. If it is wrong
or has gone stale, open an issue.
