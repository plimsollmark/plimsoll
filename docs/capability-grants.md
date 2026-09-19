# Capability grants

How agent-written code calls your API without ever receiving the credential, the base URL, or general network access; how the policy and the model-facing tool description are generated from one source; and how the broker protects the API from the agent.

Part of the [plimsoll README](../README.md).

Without a grant, a run has **no network at all**. A grant is opt-in twice over: a nil
grant reaches nothing, and a grant with an empty allow list also reaches nothing.

A grant is **per-run**, not provider state, and it is domain-agnostic. It lets guest
code call an allowlisted HTTP API through an injected generic client
(`host.get/put/post/del/call`).

**The credential is supplied per run and never injected into guest code.** A grant
carries a `TokenMinter`: JWT profiles issue fresh, expiring tokens with the caller's
identity and any declared scopes; static profiles reuse a configured bearer.
See the [INTERNAL · credential-minting diagram and enhancement notes →](architecture/credential-minting.md).
Enforcement lives in a shared
broker on the host side: Docker runs keep `--network none` and frame calls over a
per-run Unix socket, while WASM uses a direct wazero host function where only
`{method, path, body}` and a bounded response cross linear memory. In both cases the
token stays in Go.

The broker accepts only decoded, canonical paths that are byte-identical to an
approved route. Queries, traversal, and percent-encoding tricks are rejected before
anything is dispatched upstream.

Over RPC, a caller selects a **named server-side profile** by id. Raw caller-supplied
grants are intentionally not accepted over the wire, so base URL, routes, and
credential all stay server-side, and every profile carries an `allowed_callers` ACL.

### The policy and the tool description are generated from one source

Three things describe the same API surface, and in every hand-maintained setup they
drift apart:

- the **allow list**, which is what the broker enforces,
- the **preamble**, the JavaScript client the agent actually calls,
- the **tool description**, the text a gateway shows the model so it knows what exists.

When they disagree the failure is quiet and specific: the model is told about a route
the broker will refuse, or the client offers a method the policy never approved. You
find out at runtime, in an agent transcript.

[`plimsoll-specgen`](../cmd/plimsoll-specgen) derives **all three from one OpenAPI 3.x
document**, so they cannot disagree. Path parameters become whole-segment `*` routes,
operations become typed methods on a global, and summaries become the description. It
is deterministic and fully offline: no server is contacted and no credential is
needed. It fails closed on ambiguous input, and it **reports rather than silently
drops** what it cannot express, so a verb the broker cannot enforce (`HEAD`,
`OPTIONS`, `TRACE`) is a warning rather than a gap you discover later.

```sh
plimsoll-specgen -outdir ./generated api.openapi.json  # every artifact, as files
plimsoll-specgen -emit catalog       api.openapi.json  # every route, for operator advice
plimsoll-specgen -emit health        api.openapi.json  # the recovery probe, if marked
```

**It generates a subset of OpenAPI, and says so when your document leaves it.** A grant
authorizes a literal path template, so an operation that *requires* a query, header, or
cookie parameter cannot be called through the broker at all: it is skipped with its
reason rather than granted as a route the agent can never use, and an operation with
optional ones is generated with a warning that the method always calls the bare route.
A `$ref` path item or parameter is an error, not a silent omission. The emitted SDK is
run in the embedded QuickJS engine by the project's own tests, so a generated method
that cannot parse or throws on its first call fails the build rather than the agent.

**One decision the generator cannot make for you.** The `allow` list it emits is
*every* operation in the document, because a spec describes what an API has, not what
an agent should be able to reach. Pasting it unedited into a profile grants the agent
the whole API. Trim it to the routes you actually want reachable, and keep the
untrimmed list in the profile's `catalog` field: the gap between the two is what lets
the advisor name the specific missing route to add, instead of reporting a vague
shortfall you still have to diagnose.

Worked example, with the input document and every generated artifact side by side:
[docs/examples/specgen](examples/specgen).

### The broker also protects the API from the agent

A sandbox usually protects your infrastructure from the agent's code. This one also
protects your upstream API from the agent's behaviour, which is a different failure:
**an agent loop that reacts to a 429 by trying again, faster.**

Nothing in a model's training makes it back off. So the broker does it host-side. When
an upstream returns 429 or 503, a **per-run circuit breaker** opens for a cooldown
that honours `Retry-After` (capped at 30s), and further permitted calls are *shed* with
a fast 503 rather than piled onto an API that has already asked for room.

Recovery depends on which of those two the upstream said, because they ask different
questions. A **503** means the service is degraded, and the grant's declared
`health_check` route can speak to that: while shedding, one elected caller per second
probes it and a 2xx closes the breaker early, so recovery does not wait out the full
cooldown or burn an expensive call to discover it. A **429** means *this caller* has
spent its allowance, which a healthy service says nothing about — so that window is
never probed and is simply waited out. Reopening it on a cheerful 200 would push the
run's traffic straight back into the limiter that just asked it to stop. For the same
reason, the generator will not pick a probe because an endpoint is *named* `/status`
or `/healthz`; you mark the one that answers "can this API take traffic again" with
`x-plimsoll-health-check`.

The probe uses the run's credential but is neither traced nor charged to the call
budget. Sheds are counted separately from policy denials (`CallTrace.Shed` versus
`Denied`) and surface on the audit line as `host_calls_shed`, so "the agent was
throttled" and "the agent tried something it was not allowed to" never look alike.

**The call budget is per profile, with a default and a ceiling.** A run gets 256
brokered calls unless its profile sets `max_calls`, and no profile may ask for more
than 100,000. The reason to raise it is a workload that is a loop by design, such as
a controller stepping a simulated plant once per tick, where 256 calls is a few
seconds of simulated time. The reason there is still a ceiling is that a capability
must never amount to an unbounded number of requests against your API. The metadata
trace stays capped at 256 rows whichever budget applies: it is bounded evidence, not
a ledger, and the calls past the cap are counted as `Dropped` so a finding says "at
least" rather than reporting a number it cannot support.

**The scope is one run.** This is not fleet-wide overload protection and does not
coordinate across concurrent runs; it stops a single agent loop from hammering an
endpoint that is already struggling.

### Prior art, and what differs here

Keeping the credential out of the guest is not a new idea, and two funded platforms
ship a version of it. Vercel Sandbox's **credentials brokering** injects the credential
into egressing traffic host-side, so that "the secrets never enter the sandbox, so code
running inside it cannot exfiltrate them." Cloudflare's **Code Mode** holds the access
tokens in a supervisor outside the isolate and makes `fetch()` and `connect()` throw
inside it. Two teams building the same control independently is the best evidence
available that it is the right control.

Checked September 2026 against their current documentation, four things differ here:

- **Route granularity, and denial as the default.** Vercel states plainly that
  "Matchers never block traffic": access is decided per domain from the TLS SNI, and a
  request matching no rule still reaches that domain, simply without the credential
  attached. Restricting a domain to particular paths means routing it through a proxy
  you write and rejecting the rest there. plimsoll refuses anything that is not
  byte-identical to an approved route, and that refusal is the component rather than an
  integration point.
- **JWT profiles mint a fresh credential per run.** Their documented
  examples interpolate a long-lived token from the operator's environment. A grant here
  carries a `TokenMinter` called once per run with that run's scopes and the calling
  principal as the subject; static profiles deliberately reuse their bearer.
- **No parallel path to bypass.** Vercel documents that traffic permitted by
  `subnets.allow` "bypasses SNI filtering, credentials brokering, and requests
  proxying", and that domain fronting is possible because matching reads the SNI alone.
  A plimsoll guest has no network at all outside the broker: Docker runs with
  `--network none`, and the WASM guest has a host function and no sockets.
- **Backpressure and generation.** Neither documents a circuit breaker or backoff on an
  upstream 429/503, and while generating a model-facing tool surface from OpenAPI is
  well populated, generating the *enforced* allow list from the same document is not
  something this project has found elsewhere.

**Where theirs is broader, and it is a real trade.** Vercel's firewall governs whatever
the sandbox runs, so package installs, `git`, and Postgres clients all work with a
credential attached at the boundary. plimsoll's broker serves JavaScript runs through
the injected client, and everything else in the guest has no egress whatsoever: the
project toolchain is baked into the image precisely because runtime has no network. If
your agent needs to `npm install` mid-run against a private registry, their model covers
that case and this one does not. What this one offers instead is dependencies baked
into the image at build time, with the registry credential never present in a run:
[docs/guest-dependencies.md](guest-dependencies.md).

Vendor documentation changes; this comparison is dated for that reason. If it is wrong
or has gone stale, open an issue.
