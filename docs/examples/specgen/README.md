# Worked example: generate a grant description from an OpenAPI spec

This is the Sluice **spec-import** deliverable end to end: one OpenAPI document in,
the three grant artifacts out, from a single command. It exists to kill a real
cross-repo drift cost.

## The drift it removes

When agent-generated code calls a customer's API through a plimsoll grant, three
things must describe the *same* surface and stay in lockstep:

1. the grant profile's **`allow`** route list (what the broker will permit),
2. the typed **`preamble`** SDK (so agent code writes `home.getLight(id)` instead of a
   raw path), and
3. the **model-facing tool description** (the text a gateway puts in its MCP
   `run_javascript` tool description — the *only* way the model learns the surface).

Today those are hand-written and hand-mirrored. The motivating case: an MCP gateway
consumer hand-copies its SDK preamble into its MCP tool description, because a model
only learns that surface from the description text. So a new endpoint
means editing the Go preamble, the `allow` list, **and** the description by hand — three
edits that silently rot out of sync.

`plimsoll-specgen` generates all three from the spec, so the spec is the single
source and drift becomes impossible.

## Run it

```sh
go run ./cmd/plimsoll-specgen -global home \
  -outdir docs/examples/specgen \
  docs/examples/specgen/smart-home.openapi.json
```

That reads [smart-home.openapi.json](smart-home.openapi.json) and (re)writes these files
in this directory:

| File | What it is | Where it goes |
|------|------------|---------------|
| [allow.json](allow.json) | the `"METHOD /path"` route list, params → `*` | paste as the profile's `allow` |
| [preamble.js](preamble.js) | typed JS SDK attached to `globalThis["home"]` | the profile's `preamble_file` |
| [description.txt](description.txt) | model-facing operation listing | the gateway's MCP tool description |
| [health_check.txt](health_check.txt) | the `"GET /path"` backpressure probe, if the spec declares one | the profile's `health_check` |

[grants.json](grants.json) assembles the generated fields into a real, loadable profile.
The `preamble`, route list, and `health_check` are generated; the rest (`base_url`,
`token`, `allowed_callers`) is operator policy the spec does not carry. The generated
route list appears twice, for two different jobs:

- **`catalog`** is the *full* list verbatim — every endpoint the API exposes.
- **`allow`** is the subset the operator actually grants. Here it deliberately omits
  `GET /lights` (the batch collection), modelling the common gap where the per-item
  routes are granted but the batch one is forgotten.

Prospector reads `catalog` so that when a run fans out on `GET /lights/*`, its advice can
name the concrete fix — *grant `GET /lights`* — instead of a vague "the API needs a
change." With `advice_retention: detailed`, that surfaces on the operator audit line as
`grant_route`. A route that IS already granted stays a caller-facing suggestion the agent
can act on now; only an ungranted-but-cataloged route becomes this operator action. Get
the full list for `catalog` with `plimsoll-specgen -emit catalog`.

## The health route wires straight into backpressure

The spec's `GET /status` endpoint is a cheap read that reports the gateway's health and
current capacity, and it carries `"x-plimsoll-health-check": true`. That marker is what
makes it the profile's `health_check` — the backpressure recovery probe — so specgen
writes it to `health_check.txt` and `grants.json` sets `"health_check": "GET /status"`
with no hand-wiring. At runtime an upstream `503` trips the per-run circuit breaker;
while the broker sheds calls, one elected caller/sec probes `GET /status` host-side and
closes the breaker early on a `2xx`.

**The marker is the only way to designate one, and that is deliberate.** specgen used to
pick a route whose last segment looked like a health endpoint (`/status`, `/healthz`,
`/readyz`, …). That heuristic was deleted on 2026-09-17: a name is not evidence of what
an endpoint measures, so it would happily select an account-status read, and a probe that
answers `200` for the wrong reason closes the breaker and puts the traffic straight back
onto a struggling API. No probe is better than a wrong one — the breaker then simply
waits out its cooldown.

Mark exactly one operation, and make it an endpoint that answers *"can this API take
traffic again"*. A marker on a non-`GET`, a parameterized path, or an operation that
cannot be called at all fails generation closed. With no marker, no `health_check.txt` is
written, `plimsoll-specgen` says so on stderr, and the profile gets reactive shedding with
no recovery probe. Get just this line with `plimsoll-specgen -emit health`.

Note what the probe does **not** cover: a `429`. A healthy service says nothing about
whether *this caller's* rate limit or quota has reset, so a `429` rides out its full
cooldown (the upstream's own `Retry-After` when it sent one) and is never closed early by
a probe. Only a `503` — the upstream reporting itself degraded — is probed for recovery.

## What the generator guarantees

- **Deterministic and offline.** Byte-identical output for a given spec; it never
  fetches the spec's server and embeds no credential. Commit the artifacts and diff
  them in review — a spec change shows up as an artifact change.
- **Path params → whole-segment `*`.** `/lights/{id}` becomes the allow template
  `/lights/*` and the method `home.getLight(id)`. A param that is only part of a
  segment (e.g. `/files/{name}.json`) is rejected, never over-permitted.
- **Raw interpolation, gated by the broker.** `home.getLight(id)` builds
  `"/lights/" + id` and calls the generic client; it does not `encodeURIComponent`
  (which the client rejects) and cannot smuggle a `/` past the segment matcher. The
  host-side broker remains the authoritative gate; the SDK is ergonomics + a
  client-side mirror.
- **Unrepresentable verbs are reported, not dropped.** The host-API broker enforces
  `GET/PUT/POST/DELETE/PATCH`, so those five verbs (including this spec's
  `PATCH /lights/{id}` → `home.updateLight(id, body)`) become first-class routes. A verb
  the broker cannot enforce — `HEAD`, `OPTIONS`, `TRACE` — is **skipped with a warning**
  rather than emitted as an allow route the grant validator would reject:

  ```
  plimsoll-specgen: skipped OPTIONS /lights (host-API grants enforce only GET/PUT/POST/DELETE/PATCH)
  ```

- **Query, header, and cookie parameters cannot be sent.** A grant authorizes a literal
  path template: the broker rejects any target carrying a `?`, and guest code sets no
  headers. An operation that *requires* one is skipped with its reason, and one that
  merely offers optional ones is generated with a warning saying the method always calls
  the bare route. This spec has none; a spec with a `GET /search?q=` gets:

  ```
  plimsoll-specgen: skipped GET /search (requires query "q", which a brokered call cannot send: …)
  ```

- **`$ref` is not resolved.** A `$ref` path item or parameter is an error, not a silent
  omission — bundle or dereference the spec first. Before 2026-09-17 a `$ref` path item
  parsed to an empty entry and vanished from the generated surface without a word.
- **The emitted SDK is executed in tests, not just string-matched.** `internal/specgen`
  runs the generated preamble in the embedded QuickJS engine and calls every method it
  defines, so a body argument that was never bound, an operation named after one of the
  client's own verbs, or a path parameter that is not a legal identifier (`{item-id}`,
  `{default}`, `{h}`) fails the build rather than the agent's first call.

## Using it in a build

Wire the command into the consumer's build (a `go generate` directive or a Make
target), commit the three artifacts, and delete the hand-maintained copies. From then
on, the spec is the one place the API surface is described.
