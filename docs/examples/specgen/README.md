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
current capacity. specgen recognizes it as the profile's `health_check` — the backpressure
recovery probe — and writes it to `health_check.txt`, so `grants.json` sets
`"health_check": "GET /status"` with no hand-wiring. At runtime, an upstream `429`/`503`
trips the per-run circuit breaker; while the broker sheds calls, one elected caller/sec
probes `GET /status` host-side and closes the breaker early on a `2xx`.

Detection needs no annotation: a concrete `GET` whose last path segment is a well-known
health/readiness/capacity name (`/status`, `/healthz`, `/readyz`, `/capacity`, …) is
picked automatically, preferring a readiness/capacity signal over a bare liveness/ping (a
process can be live but still shedding). To designate a non-standard route, or to
disambiguate when two equally-ranked names tie, mark exactly one operation with the
`x-plimsoll-health-check: true` OpenAPI extension — that wins over the heuristic, and a
marker on a non-`GET` or parameterized path fails generation closed. If the spec declares
no health route, no `health_check.txt` is written and the profile simply gets reactive
shedding with no recovery probe. Get just this line with `plimsoll-specgen -emit health`.

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

## Using it in a build

Wire the command into the consumer's build (a `go generate` directive or a Make
target), commit the three artifacts, and delete the hand-maintained copies. From then
on, the spec is the one place the API surface is described.
