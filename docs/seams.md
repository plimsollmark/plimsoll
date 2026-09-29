# Deferred seams (anticipated extension points)

Three capabilities we have deliberately **not** built, each staged in the code as a
`SEAM(...)` marker at its exact attach point so that if we later decide to build it,
it is a clean addition rather than a rework. None of these is on the moving edge;
this file is the map, not a commitment.

The prompt for all three was a competitive read of platform-bundle agent sandboxes
(VMware Tanzu "Agent Foundations" and similar). That comparison is not part of this
repository; this file is only the "where would it plug in, and what must it not
break" detail.

Grep the tree for `SEAM(` to find the live markers.

---

## Forensic logging

**The idea.** Some agent platforms sell a "forensic audit trail of every tool the
agent called," logging the full request and response of each brokered call. plimsoll
deliberately does the opposite today: its per-run [`CallTrace`](../sandbox/calltrace.go)
records **metadata only** (route template, verb, byte counts, status, latency), and
`CallRow` has **no field** for a path, query, body, or credential, so none can enter
it by construction. That is privacy-by-construction, and it is an
[AGENTS.md](../AGENTS.md) invariant.

**Why it is a seam, not a feature.** A minority of customers (regulated, incident-
response heavy) may genuinely want full-call capture for a specific profile. That is a
legitimate *opt-in*, but it must never become the default and must never widen the
metadata-only type.

**Why the default is defensible without it.** The obvious challenge to
privacy-by-construction is *"that is not a design, you just record less — now nobody
can answer which record the agent read."* Half of that lands: plimsoll's line alone
cannot answer it, and this seam is what a customer who genuinely needs it would buy.
The other half does not, because the answer is not gone, it is one layer up. The API a
brokered call reaches is the **caller's own service**, which logs its own requests, and
the run request carries an opaque [`trace_id`](../internal/rpc/trace.go) that the
daemon echoes onto the run's audit line. The two logs join on that id. The sensitive
payload therefore lives in exactly one place instead of two, and declining to duplicate
it is a reduction in blast radius rather than a loss of information. Without the join
key this seam would be carrying far more weight than it should; with it, the default
posture is complete on its own and forensic capture is a real minority need rather than
a gap.

**Attach point.** `brokerSession.Call` in
[sandbox/broker.go](../sandbox/broker.go), the provider-neutral point where one
call's bounded request and response bytes are simultaneously in scope. A forensic
sink taps there, alongside the existing metadata `trace.record(...)`, never through
it; otherwise Docker and WASM would produce different evidence.

**Invariants it must preserve.**

- `CallRow` and the default `CallTrace` path stay byte-identical when the sink is off.
  Forensic capture is a separate sink, not a wider row.
- Off by default. It would be gated by an explicit per-profile config (sibling to
  `advice`/`advice_retention` in [internal/grants](../internal/grants/)) plus a
  deployment-level enable, so it cannot be turned on by accident.
- It writes to its own durable stream with its own retention and access control, never
  to the metadata audit line, `/metrics`, or the caller wire hint, all of which stay
  metadata-only.
- The advisory pipeline never reads it; Prospector stays metadata-only regardless.

**Rough shape if built.** Placement (choosing a backend per request) starts as a small
routing **library** an embedder links, and becomes a separate service only when several
callers need one endpoint or one central quota. Either way it is a consumer of the
existing wire contract, in its own repo or binary, not a change to `sandbox` or
`plimsolld`. An in-process multi-provider daemon is the wrong shape: it would put the
WASM engine's escape surface in the same process as every cloud credential.

1. **Filter, then rank.** Keep only backends whose `Describe` evidence meets the
   request's `minimum_isolation`, that support the payload kind and `grant_profile`, and
   whose `max_timeout_ms` for that kind covers the request's timeout (a longer timeout is
   cut to the ceiling, not refused).
   Rank the survivors by cost only after that; a missing or stale price fails the
   comparison instead of counting as zero, and local compute is not free.
2. **Keep the caller's identity.** Forward the caller's own credential. A router that
   forwards with one shared bearer collapses every profile's `allowed_callers` and the
   per-run minted token's `sub` into one principal.
3. **Reselect only after a refusal that ran nothing.** A `Run` error carrying the
   `NotDispatched` detail with reason `unsupported`, `isolation` or `capacity` may go to
   the next backend; `request`, `permission` and `protocol` would fail the same way
   elsewhere. An error without the detail may have executed, so it is never re-sent
   ([run results](run-results.md#did-anything-run-the-error-says-so)).
4. **Equal tiers are not equal environments.** Two `vm` backends can run different
   engines, packages and numerics. `Describe` states each payload kind's environment
   `identity` only when it is content-addressed (a verified image ID, an image digest, the
   interpreter's hash): equal strings mean the same software, and an empty or different
   string claims nothing. Treat backends as interchangeable for a request only when their
   identities match, or their environments are declared compatible and tested to be.
5. **Re-check the returned isolation evidence**, as the official client does.

A request field the daemon enforces would need a protocol bump; everything above uses
fields that already exist.

---

## Why documented markers, not stub interfaces

This is a hostile-code TCB. Speculative interfaces, unused hooks, and dead abstractions are
themselves attack surface and review burden, and the codebase is deliberately tightly
scoped. So each seam is a precise comment at the real attach point plus this design note,
not a pre-built extension mechanism. When one of these is promoted to the moving edge, the
marker says exactly where it plugs in and what it must not break.
