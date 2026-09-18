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

**Rough shape if built.** `forensic: off|headers|bodies` on a grant profile; when set,
the broker core copies the already size-capped request/response to a
deployment-provided sink writer. Default absent. One redaction test proving the metadata
surfaces are unchanged when it is off.

---

## Supply-chain provenance

**The idea.** Platform bundles pitch an "immutable supply chain" built from
**buildpacks** with automatic base-image patching. plimsoll's current model is
different: **immutability by pinning**. Images are required to be pinned to an immutable
`@sha256:` digest (`RequirePinnedImages`), and every run launches the
content-addressed ID that Preflight actually inspected (`verifyImageForRun`,
`verifiedImageIDs` in [sandbox/docker.go](../sandbox/docker.go)), so a mutable tag
re-pointed after startup cannot substitute an unverified image.

**What buildpacks are.** A buildpack is a build tool (Cloud Native Buildpacks is the CNCF
standard; Paketo is a common implementation) that turns application source into a
container image **without a hand-written Dockerfile**. Instead of `FROM someimage; RUN
...`, a set of buildpacks detect what the app needs (a Node runtime, say), assemble the
image from vendor-maintained, versioned layers, and record a bill of materials. The
selling point for security is twofold: (1) no arbitrary `RUN` steps, so there is less
room to smuggle in a malicious layer, and (2) because the base ("run image") is a known,
vendor-maintained layer rather than a snapshot baked into a Dockerfile, the platform can
**rebase** it, swapping in a patched base under the same app layers, so CVEs in the base
get patched automatically instead of waiting for someone to rebuild. The tradeoff versus
plimsoll's pin-and-verify: buildpacks buy auto-patching and a standard SBOM at the cost
of trusting the buildpack toolchain and giving up a byte-for-byte pin. plimsoll today
chooses determinism (you run exactly the digest you verified) over auto-patching.

**Why it is a seam, not a feature.** Auto-patching is a real operational nicety we
currently trade away. If a deployment wants buildpack-built, attested, auto-patched images
instead of hand-pinned digests, that provenance model should slot in without weakening the
"a run launches only content the provider verified" guarantee.

**Attach point.** The Preflight image-verification step in
[sandbox/docker.go](../sandbox/docker.go) (`Preflight` -> `verifyImageForRun`, which today
enforces digest-pinning and resolves the content-addressed ID). An alternative provenance
check (verify a signature/attestation, or resolve a buildpack run-image reference) attaches
here as an additional or alternative gate selected by config, feeding the same
`verifiedImageIDs` map.

**Invariants it must preserve.**

- Whatever the provenance story, a run still launches a **content-addressed ID this
  provider inspected**, never a mutable tag. Auto-rebase changes *which* digest is current;
  it does not remove the "verify then launch that exact ID" step.
- No new network in the run path. Attestation/signature checks happen at Preflight
  (startup/readiness), not per run, and pull no dependency into the hostile-code TCB
  without cause ([AGENTS.md](../AGENTS.md) dependency rule).
- `RequirePinnedImages` and this stay composable: a deployment can demand *both* a pinned
  digest and a valid attestation.

**Rough shape if built.** A `SANDBOX_IMAGE_PROVENANCE=pinned|attested|buildpack` selector;
`attested` additionally verifies a cosign/in-toto attestation before recording the content
ID; `buildpack` resolves the current run-image digest from the builder and then follows the
same verify-and-record path. Default `pinned` (today's behavior).

---

## Gateway

**The idea.** Platform bundles ship a centralized gateway (an "MCP gateway") that fronts
many agents, routes their tool calls, and aggregates logs fleet-wide. plimsoll today is
a **component**, not a platform: one `plimsolld` is the enforcement point, and its
control surface is per-instance (grant profiles, `allowed_callers`, multi-client auth, and
the `Describe` discovery RPC). A "gateway story" is a control plane in **front of** many
plimsolld instances.

**Why it is a seam, not a feature.** A single embedder does not need it; a fleet operator
eventually might (route a run to the instance with the required isolation tier, aggregate
`/metrics` and advisory findings across instances, present one policy surface). We want that
to compose over what exists rather than force a redesign, and any plimsoll-native gateway
must inherit the metadata-only telemetry invariant instead of becoming the surveillance hub
the platform pitch describes.

**Attach point.** The `Describe` RPC in
[internal/rpc/sandbox_service.go](../internal/rpc/sandbox_service.go), which is already the
side-effect-free, structural capability-discovery surface, plus the per-run `isolation`
evidence on each result and the `minimum_isolation` per-dispatch floor already in the wire
protocol. A gateway reads these; it does not need new hooks in the service.

**Invariants it must preserve.**

- `Describe` stays truthful and side-effect-free (runs no code, takes no limiter slot), so a
  gateway can trust it without a separate control channel.
- Routing by isolation tier uses the **evidence** already on `Describe`/results and the
  existing `minimum_isolation` floor; the gateway must not let a stale `Describe` authorize a
  downgrade (the consumer-stamps-the-floor rule in [AGENTS.md](../AGENTS.md) already guards
  this, and a gateway must not weaken it).
- Fleet-level telemetry aggregation stays **metadata-only**, the same invariant as a single
  instance. A gateway aggregates route templates, counts, and findings, never paths, bodies,
  or credentials.
- Per-run credential minting stays server-side and per-instance. A gateway routes and
  observes; it does not become a place credentials or raw grants live.

**Rough shape if built.** A separate small service that periodically calls `Describe` on each
backend, keeps a capability table, and dispatches a `Run` (of whatever payload kind) to a
backend satisfying the request's `minimum_isolation` and `grant_profile`, re-checking the
returned isolation evidence. It scrapes each backend's `/metrics` and tails their audit
streams into one dashboard. It is a consumer of the existing wire contract, in its own
repo/binary, not a change to `sandbox` or `plimsolld`.

---

## Why documented markers, not stub interfaces

This is a hostile-code TCB. Speculative interfaces, unused hooks, and dead abstractions are
themselves attack surface and review burden, and the codebase is deliberately tightly
scoped. So each seam is a precise comment at the real attach point plus this design note,
not a pre-built extension mechanism. When one of these is promoted to the moving edge, the
marker says exactly where it plugs in and what it must not break.
