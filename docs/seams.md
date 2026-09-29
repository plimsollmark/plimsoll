# Deferred seams (anticipated extension points)

A *seam* here is the place in the code where a capability we chose not to build would
plug in. Three capabilities are deliberately **not** built, and each is marked with a
`SEAM(...)` comment at its exact attach point, so that if we later decide to build it,
it is a clean addition rather than a rework. None of them is being worked on; this file
is the map, not a commitment.

All three came from comparing plimsoll with agent sandboxes sold as part of a larger
platform (VMware Tanzu "Agent Foundations" and similar). That comparison is not part of
this repository; this file holds only where each would plug in and what it must not
break.

Grep the tree for `SEAM(` to find the markers in the code.

---

## Forensic logging

**The idea.** Some agent platforms sell a "forensic audit trail of every tool the agent
called": a log of the full request and response of every API call the agent's code made.
In plimsoll those calls go through the <dfn>*broker*</dfn>, the part of plimsoll that makes
each API call for the sandboxed code: it checks the call against the run's
<dfn>*grant*</dfn> (its permission to call listed routes of one API), attaches the
credential itself and counts the calls.
plimsoll deliberately does the opposite of full logging today. For each run, the
[`CallTrace`](../sandbox/calltrace.go) keeps **metadata only**: the route template (the
matched route pattern, such as `/orders/*`, not the actual path), verb, byte counts,
status and latency. Its row type, `CallRow`, has **no field** for a path, query, body, or
credential, so none can get into it. That is privacy by construction, and it is one of the
invariants, the rules no change may break, in [AGENTS.md](../AGENTS.md).

**Why it is a seam, not a feature.** A minority of customers (regulated ones, or ones
that do a lot of incident response) may really want every call captured in full for one
<dfn>*grant profile*</dfn>, a grant stored on the server under a name. That is a legitimate *opt-in*, but it must never become the default and must
never add fields to the metadata-only type.

**Why the default is defensible without it.** The obvious challenge to privacy by
construction is *"that is not a design, you just record less: now nobody can answer which
record the agent read."* Half of that is right: plimsoll's own audit line cannot answer
it, and this seam is what a customer who really needs the answer would buy. The other half
is wrong, because the answer is not gone; it is one layer up. The API the broker calls is
the **caller's own service**, which logs its own requests. The run request carries a
[`trace_id`](../internal/rpc/trace.go), an ID from the caller's own log that the daemon
copies onto the run's audit line without interpreting it. The two logs join on that ID. So
the sensitive data lives in exactly one place instead of two, and not copying it shrinks
what one leak can expose rather than losing information. Without that shared ID this seam
would be carrying far more weight than it should. With it, the default is complete on its
own, and full-call capture is a real need of a few customers rather than a gap.

**Attach point.** `brokerSession.Call` in [sandbox/broker.go](../sandbox/broker.go): the
one place, shared by every <dfn>*provider*</dfn> (the backend that runs the code), where
one call's request and response bytes, both already size-capped, are in hand at the same
time. A forensic sink, the writer that would store the full calls, hooks in there next to
the existing metadata `trace.record(...)`, never through it; otherwise the `docker` and
`wasm` providers would produce different evidence.

**What it must not break.**

- `CallRow` and the default `CallTrace` path stay byte-identical when the sink is off.
  Forensic capture is a separate sink, not extra fields in the row.
- Off by default. It would need both an explicit setting in the grant profile (next to
  `advice` and `advice_retention` in [internal/grants](../internal/grants/)) and a switch
  for the whole deployment, so it cannot be turned on by accident.
- It writes to its own stored log, with its own retention period and access control,
  never to the metadata audit line, `/metrics`, or the advice returned to the caller, all
  of which stay metadata-only.
- The efficiency advisor, Prospector, never reads it; the advisor stays metadata-only
  regardless.

**Rough shape if built.** A setting `forensic: off|headers|bodies` on a grant profile.
When it is set, the broker copies each call's request and response, already size-capped,
to a writer the deployment supplies. It is absent by default, and one test would prove
that every metadata record stays the same when it is off.

---

## Supply-chain provenance

**The idea.** Platforms that bundle agent sandboxes promise an "immutable
<dfn>*supply chain*</dfn>", the supply chain being everything outside your own code that
ends up in what you run: dependencies, base images, build tools. Theirs is built with
**buildpacks** that patch base images automatically. plimsoll gets immutability a
different way, by <dfn>*pinning*</dfn>: fixing each image to one exact version. An image
must be named by its `@sha256:` <dfn>*digest*</dfn>, a SHA-256 hash of its content
(`RequirePinnedImages`), and every run launches the exact image ID that
<dfn>*preflight*</dfn>, the check a provider runs at startup and on each readiness poll,
inspected (`verifyImageForRun` and `verifiedImageIDs` in
[sandbox/docker.go](../sandbox/docker.go)). So a tag moved to another image after startup
cannot slip an unchecked image into a run.

**What buildpacks are.** A buildpack is a build tool (Cloud Native Buildpacks is the
standard, from the Cloud Native Computing Foundation; Paketo is a common implementation)
that turns application source into a container image **without a hand-written
Dockerfile**. Instead of `FROM someimage` followed by `RUN` steps, buildpacks detect what
the application needs (a Node runtime, say), assemble the image from versioned layers
their vendor maintains, and record a bill of materials (an SBOM: the list of everything
in the image). They sell two security points. There are no arbitrary `RUN` steps, so
there is less room to slip in a malicious layer. And because the base image (the "run
image") is a known layer the vendor maintains, rather than a snapshot a Dockerfile baked
in, the platform can **rebase** it: swap in a patched base under the same application
layers, so publicly known vulnerabilities (CVEs) in the base are patched without anyone
rebuilding. The trade against plimsoll's pin and verify: buildpacks buy automatic
patching and a standard bill of materials, at the cost of trusting the buildpack
toolchain and giving up a byte-for-byte pin. plimsoll today chooses to run exactly the
digest it verified over automatic patching.

**Why it is a seam, not a feature.** Automatic patching is a real convenience plimsoll
gives up today. If a deployment wants images built by buildpacks, patched automatically
and shipped with signed <dfn>*provenance*</dfn> (a record of where an artifact came from
and how it was built, kept so that someone else can check it) instead of digests pinned
by hand, that model should plug in without weakening the guarantee that a run launches
only content the provider verified.

**Attach point.** The image check in preflight, in
[sandbox/docker.go](../sandbox/docker.go): `Preflight` calls `verifyImageForRun`, which
today enforces the digest pin and resolves the image ID, which docker derives from the
image's content. Another provenance check (verifying a signature, or resolving the base
image a buildpack builder currently names) would attach here, as an extra or alternative
check chosen by configuration, feeding the same `verifiedImageIDs` map.

**What it must not break.**

- Whatever the provenance model, a run still launches an image ID this provider
  inspected, named by its content, never a tag that can be moved. Automatic rebasing
  changes *which* digest is current; it does not remove the step that verifies an exact
  ID and then launches that ID.
- No new network access on the run path. Signature and provenance checks happen at
  preflight (startup and readiness), not per run, and add no dependency to the code that
  handles hostile code without cause (the dependency rule in [AGENTS.md](../AGENTS.md)).
- `RequirePinnedImages` and this check combine: a deployment can demand both a pinned
  digest and valid signed provenance.

**Rough shape if built.** A `SANDBOX_IMAGE_PROVENANCE=pinned|attested|buildpack` setting.
`attested` additionally verifies a signed statement about the image (a cosign signature,
or an <dfn>*in-toto*</dfn> statement, a standard format for signed statements about
software) before recording its ID; `buildpack` resolves the current base image's digest
from the builder, then follows the same verify-and-record path. The default, `pinned`, is
today's behavior.

---

## Gateway

**The idea.** Platforms that bundle agent sandboxes ship a central gateway that sits in
front of many agents, routes their tool calls, and collects logs across the whole fleet.
Agents call tools over <dfn>*MCP*</dfn> (the Model Context Protocol), so it is often sold
as an "MCP gateway".
plimsoll is a **component**, not a platform: one `plimsolld` enforces the rules, and it is
configured per instance (grant profiles, `allowed_callers`, the clients file that
authenticates callers, and the `Describe` call through which a daemon reports what it
offers). A gateway would be a control layer in **front of** many plimsolld instances.

**Why it is a seam, not a feature.** One program embedding plimsoll does not need it. An
operator running many daemons eventually might: to send a run to an instance with the
required <dfn>*isolation tier*</dfn> (how strong the wall around a run is), to add up
`/metrics` and advice across instances, or to present one policy. That should build on
what exists rather than force a redesign, and any gateway plimsoll ships must keep the
rule that telemetry is metadata only, instead of becoming the surveillance hub the
platform pitch describes.

**What exists now.** The routing part is built, as a library rather than a service:
[package placement](../placement/) picks one daemon per request by what each daemon's
`Describe` states, sends each request with the caller's own credential, and tries another
daemon only after a refusal that ran nothing ([placement](placement.md)). One daemon
serving several providers in one process stays the wrong shape: it would put every cloud
credential in the process that runs the `wasm` provider's JavaScript engine, so an
<dfn>*escape*</dfn> from that engine (a bug that lets code act outside it) could reach
them.

**Attach point.** The `Describe` RPC in
[internal/rpc/sandbox_service.go](../internal/rpc/sandbox_service.go), which already
reports what a daemon offers without side effects, plus the isolation tier stated on each
result and the `minimum_isolation` <dfn>*floor*</dfn> (the weakest tier a request accepts)
already in the request. A gateway reads these; it needs no new hooks in the service.

**What it must not break.**

- `Describe` stays truthful and free of side effects (it runs no code and takes no
  capacity slot), so a gateway can trust it without a separate control channel.
- Routing by tier uses the tier the daemons already report and the existing
  `minimum_isolation` floor. A gateway must not let an out-of-date `Describe` answer
  approve a weaker sandbox: the rule that a caller stamps the floor onto every request
  ([AGENTS.md](../AGENTS.md)) already guards this, and a gateway must not weaken it.
- Fleet-wide telemetry stays **metadata only**, the same rule as for one instance: a
  gateway adds up route templates, counts and findings, never paths, bodies or
  credentials.
- Credentials are still <dfn>*minted*</dfn>, created fresh for each run, on the server and
  per instance. A gateway routes and observes; it never becomes a place where credentials
  or raw grants live.

**Rough shape if built.** The service that placement becomes when several callers need
one address or one shared quota ([what placement does not do](placement.md#what-this-does-not-do)):
it keeps each daemon's `Describe` answer current, sends each `Run` to a daemon that
satisfies the request's `minimum_isolation` and `grant_profile`, re-checks the isolation
tier stated on the response, scrapes each daemon's `/metrics`, and gathers their audit
logs into one dashboard. It uses the existing RPC messages, in its own repository or
program, not a change to `sandbox` or `plimsolld`. A new request field that the daemon
enforces would need a new <dfn>*protocol number*</dfn> (the version every request states,
so a daemon that predates the field refuses the request instead of running it without the
field).

---

## Why documented markers, not stub interfaces

plimsoll is part of the <dfn>*TCB*</dfn> (trusted computing base: the code that has to be
correct for the security promise to hold) around hostile code. Interfaces written for
features that may never come, unused hooks, and dead abstractions are themselves more to
attack and more to review, and the codebase is deliberately kept small. So each seam is a
precise comment at the real attach point plus this design note, not a pre-built extension
mechanism. When one of them is scheduled for work, the marker says exactly where it plugs
in and what it must not break.
