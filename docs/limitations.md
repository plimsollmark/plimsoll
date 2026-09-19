# What plimsoll does not do

Stated here so you do not have to discover it in review.

Part of the [plimsoll README](../README.md).

Stated so you do not have to discover it in review:

- It does not implement an isolation boundary. gVisor and Firecracker do that.
- WASM supports snippets only, not multi-file projects, and WASM project grants are
  rejected outright.
- **No package installation during a run.** A run has no network, so `npm install`
  cannot happen inside it, from a public registry or a private one. Dependencies are
  baked into the project image at build time, which is also where the registry
  credential lives and the only place it ever exists;
  [docs/guest-dependencies.md](guest-dependencies.md) is the recipe. An agent
  that must install arbitrary packages mid-run is the case the general-purpose
  sandbox VMs cover and this component does not.
- E2B grants require `E2B_GUARD_URL`; the forced, authenticated guard keeps
  credentials and route enforcement outside the hostile VM. Without a grant,
  E2B runs deny egress.
- **The E2B guard is process-local, so it does not sit behind an ordinary load
  balancer.** A run's guard credential lives in the memory of the process that
  created that run, so a guard request routed to a second replica is rejected as an
  unknown credential even though it is valid. Whatever serves the public guard URL
  must be the same process that launches the runs. Running more than one replica
  needs the guard path pinned per instance (a distinct hostname or path per daemon),
  not round-robin.
- **`/readyz` reports configuration and reachable dependencies, not a working run.**
  For `docker` it probes the pinned daemon and runtime; for `e2b` it validates
  configuration and does not prove the API is reachable, the key is valid, or the
  guard is routable. The behavioural proof is the startup `SmokeTest`, which runs
  once and creates a real (billable) microVM — deliberately not on an unauthenticated
  poll path. A green `/readyz` on `e2b` means "configured", not "working".
- **The isolation tiers are evidence, not attestation.** `kernel` and `vm` rest on
  provider identity and daemon/runtime configuration plus the behavioural smoke
  tests, as spelled out above. Nothing here measures a hypervisor or verifies a
  kernel boundary cryptographically. If your threat model needs attestation, no tier
  in this component supplies it.
- There is no fleet-level gateway across instances. The control surface is per
  instance.
- There is no auto-patching supply chain. Images, the QuickJS artifact, gVisor, the
  codegen plugins, and the three tools the gate shells out to are pinned instead,
  which buys determinism and gives up automatic updates. One qualification, because
  "verified by digest" is not uniformly true: the gVisor installer pins the release
  on every architecture, but the checksum it compares against is recorded in this
  repository only for x86_64. Elsewhere it verifies the release bucket's own
  `.sha512`, which catches a corrupted transfer, not a compromised bucket.
