# What plimsoll does not do

Stated here so you do not have to discover it in review.

Part of the [plimsoll README](../README.md).

- **It does not build the walls itself.** <dfn>*gVisor*</dfn> (a layer that answers a
  container's requests to the kernel itself) and <dfn>*Firecracker*</dfn> (AWS's
  open-source virtual machine monitor) do that.
- **`wasm` runs snippets only.** That <dfn>*provider*</dfn> (a provider is the backend
  that runs the code) runs JavaScript on <dfn>*QuickJS*</dfn>, a small engine compiled to
  <dfn>*WebAssembly*</dfn> (a portable bytecode), inside the daemon. It has no multi-file
  projects, so a project <dfn>*grant*</dfn>, permission for a run's code to call listed
  routes of your API, is rejected on it outright.
- **No package installation during a run.** A run has no network, so `npm install`
  cannot happen inside it, from a public registry or a private one. Dependencies are
  built into the project image ahead of time, which is also where the registry
  credential lives and the only place it ever exists;
  [docs/guest-dependencies.md](guest-dependencies.md) is the recipe. An agent that must
  install arbitrary packages mid-run is the case general-purpose sandbox virtual machines
  cover and plimsoll does not.
- **<dfn>*E2B*</dfn> grants need `E2B_GUARD_URL`.** E2B is a hosted service that runs each
  request in a <dfn>*microVM*</dfn>, a small virtual machine made for one run. With a
  grant, the VM's one permitted connection goes to the <dfn>*guard*</dfn>, an address on
  the plimsoll server that checks each call, so the credential and the route checks stay
  outside the hostile VM. Without a grant, an E2B run has no <dfn>*egress*</dfn>: nothing
  leaves the VM.
- **The E2B guard only works in the daemon process that started the run, so it cannot sit
  behind an ordinary load balancer.** A run's guard credential lives in the memory of the
  process that created the run, so a guard request sent to a second copy of the daemon is
  rejected as an unknown credential, even though it is valid. Whatever serves the public
  guard URL must be the same process that launches the runs. Running more than one copy
  needs a separate guard address for each daemon (a distinct hostname or path), not
  requests spread across the copies in turn.
- **`/readyz` reports configuration and reachable dependencies, not a working run.** For
  `docker` it checks the docker daemon and runtime it is configured to use. For `e2b` it
  checks settings only, and does not prove the API is reachable, the key is valid, or the
  guard can be reached. The proof of behaviour is the startup `SmokeTest`, which runs once
  and creates a real microVM that costs money, so it deliberately does not run on
  `/readyz`, which anyone can poll without logging in. A green `/readyz` on `e2b` means
  "configured", not "working".
- **The <dfn>*isolation tiers*</dfn> are evidence, not <dfn>*attestation*</dfn>.** A tier
  is how strong the wall around a run is; attestation is cryptographic proof from the
  hardware of what software is running. `kernel` and `vm` rest on which provider it is,
  the daemon's and the runtime's configuration, and the startup tests, as
  [isolation-tiers.md](isolation-tiers.md) spells out. Nothing here measures a
  <dfn>*hypervisor*</dfn> (the program that runs virtual machines) or checks a kernel wall
  cryptographically. If your <dfn>*threat model*</dfn> (the attacks
  you must hold out against) needs attestation, no tier here supplies it.
- **There is no single control point across several daemons.** Each daemon is configured
  and controlled on its own.
- **Nothing updates itself.** Updates are manual. The QuickJS build is
  <dfn>*pinned*</dfn>, fixed to one exact version, by its SHA-256, and gVisor by a SHA-512 of its release recorded for
  each architecture the installer supports (x86_64 and aarch64); the installer refuses
  any other architecture. Code generators are pinned by `go.mod` tool directives and
  the gate tools by `gate-tools.versions`. The sandbox image recipes use mutable base
  tags and apk version ranges; only the wasi-sdk stage is pinned by its
  <dfn>*digest*</dfn> (a hash of its content). Rebuilding an image can therefore change
  its installed software. Launch-time image digest pinning is opt-in through
  `SANDBOX_REQUIRE_PINNED_IMAGES=1`.
