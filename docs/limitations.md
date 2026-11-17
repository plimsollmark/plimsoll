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
- **A one-shot E2B run's code can be root inside its own microVM.** E2B's base template
  gives its default user `sudo` without a password, and a one-shot run starts as that
  user. The VM is the boundary: root inside it reaches nothing outside, and the VM is
  deleted after the run. In a <dfn>*session*</dfn> (one sandbox kept for many calls),
  the code runs as a user that cannot become root ([sessions](sessions.md)).
- **A hosted provider can read what it stores and runs.** Docker Cloud keeps an image in
  its store and runs it on its machines; E2B its templates; an
  [OpenShell (INTERNAL · glossary →)](trainers/glossary.html#openshell) gateway or a
  Kubernetes cluster its pods. The provider can read the image and a running sandbox, and
  plimsoll has no provider whose hardware hides a run from its host to change that. Keep
  what must stay from the provider out of the image: `plimsoll-withheld scan-image` checks
  an image against a withheld set before a push
  ([INTERNAL · the ship scan →](ship-scan.md)).
- **An upload has 30 seconds to arrive.** The daemon's read timeout covers the request
  body, up to its 8 MiB limit, so a client slower than about 280 KB/s on a full-size
  project is cut off (8 MiB in 30 seconds); a faster link or a smaller project is the
  remedy.
- **The [agent-sandbox (INTERNAL · glossary →)](trainers/glossary.html#agent-sandbox)
  provider's pods all share one TLS key.** plimsolld reaches each Kubernetes pod over TLS
  that it checks against the deployment's own certificate authority, but every pod serves
  the same certificate from one Secret, so code that broke out to root inside one pod could
  read the key and, from a position on the pod network, pass for any pod until the Secret is
  rotated. Code in the sandbox cannot read the key without such a break, which the startup smoke test
  checks; rotate the Secret on a schedule. The same fact has a second consequence: the certificate
  proves the peer is a plimsoll sandbox pod of the deployment, not the pod plimsolld dialed, so
  an attacker who can rewrite traffic on the pod network can redirect one caller's connection
  into another pod of the deployment (such as one their own run holds) and receive that run's
  code, files and token. Until each pod has a key of its own, plimsolld started with `PLIMSOLL_HARDENED=1`
  ([what that setting enforces](hardened-mode.md)) refuses to serve this provider unless `SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK=1` states that an authenticated,
  encrypted pod network or a service mesh with mutual TLS runs under it, since the daemon cannot
  check that itself
  ([agentsandbox.md](agentsandbox.md#the-control-channel-is-tls)).
- **The E2B guard only works in the daemon process that started the run, so it cannot sit
  behind an ordinary load balancer.** A run's guard credential lives in the memory of the
  process that created the run, so a guard request sent to a second copy of the daemon is
  rejected as an unknown credential, even though it is valid. Whatever serves the public
  guard URL must be the same process that launches the runs. Running more than one copy
  needs a separate guard address for each daemon (a distinct hostname or path), not
  requests spread across the copies in turn.
- **The guard needs an address of its own, `PLIMSOLL_GUARD_ADDR`.** Code in a granted
  E2B or Docker Cloud run may connect to the guard and nowhere else, so plimsolld serves
  the guard on a listener that answers the guard path (`/v1/e2b/guard`,
  `/v1/dockercloud/guard`) and nothing else, never on the address callers use for the
  RPC procedures, `/healthz` and `/readyz`. Setting a guard URL without
  `PLIMSOLL_GUARD_ADDR` fails startup, and the public guard URL must reach that address,
  so a deployment with grants publishes two addresses: the guard to the provider's
  network, and the RPC address to its callers. On E2B the guard's network rule names a
  host, never an address (E2B refuses an address, so `E2B_GUARD_URL` must use a name):
  E2B sends port 443 connections from code in a granted run to that name's own host, whatever
  address the code asked for, and lets it reach port 80 of the same host. Serve nothing
  else on ports 80 and 443 of the guard's host name.
- **`/readyz` reports configuration and reachable dependencies, not a working run.** For
  `docker` it checks the docker daemon and runtime it is configured to use. For `e2b` it
  checks settings only, and does not prove the API is reachable, the key is valid, or the
  guard can be reached. The proof of behaviour is the startup `SmokeTest`, which runs once
  and creates a real microVM that costs money, so it deliberately does not run on
  `/readyz`, which anyone can poll without logging in. A green `/readyz` on `e2b` means
  "configured", not "working". A red one says only `not ready`; why is in the daemon's
  log, since a poller without a login has no business reading host or image names.
- **The <dfn>*isolation tiers*</dfn> are evidence, not <dfn>*attestation*</dfn>.** A tier
  is how strong the wall around a run is; attestation is cryptographic proof from the
  hardware of what software is running. `kernel` and `vm` rest on which provider it is,
  the daemon's and the runtime's configuration, and the startup tests, as
  [isolation-tiers.md](isolation-tiers.md) spells out. Nothing here measures a
  <dfn>*hypervisor*</dfn> (the program that runs virtual machines) or checks a kernel wall
  cryptographically. If your <dfn>*threat model*</dfn> (the attacks
  you must hold out against) needs attestation, no tier here supplies it.
- **The `wslc` provider is not a security sandbox by its own vendor's account.** Microsoft
  states that WSL, the Windows Subsystem for Linux that the provider's WSL containers run
  in, is "not a security sandbox for running untrusted code". The per-run mode gives each
  run its own Hyper-V VM. It reports the `container` tier, because Microsoft states that
  WSL is not a security sandbox for running untrusted code; an operator who accepts that
  statement sets `SANDBOX_WSLC_ACCEPT_VM_TIER=1`, and it then reports `vm` with that
  statement attached. Inside each of its virtual machines a container gets no read-only
  root filesystem, no <dfn>*seccomp*</dfn> profile (the kernel's filter on which requests a
  process may make) beyond docker's default, no no-new-privileges, no per-run process limit
  and no user <dfn>*namespaces*</dfn> (which map a container's root user to a powerless one
  outside it): five controls the docker provider applies. Its process count, `--ulimit
  nproc`, counts every process of the code's user in the virtual machine, so the shared
  mode, whose runs share one, runs one run at a time. The per-run mode relies on `wslc
  system session enter`, a command Microsoft has not documented. With gVisor on inside the
  per-run mode's virtual machines, a run is occasionally refused because its session was
  lost, cause not yet known. CI runs on hosted Linux runners, which have no WSL, so it
  tests the provider against a stand-in only; the live suites run by hand on a Windows
  machine, and they have run on one machine and one WSL release. <dfn>*Hardened mode*</dfn>
  (the daemon's strict production check, `PLIMSOLL_HARDENED=1`) refuses the provider in
  both modes ([INTERNAL · WSL containers →](wslc.md)).
- **There is no single control point across several daemons.** Each daemon is configured
  and controlled on its own.
- **Nothing updates itself.** Updates are manual. The QuickJS build is
  <dfn>*pinned*</dfn>, fixed to one exact version, by its SHA-256, and gVisor by a SHA-512 of its release recorded for
  each architecture the installer supports (x86_64 and aarch64); the installer refuses
  any other architecture. Code generators are pinned by `go.mod` `tool` directives and
  the gate's programs by `gate-tools.versions`. Every base image the recipes build on is
  pinned by its <dfn>*digest*</dfn> (a hash of its content), but the packages they install
  are not: apk takes version ranges (`python3~3.14`) and apt the distribution's current
  release, so rebuilding an image can change its installed software. Launch-time image
  digest pinning is opt-in through `SANDBOX_REQUIRE_PINNED_IMAGES=1`.
- **A restarted daemon forgets the sandboxes it was still removing.** When a sandbox's
  removal is not confirmed, the daemon keeps counting it against its capacity until it
  is gone. That count lives in the daemon's memory: after a restart, such a leftover is
  removed once the lifetime label it was started with has passed, but until then it does
  not count against the new process's limits. Several daemons may share one docker host,
  and a leftover names no daemon, so a restarted daemon cannot tell its own leftovers from
  another daemon's live sandboxes.
