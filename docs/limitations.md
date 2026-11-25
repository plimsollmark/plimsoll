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
- **An E2B session needs a template with node v22.14.0 or later; a single run does not.**
  A template is the machine image E2B starts each virtual machine from. A
  single run (one snippet, or one project's files and steps) works on E2B's own `base`
  template, because it starts none of plimsoll's own programs inside the machine, only the
  run's `node` and `sh`. A session starts several (the open, the stager, the process lister,
  the sweep, the relays), each with node's `--disable-sigusr1` option, so that the session's
  code cannot open their debugger (the part of node that runs whatever code it is
  sent to it) by sending them a signal. Node accepts that option from v22.14.0
  (v23.7.0 in the 23 line, every release from 24). `base` carried node v20.9.0 when a live
  check read it on 2026-11-20, and E2B no longer publishes its recipe (removed on
  2026-10-13); on a template whose node is that old a session is refused at its open,
  marked as never run, with the node version needed; a daemon with sessions on stops at
  startup instead of serving them. A session also needs a node outside `/usr/local`: E2B's
  template build leaves that folder writable by every user in the machine, `base` and
  node's own images keep node there, and plimsoll's own programs never take one from it, so
  on `base` a session is refused at its open, marked as never run, in words that say so. In a session, the session's code cannot
  write `/usr/local` either: the open takes that write permission back before any of the
  session's code runs, because E2B's own programs that run as root live there, and a
  template where it cannot is refused at the open ([sessions](sessions.md#e2b)). So a
  session's code cannot install into `/usr/local` (`npm install -g`, for one) on E2B. A
  single run's code still can: it runs as E2B's default user, and plimsoll leaves its
  machine as E2B builds it. The template plimsoll's recipe builds
  ([e2b/README.md](../e2b/README.md)) has node 24, with a copy in `/usr/bin`.
  Building it is one command on E2B's side; E2B's pages do not say whether a build is
  billed.
- **An E2B template's system files are the operator's to
  trust.** A template is the machine image an operator chooses for E2B's virtual
  machines, and plimsoll does not read its files. In a session, plimsoll's own programs
  run as root beside `/work`, and plimsoll closes from its side the routes by which they
  could load a file the session wrote: each starts in `/`, with an empty environment and
  an empty OpenSSL settings file, by the full path the session's open found for it
  ([sessions](sessions.md#e2b)). It does not check a template that replaces a system
  file those programs load so that it points into `/work`: a library, the loader's own
  settings (the loader is the part of the system that loads the libraries a program
  needs; `/etc/ld.so.preload`, for one, names libraries it loads into every program), or
  the settings file of a library other than OpenSSL. Nor does it check a template that
  sets an environment variable which loads code into the first two programs of every
  command, E2B's `/bin/sh` and plimsoll's `/usr/bin/env`, which start before the
  environment is cleared. Such a template would let a session's code run inside
  plimsoll's programs as root, so use E2B's base template or one built from a base you
  trust.
- **A hosted provider can read what it stores and runs.** Docker Cloud keeps an image in
  its store and runs it on its machines; E2B its templates; an
  [OpenShell (INTERNAL · glossary →)](trainers/glossary.html#openshell) gateway or a
  Kubernetes cluster its pods. The provider can read the image and a running sandbox, and
  plimsoll has no provider whose hardware hides a run from its host to change that. Keep
  what must stay from the provider out of the image: `plimsoll-withheld scan-image` checks
  an image against a withheld set before a push
  ([INTERNAL · the ship scan →](ship-scan.md)).
- **On Docker Cloud the no-network statement rests on a check of ordinary connections;**
  one other route has not been measured.
- **An upload has 30 seconds to arrive.** The daemon's read timeout covers the request
  body, up to its 8 MiB limit, so a client slower than about 280 KB/s on a full-size
  project is cut off (8 MiB in 30 seconds); a faster link or a smaller project is the
  remedy.
- **Form and upload bodies are forwarded unread.** Some web frameworks run a POST as the
  method a `_method` field of its body names (this is called method override). The
  <dfn>*broker*</dfn>, the part of plimsoll outside the sandbox that makes each API call for
  the code, refuses the override headers and a JSON body whose top level names `_method`, but
  forwards a form body or a multipart (file upload) body unread on a route the profile opened
  for that type. On an API that honors method override, such a body can make a granted method
  run as another method on the same path. To close it, turn method override off at the API,
  grant JSON routes only (the standard setting), or give the per-run credential (the key the
  broker adds to a run's calls) only the permissions the grant means
  ([INTERNAL · capability grants →](capability-grants.md#method-and-path-override)).
- **The [agent-sandbox (INTERNAL · glossary →)](trainers/glossary.html#agent-sandbox)
  provider trusts every node, and whoever may have a certificate signed in the warm pool's
  [namespace (INTERNAL · glossary →)](trainers/glossary.html#namespace).** Each sandbox pod serves a key and certificate of its own, which an issuer in
  the cluster signs for that pod as it starts, and plimsolld checks in every handshake that
  the certificate names the pod it read from the API server, so a party on the pod network
  cannot redirect one caller's run into another pod, and code that broke out to root in one
  pod holds that pod's key alone. But the node plugin that requests those certificates (the
  certificate manager's CSI driver) may request one for any pod in the cluster, so root on
  any node, or anyone holding that plugin's credentials, can pass for any sandbox pod; so
  can any account that may create certificate requests in the pool's namespace while the
  issuer signs every request made there. The operator guide says who must not hold that
  right ([agentsandbox.md](agentsandbox.md#what-the-operator-sets-up)). The provider also
  now requires that certificate manager and its CSI driver in every cluster it runs on.
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
- **The no-execute mark is a second layer, not a wall.** In a `docker` run or session, the
  writable folders `/tmp`, `/dev/shm` and `/work` are mounted <dfn>*noexec*</dfn> (a file
  stored there cannot be started as a program), a second layer behind the sandbox itself.
  The code cannot add a folder without the mark: that needs a user <dfn>*namespace*</dfn> of
  its own (a private view of the system in which it acts as administrator) and a mount in it,
  and the <dfn>*guest guard*</dfn>, plimsoll's own <dfn>*seccomp*</dfn> filter (the kernel's
  filter on which requests a process may make) in front of every program the docker provider
  starts, refuses both under `runc` and gVisor alike
  ([seccomp.md](seccomp.md#the-guest-guard-a-second-filter-in-front-of-every-program)).
  What the mark never stopped still works: code that can run Python or Node can put a
  program in memory (an in-memory file, `memfd_create`) and start it from there. What a
  user meets because of it: a program built or written in the run or session cannot be
  started there. Measured 2026-11-19 in a docker session: `cargo test` on a Rust crate (a
  Rust package) with a build script or a derive macro (small programs Cargo compiles and
  then starts during the build), a C build that runs what it compiled, and `./script.sh`
  are refused; Go tests work when built to WebAssembly (a portable program format a runner
  reads as data, so the kernel is never asked to start it). An E2B session is different:
  its work folder is on the machine's own disk, with no such mark, and a copied program
  and a shell script written there ran (measured 2026-11-20 on a template built from
  plimsoll's recipe). That recipe has no Rust or C toolchain, so such builds on E2B need a
  template of the operator's own with one; plimsoll has not measured one.
- **The guest guard costs debuggers, and it covers the docker provider only.** It refuses
  tracing, so `gdb`, `strace` and other debuggers do not work in a docker sandbox (under
  docker's built-in profile and under gVisor they worked before it), and it refuses the
  `unshare` command and every program that builds a sandbox of its own from namespaces. It is
  built for x86-64 only; on
  another machine type the docker provider does not start, and it refuses a docker daemon,
  `DOCKER_DEFAULT_PLATFORM` or image for another machine than plimsolld's own, emulated ones
  included. The Kubernetes, WSL containers
  and OpenShell providers do not start their commands behind it yet, and E2B and Docker Cloud,
  whose wall is a virtual machine, do not apply it.
- **Code of a docker session can end or stall its own session through process 1.** In a
  session the guest guard is the container's first process (process 1), which collects every
  process that ends and passes no signal on. Code of the session could always end its own
  session by ending the main process, and it can do so through process 1 too, by causing a
  signal that reads as one from outside the container. Under gVisor it can also stop process 1
  (which then collects no ended process for the rest of the session) or end it, since gVisor
  does not give a container's process 1 the protection from its own container's signals that
  Linux gives it. And while it keeps sending process 1 a stop signal, an outside `docker stop`
  waits its whole timeout before docker kills the container; plimsoll's own close removes the
  container without waiting. None of this reaches past the session itself
  ([seccomp.md](seccomp.md#the-guest-guard-a-second-filter-in-front-of-every-program)).
- **The `wslc` provider is not a security sandbox by its own vendor's account.** Microsoft
  states that WSL, the Windows Subsystem for Linux that the provider's WSL containers run
  in, is "not a security sandbox for running untrusted code". The per-run mode gives each
  run its own Hyper-V VM. It reports the `container` tier, because Microsoft states that
  WSL is not a security sandbox for running untrusted code; an operator who accepts that
  statement sets `SANDBOX_WSLC_ACCEPT_VM_TIER=1`, and it then reports `vm` with that
  statement attached. Inside each of its virtual machines a container gets no read-only
  root filesystem, no seccomp profile (the kernel's filter on which requests a
  process may make) beyond docker's default, no no-new-privileges, no per-run process limit
  and no user namespaces (which map a container's root user to a powerless one
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
- **A session call whose answer was lost does not run exactly once by itself.** The daemon
  refuses any call made from a stale view of the session, returns the lost call's record and,
  when it still keeps it, its answer, and the official clients refuse every call until the
  application handles the lost one ([sessions](sessions.md#carrying-a-session-on-from-another-worker)). A call that
  ended unanswered may have done none, part or all of its work. An effect outside the sandbox
  happens once only when the code carries the outside service's own key for doing the work once
  ([sessions](sessions.md#what-the-daemon-keeps-of-an-answer)).
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
