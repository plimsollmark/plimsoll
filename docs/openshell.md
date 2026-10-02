# The OpenShell provider

`SANDBOX_PROVIDER=openshell` selects the `openshell` <dfn>*provider*</dfn> (the backend
that actually runs the code): <dfn>*OpenShell*</dfn>, NVIDIA's agent sandbox runtime
([NVIDIA OpenShell (EXTERNAL · official docs ↗)](https://docs.nvidia.com/openshell/)).
Each snippet or project runs in its own sandbox, which an OpenShell gateway (the server
that creates and deletes sandboxes on request) makes for it; plimsoll talks to the gateway
through the gateway's gRPC API. The provider also keeps <dfn>*sessions*</dfn>: one
sandbox kept open for many calls ([Sessions](#sessions) below).

It is reported at the `container` <dfn>*isolation tier*</dfn>, one of four levels of wall
strength (`process`, `container`, `kernel`, `vm`), and for that the gateway must use its
docker compute driver (the part of the gateway that turns a sandbox into a docker
container), the only driver plimsoll has tested. The code is
[sandbox/openshell](../sandbox/openshell/openshell.go), and plimsolld builds it in
[cmd/plimsolld/openshell.go](../cmd/plimsolld/openshell.go).

## How it was built and verified

plimsoll's client for the gateway is generated from OpenShell's own API definitions (its
`.proto` files), copied into this repository at v0.1.2 under
[third_party/openshell](../third_party/openshell/README.md) (Apache-2.0). It speaks gRPC
through connect-go, the RPC library plimsoll already uses, so neither grpc-go (Google's
gRPC library) nor OpenShell's Go SDK is a dependency. It lives in its own package because
the generated code registers the same <dfn>*protobuf*</dfn> names as OpenShell's Go SDK
(protobuf is the binary message format gRPC carries), and protobuf-go, Go's protobuf
library, refuses to start a program that registers a name twice. Only a program that
imports the package compiles it in, so an application can use plimsoll's client and
OpenShell's SDK together. plimsoll is an independent project, not affiliated with or
endorsed by NVIDIA.

`make audit OPENSHELL=1` runs the live suite against a gateway. The provider's tests
cover the startup smoke test (below), snippets, timeouts, output caps, projects, the
largest plan a project can produce (the plan is the list of files and steps the project
runner receives), and the deletion of sandboxes a crashed daemon left behind. A daemon
test serves a snippet and a project over RPC, then requires every sandbox to be deleted
after the daemon receives SIGTERM. The suite passed on 2026-09-28 against a v0.1.2
gateway with the docker driver.

## What the operator sets up

- **A gateway with the docker compute driver.** Any other driver (podman, vm,
  kubernetes) is refused until plimsoll has tested it.
- **Mutual TLS files** (in mutual TLS, both sides present a certificate).
  `SANDBOX_OPENSHELL_GATEWAY_URL` (`https://host:port`), `SANDBOX_OPENSHELL_CA_FILE` (the
  certificate authority the gateway's certificate chains to), and
  `SANDBOX_OPENSHELL_CERT_FILE` and `SANDBOX_OPENSHELL_KEY_FILE` (a client certificate and
  key the gateway accepts).
- **An identity that may read the compute driver.** The tier comes from
  `GetGatewayInfo`. If the gateway refuses that call (when the gateway signs users in
  through OIDC, a standard single sign-on protocol, the call needs the `platform_admin`
  role), the provider refuses to serve.
- **An image with the runner.** `SANDBOX_OPENSHELL_IMAGE` must carry `node`, `sh`,
  `/runner.mjs` and `/usr/local/lib/plimsoll-runner-guard.so`, as `plimsoll/sandbox`
  does. The runner (`/runner.mjs`, the program that writes a project's files and runs its
  steps) refuses a plan unless a child process running as the same user is denied access
  to the runner's plan descriptor, its report descriptor and its memory (the descriptors
  are the open files it reads the plan from and writes its report to). With
  `SANDBOX_REQUIRE_PINNED_IMAGES=1` the image must be named by an `@sha256:` reference, a
  hash of its content.
- **Agent policy proposals off.** A sandbox's policy is the set of rules it runs under. A
  sandbox whose effective settings let code inside it propose changes to its policy is
  refused: a gateway in automatic approval mode could apply one after plimsoll has checked
  the policy. The setting must be provably off: reported as `false`, or reported with no
  value, which is the gateway's default of `false`. A gateway that does not report
  `agent_policy_proposals_enabled` at all, or reports anything but a boolean `false`, is
  refused. Measured on v0.1.2: a sandbox nobody configured reports the key with no value.
  Treating no value as off rests on v0.1.2's default; a gateway release that changed that
  default would need this check changed.
- **`allow_driver_config = true`, only if `SANDBOX_DISK_MB` is set.** The disk cap mounts
  a run's `/tmp` through the sandbox's driver config (settings passed straight to the
  compute driver), which a gateway refuses by default ("administrator must enable
  allow_driver_config"), so startup fails until it is on. The setting is gateway-wide: any
  client of the gateway may then send driver settings for its own sandboxes too, such as
  Docker volumes the operator has labelled `openshell.ai/sandbox-attachable` for that
  workspace. Host bind mounts (a directory of the gateway host mounted into a sandbox)
  need a separate setting, `enable_bind_mounts`, off by default; that was read from the
  v0.1.2 source, not tested. This is one more reason to give plimsoll the gateway of its
  own that [Sessions](#sessions) asks for.

## What each run does

1. Checks the gateway's compute driver. The tier is evidence from this check, not
   configuration.
2. Creates a sandbox with plimsoll's policy:
   - no network rules, so the gateway's default holds: <dfn>*deny-all*</dfn> for
     <dfn>*egress*</dfn>, meaning every connection out of the sandbox is blocked unless a
     rule allows it;
   - a filesystem allowlist in which `/tmp` is the only writable directory;
   - Landlock (the Linux kernel's feature for restricting which files a process can
     reach) as a hard requirement.

   Memory and CPU are always requested (default 256 MiB and 1 CPU, the docker provider's
   defaults), because OpenShell's own default is no limit. With `SANDBOX_DISK_MB` set,
   `/tmp` is a <dfn>*tmpfs*</dfn> (a filesystem held in memory, with a size limit) of that
   size, mounted `noexec`, so no file there can be run as a program.
3. Reads the sandbox back and refuses to run on any difference: its labels, image,
   limits, driver config and policy, the policy's hash and source, and no credential
   providers attached.
4. Runs the code through the gateway's streamed exec call (one command, its output
   streamed back while it runs), with the plan on stdin for a project. The run's deadline
   is enforced by cancelling the stream, which kills the command and its process group
   (the command and the children it started). A descendant that detaches with `setsid`,
   which moves it into a new group of its own, survives the cancel and lives until step
   5's delete, seconds later (measured on v0.1.2's docker driver). OpenShell's own exec
   timeout is not used for that, because it reports exit 124 while the process keeps
   running.
5. Returns the result, then deletes the sandbox without making the caller wait for the
   delete. Daemon shutdown waits for those deletes.

**Resources.** `SANDBOX_MEMORY_MB` and `SANDBOX_CPUS` are requested and read back.
OpenShell sets no swap limit, so on a gateway host with swap a sandbox may also use as
much swap as its memory limit, Docker's default (measured on v0.1.2: `memory.swap.max`
equals `memory.max` inside the sandbox). The docker provider turns swap off; OpenShell
v0.1.2 has no setting for it. `SANDBOX_PIDS` fails startup, because the gateway sets the
process limit for all of its sandboxes.

**Disk, with `SANDBOX_DISK_MB` set.** A run's `/tmp` (the only directory the policy lets
code write) is a tmpfs of that size with `noexec`, sent in the sandbox's driver config
(`driver_config.docker.mounts`) and read back before the run. Docker adds `nosuid` and
`nodev` itself; it refuses them as requested options. A write past the size fails with
"no space left on device" (measured on v0.1.2: a 100 MiB write into a 64 MiB `/tmp`
stopped at exactly 64 MiB), and a file in `/tmp` cannot be executed. A tmpfs lives in
memory, and Linux charges its pages to the memory of the container that wrote them, so a
run's files share the memory limit (and the swap beside it) with its processes: with 64
MiB of memory, a run was killed (exit 137) after writing 96 MiB into a 512 MiB `/tmp`. A
`/tmp` larger than the memory limit fills only as far as memory allows.

**Disk, without `SANDBOX_DISK_MB`.** `/tmp` sits on the gateway host's disk (on the
docker driver, in the container's writable layer, the storage docker keeps for each
container's changes), so a run can write there until its deadline, at most two minutes
for a project, and the delete frees it. Size that disk with this in mind. A session's
`/tmp` is always on that disk, whatever `SANDBOX_DISK_MB` says ([Sessions](#sessions)).

## Sandboxes a crashed daemon leaves behind

OpenShell sandboxes never expire. Each one plimsoll creates carries three labels: its
creator's instance (which running daemon made it), `plimsoll.run=1`, and
`plimsoll.lifetime`, the seconds from creation to the run's deadline. Once a minute the
daemon deletes its own sandboxes that no run tracks, and any other instance's once the
gateway's creation time plus the declared lifetime plus 5 minutes has passed. The 5
minutes is far above the clock difference between hosts that keep their clocks
synchronized, and above the minute a creator's own delete may still be retrying; a larger
margin only means a leftover sandbox lives longer. A sandbox without a valid declaration
is never deleted by another instance.

## Startup smoke test

Before the provider serves, one throwaway sandbox must prove, from inside:

- the policy read back equals the one sent;
- a write attempted at every mount point and standard directory succeeds only under
  `/tmp`;
- outbound connections are refused, and loopback is the only network interface;
- the sandbox's own <dfn>*cgroup*</dfn> (the kernel feature that caps the memory, CPU
  time and process count of a group of processes) holds the requested memory and CPU
  limits;
- with `SANDBOX_DISK_MB` set, `/tmp` is a tmpfs of exactly that size, mounted `noexec`,
  `nosuid` and `nodev` (the read-back before each run proves the gateway kept the driver
  config; this proves the driver turned it into that mount);
- a runner round trip with a plan near the 4 MiB project ceiling works;
- a hung command's processes are gone after its exec is cancelled, confirmed by a
  second exec;
- the actual project runner starts with its protection library
  (`plimsoll-runner-guard.so`) active, and a project step cannot open the runner's plan
  descriptor, report descriptor or memory.

## Grants

A <dfn>*grant*</dfn> gives one run permission to call listed routes of one HTTP API. A
run with a grant keeps the no-grant policy: no network rules at all, read back by hash as
every run's is. So the <dfn>*guest*</dfn> (the code in the sandbox) reaches the
<dfn>*broker*</dfn>, the part of plimsoll that makes the real API call, the other way
round: plimsoll connects in, instead of the sandbox connecting out.

- The guest gets the same client library as on docker: `host.*` calls, sent as HTTP over
  the Unix socket that `HOST_API_SOCKET` names. It is prepended to a snippet and
  preloaded into every project step.
- Before the code runs, the provider starts a relay in the sandbox: a node script, passed
  in its command's arguments, that listens on that socket under `/tmp` and on a random
  loopback port. Each time a guest connection arrives with nothing to pair it with, the
  relay prints a line.
- For each such line, plimsoll opens a connection into the relay's port through the
  gateway's `ForwardTcp` call, which carries a TCP connection into a sandbox, and serves
  the shared broker on it. The broker's whole job stays in plimsoll's process: the
  grant's exact routes, the credential <dfn>*minted*</dfn> (created fresh) for this run,
  the traffic budgets, and the call trace, which records metadata only. The relay only
  copies bytes.
- Whoever holds a relayed connection (the guest, the relay, or a process that took the
  relay's port first) can only send the broker requests, which it checks. The credential
  never enters the sandbox (checked live: not in any process's environment or command
  line, nor in any file under `/tmp`).

How plimsoll manages those connections:

- **Tokens.** `ForwardTcp` needs a token from `CreateSshSession`, and the v0.1.2 gateway
  allows three live connections per token and twenty per sandbox. So the provider opens
  a token for every three connections, holds at most eighteen connections, and revokes
  every token when the run ends. A connection's room on its token is given back when its
  stream has ended at the gateway, which counts it until then.
- **The relay's output is untrusted.** The relay asks for a connection by printing a
  line. A request only adds one to a count that eighteen fixed workers answer, so no
  amount of output (the relay's, or a sandbox process writing to it) grows plimsoll's
  goroutines, tokens or buffers, and each counted line costs at most one dial.
- **Failures back off.** A dial that fails, or a stream the gateway refuses, puts its
  request back and makes every worker wait (100 ms, doubling to 6.4 s, until a stream
  carries data again), so failing dials cost at most eighteen per wait. A token the
  gateway stops accepting is replaced.
- **One known limit.** A stream the gateway takes more than 5 s to open is closed by the
  broker's header timeout and not dialed again, so its guest connection waits until the
  call's deadline.
- **A token is powerful.** A token also opens an SSH session into the sandbox, which is
  why it never leaves plimsoll and is revoked at the run's end; one whose revocation
  failed is useless once the sandbox is deleted. The gateway's `ssh_session_ttl_secs`
  (default 24 hours) must exceed the longest run.
- **Cost.** A relayed call costs a few milliseconds more than a docker socket call (the
  first connection is dialed when the guest opens it). Measured end to end, a granted
  snippet took 0.7 to 1.0 s against 0.55 s for one without a grant.

## Sessions

The provider keeps sessions ([docs/sessions.md](sessions.md)): one sandbox for many
calls, with files persisting and, of processes, only the interpreters a session keeps for
its [cells (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#cell), as of the sweep after each call ([sessions.md](sessions.md#interpreters-state-between-calls)). A session's sandbox is a run's sandbox
(the same policy, read back the same way) with three differences, each measured on a
v0.1.2 gateway with the docker driver:

- **The main process is `sleep`.** An OpenShell sandbox without a command gets a login
  shell as its main process. The sweep after each call (below) spares the main process,
  so a shell left there, reading a stream, would be a place leftover code could inject
  commands; a shell also waits out the stop timeout, so a stop took 5.3 s. With
  `sleep 2147483647` (the largest 32-bit signed number of seconds, about 68 years) as the
  main process a stop takes about 0.1 s.
- **A sweep after every call.** Left alone, a process a call starts outlives the call:
  cancelling an exec kills only the command's process group, and a normal exit kills
  nothing. So after every call, one exec kills every process except the sandbox's own
  two, the session's live interpreters and their relays, its own ancestors and itself, until a scan finds
  none. The sandbox's own two are
  OpenShell's supervisor (the process that manages the sandbox from inside) and the
  `sleep`, recorded by process ID and start time when the sandbox became ready. The same
  exec then measures the session's files under `/tmp` against the disk budget
  (`SANDBOX_SESSION_DISK_MB`). It runs after the call has answered; the next call or a
  suspend waits for it, so a session the sweep ends is reported to the next call. A close
  does not wait: it ends the session and deletes the sandbox, which stops the sweep with
  everything else in it.

- **Grants in a session.** A granted session call starts its relay, the in-sandbox end of
  the grant's connection, as one of the call's processes, and the sweep after the call
  ends it. While the call runs, anything an earlier call left running can connect to the
  relay too, as on docker, so a granted call needs a grant that allows sessions
  ([sessions.md](sessions.md#what-a-session-gives-up)).

  The budget is measured after the call, not enforced during it: `SANDBOX_DISK_MB` sizes
  a run's `/tmp` but never a session's, because docker discards a tmpfs when its
  container stops, and suspending a session stops it (measured on v0.1.2: a file written
  before a suspend was gone after it).

  The sweep's script travels in its arguments, not on its input, so a leftover process
  cannot append to it, and only its exit status counts. Code in the sandbox cannot forge
  an exit status without attaching to the sweep the way a debugger does (`ptrace`), which
  the kernel's Yama `ptrace_scope` setting forbids at 1 or more, so a session is refused
  on a gateway host where it is 0 or unreadable. When the sweep does not prove the
  sandbox clean, the sandbox is stopped and started, which ends every process; when that
  fails, the session ends.
- **A read-back before every call.** Anyone who can call the gateway can change a
  sandbox's policy or settings between calls, so before every call the provider reads the
  sandbox and its effective configuration back and ends the session on any difference,
  the main process included.

An idle session is stopped, not deleted: a stopped container holds no memory or CPU and
keeps its files, and the next call starts it and records its processes again (about
0.8 s in all). A stop ends the session's interpreters, so the first cell after it starts
a fresh one and says so. Code that kills the main process puts the sandbox in OpenShell's error
phase, and the session ends as `main_process_ended`. The check after that call notices
it; when the gateway marks the sandbox only after that check has run (seen twice on
v0.1.2), the next call's read-back notices it instead and refuses that call before it
runs. A session's sandbox declares the session's lifetime, so another instance's cleanup
of leftover sandboxes removes it only after the lifetime plus 5 minutes.

Measured costs: a session call took 61 to 87 ms end to end (the read-back, the call and
the sweep) against 550 ms for a snippet that creates its own sandbox.

What code in a session's sandbox can see of the supervisor (PID 1, which runs as the
same user): its status, but not its file descriptors, memory or environment (permission
denied), and it cannot signal it at all.

**A session is only as private as the gateway.** Any other client of the same gateway
can reach a session's sandbox between plimsoll's calls: exec into it, open a shell,
forward a port, change a file. OpenShell's logs record an exec as a count with no caller,
so plimsoll cannot detect this. Give plimsoll a gateway of its own, or an OpenShell
workspace only its identity belongs to.

## What it does not do

- **End a run whose leftover process holds its output.** A process a run starts that
  outlives it and keeps the run's output open holds the run open: OpenShell's exec waits
  for that output, so the run ends at its deadline, reported as timed out with the output
  produced so far. On the docker provider the container's end ends such a process
  instead.
- **Run compiled simulators.** A <dfn>*module run*</dfn> (a compiled simulator run once per row of a
  parameter table) returns `ErrUnsupported`.
- **Serve in the strict production mode.** <dfn>*Hardened mode*</dfn> (`PLIMSOLL_HARDENED=1`, under which the
  daemon refuses to start unless every production safeguard is configured) refuses the
  provider: the docker driver is a container boundary, and plimsoll cannot tell which
  <dfn>*OCI runtime*</dfn> (the program docker hands a container to, which builds its
  walls) the gateway's docker uses, because OpenShell neither selects nor reports one.
