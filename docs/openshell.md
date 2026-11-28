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
`.proto` files), copied into this repository at v0.1.10 under
[third_party/openshell](../third_party/openshell/README.md) (Apache-2.0); they were copied at
v0.1.2 until 2026-11-25, and every change between the two is an addition. It speaks gRPC
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
gateway with the docker driver, and on 2026-11-25 against a v0.1.10 gateway with the
docker driver (110 tests, none skipped, the disk cap's included).

## Which OpenShell releases

plimsoll has been measured against two gateway releases, v0.1.2 and v0.1.10, both with the
docker driver. It refuses no release by its number: every release is held to the same
read-back and startup smoke test, and one setting is stricter on an unmeasured release
(agent policy proposals, below). v0.1.10 is the release to run: v0.1.6 made a gateway
refuse to start with no authentication configured, and fixed a vulnerability in its SSH
library (CVE-2026-111061 in russh).

What changed between the two, for this provider:

- **Nothing plimsoll calls changed shape.** OpenShell's v0.1.6 notes say new sandboxes
  open their control connection from the sandbox to its supervisor, and that older
  supervisor and sandbox binaries reject the new setup. That connection is inside
  OpenShell, between two of its own programs; plimsoll talks only to the gateway, and the
  whole suite passed against v0.1.10. Upgrade the gateway, supervisor and sandbox images
  together, as OpenShell says.
- **Settings an operator moves.** `allow_driver_config` is set in the driver's own table
  (`[openshell.drivers.docker]`). With a client CA configured, mutual TLS authentication is
  on by default. From v0.1.10 the default supervisor and sandbox images come from
  `quay.io/ai-openshell`.
- **Fields the gateway adds.** v0.1.10 stores a restart policy on every sandbox (`NEVER`
  unless asked otherwise) and can carry application routes into a sandbox; the read-back
  checks both (step 3 below). Three fields of the configuration were already in v0.1.2's
  API and were neither compared nor refused before plimsoll's v0.30.0: the policy
  validation failure mode, the middleware services and whether the gateway can sign in
  to them. The first two are refused unless they read back as plimsoll needs (step 3). A field newer than plimsoll's copy of the API is refused
  (step 3), so a future release that adds one to a sandbox's spec or configuration stops
  this provider, with an error naming the field, until plimsoll's copy is updated.

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
  role), the provider refuses to serve. The call is made again before every run and
  session call, apart from the caller's request (bounded at 10 seconds), so a request
  that times out or hangs up cannot change the tier every other caller is checked
  against; when the gateway fails it, the run is refused before any of its code runs.
- **An image with the runner.** `SANDBOX_OPENSHELL_IMAGE` must carry `node` (v22.14.0 or later, which the startup smoke test checks: [the image's node](guest-dependencies.md)), `sh`,
  `/usr/bin/env` (plimsoll's own programs start under `env -i`) and the project runner,
  plimsoll's native helper, at `/usr/local/libexec/plimsoll-helper`, as `plimsoll/sandbox` does.
  The runner is the program that writes a project's files and runs its steps. It is one static
  x86-64 program with no outside library, so it runs in any Linux image. The startup smoke test
  reads it from inside a sandbox, as the sandbox's user, and refuses the image unless it is a
  regular file, owned by root, writable by no one else, readable by root alone (mode 0711: the
  sandbox user's read of it is refused, and from the exec of a program its user cannot read the
  kernel lets no other process of that user open its memory), with no setuid or setgid bit, the size of the helper this plimsolld was built
  with, and, started with its `identity` command, prints that build's line (`inputs` and the
  SHA-256 of the build's inputs, compiled in); the refusal names what is wrong. The sandbox's
  user cannot read the bytes, so this check does not prove them byte for byte; the docker
  provider's check of `plimsoll/sandbox`, which reads the file as root, does. The identity line
  is what tells this build from another of the same size (a stale image's, another release's):
  the builds of two consecutive releases' work were both 586,400 bytes. It is not a defense: a
  program built to lie could print any line, and the image is yours. The runner itself
  refuses a plan unless a child process running as the same user is denied access to the
  runner's plan descriptor, its report descriptor and its memory (the descriptors are the open
  files it reads the plan from and writes its report to). With
  `SANDBOX_REQUIRE_PINNED_IMAGES=1` the image must be named by an `@sha256:` reference, a
  hash of its content.

  **An image built for an earlier plimsoll is refused.** Until v0.28.0 the runner was a Node
  program, `/runner.mjs`, loaded with the library `/usr/local/lib/plimsoll-runner-guard.so`;
  neither is read by this provider now (the library stays in `plimsoll/sandbox`, where the
  docker provider still loads it into its own node programs). To bring an image of your own up
  to date, either build it `FROM` a `plimsoll/sandbox` built from the same release as your
  plimsolld (`make docker-images`), or add the file, from the release's source tree, in your
  image's recipe:

  ```dockerfile
  COPY --chown=root:root --chmod=0711 sandbox/internal/nativehelper/program/plimsoll-helper_amd64 /usr/local/libexec/plimsoll-helper
  ```

  and check it against the checksum file shipped beside it
  (`sandbox/internal/nativehelper/program/plimsoll-helper.sha256`, the line for
  `plimsoll-helper_amd64`). The file must be the one from the same release as plimsolld: a
  helper from another release is refused by its size or by its identity line (one from before
  the line existed prints none). Only an x86-64 build exists, so
  the sandboxes must run on x86-64: the startup test reads the sandbox's machine and refuses
  any other by name ("the sandbox's machine is arm64"). plimsolld's own machine does not
  matter, so a plimsolld on an ARM computer serves an x86-64 gateway.
- **Agent policy proposals off.** A sandbox's policy is the set of rules it runs under. A
  sandbox whose effective settings let code inside it propose changes to its policy is
  refused: a gateway in automatic approval mode could apply one after plimsoll has checked
  the policy. The setting must be provably off: reported as `false`, or reported with no
  value by a gateway release whose default is known to be `false` (below). A gateway that
  does not report `agent_policy_proposals_enabled` at all, or reports anything else, is
  refused. Measured on v0.1.2 and on v0.1.10: a sandbox nobody configured reports the key
  with no value, and the release defaults it to `false` (on v0.1.10, measured from inside a
  sandbox: no policy advisor skill is installed, and `policy.local`, the proposal API,
  answers 404 `feature_disabled`). So no value counts as off only on a release measured that
  way (v0.1.2 and v0.1.10, not the releases between); on any other release the key must be
  reported as `false`, which an operator gets by setting it to `false` gateway-wide.
- **`allow_driver_config = true`, only if `SANDBOX_DISK_MB` is set.** The disk cap mounts
  a run's `/tmp` through the sandbox's driver config (settings passed straight to the
  compute driver), which a gateway refuses by default ("administrator must enable
  allow_driver_config"), so startup fails until it is on. On v0.1.10 it is set in the
  driver's table, `[openshell.drivers.docker]`. The setting covers every sandbox: any
  client of the gateway may then send driver settings for its own sandboxes too, such as
  Docker volumes the operator has labelled `openshell.ai/sandbox-attachable` for that
  workspace. Host bind mounts (a directory of the gateway host mounted into a sandbox)
  need a separate setting, `enable_bind_mounts`, off by default; that was read from the
  v0.1.2 source, not tested. This is one more reason to give plimsoll the gateway of its
  own that [Sessions](#sessions) asks for.

## What each run does

1. Checks the gateway's compute driver. The tier rests on this check and on the startup
   smoke test, not on plimsoll's own configuration. The driver's name is the gateway
   operator's configuration and the driver's own report, not proof: a gateway can be
   pointed at an external driver's socket under the built-in name `docker`
   (`--compute-driver docker --compute-driver-socket`, read in the gateway's source at
   v0.1.10, not tried), and the smoke test, not the name, is what checks the walls.
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
   limits, driver config and policy, the policy's hash and source, no credential
   providers attached, and none of the settings plimsoll never makes: an agent socket,
   injected environment variables, a runtime class, remapped user IDs, or platform labels
   and annotations, a restart policy other than `NEVER` (under which the gateway would
   start a new runtime after the main process exits), a GPU request, a sandbox made from
   a stored workload template, an application route into the sandbox, or a supervisor
   middleware service bound to it (a service of the operator's that sees the traffic a
   policy sends through it; plimsoll's policy names none). The gateway's policy
   validation failure mode must be `fail_closed`: under `retain_last_valid`, a sandbox
   that rejects a new policy keeps enforcing the one it loaded before, so the policy read
   back would no longer be the one in force, and plimsoll refuses to run on such a
   gateway. A field that plimsoll's copy of the gateway API does not define, anywhere in
   the sandbox's spec or its effective configuration, is refused too, naming the message
   and field number: plimsoll cannot compare a setting it cannot decode, so it does not
   pass over one. Every field the copy does define has a row in one table
   (`readBackFields`, sandbox/openshell/readback.go) that says whether it is compared,
   refused when set or ignored, and why; a test fails on a field with no row, so each
   update of the copy decides each new field. Not compared, for the reasons in that table:
   the terminal the gateway gives the idle main process (v0.1.2 and v0.1.10 set one on
   every sandbox), the log level, whether the gateway can sign in to middleware services
   (it has none to reach), and the revision numbers the gateway keeps for itself.
4. Runs the code through the gateway's streamed exec call (one command, its output
   streamed back while it runs), with the plan on stdin for a project. The run's deadline
   is enforced by cancelling the stream, which kills the command and its process group
   (the command and the children it started). A descendant that detaches with `setsid`,
   which moves it into a new group of its own, survives the cancel and lives until step
   5's delete, seconds later (measured on v0.1.2's docker driver). OpenShell's own exec
   timeout is not used for that, because it reports exit 124 while the process keeps
   running.
5. Returns the result, then deletes the sandbox without making the caller wait for the
   delete. (A run whose code was allowed to call the caller's API through the relay first
   revokes that credential and waits for the relay to exit, each bounded at 10 seconds, so
   a gateway that stops answering can hold the result about 20 seconds.) The run keeps its concurrency slot, and its share of `SANDBOX_TOTAL_MEMORY_MB`,
   until the delete is through, since the sandbox and any process the run left in it live
   until then. Daemon shutdown waits for those deletes.

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
- the actual project runner (the native helper) starts, and a project step cannot open
  the runner's plan descriptor, report descriptor or memory.

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

- **Tokens.** `ForwardTcp` needs a token from `CreateSshSession`, and the v0.1.2 and
  v0.1.10 gateways allow three live connections per token and twenty per sandbox. So the provider opens
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


  The budget is measured after the call, not enforced during it, by a walk of `/tmp` that
  stops at 200,000 entries (counted as over the budget) and that code of the session can
  hide files from (a deleted file it still holds open, a directory swapped for a link
  mid-walk): an estimate, where docker's sessions read their filesystems' usage. `SANDBOX_DISK_MB` sizes
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
- **Each exec is walled off from the others.** A process of one exec could not open the
  input or output of a process another exec started, not even the sandbox's own `sleep`,
  although all run as the same user and the relay stays readable by it (measured on v0.1.2,
  2026-10-01; the session smoke test found the same on v0.1.10, 2026-11-25). So code of the session cannot write into a cell's relay, the interpreter
  launcher or a project's runner, which on docker it can for the moment each starts
  ([sessions.md](sessions.md#interpreters-state-between-calls)). This is OpenShell's
  behavior as measured, not something plimsoll sets: the relay protocol and the cell's two
  steps assume it does not hold. plimsoll checks it at startup all the same: with sessions
  on, the session smoke test has a call try to open a running relay's input and output, and
  a gateway where that succeeds gets no sessions (the daemon refuses to start).
- **Grants in a session.** A granted session call starts its relay, the in-sandbox end of
  the grant's connection, as one of the call's processes, and the sweep after the call
  ends it. While the call runs, anything an earlier call left running can connect to the
  relay too, as on docker, so a granted call needs a grant that allows sessions
  ([sessions.md](sessions.md#what-a-session-gives-up)).
- **A read-back before every call.** Anyone who can call the gateway can change a
  sandbox's policy or settings between calls, so before every call the provider reads the
  sandbox and its effective configuration back and ends the session on any difference,
  the main process included. A read-back the gateway does not answer refuses that call
  before any of it runs (reason `environment`), and the session goes on, as on docker.
- **plimsoll's programs start with no variables of the exec's.** The process lister, the
  sweep, the interpreters' relays and a grant's relay start under `/usr/bin/env -i` with a
  fixed PATH. A v0.1.2 gateway hands every exec the same few variables of its own (HOME,
  PATH, its CA settings, `OPENSHELL_SANDBOX`, `TERM`, `USER`), never the image's
  (measured 2026-10-03; read in full on 2026-11-25, v0.1.2 and v0.1.10 hand the same
  names, the shell's `PWD`, `SHELL` and `SHLVL` among them, and none of the image's). So
  this changes nothing today; it keeps a variable that loads
  code, such as `NODE_OPTIONS`, out of those programs on a gateway that starts passing
  the image's. A project's runner and the interpreter launcher keep the gateway's
  variables, because the steps and the interpreter they start inherit them.

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

**File calls: the sandbox scope only.** OpenShell sessions take the file calls docker
sessions and [E2B](trainers/glossary.html#e2b) sessions take ([session-files.md](session-files.md)),
in the sandbox scope (an absolute path, resolved as the guest's own shell resolves it) and
not in the work scope (a path confined to the work folder), and say so: `Describe` states
`file_scopes` `[FILES_SCOPE_SANDBOX]` on the session environment, the open's answer states
the same, and a work-scope call is refused before anything runs (marked
[not dispatched](trainers/glossary.html#dispatch), reason `unsupported`). Each call's record
names the scope that call used (`FilesRun.scope` is in the request's
[digest](trainers/glossary.html#digest), the hash the record carries of it), so no record of
an OpenShell session claims the work scope's confinement. Why the work scope is refused here, both measured on v0.1.2 with the docker
driver (2026-11-27):

- **The work folder is not a mount of its own.** The native helper keeps the work scope's
  promise (no call acts outside the work folder, whatever the session's own code does
  meanwhile) only where a rename out of the work folder is refused by the kernel, which a
  mount boundary does: a folder the helper holds open could otherwise be moved out from
  under a call by a process of the session, and the call's write would land where it went.
  `/tmp/work` is on the container's root filesystem, whose only mounts besides it are
  `/proc`, `/dev` and its parts, `/sys`, three files of docker's under `/etc`, OpenShell's own
  channel volume and its supervisor's certificate folder, and the code in the sandbox runs as
  an ordinary user and cannot make a mount.
- **OpenShell's Landlock policy does not refuse such a rename either.** The sandbox's
  Landlock rules (a Linux facility that limits which files a process may reach) grant `/tmp`
  every right, the reparenting right included, so a process of the session moved a folder
  from `/tmp/work` to `/tmp`, and the work folder itself to another parent, with no
  refusal. A Landlock domain the code made for itself without that right did refuse the same
  move, so the measurement could see a refusal had there been one.

The one mount plimsoll could ask the gateway for at create is an in-memory filesystem in the
sandbox's driver settings (as `SANDBOX_DISK_MB` does for a run's `/tmp`), which docker
discards when the container stops, and a session stops its sandbox to suspend it and to
recover from a failed sweep, so its files would be lost (measured on v0.1.2, 2026-09-29). A
Docker volume would survive a stop, but the gateway attaches only volumes an operator made and
labelled beforehand ([setup](#what-the-operator-sets-up)), and no two sessions may share one.

**What the sandbox scope means for a link.** The sandbox scope follows a symbolic link
wherever it points, as the guest's shell does: a link the session's code made inside the work
folder that points out of it is followed, out of the work folder, to anything the sandbox's
user may reach there. The sandbox's walls (its policy, its user's permissions) are the
boundary, not the work folder. The Python client's `Workspace` on an OpenShell session names
its paths in the sandbox scope under the work folder and checks them by their names (a `..`
that leads out, or an absolute path outside the work folder, is refused before any call), so
it follows such a link too ([the client's README](../clients/python/README.md)). The helper
is the one every project image carries, checked at startup by its SHA-256, started by the
gateway's exec as the sandbox's user under plimsoll's empty control environment, in the work
folder (made by the call if no call has made it yet). The sweep runs after a write, a folder
made, and any call the helper did not answer: a session's `/tmp` here is not size-capped, so
the sweep's measurement is what holds the session to `SANDBOX_SESSION_DISK_MB`. A stat, read,
listing, removal or rename the helper answered starts nothing else, so no sweep follows it.

**A warm pool, when `SANDBOX_SESSION_POOL` is set.** The daemon keeps that many session
sandboxes ready, each made as an open makes one (the run policy, `sleep` as the main
process, read back, its processes recorded) with an interpreter started and its relay
attached for a set of the languages the image runs, and an open hands one over instead
of creating a sandbox. It is the docker provider's pool ([sessions.md](sessions.md#docker),
"A warm pool"), with the same rules: a waiting sandbox has run only plimsoll's programs
and the gateway's supervisor, goes to one session (or to one `Run` cell that asks for
one, [sessions.md](sessions.md), "A cell for one call"), and is deleted when that ends;
the same language hints and split; a waiting sandbox is replaced after 30 minutes. What
differs here:

- A waiting sandbox is handed over only under the tier and gateway version the last
  driver check read. The image, policy and resources are the provider's configuration,
  and the read-back before every call, the first one included, compares them.
- Its relays are exec streams held open to the gateway, as a session's are; one whose
  stream ended is not handed over and is replaced.
- It declares 30 minutes plus `SANDBOX_SESSION_LIFETIME` as its lifetime, so another
  instance's cleanup removes a crashed daemon's waiting sandboxes within that bound; the
  instance that made them never reaps them while they wait.
- As for any session here, another client of the same gateway can change a waiting
  sandbox, and the read-back catches only what it compares: give plimsoll a gateway of its
  own.

On a laptop (measured 2026-10-28, gateway v0.1.2, docker driver), opening a session and
running its first cell took 15 ms (JavaScript) and 11 ms (Python) with a pool, against 716
and 763 ms without one, of which the open alone was about 610 to 660 ms. A waiting sandbox
held 65 MiB with both interpreters running, against 21 MiB bare (the sandbox's container
and the gateway's supervisor container beside it); that memory counts inside the
session's limit, the language a session never uses included
([warm pool page](https://plimsollmark.github.io/plimsoll/measurements/warm-pool/index.html),
"OpenShell", with the data and the program).

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
