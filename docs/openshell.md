# The OpenShell provider

`SANDBOX_PROVIDER=openshell` runs each snippet or project in its own sandbox on an
[NVIDIA OpenShell (EXTERNAL · official docs ↗)](https://docs.nvidia.com/openshell/)
gateway, through the gateway's gRPC API. It is reported as the `container` tier: the
gateway must run the docker compute driver, the only one plimsoll has tested. The code
is [sandbox/openshell](../sandbox/openshell/openshell.go), and plimsolld builds it in
[cmd/plimsolld/openshell.go](../cmd/plimsolld/openshell.go).

## How it was built and verified

The client is generated from OpenShell's own protos, vendored at v0.1.2 under
[third_party/openshell](../third_party/openshell/README.md) (Apache-2.0), and speaks
gRPC through connect-go, so neither grpc-go nor OpenShell's SDK is a dependency. It
lives in its own package because the generated code registers the same protobuf names
as OpenShell's Go SDK, and protobuf-go refuses to start a program that registers a name
twice. Only a program that imports the package links it, so an application can use
plimsoll's client and OpenShell's SDK together. plimsoll is an independent project, not
affiliated with or endorsed by NVIDIA.

`make audit OPENSHELL=1` runs the live suite against a gateway. The provider's tests
cover the smoke test, snippets, timeouts, output caps, projects, the largest plan a
project can produce, and orphan reaping. A daemon test serves a snippet and a project
over RPC, then requires every sandbox deleted after SIGTERM. The suite passed on
2026-09-28 against a v0.1.2 gateway with the docker driver.

## What the operator sets up

- **A gateway with the docker compute driver.** Any other driver (podman, vm,
  kubernetes) is refused until plimsoll has tested it.
- **Mutual TLS files.** `SANDBOX_OPENSHELL_GATEWAY_URL` (`https://host:port`),
  `SANDBOX_OPENSHELL_CA_FILE` (the CA the gateway's certificate chains to), and
  `SANDBOX_OPENSHELL_CERT_FILE` and `SANDBOX_OPENSHELL_KEY_FILE` (a client identity the
  gateway accepts).
- **An identity that may read the compute driver.** The tier comes from
  `GetGatewayInfo`. If the gateway refuses that call (under OIDC it needs the
  `platform_admin` role), the provider refuses to serve.
- **An image with the runner.** `SANDBOX_OPENSHELL_IMAGE` must carry `node`, `sh`,
  `/runner.mjs` and `/usr/local/lib/plimsoll-runner-guard.so`, as `plimsoll/sandbox`
  does. The runner refuses a plan unless a same-uid child is denied access to its
  plan descriptor, report descriptor and memory. With `SANDBOX_REQUIRE_PINNED_IMAGES=1` it
  must be an `@sha256:` reference.
- **Agent policy proposals off.** A sandbox whose effective settings let code inside it
  propose policy changes is refused: a gateway in automatic approval mode could apply
  one after plimsoll has checked the policy. The setting must be provably off: reported
  as `false`, or reported with no value, which is the gateway's default of `false`.
  A gateway that does not report `agent_policy_proposals_enabled` at all, or reports
  anything but a boolean `false`, is refused. Measured on v0.1.2: a sandbox nobody
  configured reports the key with no value. Treating no value as off rests on v0.1.2's
  default; a gateway release that changed that default would need this check changed.

## What each run does

1. Checks the gateway's compute driver. The tier is evidence from this check, not
   configuration.
2. Creates a sandbox with plimsoll's policy: no network rules, so the gateway's deny-all
   egress default holds; a filesystem allowlist in which `/tmp` is the only writable
   directory; Landlock as a hard requirement. Memory and CPU are always requested
   (default 256 MiB and 1 CPU, the docker provider's defaults), because OpenShell's own
   default is no limit.
3. Reads the sandbox back and refuses to run on any difference: its labels, image,
   limits and policy, the policy's hash and source, and no credential providers
   attached.
4. Runs the payload over the streamed exec call, with the plan on stdin for a project.
   The run's deadline is enforced by cancelling the stream, which kills the command and
   its process group. A descendant that detaches with `setsid` survives the cancel and
   lives until step 5's delete, seconds later (measured on v0.1.2's docker driver).
   OpenShell's own exec timeout is not used for that, because it reports exit 124 while
   the process keeps running.
5. Returns the result, then deletes the sandbox off the result path. Daemon shutdown
   waits for those deletes.

Resources: `SANDBOX_MEMORY_MB` and `SANDBOX_CPUS` are requested and read back.
`SANDBOX_PIDS` and `SANDBOX_DISK_MB` fail startup: the gateway sets the process limit
for all of its sandboxes, and OpenShell has no disk control. A sandbox's `/tmp` sits on
the gateway host's disk (the container's writable layer on the docker driver), so a run
can write there until its deadline, at most two minutes for a project, and the delete
frees it. Size that disk with this in mind.

## Sandboxes a crashed daemon leaves behind

OpenShell sandboxes never expire. Each one plimsoll creates is labelled with its
creator's instance, `plimsoll.run=1`, and `plimsoll.lifetime`, the seconds from creation
to the run's deadline. Once a minute the daemon deletes its own sandboxes that no run
tracks, and any other instance's once the gateway's creation time plus the declared
lifetime plus 5 minutes has passed. The 5 minutes is far above the clock skew between
synchronized hosts and above the minute a creator's own delete may still be retrying; a
larger margin only means an orphan lives longer. A sandbox without a valid declaration
is never deleted by another instance.

## Startup smoke test

One throwaway sandbox must prove, from inside:

- the policy read back equals the one sent;
- a write attempted at every mount point and standard directory succeeds only under
  `/tmp`;
- outbound connections are refused, and loopback is the only interface;
- the sandbox's own cgroup holds the requested memory and CPU limits;
- a runner round trip with a plan near the 4 MiB project ceiling works;
- a hung command's processes are gone after its exec is cancelled, confirmed by a
  second exec;
- the actual project runner starts with its guard active, and a project step cannot
  open the runner's plan descriptor, report descriptor or memory.

## Grants

A run with a host-API grant keeps the no-grant policy: no network rules at all, read
back by hash as every run's is. The guest reaches the broker the other way round:

- The guest gets the same injected client as on docker: `host.*` is HTTP over the Unix
  socket named by `HOST_API_SOCKET`, prepended to a snippet and preloaded into every
  project step.
- Before the payload, the provider starts a relay in the sandbox (a node script, passed in
  its arguments), which listens on that socket under `/tmp` and on a random loopback
  port, and prints a line each time a guest connection arrives with nothing to pair it
  with.
- For each such line plimsoll opens a connection into the relay's port through the
  gateway's `ForwardTcp`, and serves the shared broker on it: the grant's exact routes,
  the credential minted for this run, the budgets and the metadata-only call trace, all
  in plimsoll's process. The relay only pipes bytes.
- Whoever holds a relayed connection (the guest, the relay, or a process that took the
  relay's port first) can only send the broker requests, which it checks. The credential
  never enters the sandbox (checked live: not in any process's environment or command
  line, nor in any file under `/tmp`).

`ForwardTcp` needs a token from `CreateSshSession`, and the v0.1.2 gateway allows three
live connections per token and twenty per sandbox, so the provider opens a token for
every three connections, holds at most eighteen, and revokes every token when the run
ends. The relay asks for a connection by printing a line, and its output is treated as
untrusted: a request only adds one to a count that eighteen fixed workers answer, so no
amount of output (the relay's, or a sandbox process writing to it) grows plimsoll's
goroutines, tokens or buffers, and each counted line costs at most one dial. A
connection's room on its token is given back when its stream has ended at the gateway,
which counts it until then. A dial that fails, or a stream the gateway refuses, puts its
request back and makes every worker wait (100 ms, doubling to 6.4 s, until a stream
carries data again), so failing dials cost at most eighteen per wait; a token the
gateway stops accepting is replaced. One known limit: a stream the gateway takes more
than 5 s to open is closed by the broker's header timeout and not dialed again, so its
guest connection waits until the call's deadline. A token also opens an SSH session into
the sandbox, which is why it never leaves plimsoll and is revoked at the run's end; one
whose revocation failed is useless once the sandbox is deleted. The gateway's
`ssh_session_ttl_secs` (default 24 hours) must exceed the longest run. A relayed call
costs a few milliseconds more than a docker socket call (the first connection is dialed
when the guest opens it); measured end to end, a granted snippet took 0.7 to 1.0 s
against 0.55 s for one without a grant.

## Sessions

The provider keeps sessions ([docs/sessions.md](sessions.md)): one sandbox for many
calls, with files persisting and processes not. A session's sandbox is a run's sandbox
(the same policy, read back the same way) with three differences, each measured on a
v0.1.2 gateway with the docker driver:

- **The main process is `sleep`.** An OpenShell sandbox without a command gets a login
  shell as its main process. A shell that a later call spares, reading a stream, is a
  place leftover code could inject commands, and it waits out the stop timeout, so a stop
  took 5.3 s. With `sleep 2147483647` as the main process a stop takes about 0.1 s.
- **A sweep after every call.** A process a call starts outlives the call: cancelling an
  exec kills only the command's process group, and a normal exit kills nothing. So after
  every call one exec kills every process except the sandbox's own two (OpenShell's
  supervisor and the `sleep`, recorded by process ID and start time when the sandbox
  became ready), its own ancestors and itself, until a scan finds none, then measures the
  session's files under `/tmp` against the disk budget. The sweep's script travels in its
  arguments, not on its input, so a leftover process cannot append to it, and only its
  exit status counts. Code in the sandbox cannot forge an exit status without attaching
  to the sweep, which the kernel's Yama `ptrace_scope` of 1 or more forbids, so a session
  is refused on a gateway host where it is 0 or unreadable. When the sweep does not prove
  the sandbox clean, the sandbox is stopped and started, which ends every process; when
  that fails, the session ends.
- **A read-back before every call.** Anyone who can call the gateway can change a
  sandbox's policy or settings between calls, so before every call the provider reads the
  sandbox and its effective configuration back and ends the session on any difference,
  the main process included.

An idle session is stopped, not deleted: a stopped container holds no memory or CPU and
keeps its files, and the next call starts it and records its processes again (about
0.8 s in all). Code that kills the main process puts the sandbox in OpenShell's error
phase, and the session ends as `main_process_ended`. A session's sandbox declares the
session's lifetime, so another instance's reaper removes it only after the lifetime
plus 5 minutes.

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

A process a run starts that outlives it and keeps the run's output open holds the run
open: OpenShell's exec waits for that output, so the run ends at its deadline, reported
as timed out with the output produced so far. On the docker provider the container's end
ends such a process instead.

Module runs return `ErrUnsupported`. Every run gets a fresh
sandbox; a session keeps one across calls. Hardened mode refuses the provider: the
docker driver is a container boundary, and plimsoll cannot tell which OCI runtime the
gateway's docker uses, because OpenShell neither selects nor reports one.
