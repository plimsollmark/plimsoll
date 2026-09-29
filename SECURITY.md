# Security policy

plimsoll runs untrusted code written by AI agents. It is a <dfn>*trusted computing
base*</dfn>, code that has to be correct for a security promise to hold: a bug here can
mean hostile code escaping the boundary it was promised to stay inside. Treat reports
accordingly.

## No third-party audit has been performed

**This code has never been audited by an independent security firm.** The security
work that exists is self-review by the author, plus the test suite and the runtime
verification described below. That is not the same thing as an audit, and nothing in
this repository should be read as claiming it is.

Two dated self-review ledgers, the author's own records of what was checked and what
was found, exist and are **not published**. They are working documents rather than
documents written for a reader: they carry the project's former name, private
infrastructure paths, and superseded capability matrices (tables of what each part
supported at the time) that are false today. Publishing them as they are would put
wrong statements about this component into a permanent public record. Saying they
exist and are withheld is more honest than either publishing them unredacted or
leaving the impression that no self-review happened. What you can check without them
is the part that does not rely on trusting the author: the tests, `make audit` (the
project's full local check), and the isolation evidence each run reports.

## What the project does and does not claim

- Each <dfn>*provider*</dfn>, the backend that actually runs the code, reports its
  isolation boundary through `IsolationClass()` and in the `isolation` field of every
  response. A caller can assert a <dfn>*floor*</dfn>, the weakest isolation it will
  accept, with `minimum_isolation`. The floor is checked immediately before
  <dfn>*dispatch*</dfn>, the moment the daemon hands the request to the provider to
  run.
- **What "verified" means here, precisely.** The boundary is reported as an
  <dfn>*isolation tier*</dfn>, one of four levels, weakest first: `process`,
  `container`, `kernel`, `vm`.
  - The docker provider reaches kernel tier by checking that the docker daemon it is
    connected to registers the configured <dfn>*OCI runtime*</dfn> (the program docker
    hands each container to, which builds the walls around it), and that `runsc`
    resolves there to an executable named `runsc`, then launching runs under it.
  - On top of that, a startup smoke test proves from inside a container its own mount
    and write behavior, and the process limit where the runtime enforces it: the
    container's <dfn>*cgroup*</dfn> (the kernel feature that caps how many processes, and
    how much memory and CPU, a group of processes may use) under <dfn>*runc*</dfn>,
    docker's default runtime, and the sandbox's host cgroup under <dfn>*runsc*</dfn>, the
    runtime of
    <dfn>*gVisor*</dfn> (a stand-in kernel that runs as an ordinary program and answers
    the container's requests to the kernel itself).
  - The <dfn>*E2B*</dfn> provider, which runs code on E2B's hosted service, reports VM
    tier from provider identity, that is, from being the E2B provider. Its smoke test
    proves that a real <dfn>*microVM*</dfn> (a small virtual machine made for one run)
    is created, receives the project files, runs a step, and is denied
    <dfn>*egress*</dfn> (network traffic leaving the VM).

  **Neither cryptographically <dfn>*attests*</dfn> the runtime implementation.** To
  attest is to give cryptographic proof, usually rooted in the hardware, of exactly
  what software is running. A compromised Docker daemon, or an E2B control plane (the
  E2B servers that create and manage the microVMs) that did not do what it says,
  defeats the evidence. Treat the tier as this daemon's
  observation, not as remote attestation.
- **The `wasm` provider is process-tier.** It is an in-process <dfn>*QuickJS*</dfn>
  engine under <dfn>*wazero*</dfn>: QuickJS is a small JavaScript engine compiled to
  <dfn>*WebAssembly*</dfn> (a portable bytecode that runs inside a host program), and
  wazero is the Go library that runs it inside the daemon's own process. It is not an
  OS boundary and not a VM boundary. An engine <dfn>*escape*</dfn>, a bug that lets
  code out of the engine, lands in the daemon process. Do not deploy it against
  hostile code.
- For hostile production workloads, use the VM tier (E2B, on
  <dfn>*Firecracker*</dfn>, AWS's open-source virtual machine monitor) or the verified
  kernel tier (Docker under gVisor `runsc`). A Docker provider under stock `runc` is
  container-tier and shares the host kernel.
- Isolation itself is delegated to gVisor and Firecracker. This project is the layer
  in front of them that decides which requests may run and reports the evidence; it
  does not implement a sandbox boundary of its own and does not claim to.

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
**Security → Report a vulnerability** on this repository. That keeps the report
private until a fix exists.

Please do not open a public issue for a vulnerability.

### What to expect

This is maintained by one person, unpaid, alongside other work. The honest
commitment, rather than a service level the project cannot meet:

- **Acknowledgement within 7 days.** If you have not heard back in 7 days, assume the
  message was missed and ping the advisory thread again.
- An assessment, and either a fix or an explicit "will not fix" with the reasoning,
  **within 90 days**.
- Credit in the advisory and the release notes, unless you ask otherwise.

If a report is critical and unanswered after 90 days, disclose publicly. You do not
need permission, and waiting longer does not serve anyone.

### Especially interesting reports

- Any escape from a provider boundary, or any way to obtain a stronger effective
  capability than the run's <dfn>*grant*</dfn> allows. A grant is the permission,
  attached to one run, for its code to call listed routes of one HTTP API.
- Any path by which a <dfn>*minted*</dfn> credential (plimsoll asks for one per run, so
  it can be a fresh, short-lived token) reaches the memory of the <dfn>*guest*</dfn>,
  the code inside the sandbox. The design intent is that the token never enters the container or the
  WASM guest.
- Any way to get a raw path, query string, request body, or credential into
  `CallTrace` (each run's list of the calls its code made through its grant), the
  audit log, or
  `/metrics`. Those surfaces are metadata-only **by construction**: they are built to
  hold only facts about a run and its calls, such as route templates (the allowed
  route patterns, like `/orders/*`), counts and timings, never the paths, queries,
  bodies or credentials themselves. So a counterexample is a design break, not just a
  bug.
- Any case where reported isolation evidence does not match the boundary that
  actually ran, or where a `minimum_isolation` floor is bypassed.
- Any way to make `Build()` or the daemon execute code when `SANDBOX_PROVIDER` is
  unset. The default is Disabled, a provider that refuses every run, and execution is
  meant to be opt-in.

## Supported versions

Pre-1.0. Only the latest tagged release gets fixes. There are no backported patches
(fixes applied to older releases) and no long-term support branch.

## Deployment note

The defaults are deliberately safe rather than convenient: no provider, no network,
no grant. A deployment is only as isolated as its configuration. If you are running
this against genuinely hostile input, set `PLIMSOLL_HARDENED=1`, which refuses to
start unless all of these are verifiably in force:

- VM or verified kernel isolation;
- multi-client auth, where each caller has its own token
  ([docs/callers.md](docs/callers.md));
- TLS on non-loopback listeners, that is, on every listener not bound to a loopback
  address such as `127.0.0.1`, `::1` or `localhost`, which only this machine can
  reach;
- <dfn>*pinned*</dfn> images, each fixed to one exact version, usually by a hash of its
  content;
- an explicit resource envelope: the per-run limits, such as memory and CPU, that the
  operator sets;
- per-caller rate limiting;
- a per-caller concurrency cap.

`/metrics` has no authentication, and its labels name <dfn>*grant profiles*</dfn>
(grants stored on the server under a name, which a caller selects by that name) and
route templates. It is therefore served on a listener of its own, bound to this host
only by default (`PLIMSOLL_METRICS_ADDR`, default `127.0.0.1:9464`; `off` disables
it). Bind it to an address other hosts can reach only behind a firewall rule that
lets through just the scraper, the monitoring system that collects the metrics.
