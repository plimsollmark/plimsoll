# Security policy

plimsoll runs untrusted, agent-authored code. It is a trusted computing base: a bug
here can mean hostile code escaping the boundary it was promised to stay inside. Treat
reports accordingly.

## No third-party audit has been performed

**This code has never been audited by an independent security firm.** The security
work that exists is self-review by the author, plus the test suite and the runtime
verification described below. That is not the same thing as an audit, and nothing in
this repository should be read as claiming it is.

Two dated self-review ledgers exist and are **not published**. They are working
documents rather than documents written for a reader: they carry the project's former
name, private infrastructure paths, and superseded capability matrices that are false
today, so publishing them as-is would put wrong statements about this component into
a permanent public record. Saying they exist and are withheld is more honest than
either publishing them unredacted or leaving the impression that no self-review
happened. What you can check without them is the part that does not rely on trusting
the author: the tests, `make audit`, and the isolation evidence each run reports.

## What the project does and does not claim

- Each provider reports its isolation boundary through `IsolationClass()` and in the
  `isolation` field of every response. A caller can assert a floor with
  `minimum_isolation`, which is checked immediately before dispatch.
- **What "verified" means here, precisely.** Docker reaches kernel tier by checking
  that the daemon it is connected to registers the configured OCI runtime and that
  `runsc` resolves there to an executable named `runsc`, then launching runs under
  it, plus a startup smoke test that proves the container's own mount and write
  behavior from inside. E2B reports VM tier from provider identity, with a smoke test
  that proves a real microVM creates, stages, runs a step, and is denied egress.
  **Neither cryptographically attests the runtime implementation.** A compromised
  Docker daemon, or an E2B control plane that did not do what it says, defeats the
  evidence. Treat the tier as this daemon's observation, not as remote attestation.
- **The WASM provider is process-tier.** It is an in-process QuickJS engine under
  wazero. It is not an OS boundary and not a VM boundary. An engine escape lands in
  the daemon process. Do not deploy it against hostile code.
- For hostile production workloads, use the VM tier (E2B Firecracker) or the verified
  kernel tier (Docker under gVisor `runsc`). A Docker provider under stock `runc` is
  container-tier and shares the host kernel.
- Isolation itself is delegated to gVisor and Firecracker. This project is the policy
  and attestation layer in front of them; it does not implement a sandbox boundary of
  its own and does not claim to.

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
  capability than the run's grant allows.
- Any path by which a minted credential reaches guest memory. The design intent is
  that the token never enters the container or the WASM guest.
- Any way to get a raw path, query string, request body, or credential into
  `CallTrace`, the audit log, or `/metrics`. Those surfaces are metadata-only **by
  construction**, so a counterexample is a design break, not just a bug.
- Any case where reported isolation evidence does not match the boundary that
  actually ran, or where a `minimum_isolation` floor is bypassed.
- Any way to make `Build()` or the daemon execute code when `SANDBOX_PROVIDER` is
  unset. The default is Disabled and execution is meant to be opt-in.

## Supported versions

Pre-1.0. Only the latest tagged release gets fixes. There are no backported patches
and no long-term support branch.

## Deployment note

The defaults are deliberately safe rather than convenient: no provider, no network,
no grant. A deployment is only as isolated as its configuration. If you are running
this against genuinely hostile input, set `PLIMSOLL_HARDENED=1`, which refuses to
start unless VM or verified kernel isolation, multi-client auth, TLS on non-loopback
listeners, pinned images, an explicit resource envelope, and per-caller rate limiting
are all verifiably in force.
