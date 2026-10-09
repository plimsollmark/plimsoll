# Hardened mode

The startup policy that refuses to serve unless every advertised production property is verifiably in force.

Part of the [plimsoll README](../README.md).

`PLIMSOLL_HARDENED=1` turns the production recommendations into a check the daemon
enforces at startup, because a warning is not a policy. The daemon refuses to serve
unless all of the following are verifiably in force:

- VM or verified kernel isolation, the two strongest of the four levels described in
  [isolation-tiers.md](isolation-tiers.md);
- multi-client auth, where each caller has its own token ([callers.md](callers.md));
- TLS on any non-loopback listener (the metrics listener and the one hosted sandboxes call
  for API access, `PLIMSOLL_GUARD_ADDR`, included), that is, any
  listener not bound to a loopback address such as `127.0.0.1`, `::1` or `localhost`,
  which only this machine can reach;
- an execution surface that cannot change under the daemon. For docker that means
  <dfn>*pinned*</dfn> images (`SANDBOX_REQUIRE_PINNED_IMAGES=1`), each fixed to one exact
  version by a hash of its content. For Docker Cloud it means a pinned image or an image
  from the account's own store, with `SANDBOX_DOCKERCLOUD_API=connect` set explicitly,
  since only that API reports which image a sandbox booted. For docker also no `unconfined`
  <dfn>*seccomp*</dfn>: seccomp is the kernel feature that limits which requests a
  container may make to the kernel, and `unconfined` switches it off.
  <dfn>*E2B*</dfn>, a hosted service that runs each sandbox in a small virtual machine,
  offers no such pinning, so there it means an explicit `E2B_TEMPLATE` rather than the
  implicit default: a named template, not a fixed version;
- an explicit per-run resource envelope (the memory, CPU and other limits each run
  gets), and for docker, whose runs share the daemon's machine, an aggregate memory
  budget, the total memory all runs at once may use;
- per-caller rate limiting, with `SANDBOX_RATE_BURST` no larger than
  `SANDBOX_RATE_PER_MIN`: a burst past one minute's allowance lets a caller start more
  at once than the limit allows in a minute;
- a per-caller concurrency cap (`SANDBOX_PER_KEY_CONCURRENT` positive and below
  `SANDBOX_MAX_CONCURRENT`, since a cap equal to the global one lets one caller hold
  every slot). A rate limit bounds what a caller starts, not the slots its long runs or
  open <dfn>*sessions*</dfn> hold; a session is one sandbox kept open for many calls;
- with sessions on, a per-caller session cap (`SANDBOX_MAX_SESSIONS_PER_CALLER`
  positive): a suspended session holds no concurrency slot, so the concurrency cap does
  not bound how many one caller keeps open;
- with a <dfn>*provider*</dfn> (the backend that runs the code) billed by the second
  (E2B, Docker Cloud), a daily allowance on every
  caller, its `paid_seconds_per_day` in the clients file ([callers.md](callers.md)): a
  rate limit bounds runs per minute, not the seconds of virtual machine the operator
  pays for.

Every rule but isolation is checked before the startup smoke test, which on E2B and
Docker Cloud creates a billed virtual machine; isolation is checked once the smoke test
has proven the isolation level. Every violation is reported at once, so it is one fix pass rather
than a startup loop.
