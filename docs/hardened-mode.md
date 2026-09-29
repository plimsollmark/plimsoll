# Hardened mode

The startup policy that refuses to serve unless every advertised production property is verifiably in force.

Part of the [plimsoll README](../README.md).

`PLIMSOLL_HARDENED=1` turns the production recommendations into a check the daemon
enforces at startup, because a warning is not a policy. The daemon refuses to serve
unless all of the following are verifiably in force:

- VM or verified kernel isolation, the two strongest of the four levels described in
  [isolation-tiers.md](isolation-tiers.md);
- multi-client auth, where each caller has its own token ([callers.md](callers.md));
- TLS on any non-loopback listener (the metrics listener included), that is, any
  listener not bound to a loopback address such as `127.0.0.1`, `::1` or `localhost`,
  which only this machine can reach;
- <dfn>*pinned*</dfn> images, each fixed to one exact version (usually by a hash of its
  content), with no `unconfined` <dfn>*seccomp*</dfn>: seccomp is the kernel feature
  that limits which requests a container may make to the kernel, and `unconfined`
  switches it off;
- an explicit per-run resource envelope (the memory, CPU and other limits each run
  gets) with an aggregate memory budget, the total memory all runs at once may use;
- per-caller rate limiting;
- a per-caller concurrency cap (`SANDBOX_PER_KEY_CONCURRENT` positive). A rate limit
  bounds what a caller starts, not the slots its long runs or open
  <dfn>*sessions*</dfn> hold; a session is one sandbox kept open for many calls.

Every violation is reported at once, so it is one fix pass rather than a startup loop.
