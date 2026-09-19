# Hardened mode

The startup policy that refuses to serve unless every advertised production property is verifiably in force.

Part of the [plimsoll README](../README.md).

`PLIMSOLL_HARDENED=1` turns the soft production posture into an enforced startup
policy, because a warning is not a policy. The daemon refuses to serve unless all of
the following are verifiably in force: VM or verified kernel isolation, multi-client
auth, TLS on any non-loopback listener, pinned images with no `unconfined` seccomp, an
explicit per-run resource envelope with an aggregate memory budget, and per-caller
rate limiting. Every violation is reported at once, so it is one fix pass rather than
a startup loop.
