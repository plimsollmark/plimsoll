# Hardened mode

The startup policy that refuses to serve unless every advertised production property is verifiably in force.

Part of the [plimsoll README](../README.md).

`PLIMSOLL_HARDENED=1` turns the production recommendations into a check the daemon
enforces at startup, because a warning is not a policy. The daemon refuses to serve
unless all of the following are verifiably in force:

- VM or verified kernel isolation, the two strongest of the four levels described in
  [isolation-tiers.md](isolation-tiers.md), checked at startup and then held on every run
  (below);
- multi-client auth, where each caller has its own token ([callers.md](callers.md));
- TLS on any non-loopback listener (the metrics listener and the one hosted sandboxes call
  for API access, `PLIMSOLL_GUARD_ADDR`, included), that is, any
  listener not bound to a loopback address such as `127.0.0.1` or `::1`, which only this
  machine can reach. It is judged from the address the listener actually bound, so
  `localhost` counts only when it resolved to a loopback address. With `PLIMSOLL_ADDR`
  unset the RPC listener binds `127.0.0.1:8746`, this machine only; a deployment that
  other hosts call (a container, a pod, a server) sets `PLIMSOLL_ADDR`, for example
  `0.0.0.0:8746` for every network interface, and then needs TLS;
- an execution surface that cannot change under the daemon. For docker that means
  <dfn>*pinned*</dfn> images (`SANDBOX_REQUIRE_PINNED_IMAGES=1`), each fixed to one exact
  version by a hash of its content: `name@sha256:` and 64 lower-case hexadecimal digits,
  the form the OCI image specification requires (upper-case letters are refused, as
  docker itself refuses them). For Docker Cloud it means a pinned image or an image
  from the account's own store, with `SANDBOX_DOCKERCLOUD_API=connect` set explicitly,
  since only that API reports which image a sandbox booted. For docker also no `unconfined`
  <dfn>*seccomp*</dfn>: seccomp is the kernel feature that limits which requests a
  container may make to the kernel, and `unconfined` switches it off; the check covers
  both profile settings, `SANDBOX_DOCKER_SECCOMP` and `SANDBOX_DOCKER_SECCOMP_SDK`. And for
  docker, the <dfn>*guest guard*</dfn> proven in force: plimsoll's own seccomp filter in front
  of every program plimsoll starts in a docker container, which refuses the code a private view
  of the system of its own, mounts and tracing
  ([seccomp.md](seccomp.md#the-guest-guard-a-second-filter-in-front-of-every-program)). The
  startup smoke test proves it from inside each image, and the daemon refuses to serve,
  saying so, when docker does not state it proven.
  <dfn>*E2B*</dfn>, a hosted service that runs each sandbox in a small virtual machine,
  offers no such pinning, so there it means an explicit `E2B_TEMPLATE` rather than the
  implicit default: a named template, not a fixed version;
- for the backend that runs each sandbox in a Kubernetes pod (`SANDBOX_PROVIDER=agentsandbox`),
  `SANDBOX_AGENTSANDBOX_SANDBOXD_TRUST_DOMAIN`, the trust domain of the identity each
  sandbox pod's own certificate carries. Each pod serves a certificate made for it alone by
  an issuer in the cluster, naming the pod's UID (the identifier Kubernetes gives each pod,
  new for every pod), and the daemon's TLS connection to the pod checks it against the pod
  it read from the API server, so someone who can rewrite traffic on the pod network cannot
  send one caller's run into another pod. That backend requires the setting with or
  without this mode, and this mode states it as its own rule. Earlier releases asked instead for
  `SANDBOX_AGENTSANDBOX_ENCRYPTED_POD_NETWORK=1`, the operator's statement about the
  network, which is gone ([agentsandbox.md](agentsandbox.md#the-control-channel-is-tls));
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
  pays for;
- the files that decide who may call and what a run may reach (the callers file,
  `PLIMSOLL_CLIENTS_FILE`; the file of <dfn>*grant*</dfn> profiles, each a permission for
  a run to call listed routes of one outside API, `PLIMSOLL_GRANTS_FILE`, and any
  `preamble_file` it names; the withheld set, `PLIMSOLL_WITHHELD_FILE`) safe from every
  other user of the machine ([below](#files-another-user-could-change)).

Every rule but isolation is checked before the startup smoke test, which on E2B and
Docker Cloud creates a billed virtual machine; isolation is checked once the smoke test
has proven the isolation level. Every violation is reported at once, so it is one fix pass rather
than a startup loop.

One provider is refused whatever <dfn>*isolation tier*</dfn> (how strong the walls around
a run are) it reports: `wslc`, WSL containers on Windows, in both of its modes, the
per-run mode's `vm` (stated only with `SANDBOX_WSLC_ACCEPT_VM_TIER=1`) included, with or
without <dfn>*gVisor*</dfn> (Google's sandbox kernel) inside its virtual machines.
Microsoft states that WSL is not a security sandbox for running untrusted code, and
inside each of its virtual machines five of the docker provider's controls are missing
([wslc.md](wslc.md#the-tier-and-why-hardened-mode-refuses-it)).

## Files another user could change

The callers file says who may run code, the grants file says which outside services a
run may call, and the withheld set says what must never enter a sandbox. Another user of
the same machine who can write one of them, or who can put a file of their own in its
place, could add a caller for themselves, which takes effect at the next restart. So the
daemon judges each of these files as it reads it, by the rule OpenSSH applies to a
user's `authorized_keys` file (the list of keys that may log in as that user) when its
`StrictModes` setting is on, the default:

- The file is a regular file owned by `root` or by the user the daemon runs as, and its
  mode (the permission bits `ls -l` shows) has neither the group-write bit
  (`0020`) nor the others-write bit (`0002`). Read bits are not judged: a file readable
  by its group (`0640`, or `0440`) is accepted. The mode is read from the file the daemon
  opened, not by looking the name up a second time.
- Every directory on the way to the file, up to `/`, is owned by `root` or by the
  daemon's user and cannot be written by its group or by others, since a user who can
  write a directory can rename the file in it and put another there. One difference from
  OpenSSH: a directory with the sticky bit (`1000`, as on `/tmp`) is accepted
  even when others can write it, because in such a directory only an entry's owner, the
  directory's owner and `root` may rename or delete the entry, and every entry on the
  way is itself held to an owner of `root` or the daemon's user.
- A file reached through a symbolic link (a name that points to another
  path) is judged by what the link points to and by the directory the link sits in, so
  both paths must pass.

With `PLIMSOLL_HARDENED=1` a file that fails refuses startup, before the smoke test, naming the
setting, the path and the mode bits; the fix is `chmod go-w` on the file or directory
named, and an owner of `root` or the daemon's user. Without it the daemon
starts and logs one warning line per such file, naming the setting and the problem. No
message quotes the file's content.

A Kubernetes secret or config map mounted as a volume passes:
the kubelet (the agent that runs pods on each node) mounts it read-only, with each key a
symbolic link into a directory of its own inside a sticky volume root owned by `root`, and
with `fsGroup` set it adds group read (`0440`), not group write. A volume the kubelet
mounts writable with `fsGroup` (an `emptyDir` or a persistent volume) gets group write
added (`0660`), and a `defaultMode` that grants group write does the same; `PLIMSOLL_HARDENED=1`
refuses either until the mode is fixed (`defaultMode: 0440`, or a read-only secret or
config map).

## Isolation is a floor on every run, not only a startup check

A provider can find a weaker boundary after startup than the one the smoke test proved.
The Kubernetes provider reads its runtime class again on every run
([agentsandbox.md](agentsandbox.md#what-each-run-does)), so a class replaced under a
running daemon with one whose handler is `runc` would give its next pod the container
level. (That provider also refuses a class other than the one its smoke test ran on, but
the rule below does not depend on it.) A daemon that checked isolation only at startup
would then run code at that level for any caller that set no `minimum_isolation` of its
own.

So with `PLIMSOLL_HARDENED=1` the daemon also holds a <dfn>*floor*</dfn> of its own, the
weakest isolation level a run may have: `kernel`, the weaker of the two levels this policy
accepts. It is joined to every request's minimum, the stronger of the two winning, as the
request is read and before any check that uses it: a run (snippet, project or module), the
opening of a session, and each call in a session. The provider receives the joined minimum
in the request and checks it against the boundary it finds for that run, session or call,
as it checks a caller's own minimum, so a weaker sandbox is refused before any code runs:
the refusal is marked as one where nothing ran, with the reason `isolation`, and is safe to
retry once the cluster is fixed. `/readyz` answers not ready while the provider's reported
level is below the floor, since every run would be refused; it reads that level on every
request, while the provider's own readiness check runs at most one at a time and its answer
stands for 5 seconds, so a provider that recovers reads not ready for up to 5 seconds more. Without `PLIMSOLL_HARDENED`, the
operator's `SANDBOX_MIN_ISOLATION` is held the same way ([isolation-tiers.md](isolation-tiers.md));
a daemon with neither holds no floor and runs as before, and a caller that needs a floor
on every run against such a daemon sets `minimum_isolation`.
