# Placement: several daemons, one caller

One `plimsolld` serves one provider. That is deliberate: each daemon holds only its
own provider's credentials, in its own process, so an escape from the in-process
WebAssembly engine cannot reach a cloud API key that belongs to another provider
([docs/seams.md](seams.md)).

A caller that wants a choice runs several daemons and links
[package placement](../placement/), which picks one per request. It is a library, not
a service and not a change to the daemon: a pool is built from clients the caller
already made, so each daemon keeps the caller's own credential, and a grant profile's
`allowed_callers` and a minted token's subject stay the caller's identity rather than
a router's.

```go
docker, _ := client.New("http://127.0.0.1:8746", client.WithToken(dockerToken))
cloud, _ := client.New("https://sandbox.internal:443", client.WithToken(cloudToken))
pool, err := placement.New([]placement.Backend{
    {Name: "local-docker", Client: docker},
    {Name: "cloud-vm", Client: cloud},
}, time.Minute)

res, choice, err := pool.RunJavaScript(ctx, sandbox.Request{Code: code},
    placement.Requirement{MinimumIsolation: sandbox.IsolationVM})
// choice.Backend is where it ran; choice.Retried names any backend that refused first.
```

## What decides

Each request is filtered against what the daemons state in `Describe`, then ranked,
then sent:

| `Requirement` field | Effect |
|---|---|
| `Backend` | Use this backend only. One that cannot take the request is an error, not a fallback: the caller asked for it by name. |
| `Provider` | Keep only backends reporting this provider id (`docker`, `e2b`, `openshell`, ...). |
| `MinimumIsolation` | Keep only backends whose current evidence meets the floor. The router merges it with the request's own `MinimumIsolation` (the stronger wins; an invalid one is refused) and stamps the result onto the request, so the daemon checks it again immediately before dispatch and the client checks the returned evidence: a backend whose tier dropped since its last `Describe` refuses or fails that check instead of running below the floor. |
| `Environment` | Keep only backends whose environment identity for the payload kind equals this string. Identities are content-addressed, so equal strings mean the same software; a backend that states none is never kept, because an empty identity claims nothing. |
| `GrantProfile` | The request carries a grant, so keep only backends that support grants for that payload kind. |
| `Prefer` | Rank the survivors (by tier, by a price table of the caller's own, by anything in `client.Info`). Without it, the order the backends were given decides. |

Payload kind is read from the call: a project needs `supports_project`, a module run
needs `supports_module` and can never carry a grant.

## Retrying

A refusal is retried on the next backend **only when it proves nothing ran**: the
not-dispatched mark with reason `unsupported`, `isolation` or `capacity`. A mark of
`request`, `permission` or `protocol` would fail the same way everywhere, and an error
with no mark at all may have executed, so neither is re-sent
([run results](run-results.md#did-anything-run-the-error-says-so)). The refusals that
came before the answer are in `Choice.Retried`.

## Descriptions

`Refresh` describes every backend in parallel; a caller may run it at startup and on a
timer. Either way a backend whose description is missing or older than the pool's TTL
is described again when a request needs it, so a daemon that was down is used again
without restarting the caller, and one that now reports a weaker tier stops receiving
requests that need a stronger one.

## Sessions

A [session](sessions.md) lives on one daemon, so `OpenSession` places it once and
every call on the returned session goes to that daemon. The pool keeps only backends
whose `Describe` states session support.

## What this does not do

- **Nothing is enforced here.** The filter reads what each daemon states. The daemon
  checks the floor against its own evidence before it dispatches, and the official
  client checks the evidence that comes back; the router is a convenience on top of
  both, not a security boundary.
- **No central quota.** Each daemon still applies its own limits. A pool that needs one
  shared quota, or one endpoint for many callers, is the point at which this library
  becomes a service of its own.
- **No cost model.** `Prefer` takes a comparison the caller writes; plimsoll ships no
  price table, because a stale price is worse than none.
