# Placement: several daemons, one caller

One `plimsolld` serves one <dfn>*provider*</dfn>, the backend that actually runs the
code (`docker`, `e2b`, `openshell` and the rest). That is deliberate: each daemon holds
only its own provider's credentials, in its own process. So an <dfn>*escape*</dfn> (a bug
that lets code act outside its sandbox) from the `wasm` provider's engine, which runs
<dfn>*WebAssembly*</dfn> (a portable bytecode format) inside the daemon's own process,
cannot reach a cloud API key that belongs to another provider
([docs/seams.md](seams.md)).

A caller that wants a choice runs several daemons and links
[package placement](../placement/), which picks one daemon per request. It is a library,
not a service: the caller builds a pool, the set of daemons to choose from, out of
clients it already made, so each daemon sees the caller's own credential and identity,
not a router's. Two checks depend on that identity. A <dfn>*grant*</dfn>, permission for a run's code to call listed routes of one
API, is stored on the daemon as a <dfn>*grant profile*</dfn>, whose `allowed_callers` list
names the callers who may use it. A <dfn>*minted*</dfn> token, a credential created fresh
for one run, names the caller as its subject.

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

Each request is filtered against what the daemons state in `Describe` (the procedure
through which a daemon reports what it offers), then ranked, then sent:

| `Requirement` field | Effect |
|---|---|
| `Backend` | Use this backend only. One that cannot take the request is an error, not a fallback: the caller asked for it by name. |
| `Provider` | Keep only backends reporting this provider id (`docker`, `e2b`, `openshell`, ...). |
| `MinimumIsolation` | Keep only backends whose current isolation evidence meets this <dfn>*floor*</dfn>: the weakest <dfn>*isolation tier*</dfn> (sandbox strength: `process`, `container`, `kernel` or `vm`) the caller accepts. The pool merges it with the request's own `MinimumIsolation` (the stronger wins; an invalid one is refused) and writes the result onto the request. The daemon then checks it again immediately before <dfn>*dispatch*</dfn> (handing the code over to run), and the client checks the evidence that comes back, so a backend whose tier dropped since its last `Describe` refuses or fails that check instead of running below the floor. |
| `Environment` | The older filter on the exact identity of the outer image or interpreter. That identity can change on a rebuild that changed nothing, when an OCI image index (explained below this table) includes fresh build metadata. The pool checks the returned record too, but an out-of-date description can let a run happen before that check. Use `Software` when you require one execution image. |
| `Software` | Select one exact software identity (which image the code ran in, explained below this table) or an approved set of identities. The pool filters on `Describe` and sends the rule with the request. The daemon checks its current selection before dispatch, and the client verifies the selected identity and the rule in the <dfn>*run record*</dfn>, the daemon's statement of what it ran and where, which comes back with every result. An unknown identity fails a required rule. |
| `GrantProfile` | The request carries a grant, so keep only backends that support grants for that kind of payload. |
| `Prefer` | Rank the backends that are left (by tier, by a price table of the caller's own, by anything in `client.Info`). Without it, the order the backends were given decides. |

The kind of payload comes from the method called: a project needs `supports_project`,
and a <dfn>*module run*</dfn> (a compiled simulator run once per row of a parameter
table) needs `supports_module` and can never carry a grant.

An **OCI image index** is a list that can point to images for several operating
systems and processors (OCI, the Open Container Initiative, publishes the standard
image format). Its <dfn>*digest*</dfn>, the SHA-256 hash that names it, identifies that
list, including any attached build metadata. A <dfn>*manifest*</dfn> is the file that
lists one image's configuration and layers; its digest identifies that one selected
image. Docker reports `Environment.Identity` as its outer image ID and
`Environment.SoftwareIdentity` as `oci-manifest:<OS>/<processor>@sha256:<digest>`
when docker's image store exposes a selected manifest it can verify. That takes the
containerd image store (docker's newer way of storing images, which keeps each
platform's manifest) and Docker Engine 28.1 or later, the first release whose
`docker image inspect` can select one platform. On the older, classic image store the
identity is empty and a required rule is refused. On the containerd store with an
engine older than 28.1 the docker provider refuses to start, rather than run without an
identity that store should give it. For example:

```go
tested := "oci-manifest:linux/amd64@sha256:<the manifest digest from Describe>"
rule := sandbox.SoftwareRule{Mode: sandbox.SoftwareExact, Identities: []string{tested}}
res, choice, err := pool.RunJavaScript(ctx, sandbox.Request{Code: code},
    placement.Requirement{Software: rule})
```

Copy the complete `SoftwareIdentity` string from `Describe` or a checked run
record; the angle-bracket text in the example is a placeholder. To approve more
than one tested image, use `SoftwareApproved` with an explicit list.

- The same rule can be put directly on `sandbox.Request`, `ProjectRequest` or
  `ModuleRequest` when calling one daemon. When the pool's requirement and the request
  both state a rule, only identities both rules accept will do.
- For a <dfn>*session*</dfn>, one sandbox kept open for many calls, the rule is supplied
  through `client.SessionOptions.Software` at open, then included in every call's record.
- Without a rule, a request runs on whatever image the daemon has, as it always did:
  plimsoll cannot infer which image a caller tested. A caller promising a tested
  environment should set `SoftwareExact`.
- Approved sets accept at most 32 distinct identities of at most 256 bytes each, keeping
  the rule, which the caller controls, below about 8 KiB.

The manifest digest identifies image bytes, not the source or build inputs that
produced them. Two clean builds can still produce different manifests. A checked
record reports what the daemon says it selected; it does not prove that the daemon
or host is uncompromised. Providers that cannot establish which image they selected
state an empty `SoftwareIdentity` and refuse a required rule.

A grant profile's name means only what the caller believes it means across its daemons.
Two daemons can load different profiles under the same name, including different
upstream APIs, so a retry can reach a different upstream API. Placement checks that a
backend supports grants, not that its profile matches another daemon's profile of the
same name; the caller must keep the profiles aligned when that distinction matters.

## Retrying

A refusal is retried on the next backend **only when it proves nothing ran**: it carries
the not-dispatched mark with reason `unsupported`, `isolation`, `environment` or `capacity`. A mark of
`request`, `permission` or `protocol` would fail the same way everywhere, and an error
with no mark at all may have executed, so neither is re-sent
([run results](run-results.md#did-anything-run-the-error-says-so)). The refusals that
came before the answer are in `Choice.Retried`.

## Descriptions

`Refresh` calls `Describe` on every backend in parallel; a caller may run it at startup
and on a timer. Either way, a backend whose description is missing or older than the
pool's time-to-live (the second argument to `placement.New`, `time.Minute` in the example
above) is described again when a request needs it. So a daemon that was down is used
again without restarting the caller, and one that now reports a weaker tier stops
receiving requests that need a stronger one.

## Sessions

A [session](sessions.md) lives on one daemon, so `OpenSession` places it once and
every call on the returned session goes to that daemon. The pool keeps only backends
whose `Describe` states session support.

## What this does not do

- **Enforce the required image: the daemon does.** The pool's filter reads what each
  daemon states, but the daemon checks the software rule and isolation floor before
  dispatch. The official client checks the returned evidence. A provider with
  unknown software identity cannot satisfy a required software rule.
- **No central quota.** Each daemon still applies its own limits. A pool that needs one
  shared quota, or one endpoint for many callers, is the point at which this library
  becomes a service of its own.
- **No cost model.** `Prefer` takes a comparison the caller writes; plimsoll ships no
  price table, because a stale price is worse than none.
