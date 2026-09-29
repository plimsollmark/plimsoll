# The workflow this is built for

Why the <dfn>*isolation tier*</dfn>, how strong the wall around a run is, is chosen by the daemon's configuration and demanded by each request, and what that does and does not buy you.

Part of the [plimsoll README](../README.md).

Starting a <dfn>*microVM*</dfn> (a small virtual machine made for one run) for every run
is the right cost for production and an absurd one for the *inner loop*, the
edit-run-debug cycle a developer repeats hundreds of times a day. A JavaScript engine
inside the daemon's own process is the opposite: fast enough for that loop, and no wall
against hostile code. But developing against a weak sandbox and deploying against a
strong one is how a weak sandbox reaches production.

plimsoll's answer is that the daemon's configuration chooses the tier and **each request
demands one**, so two different people make the two decisions at different times:

1. **Locally, run inside the daemon.** `SANDBOX_PROVIDER=wasm` selects the
   <dfn>*provider*</dfn> (the backend that runs the code) that executes JavaScript on
   <dfn>*QuickJS*</dfn>, a small JavaScript engine built into the daemon. QuickJS is
   compiled to <dfn>*WebAssembly*</dfn>, a portable bytecode that runs inside a host
   program, and <dfn>*wazero*</dfn>, a WebAssembly runtime written in Go, runs it. No
   sandbox account, no API key, no docker daemon, no network, no per-run cost. Its tier is
   `process`, the weakest, and the README says so everywhere: an <dfn>*escape*</dfn> from
   the engine (a bug that lets the code act outside it) lands in your own daemon.
2. **In production, demand the tier you need.** Choose it from your
   <dfn>*threat model*</dfn>, the list of attacks you must hold out against. Every request
   carries `MinimumIsolation`, so the caller states its own <dfn>*floor*</dfn>, the weakest
   tier it accepts, rather than trusting whatever the operator configured.
3. **Then ship the configuration mistake.** A deployment still set to `wasm` while the
   caller demands `IsolationVM` is the failure this design exists to catch.
4. **The run is refused before any code starts.** Immediately before the capacity check
   that lets a run start, the request handler compares the floor with the tier the
   provider currently reports, and returns `ErrInsufficientIsolation`. **No submitted
   code ran.** The caller also re-checks the tier stated on the response. A mismatch there
   is `ErrIsolationEvidenceMismatch`, a weaker guarantee and described as one on purpose,
   because by then the code may already have run.

This is a check made at run time, requested through a typed request field. Nothing in the
type system forces a production caller to ask for `IsolationVM`. What the design gives you
is that asking takes one field, and that the request is checked before anything runs
rather than reported afterwards.

**What this workflow does not give you is a guarantee that code that works locally works
in production**, and it would be dishonest to imply otherwise:

- The engines differ. `wasm` runs QuickJS; `docker` and `e2b` run Node. `fetch` is
  undefined under QuickJS and a global under Node 22, and there is no npm. A snippet
  passing locally is not evidence it passes on a production provider.
- `RunProject` is unsupported on `wasm` and always returns `ErrUnsupported`, so
  multi-file projects cannot be tried inside the daemon at all. `RunModule` is unsupported
  there too: it needs the docker provider with a module image, an image with a compiled
  simulator built in (`SANDBOX_DOCKER_MODULE_IMAGE`; see
  [docs/guest-dependencies.md](guest-dependencies.md)).
- Support for <dfn>*grants*</dfn> (permission for a run's code to call listed routes of
  one HTTP API) differs. `wasm` always supports JavaScript grants; `e2b` supports them only
  when `E2B_GUARD_URL` is configured, so a grant that works locally fails there until the
  <dfn>*guard*</dfn> is set up. The guard is the one address on the plimsoll daemon that a
  microVM run with a grant may reach.

Treat `wasm` as a fast way to iterate on your integration, not as a staging environment.
The `Describe` call reports what the active provider actually supports, so a gateway (your
service that sends agent code to plimsoll) can find these differences at startup instead
of discovering them in production.
