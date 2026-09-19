# The workflow this is built for

Why the isolation tier is chosen by configuration and demanded by each request, and what that does and does not buy you.

Part of the [plimsoll README](../README.md).

A microVM per run is the right cost for production and an absurd one for the
*inner loop*, meaning the edit-run-debug cycle a developer repeats hundreds of times
a day. An in-process engine is the opposite: fast enough for that loop, and not a
boundary for hostile code. But developing against a weak sandbox and deploying
against a strong one is how a weak sandbox reaches production.

Plimsoll's answer is that the tier is chosen by configuration and **demanded by each
request**, so the two decisions are made by different people at different times:

1. **Locally, run in-process.** `SANDBOX_PROVIDER=wasm` executes JavaScript on an
   embedded QuickJS build through wazero. No sandbox account, no API key, no docker
   daemon, no network, no per-run cost. It is process-tier isolation and the README
   says so everywhere: an engine escape lands in your own daemon.
2. **In production, demand the tier your threat model requires.** Every request
   carries `MinimumIsolation`, so the caller states its own floor rather than trusting
   whatever the operator configured.
3. **Then ship the configuration mistake.** A deploy still pointing at `wasm` while
   the caller demands `IsolationVM` is the failure this design exists to catch.
4. **The run is refused before dispatch.** The handler compares the floor against
   current provider evidence immediately before admission, and returns
   `ErrInsufficientIsolation`. **No submitted code ran.** The caller also re-checks the
   evidence on the response; a mismatch there is `ErrIsolationEvidenceMismatch`, which
   is a weaker guarantee and deliberately described as one, because by then execution
   may already have happened.

This is enforcement at runtime, expressed through a typed request field. Nothing in
the type system forces a production caller to ask for `IsolationVM`; what the design
gives you is that asking is one field, and that asking is checked before anything
executes rather than reported afterwards.

**What this workflow does not give you is a guarantee that code behaving locally
behaves in production**, and it would be dishonest to imply otherwise:

- The engines differ. `wasm` runs QuickJS; `docker` and `e2b` run Node. `fetch` is
  undefined under QuickJS and global under Node 22, and there is no npm. A snippet
  passing locally is not evidence it passes on a production tier.
- `RunProject` is unsupported on `wasm` and always returns `ErrUnsupported`, so
  multi-file projects cannot be exercised in-process at all. So is `RunModule`,
  which needs the docker provider with a module image
  (`SANDBOX_DOCKER_MODULE_IMAGE`; see [docs/guest-dependencies.md](guest-dependencies.md)).
- Grant support differs. `wasm` always supports JavaScript grants; `e2b` supports them
  only when `E2B_GUARD_URL` is configured, so a grant that works locally fails there
  until the guard is set up.

Treat the in-process tier as a fast way to iterate on your integration, not as a
staging environment. `Describe` reports what the active provider actually supports, so
a gateway can find these differences at startup instead of discovering them in
production.
