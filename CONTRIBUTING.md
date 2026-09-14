# Contributing

Thanks for looking. Two things to know before you spend time on a change.

**Do not report security vulnerabilities here.** See [SECURITY.md](SECURITY.md) for
private disclosure through GitHub Security Advisories.

**CI runs the gate on your pull request, and you should still run it locally.** The
[audit workflow](.github/workflows/audit.yml) runs `make audit` (build, vet, race
tests, golangci-lint, `buf lint` plus a generated-code drift check, `govulncheck`)
and then `make audit DOCKER=1` with the images prepared, so the docker, seccomp,
broker and smoke tests run on every push under runc. That second job is in required
mode: a missing image or a skipped test fails it rather than passing quietly. The
[gvisor workflow](.github/workflows/gvisor.yml) runs the same suite under runsc.

What CI does not run is E2B. That suite needs a live paid account, and no automated
run in this project is permitted to spend money, so no check ever verified that a
microVM denied egress. If your change touches the E2B provider, run the live suite
locally and paste the result into the pull request.

The maintainer still runs the full gate by hand before merging, so expect merges to be
slower than on a project where the automated checks are the whole story.

## The gate

One command, and it must pass:

```sh
make audit
```

That runs build, vet, race tests, golangci-lint, `buf lint` plus a generated-code
drift check, and `govulncheck`. Run it before you open a pull request and paste the
result into the description.

It refuses to start unless buf, golangci-lint and govulncheck are the exact versions
in [gate-tools.versions](gate-tools.versions), because those three are not Go
dependencies and nothing else pins them. `make tools` installs exactly those
versions; `make tools-check` runs the comparison on its own. If your run reports a
mismatch, that is the gate working: a lint result from a different linter is not the
same result.

The infrastructure suites are opt-in because they need real infrastructure:

```sh
make docker-images                   # pull node:22-alpine, build plimsoll/sandbox:latest
make audit DOCKER=1                  # adds docker/seccomp/broker/smoke tests; skips are failures
E2B_API_KEY=... make audit E2B=1     # adds the live E2B microVM suite
```

`make help` lists individual targets. Some Docker tests need the project image:
`docker build -t plimsoll/sandbox:latest docker/`.

Generated code in `gen/` is committed and checked for drift. If you touch
`proto/`, run `buf generate` and commit the result, or the gate fails.

## What this project is

A trusted computing base for running untrusted, agent-authored code. That shapes what
gets merged more than style preferences do.

- **All executed code is hostile.** Every change is read that way.
- **Dependencies are close to non-negotiable.** The direct dependency set is Connect,
  protobuf, wazero, and `golang.org/x/net`. A pull request adding a dependency needs
  to argue why the TCB should grow. `github.com/fastschema/qjs` is permanently banned:
  its `MemoryLimit` is a no-op, which is the founding anecdote of this project.
- **Never weaken a boundary for convenience.** Network, filesystem, and capability
  restrictions on every provider are load-bearing.
- **Telemetry is metadata-only by construction.** `CallTrace` and everything derived
  from it carry route templates, counts, timings, and trusted labels. A change that
  makes it possible for a raw path, query, body, or credential to enter that stream
  will be rejected regardless of how useful the data would be. See
  [docs/advisory-privacy.md](docs/advisory-privacy.md).
- **Advice never changes a run.** Advisory analysis is post-dispatch over an
  already-final result. It must not gate admission, alter exit codes, output, or
  isolation, or slow a run down.
- **No backward compatibility.** This is pre-1.0. Prefer a clean break and a deleted
  field over a compat shim, a deprecated alias, or a nil-means-old-behavior branch.

## Style

Match the surrounding code. `golangci-lint` settles the rest, and it must report zero
issues.

Two conventions worth stating because they are easy to get wrong:

- A non-zero exit code is a **normal result**, not a Go `error`. Errors are for typed
  pre-dispatch failures, context cancellation, and unmatched infrastructure failures.
  Do not turn a failed user program into an `error`.
- Never describe the WASM provider as an OS or VM boundary. It is in-process and
  process-tier. This applies to code comments, docs, and error strings alike.

## Pull requests

Small and single-purpose. Explain what the change does to the threat model, even if
the answer is "nothing". Include the `make audit` result. If a change affects an
isolation boundary, a capability grant, or the telemetry surface, say so explicitly
in the description rather than leaving it to be discovered in review.
