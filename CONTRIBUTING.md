# Contributing

Thanks for looking. Two things to know before you spend time on a change.

**Do not report security vulnerabilities here.** See [SECURITY.md](SECURITY.md) for
private disclosure through GitHub Security Advisories.

**CI runs the gate on your pull request, and you should still run it locally.** The
gate is the project's full check, `make audit`. In CI:

- The [audit workflow](.github/workflows/audit.yml) runs `make audit`: build, vet,
  race tests, golangci-lint, `buf lint` plus a check that the generated code still
  matches its source, and <dfn>*govulncheck*</dfn>, Go's vulnerability scanner.
- It then runs `make docker-suite` with the images prepared, so the docker,
  <dfn>*seccomp*</dfn>, <dfn>*broker*</dfn> and smoke tests, which need a real docker
  daemon, run on every push to `main` and every pull request under
  <dfn>*runc*</dfn>, docker's default runtime. A push to another branch runs nothing
  until it has a pull request. Seccomp
  is the kernel feature that limits which requests a process may make to the kernel;
  the broker is the part of plimsoll that makes API calls for sandboxed code. That
  second job is in required mode: a missing image or a skipped test fails it rather
  than passing quietly.
- The same suite also runs under <dfn>*runsc*</dfn>, the runtime of
  <dfn>*gVisor*</dfn> (a stand-in kernel that runs as an ordinary program), in the
  [gvisor workflow](.github/workflows/gvisor.yml).

Race tests run in the plain audit job; the two docker-suite jobs run their isolation
tests without the race detector.

Both docker-suite jobs run on the hosted runners' classic image store, where docker
states no software identity, so there the identity tests check only that a required
software rule is refused. The half that compares the identity with the one docker
itself reports for the image needs the containerd image store and Docker Engine 28.1 or later
([docs/placement.md](docs/placement.md)). The runners have neither, so that half runs
only in a local `make audit DOCKER=1` on a machine that has both.

What CI does not run is <dfn>*E2B*</dfn>, a hosted service that runs each sandbox in a
<dfn>*microVM*</dfn> (a small virtual machine made for one run). That suite needs a
live paid account, and no automated run in this project is permitted to spend money,
so no CI run checks that a microVM denies <dfn>*egress*</dfn> (network traffic
leaving it). If your change touches the E2B <dfn>*provider*</dfn>, the backend that
runs code on E2B, run the live suite locally and paste the result into the pull
request.

The maintainer still runs the full gate by hand before merging, so expect merges to be
slower than on a project where the automated checks are the whole story.

## The gate

One command, and it must pass:

```sh
make audit
```

That runs build, vet, race tests, golangci-lint, `buf lint` plus a check that the
generated code still matches its source, and `govulncheck`. Run it before you open a
pull request and paste the result into the description.

It refuses to start unless buf, golangci-lint and govulncheck are the exact versions
in [gate-tools.versions](gate-tools.versions), because those three are not Go
dependencies and nothing else fixes their versions. `make tools` installs exactly
those versions into Go's bin directory (`GOBIN`, or `bin` under `go env GOPATH`) and
then runs the comparison, which `make tools-check` also runs on its own. That
directory has to come first on your PATH: a different copy found earlier wins, and
the check says so and names the directory. If your run reports a mismatch, that is
the gate working: a lint result from a different linter is not the same result.

The suites that need real infrastructure (a docker daemon, a paid cloud account) are
opt-in:

```sh
make docker-images                   # pull node:22-alpine, build the four plimsoll/sandbox images
make audit DOCKER=1                  # adds the docker suite; skips are failures
E2B_API_KEY=... make audit E2B=1     # adds the live E2B microVM suite
DOCKER_SBX_TOKEN=... DOCKER_SBX_USERNAME=... SANDBOX_DOCKERCLOUD_API_URL=... \
  SANDBOX_DOCKERCLOUD_IMAGE=... make audit DOCKERCLOUD=1  # adds the live Docker Cloud Sandboxes suite
SANDBOX_OPENSHELL_GATEWAY_URL=... make audit OPENSHELL=1  # adds the live OpenShell suite (plus its other SANDBOX_OPENSHELL_* settings)
```

The E2B and <dfn>*Docker Cloud Sandboxes*</dfn> (Docker's hosted microVM service)
suites create billable microVMs, so the ordinary targets strip both credentials from
the environment and no CI job runs either suite. The <dfn>*OpenShell*</dfn> suite
(NVIDIA's agent sandbox runtime) is free but needs a running OpenShell gateway, so no CI
job runs it either; its settings are in [docs/openshell.md](docs/openshell.md).

`make help` lists individual targets. The docker suite needs all five images `make
docker-images` produces: `node:22-alpine` for snippets, `plimsoll/sandbox` for
projects, and the `-python`, `-sim` and `-wasm-cc` images derived from it. Without them
those tests skip in an ordinary `make audit` and fail under `make audit DOCKER=1`.
Run the gate as a non-root user: two runner tests skip as root, because they check
that a project step cannot open the runner's descriptors and memory, and root can open
any process's.

Generated code in `gen/` is committed, and the gate checks that it still matches its
source. If you touch `proto/`, run `make generate` and commit the result, or the gate
fails.

## What this project is

A <dfn>*trusted computing base*</dfn> for running untrusted code written by AI agents:
code that has to be correct for a security promise to hold. That shapes what gets
merged more than style preferences do.

- **All executed code is hostile.** Every change is read that way.
- **Dependencies are close to non-negotiable.** The direct dependency set is
  <dfn>*Connect*</dfn> (the RPC library the daemon and its Go client use),
  <dfn>*protobuf*</dfn> (the message format of those RPCs), <dfn>*wazero*</dfn> (a Go
  library that runs the `wasm` provider's JavaScript engine inside the daemon), and
  `golang.org/x/net`. A pull request adding a dependency needs to argue why the TCB
  should grow. `github.com/fastschema/qjs` is permanently banned: its `MemoryLimit` is
  a no-op (setting it limits nothing), which is the story this project started from.
- **Never weaken a boundary for convenience.** Network, filesystem, and capability
  restrictions on every provider are load-bearing.
- **Telemetry is metadata-only by construction.** Telemetry here is what plimsoll
  records about runs. `CallTrace` (each run's list of the calls its code made through
  its <dfn>*grant*</dfn>, the permission to call listed routes of one API) and
  everything derived from it carry route templates (the allowed route patterns, such
  as `/orders/*`), counts, timings, and trusted labels. A change that makes it
  possible for a raw path, query, body, or credential to enter that stream will be
  rejected regardless of how useful the data would be. See
  [docs/efficiency-advisor.md](docs/efficiency-advisor.md).
- **Advice never changes a run.** The efficiency advisor's analysis runs after
  <dfn>*dispatch*</dfn> (the moment a request is handed to the provider to run), over a
  result that is already final. It must not gate <dfn>*admission*</dfn>, the daemon's
  capacity check just before a run starts, and must not alter exit codes, output, or
  isolation, or slow a run down.
- **No backward compatibility.** This is pre-1.0. Prefer a clean break and a deleted
  field over code kept only for old callers: a compatibility shim, a deprecated alias,
  or a branch where nil means the old behavior.

## Style

Match the surrounding code. `golangci-lint` settles the rest, and it must report zero
issues.

Two conventions worth stating because they are easy to get wrong:

- A non-zero exit code is a **normal result**, not a Go `error`. Errors are for typed
  failures before dispatch, context cancellation, and infrastructure failures that
  match none of those types. Do not turn a failed user program into an `error`.
- Never describe the `wasm` provider as an OS or VM boundary. It runs inside the
  daemon's own process, so it is at the `process` <dfn>*isolation tier*</dfn>, the
  weakest of the four levels of isolation strength (`process`, `container`, `kernel`,
  `vm`). This applies to code comments, docs, and error strings alike.

## Pull requests

Small and single-purpose. Explain what the change does to the <dfn>*threat
model*</dfn>, the attackers and attacks plimsoll is designed to hold out against, even
if the answer is "nothing". Include the `make audit` result. If a change affects an
isolation boundary, a capability grant, or the telemetry surface, say so explicitly
in the description rather than leaving it to be discovered in review.
