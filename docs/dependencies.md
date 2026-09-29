# The dependency list, and who checks the checkers

Four direct dependencies, one library banned by name with the reason attached, and the fixed tool versions that make a passing gate mean something.

Part of the [plimsoll README](../README.md).

plimsoll runs hostile code, so every dependency is more code an attacker can aim at,
written and released by someone else. There are **four direct dependencies**, and the
whole list fits here:

```
connectrpc.com/connect      the RPC transport
google.golang.org/protobuf  the wire format
github.com/tetratelabs/wazero  the WebAssembly runtime
golang.org/x/net            HTTP/2
```

`golang.org/x/sys` and `golang.org/x/text` come along indirectly. That is the entire
dependency tree. Adding to it is a decision, not a convenience.

**One library is banned by name, in the linter, with the reason attached.**
`github.com/fastschema/qjs` looked like the obvious way to embed a JavaScript engine,
and its `MemoryLimit` is a no-op: it accepts a limit and does not enforce one. When the
sandbox runs inside the daemon's own process, a memory cap that is not enforced is a
direct route to taking down the host. So plimsoll drives <dfn>*wazero*</dfn>, the
pure-Go runtime in the list above that runs the embedded JavaScript engine, directly
with `WithMemoryLimitPages` for a real per-run cap. A `depguard` linter rule fails the
build if the banned import returns, and a test asserts the same thing independently of
the linter. The lesson that carries beyond this library: a dependency that claims a
safety property is not evidence that it has one.

The embedded JavaScript engine is a <dfn>*QuickJS*</dfn> build (QuickJS is a small
JavaScript engine). It is <dfn>*pinned*</dfn> to quickjs-ng v0.15.1 **by SHA-256**:
fixed to that one exact file, so it changes only when someone edits the pin. It is
guarded by a <dfn>*provenance*</dfn> test: [sandbox/wasm/README.md](../sandbox/wasm/README.md)
records where the file came from and how it was built, and the test fails if the
embedded file's SHA-256 is not the pinned one. Likewise `docker/install-gvisor.sh`
pins a specific <dfn>*gVisor*</dfn> release and checksum rather than tracking `latest`
(gVisor is Google's stand-in kernel, which containers can run under for a stronger
wall).

### The gate pins the tools that run the gate

`make audit` is the gate: the one local command that builds, lints, tests, checks the
generated code for drift and scans for known vulnerabilities, and prints `audit: OK` only
if all of it passes. It shells out to `buf`, `golangci-lint` and `govulncheck`.
Those are not Go dependencies, so nothing in `go.mod` pins them, and without something
else doing it every machine would run a different gate while reporting the same
`audit: OK`.

So [gate-tools.versions](../gate-tools.versions) pins all three, and `tools-check` is a
prerequisite of `audit`: **the gate refuses to run against anything else.** `make
tools` installs exactly the pinned set. This matters because the alternative is a
green check that means "it passed under whatever happened to be on this `PATH`", which
is not the claim the gate is making. The code-generator plugins are pinned separately,
by `tool` directives in go.mod, so `buf generate` produces the same code every time,
with no network.
