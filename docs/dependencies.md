# The dependency list, and who checks the checkers

Four direct dependencies, one library banned by name with the reason attached, and the pins that make a passing gate mean something.

Part of the [plimsoll README](../README.md).

This runs hostile code, so every dependency is attack surface someone else controls.
There are **four direct dependencies**, and the whole list fits here:

```
connectrpc.com/connect      the RPC transport
google.golang.org/protobuf  the wire format
github.com/tetratelabs/wazero  the WebAssembly runtime
golang.org/x/net            HTTP/2
```

`golang.org/x/sys` and `golang.org/x/text` come along indirectly. That is the entire
graph. Adding to it is a decision, not a convenience.

**One library is banned by name, in the linter, with the reason attached.**
`github.com/fastschema/qjs` looked like the obvious way to embed a JavaScript engine,
and its `MemoryLimit` is a no-op: it accepts a limit and does not enforce one. In an
in-process sandbox an unenforced memory cap is a direct route to taking down the host.
So plimsoll drives wazero directly with `WithMemoryLimitPages` for a real per-run cap,
a `depguard` rule fails the build if the import returns, and a test asserts the same
thing independently of the linter. The generalisable part is not the library, it is
that a dependency claiming a safety property is not evidence that it has one.

The embedded QuickJS artifact is pinned to quickjs-ng v0.15.1 **by SHA-256** and
guarded by a provenance test, and `docker/install-gvisor.sh` pins a specific gVisor
release and checksum rather than tracking `latest`.

### The gate pins the tools that run the gate

`make audit` shells out to `buf`, `golangci-lint` and `govulncheck`. Those are not Go
dependencies, so nothing in `go.mod` pins them, and without something else doing it
every machine would run a different gate while reporting the same `audit: OK`.

So [gate-tools.versions](../gate-tools.versions) pins all three, and `tools-check` is a
prerequisite of `audit`: **the gate refuses to run against anything else.** `make
tools` installs exactly the pinned set. This matters because the alternative is a
green check that means "it passed under whatever happened to be on this `PATH`", which
is not the claim the gate is making. The codegen plugins are pinned separately, by
go.mod `tool` directives, so `buf generate` is reproducible with no network.
