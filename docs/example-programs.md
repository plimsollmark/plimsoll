# The example programs

Six runnable programs in this repository, what each one proves, and the one to read if you only read one.

Part of the [plimsoll README](../README.md).

Six runnable programs. The first four need no docker, credentials or a daemon
you start yourself; the last two need docker and the images `make docker-images`
builds. Run them from the repository root.

| Command | What it shows |
|---|---|
| `go run ./examples/minimal` | One snippet, its result, and the isolation tier the run reports. |
| `go run ./examples/grant` | The capability model: a permitted route, a refused one, the same refusal when the guest bypasses the injected client, the same request succeeding under a separate per-run grant that lists it, and a search for the credential that comes back empty. |
| `go run ./examples/daemon` | The service path: plimsolld started with a real multi-client auth file, called by the Go client, refusing an isolation floor it cannot meet and refusing a wrong bearer. Each refusal is checked for its specific error (`ErrInsufficientIsolation`, Connect `unauthenticated`), because a request that merely failed is not proof the protection fired. |
| `go run ./examples/advisor` | The efficiency advisor: one question asked twice of a fake inventory API, first as a per-item loop (13 requests, a `fan_out` finding naming the granted collection route), then as the advice suggests (1 request, no findings), same answer both times. |
| `go run ./examples/oracle` | The physics oracle: an agent-written controller sent as the only file of a project run, judged against a cart-pole plant compiled to WebAssembly and baked into the module image, by a judge that runs the controller as a separate process and fingerprints the trajectory. The accepted controller twice (one fingerprint), the agent's draft once (another, and it falls at 5.96 s). The page it writes, live: [the physics oracle](https://plimsollmark.github.io/plimsoll/examples/oracle/index.html), which replays the recorded runs (source: `docs/examples/oracle/index.html`). |
| `go run ./examples/providers` | The oracle's run on every provider the machine can reach: the same accepted controller, judge and cart-pole plant, sent as ordinary project files so no special image is needed, each provider built by the factory the daemon uses and proven ready before its run counts. The page it writes, live: [same run, different sandboxes](https://plimsollmark.github.io/plimsoll/examples/providers/index.html), shows each provider's isolation tier, Node version and fingerprint beside the one the oracle page published (source: `docs/examples/providers/index.html`). E2B and Docker Cloud rows need their credentials and are billed. |
| `go run ./examples/wasm-controller` | A controller in a compiled language: a cart-pole swing-up controller written in C, sent as a file of a project run whose first step compiles it to WebAssembly inside the sandbox (`plimsoll/sandbox-wasm-cc`), judged by the same judge and plant on four scenarios through a Node shim that gives the module no imports. Two runs: one module hash, one fingerprint per scenario, the pole up within 2.5 s in each. Two more runs compare it with the same law in JavaScript and with the same C built against Node's `Math.cos`. The page it writes, live: [a controller in C, judged by its trajectory](https://plimsollmark.github.io/plimsoll/examples/wasm-controller/index.html), which replays the swing-up and shows, tick by tick, that the C and JavaScript records differ only in a few forces' last bits while the motion is bit-identical (source: `docs/examples/wasm-controller/index.html`). Its [README](../examples/wasm-controller/README.md) says why the fingerprints are not the JavaScript law's (the last bit of `cos`) and what the example does not prove. |

`examples/grant` is the one to read if you only read one. It prints the run's
`CallTrace` after each step, which is the same metadata-only evidence the advisory
channel and the audit log are built from:

```
1. a route the grant lists
   guest | ok: Engineering 46600000
   trace | #1 GET /v1/employees/*/comp -> 200, 0B in 39B out, 1ms

3. the same forbidden route, bypassing the client
   guest | broker answered: 403 forbidden by sandbox capability allowlist
   trace | 0 call(s), 1 denied by policy, 0 shed for backpressure, 0 dropped

4. the same request, in a run handed a separate grant that lists the route
   guest | ok: {"ssn":"000-00-0000"}
   trace | #1 GET /v1/employees/*/ssn -> 200, 0B in 21B out, 1ms
```

Scenes 3 and 4 send the identical request. The guest did not change and the API did
not change; the run was handed a different grant, and the grant is what decides.

Note what the trace holds: the matched route *template*, never the path that was
requested. `CallRow` has no field for a path, query, body or credential, so none can
be recorded by accident.
