# The example programs

Nine runnable programs in this repository, what each one proves, and the one to read if you only read one.

Part of the [plimsoll README](../README.md).

Nine runnable programs. The first four need no docker, credentials or a daemon
you start yourself; the next four need docker and the images `make docker-images`
builds (the providers example also reaches the paid and gateway providers it has
settings for); the last needs an OpenShell gateway. Run them from the repository root.

| Command | What it shows |
|---|---|
| `go run ./examples/minimal` | One snippet, its result, and the isolation tier the run reports. |
| `go run ./examples/grant` | The capability model: a permitted route, a refused one, the same refusal when the guest bypasses the injected client, the same request succeeding under a separate per-run grant that lists it, and a search for the credential that comes back empty. |
| `go run ./examples/daemon` | The service path: plimsolld started with a real multi-client auth file, called by the Go client, refusing an isolation floor it cannot meet and refusing a wrong bearer. Each refusal is checked for its specific error (`ErrInsufficientIsolation`, Connect `unauthenticated`), because a request that merely failed is not proof the protection fired. |
| `go run ./examples/advisor` | The efficiency advisor: one question asked twice of a fake inventory API, first as a per-item loop (13 requests, a `fan_out` finding naming the granted collection route), then as the advice suggests (1 request, no findings), same answer both times. |
| `go run ./examples/oracle` | The physics oracle: an agent-written controller sent as the only file of a project run, judged against a cart-pole simulator compiled to WebAssembly and baked into the module image, by a judge that runs the controller as a separate process and fingerprints the trajectory. The accepted controller twice (one fingerprint), the agent's draft once (another, and it falls at 5.96 s). The page it writes, live: [the physics oracle](https://plimsollmark.github.io/plimsoll/examples/oracle/index.html), which replays the recorded runs (source: `docs/examples/oracle/index.html`). |
| `go run ./examples/providers` | The oracle's run on every provider the machine can reach, each built the way plimsolld builds it: the same accepted controller, judge and cart-pole simulator, sent as ordinary project files so no special image is needed, each provider proven ready before its run counts. The page it writes, live: [same run, different sandboxes](https://plimsollmark.github.io/plimsoll/examples/providers/index.html), shows each provider's isolation tier, Node version and fingerprint beside the one the oracle page published (source: `docs/examples/providers/index.html`). E2B and Docker Cloud rows need their credentials and are billed; the OpenShell row needs a gateway. |
| `go run ./examples/wasm-controller` | A controller in a compiled language: a cart-pole swing-up controller written in C, sent as a file of a project run whose first step compiles it to WebAssembly inside the sandbox (`plimsoll/sandbox-wasm-cc`), judged by the same judge and simulator on four scenarios through a Node shim that gives the module no imports. Two runs: one module hash, one fingerprint per scenario, the pole up within 2.5 s in each. Two more runs compare it with the same law in JavaScript and with the same C built against Node's `Math.cos`. The page it writes, live: [a controller in C, judged by its trajectory](https://plimsollmark.github.io/plimsoll/examples/wasm-controller/index.html), which replays the swing-up and shows, tick by tick, that the C and JavaScript records differ only in a few forces' last bits while the motion is bit-identical (source: `docs/examples/wasm-controller/index.html`). Its [README](../examples/wasm-controller/README.md) says why the fingerprints are not the JavaScript law's (the last bit of `cos`) and what the example does not prove. |
| `go run ./examples/wasm-buck` | A buck converter (power supply) controller in C under the same shim, judge and compile step, holding 5 V from 10 to 16 V in through a load that halves at an unknown moment. Two C runs and one run of the same law in JavaScript: one module hash, and in every scenario the C trajectory equals the JavaScript one byte for byte, because the law calls no library function and the build fuses no arithmetic. The page it writes, live: [a buck converter controller in C](https://plimsollmark.github.io/plimsoll/examples/wasm-buck/index.html), charting output voltage, inductor current and duty cycle tick by tick (source: `docs/examples/wasm-buck/index.html`). Its [README](../examples/wasm-buck/README.md) says what it does not prove. |
| `go run ./examples/sessions` | A [session](sessions.md) on an NVIDIA OpenShell sandbox through plimsolld, with a harness signing every call's [run record](run-records.md): a project whose test fails, a snippet that patches the file in place, the test passing without the files being sent again, a snippet that leaves a detached process, and a snippet that finds it gone. The signed bundle is verified, then refused with one call dropped and with one byte of output changed. The page it writes, live: [one sandbox, five calls](https://plimsollmark.github.io/plimsoll/examples/sessions/index.html), with the bundle and the harness's public key beside it (source: `docs/examples/sessions/`). Needs a gateway and the five `SANDBOX_OPENSHELL_*` settings; spends nothing. |

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
