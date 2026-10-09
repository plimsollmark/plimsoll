# The example programs

Ten runnable Go programs and one TypeScript example in this repository, what each one proves, and the one to read if you only read one.

Part of the [plimsoll README](../README.md).

The first four need no docker, no credentials and no daemon you start yourself. The next
four need docker and the images `make docker-images` builds, and `examples/providers` also
uses any paid or gateway <dfn>*providers*</dfn> (the backends that run the code) it has
settings for. `examples/sessions` needs a gateway server of <dfn>*OpenShell*</dfn>, NVIDIA's agent
sandbox runtime. Run them from the repository root, except `examples/capsule`, its own Go
module (Go 1.27), which reads the signed bundle `examples/sessions` committed and runs from
its own directory, as does the TypeScript example, last in the table, with npm.

| Command | What it shows |
|---|---|
| `go run ./examples/minimal` | One snippet, its result, and the <dfn>*isolation tier*</dfn> the run reports: how strong the wall around it was. |
| `go run ./examples/grant` | How a <dfn>*grant*</dfn>, one run's permission to call listed routes of an API, works: a permitted route, a refused one, the same refusal when the <dfn>*guest*</dfn> (the code in the sandbox) skips the client plimsoll gave it and calls out by hand, the same request succeeding in a separate run whose grant lists it, and a search for the credential that finds nothing. |
| `go run ./examples/daemon` | The service: `plimsolld`, the plimsoll server, started with a real file of callers, called by the Go client, refusing a <dfn>*floor*</dfn> (a minimum tier) it cannot meet and refusing a wrong token. Each refusal is checked for its specific error: `ErrInsufficientIsolation`, and `unauthenticated` from <dfn>*Connect*</dfn>, the RPC library plimsolld speaks. A request that merely failed is not proof the protection fired. |
| `go run ./examples/advisor` | The efficiency advisor, which reads the API calls a run made: one question asked twice of a fake inventory API. First as a loop with one request per item (13 requests, and a `fan_out` finding naming the route, already allowed by the grant, that returns the whole list), then as the advice suggests (1 request, no findings). Same answer both times. |
| `go run ./examples/oracle` | The <dfn>*physics oracle*</dfn>, which tests code by what it makes a simulation do. An agent-written <dfn>*controller*</dfn> (a program that decides at every <dfn>*tick*</dfn>, one 10 ms step of the simulation, how to push the cart) is the only file of a project run. It runs against a <dfn>*cart-pole*</dfn> simulator (a cart on a rail with a pole hinged on top, to be kept upright), compiled to <dfn>*WebAssembly*</dfn> (a portable bytecode) and built into the module image. The runner, a program also built into the image, runs the controller as a separate process, records its <dfn>*trajectory*</dfn> (every state at every tick), and hashes that into a <dfn>*fingerprint*</dfn>: a SHA-256 hash, so equal fingerprints mean identical numbers. The accepted controller runs twice (one fingerprint), the agent's draft once (another, and it drops the pole at 5.96 s). The page it writes, live: [the physics oracle](https://plimsollmark.github.io/plimsoll/examples/oracle/index.html), which replays the recorded runs (source: `docs/examples/oracle/index.html`). |
| `go run ./examples/providers` | The oracle's run on every provider the machine can reach, each built the way plimsolld builds it: the same accepted controller, runner and cart-pole simulator, sent as ordinary project files so no special image is needed, and each provider proven ready before its run counts. The page it writes, live: [same run, different sandboxes](https://plimsollmark.github.io/plimsoll/examples/providers/index.html), shows each provider's isolation tier, Node version and fingerprint beside the one the oracle page published (source: `docs/examples/providers/index.html`). The rows for <dfn>*E2B*</dfn> and <dfn>*Docker Cloud Sandboxes*</dfn>, two hosted services that run each request in its own small virtual machine, need their credentials and are billed; the OpenShell row needs a gateway. |
| `go run ./examples/wasm-controller` | A controller in a compiled language. A cart-pole swing-up controller (it swings the pole up from hanging, then balances it) is written in C and sent as a file of a project run, whose first step compiles it to WebAssembly inside the sandbox (`plimsoll/sandbox-wasm-cc`). The image's generic trial runner runs it against the same simulator on four scenarios, through a small Node adapter that gives the compiled module no outside functions to call. Two runs give one hash of the compiled module and one fingerprint per scenario, with the pole up within 2.5 s in each. Two more runs compare it with the same <dfn>*control law*</dfn> (the formula the controller applies at each tick) in JavaScript, and with the same C built against Node's `Math.cos`. The page it writes, live: [a controller in C, checked by its trajectory](https://plimsollmark.github.io/plimsoll/examples/wasm-controller/index.html), replays the swing-up and shows, tick by tick, that the C and JavaScript records differ only in the last bits of a few force values, while the motion is bit-identical (source: `docs/examples/wasm-controller/index.html`). Its [README](../examples/wasm-controller/README.md) says why the fingerprints differ from the JavaScript version's (the last bit of `cos`) and what the example does not prove. |
| `go run ./examples/wasm-buck` | A controller in C for a <dfn>*buck converter*</dfn>, a power supply that steps a voltage down by switching it on and off many times a second. It uses the same adapter, runner and compile step, and holds 5 V out from 10 to 16 V in through a load that halves at an unknown moment. Two C runs and one JavaScript run of the same control law give one module hash, and in every scenario the C trajectory equals the JavaScript one byte for byte: the law calls no library function, and the compiler is told not to merge a multiply and an add into one step (which would round differently). The page it writes, live: [a buck converter controller in C](https://plimsollmark.github.io/plimsoll/examples/wasm-buck/index.html), charts, tick by tick, the output voltage, the current through the converter's coil (inductor current) and the share of each cycle its switch is on (duty cycle) (source: `docs/examples/wasm-buck/index.html`). Its [README](../examples/wasm-buck/README.md) says what it does not prove. |
| `go run ./examples/sessions` | A <dfn>*session*</dfn>, one sandbox kept for many calls ([sessions.md](sessions.md)), on an OpenShell sandbox through plimsolld. A <dfn>*harness*</dfn>, a program outside the daemon, signs every call's <dfn>*run record*</dfn>, the daemon's statement of what was sent, what came back and where it ran ([run-records.md](run-records.md)). The calls: a project whose test fails, a snippet that patches the file in place, the test passing without the files being sent again, a snippet that leaves a background process running, and a snippet that finds it gone. The signed set of records is verified, then refused once with one call dropped and once with one byte of output changed. The page it writes, live: [one sandbox, five calls](https://plimsollmark.github.io/plimsoll/examples/sessions/index.html), with the signed set and the harness's public key beside it (source: `docs/examples/sessions/`). Needs a gateway and the five `SANDBOX_OPENSHELL_*` settings; spends nothing. |
| `cd examples/capsule && go run .` | Each call of the sessions example's signed bundle, once the `attest` verifier accepted it, stated as an Agent Action Capsule and checked by that project's Go and Python verifiers. Its own Go module, because the capsule code needs Go 1.27 and dependencies plimsoll does not take on. |
| `examples/trigger-chat` (npm) | A <dfn>*Trigger.dev*</dfn> (a hosted job runner for TypeScript) chat agent with an `executeCode` tool, written on Trigger.dev's own code-sandbox recipe with plimsoll as the sandbox, through the TypeScript client in `clients/typescript`. The tool runs Python or JavaScript and takes files, so the model hands the code another tool's output by path. On a daemon with sessions the run keeps one sandbox, warmed when a turn starts and closed right before the run sleeps, and every call runs in an interpreter that stays alive, so data loaded in one call is still in memory in the next; elsewhere each call runs fresh and the tool says nothing was kept. Its test drives two turns through Trigger.dev's offline harness and checks that one interpreter served every call, that a file reached it, and that the suspend closed the sandbox. Needs a plimsolld, a Trigger.dev project and a model key; its [README](../examples/trigger-chat/README.md) says how. |

`examples/grant` is the one to read if you only read one. After each step it prints the
run's `CallTrace`: the list of API calls the <dfn>*broker*</dfn> made for the code (the
broker is the part of plimsoll that makes those calls and holds the credential). The list
records only the route, the status, the sizes and the time taken, never the data, and the
efficiency advisor and the audit log are built from it:

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

Scenes 3 and 4 send the identical request. The guest did not change and the API did not
change; the run was handed a different grant, and the grant is what decides.

Note what the list holds: the route pattern the request matched, such as
`/v1/employees/*/comp`, never the exact path that was requested. `CallRow` has no field
for a path, query, body or credential, so none can be recorded by accident.
