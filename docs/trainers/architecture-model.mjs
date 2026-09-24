// One registry drives the map, walkthrough, and component connection index.
// Teaching examples only. Implementation anchors make content review tractable.
export const nodes = {
  caller: {name: 'Caller program', sub: 'MCP server · gateway · Go client', x: 25, y: 96,
    role: 'Submits code and receives the result.',
    detail: 'A model may write the code, but a program submits the remote procedure call (RPC). An MCP (Model Context Protocol) server is one possible caller. The submitted code later becomes the guest. Those are different roles, even when they belong to one application.',
    holds: 'A secret caller token supplied beforehand by the operator, the person running plimsoll. It selects a grant profile by name; it does not receive the downstream API token.', source: 'client/client.go'},
  ingress: {name: 'RPC entrance', sub: 'Authenticate, then decode', x: 285, y: 96,
    role: 'Turns an authenticated network request into a Go request.',
    detail: 'RPC means remote procedure call: a program asks this server to run an operation. In built-in multi-client mode, plimsolld hashes the received token with SHA-256 (a fingerprint) and looks it up in its configured client list. The match supplies the caller ID and permissions. Anyone holding the same token gets the same identity. HTTP middleware requires code:run permission before Connect reads the body. Raw bytes, decompressed bytes, read time, and concurrent decoding are bounded.',
    holds: 'Configured token fingerprints, caller IDs, and permissions. The simpler PLIMSOLL_TOKEN mode uses one shared token and assigns every holder the same identity, static. The downstream API credential is separate.', source: 'internal/rpc/clients.go'},
  service: {name: 'Run handler', sub: 'Validate · authorize · check tier', x: 535, y: 96,
    role: 'Checks whether this request may reach the selected provider.',
    detail: 'Validates code or project bounds, resolves a named profile for the authenticated caller, and checks the requested minimum isolation against current provider evidence. After dispatch, it assembles the response, analysis, and audit record.',
    holds: 'The request, caller identity, and a per-run copy of the permitted grant.', source: 'internal/rpc/sandbox_service.go'},
  limiter: {name: 'Admission limiter', sub: 'Capacity for this caller', x: 785, y: 96,
    role: 'Reserves capacity or refuses immediately.',
    detail: 'Checks global concurrency, per-caller concurrency, and per-caller rate. It does not queue. The handler holds the admitted slot while dispatching and releases it as the handler returns.',
    holds: 'Capacity counters and caller keys, not submitted source or API credentials.', source: 'internal/rpc/limiter.go'},
  operator: {name: 'Operator tools', sub: 'Configuration · probes · logs', x: 25, y: 292,
    role: 'Configures and observes the service.',
    detail: 'For the illustrated multi-client setup, the operator gives each caller a secret token and configures plimsolld with its SHA-256 fingerprint, caller ID, and permissions before requests arrive. This box also groups the operator’s log consumer and monitoring tools. These setup and observation actions are not mandatory hops in each code execution.',
    holds: 'Server configuration and emitted metadata. The run audit omits source code and credentials.', source: 'cmd/plimsolld/main.go'},
  profiles: {name: 'Grant registry', sub: 'Server-held API permissions', x: 285, y: 292,
    role: 'Resolves a name to a permitted host-API grant.',
    detail: 'A grant is permission for this run to call specific API routes. The server configures the API origin, allowed routes, credential source, and allowed caller identities. Looking up a profile does not mint its token.',
    holds: 'Frozen profiles. The handler receives a deep copy, so one run cannot rewrite later runs’ permissions.', source: 'internal/grants/grants.go'},
  minter: {name: 'Credential source', sub: 'Mint JWT or obtain static token', x: 535, y: 292,
    role: 'Supplies the broker’s downstream API credential once per granted run. It does not issue caller login tokens.',
    detail: 'JWT (JSON Web Token) mode signs a fresh token with caller identity, intended recipient (audience), permission names (scope), and expiry. Static mode returns an existing bearer unchanged. Exact route permissions are enforced by the broker; the built-in JWT does not encode the route allowlist.',
    holds: 'The signing secret or configured static bearer. Ending a run does not revoke an already issued JWT.', source: 'sandbox/capability.go'},
  provider: {name: 'Selected provider', sub: '{{provider}}', x: 785, y: 292,
    role: 'Implements the transport-independent Sandbox interface.',
    detail: 'Build selects one provider when the service starts. Each RPC calls that existing provider. It prepares the run, starts the guest, collects output, and cleans up. It also supplies the framing adapter for granted API calls.',
    holds: 'Execution resources and per-run state. {{boundary}}', source: 'sandbox/factory.go'},
  api: {name: 'Host API', sub: 'The customer’s HTTP service', x: 25, y: 494,
    role: 'Handles a permitted, credentialed HTTP request.',
    detail: '“Host” describes its relationship to the guest. This API may be on another machine or network. It verifies the downstream credential and enforces its own authorization. A broker grant cannot make an API accept a request.',
    holds: 'Application data and its own authorization rules. It receives the downstream bearer, not the plimsolld caller token.', source: 'sandbox/broker.go'},
  broker: {name: 'Shared API broker', sub: 'Route policy · budgets · HTTP', x: 285, y: 494,
    role: 'Enforces every guest API call on the trusted side.',
    detail: 'Checks the canonical method and path against the grant, applies call and byte budgets, adds the downstream bearer, and sends HTTP with proxies and redirects disabled. Responses are bounded. Bypassing the injected JavaScript client does not bypass this broker.',
    holds: 'The frozen grant and downstream credential. Trace rows retain route templates and measurements, not raw paths or bodies.', source: 'sandbox/broker.go'},
  adapter: {name: 'Guest-call adapter', sub: '{{channelShort}}', x: 535, y: 494,
    role: 'Carries a call envelope between guest code and the broker.',
    detail: '{{channel}} The adapter handles framing. The shared broker decides whether an API call is allowed. E2B additionally authenticates and admits guard requests before reading their body.',
    holds: 'A bounded method/path/body envelope and reply. {{credential}}', source: 'sandbox/broker.go'},
  guest: {name: 'Guest code', sub: '{{engine}}', x: 785, y: 494,
    role: 'Runs the submitted, untrusted program.',
    detail: 'The guest is the code being executed, not the caller program. With a grant it receives host.get/post/put/patch/del/call and any configured helper JavaScript, called the preamble. Without a grant there is no host-API capability. {{boundary}}',
    holds: 'Its code, bounded working data, and returned API data. The injected interface does not contain the downstream credential.', source: 'sandbox/sandbox.go'}
};

export const providers = {
  docker: {provider: 'Docker · runc', engine: 'Node in a container', tier: 'container', channelShort: 'HTTP over a Unix socket',
    channel: 'Docker binds a per-run Unix socket at /run/host-api.sock. Node sends HTTP over that file socket while --network none disables network access.',
    boundary: 'runc shares the host kernel. Its reported tier is container, insufficient for hostile production code.',
    credential: 'The downstream credential stays in Go outside the container.', projects: true},
  runsc: {provider: 'Docker · gVisor', engine: 'Node behind runsc', tier: 'kernel', channelShort: 'HTTP over a Unix socket',
    channel: 'Docker binds /run/host-api.sock with --network none. runsc must be registered with --host-uds=open; the startup smoke test proves that the guest can connect.',
    boundary: 'runsc places gVisor between guest code and the host kernel, mediating the guest’s operating-system calls.',
    credential: 'The downstream credential stays in Go outside the sandbox.', projects: true},
  wasm: {provider: 'WASM · QuickJS', engine: 'QuickJS in wazero', tier: 'process', channelShort: 'Direct wazero host function',
    channel: 'QuickJS calls the host_call import exposed by Go through wazero. Bounded request and response bytes cross WebAssembly linear memory; no socket is used.',
    boundary: 'WASM runs inside plimsolld. An engine escape lands in the server process; this is not an OS or VM boundary.',
    credential: 'The credential stays in Go and does not enter QuickJS, but Go and the engine share a process.', projects: false},
  e2b: {provider: 'E2B · Firecracker', engine: 'Node in a microVM', tier: 'vm', channelShort: 'HTTPS to the egress guard',
    channel: 'The VM is deny-all except for the configured E2B_GUARD_URL. E2B’s network layer injects the per-run guard header outside the VM. The guard delegates to the shared broker in the originating plimsolld process.',
    boundary: 'The guest runs in a hardware-virtualized microVM. Granted paths here assume a configured and reachable E2B guard.',
    credential: 'The VM holds neither the API bearer nor the guard credential. The guard URL must reach the process that opened this run.', projects: true},
  disabled: {provider: 'Disabled · default', engine: 'No guest starts', tier: 'none', channelShort: 'No adapter opened',
    channel: 'The disabled provider refuses execution.', boundary: 'An unset SANDBOX_PROVIDER selects Disabled. An unknown value is a configuration error, not a fallback.',
    credential: 'No credential is minted.', projects: false}
};

// kind identifies the moving object, not the strength of an isolation boundary.
const steps = {};
function add(id, from, to, kind, title, moves, why, payload, source, via) {
  steps[id] = {id, from, to, kind, title, moves, why, payload, source, via};
}
add('submit', 'caller', 'ingress', 'request', 'The program submits code',
  'Code, a time budget, a minimum isolation tier, and optionally a profile name.',
  'Before this request, the operator (the person running plimsoll) gives the caller a secret token and configures plimsolld to recognize it. The caller presents that token in the Authorization header. The daemon checks a previously supplied token; it does not issue caller tokens. The model-written code is still request data.',
  'Run\nprotocol: 1\nminimum_isolation: {{tier}}\njavascript: { code: console.log("hello") }\nAuthorization: Bearer [caller credential]', 'client/client.go');
add('submit-grant', 'caller', 'ingress', 'request', 'Select a profile by name',
  'The code and grant_profile travel over the RPC, with the caller’s credential.',
  'The caller presents the secret token supplied beforehand by the operator. Plimsolld matches it to a configured caller identity and permissions. The chosen profile, “inventory-read”, defines separate API permissions held by the server. Any token minted for those API calls stays in the broker, not with the caller. The item ID is an invented example.',
  'Run\nprotocol: 1\nminimum_isolation: {{tier}}\njavascript: { code: console.log(await host.get("/items/42")), grant_profile: inventory-read }\nAuthorization: Bearer [caller credential]', 'client/client.go');
add('submit-project', 'caller', 'ingress', 'request', 'Submit files and ordered steps',
  'A file list, build/lint/run commands, requested artifacts, and a profile name.',
  'The same Run procedure carries a project payload instead of a javascript one. Docker and E2B support project grants; WASM refuses the operation.',
  'Run\nprotocol: 1\nproject: { files: [package.json, src/main.ts, …], steps: [build, lint, run], artifacts: [dist/report.json], grant_profile: inventory-read }', 'internal/rpc/sandbox_service.go');
add('authenticate', 'ingress', 'service', 'request', 'Authenticate before decoding',
  'A decoded request plus the configured caller ID and permissions found by checking the token.',
  'In the illustrated multi-client mode, plimsolld computes a SHA-256 fingerprint of the received token and looks it up in its configured client list. The matching entry supplies client-a and its permissions. Anyone holding that token is treated as client-a. HTTP middleware requires code:run permission before decoding the body. The handler then validates the code or file bounds.',
  'Principal { UserID: "client-a", Scopes: ["code:run"] }\n+ validated Request or ProjectRequest', 'internal/rpc/clients.go');
add('profile', 'service', 'profiles', 'authority', 'Resolve the server-held permission',
  'Profile name and authenticated caller identity.',
  'The registry lookup must succeed and the caller must be in allowed_callers. Permission to execute code does not automatically grant permission to call this API.',
  'profile: inventory-read\ncaller: client-a\ncheck: allowed_callers includes client-a', 'internal/rpc/sandbox_service.go', [[625, 248], [375, 248]]);
add('grant', 'profiles', 'service', 'authority', 'Return a per-run grant copy',
  'API origin, allowed routes, declared scopes, and a credential source.',
  'The profile is copied so this dispatch cannot alter later runs. No token has been minted. No raw grant or signing key came from the caller.',
  'HostAPIGrant {\n  BaseURL: "https://api.example.test",\n  Allow: [{Method: "GET", Path: "/items/*"}],\n  Minter: [server-configured TokenMinter]\n}', 'internal/rpc/sandbox_service.go', [[375, 226], [600, 226]]);
add('admit', 'service', 'limiter', 'request', 'Check isolation, then reserve capacity',
  'The authenticated caller’s key for capacity and rate accounting.',
  'The handler compares current provider evidence with the requested floor immediately before admission. The limiter either reserves capacity or refuses; it does not queue.',
  'current tier: {{tier}}\nrequired tier: {{tier}}\nAcquire("client-a")', 'internal/rpc/sandbox_service.go');
add('dispatch', 'service', 'provider', 'request', 'The handler dispatches the admitted run',
  'A plain Go Request or ProjectRequest passed to the selected Sandbox implementation.',
  'After the limiter reserves capacity and returns a release function, the handler calls the provider. The handler releases that capacity when it returns. Build selected {{provider}} at startup.',
  'Sandbox.RunJavaScript(ctx, request)\nor Sandbox.RunProject(ctx, project)\nprovider: {{provider}}', 'internal/rpc/sandbox_service.go');
add('prepare-token', 'provider', 'minter', 'authority', 'Obtain the run’s API credential',
  'Caller identity, granted scopes and routes, and the run budget.',
  'Granted-run setup calls TokenMinter.Mint once. JWT (JSON Web Token) mode signs a fresh token; static mode returns its configured bearer. The calling program’s plimsolld bearer is not forwarded.',
  'Mint(ctx with subject "client-a", grant budget)\nJWT mode: sub, aud, scope, exp, jti\nStatic mode: existing bearer', 'sandbox/capability.go');
add('token-broker', 'minter', 'broker', 'authority', 'Keep the credential on the trusted side',
  'The downstream bearer and the frozen grant enter the per-run broker session.',
  'The built-in JWT contains claims, not the exact route allowlist. The broker enforces that list. The customer API must still verify the token and enforce its own permissions.',
  'brokerSession {\n  grant: [frozen permission],\n  token: [downstream API credential]\n}\nNo bearer inserted into guest JavaScript', 'sandbox/broker.go', [[625, 425], [375, 425]]);
add('open-adapter', 'broker', 'adapter', 'authority', 'Make the broker reachable through one channel',
  'A per-run connection to the shared enforcement core.',
  '{{channel}} The provider wires this adapter during setup. The line shows the attachment, not an API call made by the broker.',
  '{{channelShort}}\nBounded envelope: { method, path, body }\n{{credential}}', 'sandbox/broker.go');
add('launch', 'provider', 'guest', 'request', 'Start the untrusted program',
  'Submitted code and a bounded execution environment.',
  '{{boundary}} The provider prepares resources and enforces the time and output budgets. With no grant, the run has no host-API capability.',
  'engine: {{engine}}\nconsole.log("hello")\nHost API grant: none', 'sandbox/sandbox.go');
add('launch-grant', 'provider', 'guest', 'request', 'Inject a calling interface, then run',
  'The submitted code, host.* client, and any configured helper JavaScript (the preamble).',
  'The guest can describe a desired API call. It does not receive the bearer that authorizes the outgoing HTTP request. {{boundary}}',
  'engine: {{engine}}\nawait host.get("/items/42")\nGuest receives: interface + permitted API replies\nGuest does not receive: downstream bearer', 'sandbox/capability.go');
add('launch-project', 'provider', 'guest', 'request', 'Stage files and run the project steps',
  'Files and ordered build/lint/run commands inside the selected provider.',
  'Steps stop at the first failure. Docker preloads the host client into step processes with node --import; E2B uses its guard-backed client. Filesystem and artifact paths are validated and bounded.',
  'stage files → build → lint → run\nstop on first failed step\ncollect only requested, bounded artifacts', 'docker/runner.mjs');
add('guest-call', 'guest', 'adapter', 'api', 'The guest asks for an API operation',
  'Method, path, and optional body. No downstream bearer.',
  '{{channel}} The route /items/42 is just an illustrative request; the grant’s /items/* is the pattern that will authorize it.',
  '{ method: "GET", path: "/items/42", body: null }\n{{channelShort}}', 'sandbox/capability.go');
add('adapter-call', 'adapter', 'broker', 'api', 'Framing ends; policy begins',
  'The decoded, bounded call envelope.',
  'Every provider delegates to the same broker. The broker checks the method and canonical path, call and byte budgets, and any upstream cooldown before sending HTTP.',
  'GET /items/42\nallow: GET /items/*\ncheck: exact approved path equals the HTTP target\ncheck: traffic budget remains', 'sandbox/broker.go');
add('upstream', 'broker', 'api', 'api', 'The broker makes the HTTP request',
  'An approved HTTP request with the downstream bearer added by Go.',
  'This is a second connection, separate from the guest-to-adapter channel. The API authenticates and authorizes it. Non-loopback origins require HTTPS; proxies and redirects are disabled.',
  'GET https://api.example.test/items/42\nAuthorization: Bearer [downstream credential]\nOrigin chosen by server profile', 'sandbox/broker.go');
add('api-reply', 'api', 'broker', 'response', 'The API sends its response to the broker',
  'HTTP status and body bytes.',
  'The broker bounds the response size and records delivery metadata. An upstream 200 that cannot be delivered is not counted as a successful retrieved record.',
  'HTTP 200\n{ "id": "42", "name": "Example item" }\nExample data only', 'sandbox/broker.go', [[115, 606], [375, 606]]);
add('broker-reply', 'broker', 'adapter', 'response', 'Return a bounded reply through the same channel',
  'Status and response body, framed for this provider.',
  'The bearer is not part of this reply. The shared enforcement decision is complete; the adapter handles transport back to the guest.',
  'brokerResponse { status: 200, body: [bounded bytes] }\n{{channelShort}}', 'sandbox/broker.go', [[375, 625], [625, 625]]);
add('guest-reply', 'adapter', 'guest', 'response', 'Resume the guest’s awaiting call',
  'The permitted API data resolves the host.* call.',
  'The program can now use the returned data and write output. The customer API was reached by the broker, even though the guest expressed the call.',
  'await host.get("/items/42") resolves\nGuest continues executing\nNo credential needed in guest code', 'sandbox/capability.go', [[625, 606], [875, 606]]);
add('finish', 'guest', 'provider', 'response', 'Collect output and end the run',
  'stdout, stderr, exit status, timeout state, and any requested project artifacts.',
  'The provider bounds retained output and releases per-run resources before returning. Output truncation is a flag, not a marker inserted into the guest’s bytes.',
  'Result: stdout, stderr, ExitCode, TimedOut\nStdoutTruncated / StderrTruncated\nProject: Steps, Outcome, Artifacts, ArtifactsTruncated', 'sandbox/sandbox.go', [[980, 532], [980, 330]]);
add('result', 'provider', 'service', 'response', 'Return execution evidence to the handler',
  'The final result and a bounded in-memory call trace when APIs were brokered.',
  'The reported tier combines provider/configuration evidence and behavioral startup checks; it is not runtime attestation. A non-zero guest exit is a normal result, not a Go infrastructure error.',
  'Result { ExitCode: 0, Isolation: "{{tier}}", … }\nCallTrace: route templates, statuses, delivery, bytes, latency\nNo raw path, body, or credential in CallTrace', 'internal/rpc/sandbox_service.go', [[875, 208], [650, 208]]);
add('audit', 'service', 'operator', 'observe', 'Emit a metadata-only run record',
  'Caller identity, sizes, provider, outcome, duration, and an accepted trace_id if supplied.',
  'The record is emitted after dispatch returns. This is an observation branch, not a request to an operator for permission. plimsoll does not persist a database; the configured log destination controls log storage.',
  'caller: client-a\ncode_bytes: [size]\nsandbox: {{provider}}\nexit_code: 0\nNo submitted code or credential', 'internal/rpc/sandbox_service.go', [[625, 188], [245, 188], [245, 330]]);
add('wire-result', 'service', 'ingress', 'response', 'Encode the result and release admission',
  'The final response fields are mapped to protobuf; stdout and stderr are bytes.',
  'The handler returns and releases its limiter slot. Raw CallTrace is not a response field. Only eligible caller advice is added when the profile permits it.',
  'RunResponse\nsandbox, isolation: {{tier}}, duration_ms\njavascript: { stdout / stderr: bytes, exit_code }\nor project: { steps, outcome, artifacts }', 'internal/rpc/sandbox_service.go', [[625, 25], [375, 25]]);
add('caller-result', 'ingress', 'caller', 'response', 'The caller gets the answer',
  'The RPC response, including the evidence for this completed execution.',
  'The official Go client checks the returned isolation against the requested floor. The caller decides what to show a model or user. A successful RPC can still contain a failed guest program.',
  'Go client → sandbox.Result / ProjectResult\nCheckResultIsolation(returned, requested)\nThen inspect exit / outcome / truncation flags', 'client/client.go', [[375, 48], [115, 48]]);
add('bad-auth', 'ingress', 'caller', 'deny', 'Stop at the entrance',
  'Unauthenticated for a missing or invalid bearer; PermissionDenied for a missing scope.',
  'With authentication configured, HTTP middleware rejects this request before decoding its body. No handler, provider, guest, or downstream API is reached.',
  'RPC error: Unauthenticated\nor PermissionDenied\nCode executed: no', 'internal/rpc/auth.go');
add('profile-denied', 'profiles', 'service', 'deny', 'Refuse this profile selection',
  'Unknown profile: InvalidArgument. Known profile but caller not allowed: PermissionDenied.',
  'A recognized caller token selects the identity and permissions configured for its holder. That identity is not authorized for this downstream grant. No downstream token is minted and no provider is dispatched.',
  'grantFor("inventory-read", caller) → error\nCode executed: no\nCredential minted: no', 'internal/rpc/sandbox_service.go', [[375, 226], [600, 226]]);
add('floor-denied', 'service', 'ingress', 'deny', 'Refuse before admission or execution',
  'FailedPrecondition caused by ErrInsufficientIsolation.',
  'This scenario assumes the requested floor is stronger than current provider evidence. A previously acceptable Describe result cannot authorize this new dispatch.',
  'CheckMinimumIsolation(current, requested) → error\nRPC: FailedPrecondition\nCode executed: no', 'internal/rpc/sandbox_service.go');
add('capacity-denied', 'limiter', 'service', 'deny', 'There is no available admission',
  'ResourceExhausted caused by a concurrency or rate limit.',
  'This is load shedding, not a waiting queue. The provider is never called. A caller can apply its own bounded backoff before trying again.',
  'Acquire("client-a") → ResourceExhausted\nCode executed: no', 'internal/rpc/limiter.go');
add('error-wire', 'service', 'ingress', 'deny', 'Return the refusal through RPC',
  'A typed transport error describing the rejecting gate.',
  'For this early-refusal path, no guest result exists because code never ran. The provider’s post-dispatch run audit path is not reached.',
  'RPC error, not Result { ExitCode: … }\nCode executed: no', 'internal/rpc/sandbox_service.go');
add('error-caller', 'ingress', 'caller', 'deny', 'The caller receives the refusal',
  'The RPC error mapped into the caller’s error handling.',
  'An early refusal can prove that this attempt did not run code. That proof must not be confused with a network error after dispatch, where execution may already have happened.',
  'No guest output\nNo downstream API request\nFix the rejecting condition before retrying', 'client/client.go');
add('unsupported', 'provider', 'service', 'deny', 'WASM cannot run a project',
  'ErrUnsupported becomes RPC Unimplemented.',
  'The handler dispatched, but this provider does not implement project execution. No guest starts. Docker and E2B can run the project path shown by the provider selector.',
  'RunProject → ErrUnsupported\nRPC: Unimplemented\nCode executed: no', 'sandbox/wasm.go', [[875, 208], [650, 208]]);
add('disabled', 'provider', 'service', 'deny', 'Execution is disabled',
  'ErrDisabled becomes FailedPrecondition.',
  'Disabled is the safe default when SANDBOX_PROVIDER is unset. An unknown configured name is a startup error instead. This path assumes no per-request floor, so the disabled provider itself returns the refusal.',
  'RunJavaScript → ErrDisabled\nRPC: FailedPrecondition\nNo guest, adapter, or API call', 'sandbox/disabled.go', [[875, 208], [650, 208]]);
add('provider-error-wire', 'service', 'ingress', 'deny', 'Record the failed dispatch and return its error',
  'A mapped provider error, rather than an execution result.',
  'The handler records the dispatch failure, releases its admission, and maps the typed error. Disabled and unsupported failures mean no guest ran; unmatched infrastructure failures do not make that guarantee.',
  'ErrDisabled → FailedPrecondition\nErrUnsupported → Unimplemented\nUnmatched infrastructure error → Internal', 'internal/rpc/sandbox_service.go');
add('bad-path', 'adapter', 'broker', 'api', 'Try a route the grant does not allow',
  'A request for DELETE /items/42 under a read-only grant.',
  'The guest could bypass the host.* helper and write its own adapter request. It would still meet this same broker check. The synthetic inventory-read grant permits GET only.',
  '{ method: "DELETE", path: "/items/42" }\nAllowed: GET /items/*', 'sandbox/broker.go');
add('broker-denied', 'broker', 'adapter', 'deny', 'The API never receives this call',
  'A broker-generated 403 response.',
  'The broker refuses the method/path before upstream dispatch and increments its denied count. The guest is already running; this is an API-call refusal, not an RPC admission refusal.',
  'HTTP-like status: 403\nforbidden by sandbox capability allowlist\nUpstream call made: no', 'sandbox/broker.go');
add('guest-error', 'adapter', 'guest', 'deny', 'The API-call failure reaches the guest',
  'The host client surfaces the non-success response as a rejected call.',
  'Guest code can catch this error and continue. If it does not, the program may fail. The enclosing RPC does not automatically become a transport error.',
  'try { await host.call(…) } catch (error) { … }\nGuest chooses how to handle the failure', 'sandbox/capability.go');
add('upstream-503', 'api', 'broker', 'deny', 'The API reports service degradation',
  'An upstream 503 response and any Retry-After header.',
  'The broker opens a per-run cooldown, bounded by the implementation’s 30-second cap to limit a remote server’s influence over the run. Later permitted calls are shed while it is open.',
  'HTTP 503 Service Unavailable\nRetry-After: [upstream delay]\nbreaker reason: service availability', 'sandbox/broker.go');
add('upstream-429', 'api', 'broker', 'deny', 'The API says this caller must wait',
  'An upstream 429 response and any Retry-After header.',
  'A healthy service does not mean this caller has quota left. The broker waits out this cooldown and does not use a health probe to close it early.',
  'HTTP 429 Too Many Requests\nbreaker reason: caller quota\nRecovery: wait out the cooldown', 'sandbox/broker.go');
add('failure-reply', 'broker', 'adapter', 'deny', 'Send the upstream failure back',
  'The upstream non-success status and bounded response.',
  'The guest learns that its call failed. The per-run breaker remembers the reason for the cooldown, separately from the returned response.',
  'upstream status + bounded body\nNo automatic successful retry is fabricated', 'sandbox/broker.go');
add('shed', 'broker', 'adapter', 'deny', 'Shed the next permitted call',
  'A fast 503 from the broker, without an ordinary upstream request.',
  'This call matches the grant but is held back by upstream backpressure. Shed is counted separately from Denied. In a 429 window, even a configured health route is not probed.',
  'broker status: 503\nCallTrace.Shed increases\nOrdinary upstream request: skipped', 'sandbox/broker.go');
add('health-probe', 'broker', 'api', 'observe', 'Probe only an availability failure',
  'A configured concrete GET health route, using this run’s API credential.',
  'After an upstream 503, one elected caller per second may probe. The interval limits recovery traffic. The route must be explicitly configured; its name is never guessed. The probe is not traced or charged to the call budget.',
  'GET [grant.HealthCheck]\nAuthorization: Bearer [downstream credential]\nOnly for 503 recovery, never a 429 window', 'sandbox/broker.go');
add('health-ok', 'api', 'broker', 'observe', 'A successful probe closes the 503 window',
  'A 2xx response from the configured health route.',
  'The elected call may now proceed to the ordinary API route. A failed probe keeps the cooldown open. This says nothing about caller quota after a 429.',
  'health probe: 2xx\nbreaker closes\nThe permitted guest call may proceed', 'sandbox/broker.go');
add('guest-fail', 'guest', 'provider', 'deny', 'The submitted program fails',
  'A non-zero exit status and bounded stderr.',
  'The sandbox ran the code successfully as infrastructure. A guest exception or failed command is a normal execution result. In a project, later steps are skipped after the failed step.',
  'ExitCode: non-zero\nStderr: [guest error bytes]\nGo infrastructure error: nil', 'sandbox/sandbox.go', [[980, 532], [980, 330]]);
add('failed-result', 'provider', 'service', 'response', 'A failed program is still a result',
  'The non-zero exit status, output, and actual reported isolation tier.',
  'The service preserves the guest outcome. It does not turn a program failure into Internal. The caller must inspect the result after a successful RPC.',
  'Result { ExitCode: non-zero, Isolation: "{{tier}}" }\nRPC transport: successful', 'internal/rpc/sandbox_service.go', [[875, 208], [650, 208]]);
add('mismatch', 'ingress', 'caller', 'deny', 'Returned evidence fails the client check',
  'The result plus DataLoss / ErrIsolationEvidenceMismatch from the official Go client.',
  'This synthetic scenario assumes a faulty or incompatible backend returns weaker or unknown evidence. Execution may already have happened. Retrying a write automatically could duplicate its effects.',
  'CheckResultIsolation(returned, requested) → mismatch\nDataLoss / ErrIsolationEvidenceMismatch\nExecution may already have occurred', 'client/client.go');
add('configure', 'operator', 'provider', 'authority', 'Select one provider at startup',
  'SANDBOX_PROVIDER and resource, image/template, and runtime configuration.',
  'Build parses configuration and fails closed on unknown providers or malformed safety settings. An unset provider selects Disabled. The diagram groups startup controls; it is not a full line-by-line startup schedule.',
  'Build(getenv) → Provider { Sandbox, Resources }\nselected: {{provider}}\nThis selection is not repeated per RPC', 'sandbox/factory.go', [[115, 392], [875, 392]]);
add('smoke', 'provider', 'guest', 'observe', 'Prove startup behavior before serving',
  'A bounded throwaway execution for real providers, after Preflight.',
  'Docker proves the promised mount/write restrictions and broker socket reachability. E2B proves secured creation, project toolchain, cwd, and denied egress. Docker Cloud Sandboxes proves the token’s permissions, a deny-all effective network policy, file upload, project toolchain, cwd, and denied egress. Both create a billable VM at startup in an actual deployment; this page does not.',
  'EnsureReady = Preflight + SmokeTest\nWASM: process-tier configuration checks\nDocker/E2B/Docker Cloud: bounded behavioral execution\nStartup refuses if required checks fail', 'sandbox/factory.go');
add('smoke-result', 'guest', 'provider', 'observe', 'Collect startup evidence and tear down the probe',
  'The bounded smoke result and provider/configuration evidence.',
  'Docker must have verified runsc for the kernel tier. E2B’s no-grant smoke does not prove guarded egress. Docker Cloud Sandboxes also reads each run’s effective network policy back and refuses one that is not deny-all. WASM has no real-provider throwaway container or VM; this step summarizes its in-process checks.',
  'Behavioral checks + provider configuration\nNo runtime attestation\nProbe resources released', 'sandbox/factory.go', [[980, 532], [980, 330]]);
add('wasm-ready', 'provider', 'operator', 'observe', 'Check WASM configuration without a smoke guest',
  'The result of WASM’s Preflight configuration check.',
  'WASM implements Preflight but does not implement SmokeTest. EnsureReady calls only the readiness interfaces that this provider implements. No throwaway guest is started by this check.',
  'WasmSandbox.Preflight → configuration error or nil\nSmokeTester: not implemented\nGuest launched: no', 'sandbox/wasm.go', [[875, 414], [115, 414]]);
add('startup-profile', 'operator', 'profiles', 'authority', 'Load the server-held profiles',
  'The grants configuration containing route permissions and credential references.',
  'Profiles are loaded and frozen. The clients configuration establishes caller identities. Hardened mode additionally requires production isolation, multi-client auth, appropriate TLS, pinned execution inputs, and explicit budgets.',
  'PLIMSOLL_GRANTS_FILE → frozen registry\nPLIMSOLL_CLIENTS_FILE → authenticated principals\nPLIMSOLL_HARDENED=1 → enforced startup policy', 'cmd/plimsolld/main.go');
add('serve', 'provider', 'ingress', 'observe', 'Serve only after startup checks pass',
  'A ready provider wired into the RPC service and its HTTP listener.',
  'The server also checks its startup isolation floor and configured policy before listening. Startup evidence is useful, but each run still checks its own minimum tier.',
  'Provider ready → service wired → listener serves\nPer-run minimum_isolation still enforced', 'cmd/plimsolld/main.go', [[875, 205], [375, 205]]);
add('describe', 'caller', 'ingress', 'request', 'Ask what this instance supports',
  'An authenticated Describe RPC, with no code.',
  'Describe reports this instance’s current tier and structural operation support. It runs no guest and reserves no execution slot.',
  'DescribeRequest {}\nAuthorization: Bearer [caller credential]', 'internal/rpc/sandbox_service.go');
add('describe-handler', 'ingress', 'service', 'request', 'Read the provider’s reported capabilities',
  'The authenticated Describe request.',
  'The service consults the configured Sandbox interfaces. Project and grant support are structural capability claims, not proof of a completed project or routed guard request.',
  'Name / IsolationClass\nProjectCapable / GrantCapable\nMinimum-isolation protocol support', 'internal/rpc/sandbox_service.go');
add('describe-result', 'service', 'ingress', 'response', 'Return discovery, without executing',
  'Provider, current tier, and operation-specific support bits.',
  'An E2B grant support bit depends on configured guard support; it does not prove the guard is reachable. Describe never substitutes for the next run’s isolation check.',
  'sandbox: {{provider}}\nisolation: {{tier}}\nprotocol: 1\nsupports_project / supports_javascript_grants\nsupports_project_grants', 'internal/rpc/sandbox_service.go');
add('describe-caller', 'ingress', 'caller', 'response', 'Use discovery to prepare a request',
  'Capability information for the caller’s integration.',
  'Attach minimum_isolation to the actual Run request, which also states the protocol number this client speaks. A daemon on another number refuses before it reads the payload, rather than silently ignoring a field it does not know.',
  'Discovery complete\nGuest launched: no\nAdmission slot taken: no', 'client/client.go');
add('ready', 'operator', 'provider', 'observe', 'Poll /readyz without starting a guest',
  'An unauthenticated HTTP readiness probe, routed by the daemon to Preflight.',
  'Docker probes the pinned daemon/runtime and image configuration. E2B and Docker Cloud Sandboxes validate configuration only, not API reachability, key or token validity, or guard routing. /healthz only reports liveness; /metrics exports measurements.',
  'GET /readyz → bounded Preflight\nGET /healthz → liveness\nGET /metrics → bounded operational counters', 'cmd/plimsolld/main.go', [[115, 392], [875, 392]]);
add('ready-result', 'provider', 'operator', 'observe', 'Return the limited readiness claim',
  'HTTP 200 for a successful Preflight, or 503 for failure.',
  'No startup smoke test runs on this unauthenticated poll path. A green E2B or Docker Cloud Sandboxes readiness response cannot prove that creating or using a VM will work.',
  '/readyz: ready / not ready\nSmokeTest invoked: no\nGuest launched: no', 'cmd/plimsolld/main.go', [[875, 414], [115, 414]]);
add('cancel', 'caller', 'ingress', 'deny', 'The caller cancels an active request',
  'Cancellation of the request context after execution has started.',
  'A disconnect or canceled context is different from rejection before dispatch. Work and external API effects may already have occurred.',
  'request context canceled\nExecution already admitted\nDo not assume “nothing happened”', 'internal/rpc/sandbox_service.go');
add('cancel-handler', 'ingress', 'service', 'deny', 'Propagate cancellation into the run context',
  'The cancellation signal associated with the active request.',
  'The service’s run context also observes daemon shutdown. The provider uses this context to stop work and run its cleanup.',
  'request canceled or daemon shutting down\nrunCtx.Done() closes', 'internal/rpc/sandbox_service.go');
add('cancel-provider', 'service', 'provider', 'deny', 'Stop the active run and release its resources',
  'The canceled context reaches provider execution and cleanup.',
  'Containers, VM teardown, adapters, and temporary resources are provider-managed. E2B and Docker Cloud Sandboxes also periodically reconcile untracked orphan VMs left after failed cleanup, E2B by a metadata stamp and Docker Cloud by a name prefix. Cancellation does not roll back completed API writes.',
  'Stop guest work\nClose per-run broker / adapter resources\nRelease admission when handler returns\nAlready completed API writes remain', 'sandbox/e2b.go', [[625, 208], [875, 208]]);
add('cancel-result', 'provider', 'service', 'deny', 'Report cancellation or a bounded timeout outcome',
  'A context error, or the provider’s typed timeout result where applicable.',
  'Context cancellation maps to Canceled and deadline errors to DeadlineExceeded. Provider-enforced run timeouts can instead return a timed-out execution result. A disconnected caller may not receive a reply.',
  'Canceled / DeadlineExceeded\nor Result.TimedOut / ProjectOutcomeTimedOut\nNo proof of zero side effects', 'internal/rpc/sandbox_service.go', [[875, 227], [650, 227]]);
add('advice', 'service', 'operator', 'observe', 'Analyze the completed run’s API metadata',
  'Optional findings from delivered successful call groups, after execution finishes.',
  'Prospector detects per-item fan-out and repeated fixed-route reads. It sees route templates, statuses, bytes, and latencies, not guest code or response bodies. It cannot infer serial versus concurrent execution. No LLM is called.',
  'advice: off | operator | caller\nadvice_retention: none | aggregate | detailed\nRetention controls durable finding emission\nAudience controls caller hints and metrics', 'internal/rpc/advice.go', [[625, 188], [245, 188], [245, 330]]);
add('advice-wire', 'service', 'ingress', 'response', 'Only return advice the caller can act on',
  'An optional caller hint when advice=caller and a permitted alternative route is known.',
  'A catalogued but ungranted route is an operator action. If neither route is known, that is uncertainty, not proof the API needs changing. Findings never alter output, exit status, or isolation.',
  'Granted alternative → eligible caller advice\nCatalog only → operator action\nNeither known → operator investigation\nExecution result unchanged', 'internal/rpc/advice.go', [[625, 25], [375, 25]]);
add('embed', 'caller', 'provider', 'request', 'Call the Go Sandbox interface directly',
  'A plain Go Request, optionally carrying a HostAPIGrant.',
  'An embedder can call Build and EnsureReady, then use the provider without an RPC daemon. It owns authentication, admission, and any isolation-floor policy that the daemon would otherwise enforce.',
  'provider := sandbox.Build(getenv)\nprovider.EnsureReady(ctx)\nprovider.Sandbox.RunJavaScript(ctx, request)', 'sandbox/factory.go', [[115, 202], [745, 202], [745, 330]]);
add('embed-result', 'provider', 'caller', 'response', 'Return the Go result to the embedder',
  'Result or ProjectResult and any Go error.',
  'The sandbox package contains no Connect or HTTP transport types. Direct providers do not compute service-side advice. A nil grant still means no host-API capability.',
  'sandbox.Result, error\nNo RPC authentication or daemon limiter\nNo service-side advice', 'sandbox/sandbox.go', [[875, 412], [225, 412], [225, 135]]);

const entry = ['submit', 'authenticate', 'admit', 'dispatch'];
const grantEntry = ['submit-grant', 'authenticate', 'profile', 'grant', 'admit', 'dispatch'];
const setup = ['prepare-token', 'token-broker', 'open-adapter', 'launch-grant'];
const call = ['guest-call', 'adapter-call', 'upstream'];
const reply = ['api-reply', 'broker-reply', 'guest-reply'];
const end = ['finish', 'result', 'audit', 'wire-result', 'caller-result'];
export const categories = [
  {id: 'execute', name: 'Run & return', note: 'Start with a complete round trip.'},
  {id: 'api', name: 'Guest API calls', note: 'Follow authority, data, and replies.'},
  {id: 'refuse', name: 'Failures & refusals', note: 'See exactly where a path stops.'},
  {id: 'operate', name: 'Startup & observation', note: 'Explore paths outside a normal run.'}
];
export const paths = [
  {id:'run', category:'execute', title:'A run, out and back', intro:'Follow a snippet from its caller to the guest and all the way back. There is no API grant in this run.', question:'Where does my code go, and what comes back?', steps:[...entry, 'launch', ...end]},
  {id:'granted', category:'api', title:'A granted API call, round trip', intro:'Follow one host.get call. Watch the caller credential, API credential, call envelope, and response take different paths.', question:'How can isolated code reach my API without holding its credential?', steps:[...grantEntry, ...setup, ...call, ...reply, ...end]},
  {id:'project', category:'execute', title:'A project with API access', intro:'Stage files, execute ordered steps, broker an API call, then return per-step outcomes and artifacts. Select WASM to see where it stops.', question:'What changes when the request is a whole project?', steps:['submit-project', ...grantEntry.slice(1), ...setup.slice(0,-1), 'launch-project', ...call, ...reply, ...end], variants:{wasm:['submit-project','authenticate','profile','grant','admit','dispatch','unsupported','provider-error-wire','error-caller']}},
  {id:'embed', category:'execute', title:'Use plimsoll inside a Go program', intro:'The direct entry point calls the same provider interface. The embedding application owns the outer service policies.', question:'Does every execution have to travel over RPC?', steps:['embed','launch','finish','embed-result']},
  {id:'guest-failure', category:'execute', title:'The guest program fails', intro:'A non-zero exit is a result. Follow it back without mistaking it for a failed RPC.', question:'Can the RPC succeed while my code fails?', steps:[...entry,'launch','guest-fail','failed-result','wire-result','caller-result']},
  {id:'route-denied', category:'api', title:'The guest tries an ungranted route', intro:'This run has a read-only grant. The guest tries DELETE, and the broker refuses before the API is contacted.', question:'What if guest code bypasses the injected helper?', steps:[...grantEntry,...setup,'guest-call','bad-path','broker-denied','guest-error']},
  {id:'backpressure-503', category:'api', title:'The API is unavailable: 503', intro:'The guest catches an upstream failure and tries again. A configured health check can reopen this availability window.', question:'Which connection probes recovery, and which call is waiting?', steps:[...grantEntry,...setup,...call,'upstream-503','failure-reply','guest-error','guest-call','adapter-call','health-probe','health-ok','upstream',...reply,...end]},
  {id:'backpressure-429', category:'api', title:'The API limits this caller: 429', intro:'The guest catches a quota failure and retries during cooldown. The broker sheds the retry; it does not probe health.', question:'Why can a healthy API still require this caller to wait?', steps:[...grantEntry,...setup,...call,'upstream-429','failure-reply','guest-error','guest-call','adapter-call','shed','guest-error']},
  {id:'auth-denied', category:'refuse', title:'The caller is not authorized', intro:'The configured authentication layer refuses the request before it decodes a body.', question:'How early can plimsoll reject a request?', steps:['submit','bad-auth']},
  {id:'profile-denied', category:'refuse', title:'The caller cannot select this grant', intro:'A valid caller asks for a profile it is not permitted to use. Its code:run scope is not enough.', question:'Who decides which caller may reach which API?', steps:['submit-grant','authenticate','profile','profile-denied','error-wire','error-caller']},
  {id:'floor-denied', category:'refuse', title:'The isolation floor is not met', intro:'Assumption for this path: the requested floor exceeds current provider evidence. The handler refuses before admission.', question:'What prevents a weaker provider from silently running my code?', steps:['submit','authenticate','floor-denied','error-caller']},
  {id:'capacity-denied', category:'refuse', title:'The service is at capacity', intro:'The request is valid and meets its floor, but a configured concurrency or rate limit refuses admission.', question:'Does plimsoll queue work when the pool is full?', steps:['submit','authenticate','admit','capacity-denied','error-wire','error-caller']},
  {id:'disabled', category:'refuse', title:'Execution was never enabled', intro:'Assumption: the provider is unset and the request has no isolation floor. The safe default refuses execution.', question:'What happens when SANDBOX_PROVIDER is unset?', fixedProvider:'disabled', steps:['submit','authenticate','admit','dispatch','disabled','provider-error-wire','error-caller']},
  {id:'evidence-mismatch', category:'refuse', title:'The returned evidence is too weak', intro:'Assumption: a faulty backend returns insufficient evidence after execution. This is a client-side error with a different retry meaning.', question:'When does an error still mean code may have run?', steps:[...entry,'launch','finish','result','wire-result','mismatch']},
  {id:'startup', category:'operate', title:'Configure, check, and start', intro:'Follow startup controls, including the difference between selecting a provider and launching each guest. These are grouped checks, not a line-by-line startup schedule.', question:'What already happened before the first RPC arrives?', steps:['configure','smoke','smoke-result','startup-profile','serve']},
  {id:'describe', category:'operate', title:'Discover an instance with Describe', intro:'An authenticated discovery request reads capability information without running code or taking an execution slot.', question:'What can a caller learn without executing anything?', steps:['describe','describe-handler','describe-result','describe-caller']},
  {id:'readiness', category:'operate', title:'Probe readiness, liveness, and metrics', intro:'Monitoring endpoints bypass RPC authentication. Readiness uses bounded Preflight, not a new startup smoke test.', question:'What does a green readiness probe actually prove?', steps:['ready','ready-result']},
  {id:'cancel', category:'operate', title:'Cancel a run and clean up', intro:'Execution has started when the caller cancels. Follow the cancellation into the provider, without assuming completed API effects are undone.', question:'Who stops work, releases resources, and handles leaked VMs?', steps:[...entry,'launch','cancel','cancel-handler','cancel-provider','cancel-result']},
  {id:'advice', category:'operate', title:'Follow metadata into advice', intro:'This path assumes a completed run contained repeated successful API calls. Analysis runs afterward, and the profile chooses its audience and retention.', question:'What leaves the run as telemetry, and who sees the advice?', steps:[...grantEntry,...setup,...call,...reply,'finish','result','advice','advice-wire','caller-result']}
];

// Context belongs to its worked path. Shared steps must not invent identical
// payloads for a read, a denied write, a project, or a deliberately faulty reply.
const byID = id => paths.find(path => path.id === id);
byID('startup').variants = {wasm:['configure','wasm-ready','startup-profile','serve']};
byID('route-denied').overrides = {
  'submit-grant': {payload:'Run\nprotocol: 1\nminimum_isolation: {{tier}}\njavascript: { code: try DELETE /items/42 and catch any error, grant_profile: inventory-read }'},
  'launch-grant': {payload:'Guest tries a write under a read-only grant\nawait host.del("/items/42")\nNo downstream credential in guest code'},
  'guest-call': {moves:'The guest asks to delete an item, using a grant that permits only GET.', payload:'{ method: "DELETE", path: "/items/42", body: null }\n{{channelShort}}', why:'The adapter carries the requested operation. It does not turn that request into permission. {{channel}}'}
};
byID('floor-denied').overrides = {
  submit:{payload:'Run\nprotocol: 1\nminimum_isolation: [required tier]\nAssumption: current evidence is weaker or unknown\nAuthorization: Bearer [caller credential]'}
};
byID('disabled').overrides = {
  submit:{payload:'Run\nprotocol: 1\nminimum_isolation: omitted\njavascript: { code: console.log("hello") }\nSANDBOX_PROVIDER: unset'},
  admit:{title:'No floor is requested; reserve admission',moves:'A valid request without a minimum isolation requirement.',why:'This worked request omits its floor so it reaches the disabled provider’s own refusal. A required tier would be refused earlier by the handler.',payload:'minimum_isolation: omitted\nAcquire("client-a") → admitted'}
};
byID('evidence-mismatch').overrides = {
  result:{title:'A faulty backend returns inconsistent evidence',moves:'An execution result whose evidence is weaker or unknown, contrary to the requested floor.',why:'This is a deliberately faulty-backend scenario, not expected behavior of a correctly configured daemon. The official Go client independently checks the response because execution may already have occurred.',payload:'Requested: {{tier}}\nReturned: [weaker or unknown tier]\nExecution may already have happened'},
  'wire-result':{payload:'Result encoded by a faulty backend\nisolation: [weaker or unknown tier]\nNot the requested {{tier}} evidence'}
};
byID('advice').overrides = {
  'submit-grant':{payload:'Run\nprotocol: 1\njavascript: { code: repeated host.get calls in a loop, grant_profile: inventory-read }\nProfile advice configured by operator'},
  'guest-call':{title:'Broker calls repeat during the run',moves:'A series of successful API calls, collapsed here to one representative round trip.',why:'This path assumes repeated successful calls sufficient to produce a finding. The map shows one representative call; analysis only happens after all calls and execution finish.',payload:'for each item: host.get("/items/…")\nRepeated calls, collapsed in this walkthrough\nMetadata retains /items/*, never the concrete IDs'},
  advice:{payload:'Assumed: repeated delivered 2xx calls\nGranted alternative: GET /items, if it returns the same items\nadvice: caller\nadvice_retention: detailed\nThese illustrative settings are opt-in'}
};
byID('guest-failure').overrides = {
  submit:{payload:'Run\nprotocol: 1\nminimum_isolation: {{tier}}\njavascript: { code: throw new Error("example guest failure") }'},
  launch:{payload:'engine: {{engine}}\nthrow new Error("example guest failure")\nHost API grant: none'}
};

export {steps};

export function pathSteps(path, provider) {
  return (path.variants?.[provider] || path.steps).map(id => ({...steps[id],...path.overrides?.[id]}));
}

export function connections(nodeID) {
  const found = new Map();
  for (const path of paths) {
    for (const [variant, ids] of [['default', path.steps], ...Object.entries(path.variants || {})]) {
      ids.forEach((id, index) => {
        const step = {...steps[id],...path.overrides?.[id]};
        if ((step.from === nodeID || step.to === nodeID) && !found.has(id)) {
          found.set(id, {step, path, index, variant});
        }
      });
    }
  }
  return [...found.values()];
}
