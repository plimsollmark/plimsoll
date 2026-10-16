# One owner's remote MCP server

`plimsoll-mcp serve-http` adds authenticated Streamable HTTP to the same five tools
as the default stdio command. An authorization grant owns its sandbox handles and
record lookups. Chats using that grant share its files and interpreter state.
Separate grants cannot use one another's handles or records. Sandbox admission,
receipts quota and the 256-record cache remain shared across the whole process.
The grants of one approved app (its OAuth client, however many times it was approved)
hold at most one sandbox fewer than `PLIMSOLL_MAX_SANDBOXES` between them (two of the
default three), so one app alone never fills the server against another, which can
neither see nor close its sandboxes; nothing is ever closed for room. A cap of one is
refused, since it would keep nothing back. With three apps, two can still fill a cap
of three between them; the promise is about one app alone.

This is single-owner hosting, not an account system for multiple customers. A
passkey verifies the owner, followed by an explicit approval of each connection.
An allowed vendor callback does not prove which vendor account started the flow.
Approve only a connection you just initiated. Permission continues after approval;
a model does not need another passkey check for each program it runs.

## Requirements and configuration

HTTP hosting requires a supported Unix host (Linux, macOS or BSD), a fixed HTTPS
origin, a separate trusted TLS reverse proxy forwarding only to the dedicated MCP
loopback listener, an authenticated daemon with verified kernel or VM isolation,
and signed local receipts. Remote HTTP on Windows is not supported: its local
file permissions and writer locking have not been implemented. Stdio remains
available on Windows. Direct native-client OAuth callbacks are not supported;
native clients can keep using stdio.

| Variable | Setting and reason |
| --- | --- |
| `PLIMSOLL_MCP_LISTEN` | Default `127.0.0.1:8750`; a literal loopback address and nonzero port. This prevents direct internet binding. |
| `PLIMSOLL_MCP_PUBLIC_URL` | Required fixed HTTPS origin, for example `https://mcp.example.com`. No path, query or credentials. A port other than 443 is given as written in the browser's address bar (`https://mcp.example.com:8443`); `:443` is refused, because browsers omit the default port from Host and Origin, so it could never match. `/mcp` is appended for the resource. |
| `PLIMSOLL_MCP_STATE_DIR` | Required absolute directory, owner-owned mode 0700, with safe ancestors. State and control files are owner-only; symlinks and multiple writers are refused. |
| `PLIMSOLL_MCP_VISITOR_HEADER` | Unset by default. The header the local reverse proxy sets to the address each request came from, for example `X-Forwarded-For` behind a proxy that overwrites it with the address it received the request from. Per-visitor limits key on its last entry; set it only for a proxy that sets or appends that header on every request, or a visitor's own value becomes their address. Unset, every visitor shares the anonymous places (see Limits). |
| `PLIMSOLL_MCP_EXECUTION` | Default `disabled`; set exactly `enabled` only after public authorization and the network stop have been checked. Disabled execution refuses every authenticated MCP operation, while authorization and enrollment can be exercised. |
| Existing daemon variables | `PLIMSOLL_URL`, a dedicated `PLIMSOLL_TOKEN` with `code:run`, minimum isolation `kernel` or `vm`, `PLIMSOLL_SIGNING_KEY_FILE` and `PLIMSOLL_RECEIPTS_DIR` are required. The insecure transport override is refused. Other tool limits follow [INTERNAL · main configuration →](README.md#configuration). |

The origin is a durable part of the authorization state and passkey identity.
Changing it is refused. Enroll at the final origin, not at localhost first.
Passkey secrets stay in the authenticator. The state file holds public credentials,
verification counters and hashes of OAuth credentials, never raw bearer tokens.
Keep the directory private and backed up with suitable filesystem protection.
Restoring an old state backup can restore old authority; disable and require new
connections after any restore. State written after a failed filesystem sync is
uncertain: the running process refuses further authorization until restarted.

Startup authenticates a checked `Describe` request, checks the isolation floor,
and separately requires an unauthenticated request to be refused. It cannot prove
that a daemon token is dedicated; the operator must provision that caller with
only the intended scope. Keep the daemon, metrics and administrative services out
of the public proxy route.

## Enrollment and operation

Configure the proxy separately for the final HTTPS origin. This binary never
starts a public tunnel or changes another service's mapping. First run
`plimsoll-mcp enroll-http` with the three HTTP variables. It serves enrollment
only, prints one short-lived code to the local operator's console, and exposes no
OAuth or MCP tools. Open the printed enrollment URL, enter that code and approve
passkey creation on the device. A canceled attempt consumes the code: issue a fresh
one with `plimsoll-mcp enroll`. Enroll a second passkey as recovery before relying
on the connection. The local code command is deliberately not an HTTP route.

Stop enrollment-only serving, start `plimsoll-mcp serve-http` with the daemon and
receipt variables, then run `plimsoll-mcp enable`. This enables authorization; code execution still
requires the startup execution opt-in. Initial authorization state is disabled and
stays disabled across restarts until this local action. Add the HTTPS origin plus
`/mcp` to the hosted application's connector settings. Sign in with a passkey,
review the client identity, callback and permissions, then click **Approve this
connection**. Until the execution setting is enabled, authenticated MCP requests
receive HTTP 503; unauthenticated requests still receive the OAuth challenge. The code is bound to that browser transaction, client, exact callback,
resource, scope and S256 PKCE verifier (the client's proof of starting the request).

Operator commands need only `PLIMSOLL_MCP_STATE_DIR`; they use a mode-0600 Unix
socket inside the private directory when serving, or the exclusive state lock
offline. Their JSON output is local operator data, not an application log.

| Command | Effect |
| --- | --- |
| `status` | Reports disabled state, enrolled passkey count and active grant count. |
| `enroll` | Authorizes one enrollment attempt for five minutes, limiting abandoned setup windows. The raw local code is returned once. |
| `disable` | Persists disable and revokes all current grants before canceling work and closing sandboxes. `cleanup_complete: false` means authority is revoked but deletion was not confirmed within the wait; background cleanup continues. |
| `enable` | Requires a running normal server and an enrolled owner. Permits new authorizations; old grants stay revoked. It cannot override the startup execution setting. |
| `reset-owner` | Disables, revokes, clears public passkeys and registrations, and changes the owner identifier. Requires new enrollment; it never bypasses device verification for a connector. |

Network removal is a separate action against the reverse proxy's actual mapping.
A process crash or forced kill can prevent cleanup, so the daemon's independent
sandbox lifetime remains the backstop. A graceful stop waits five seconds for
cleanup, reporting uncertainty rather than claiming a sandbox was deleted.

## Hosted clients and discovery

Only these exact hosted callback URLs are accepted:

- `https://claude.ai/api/mcp/auth_callback`
- `https://chatgpt.com/connector_platform_oauth_redirect`

Discovery advertises issuer identification and authorization responses include
`iss`, supporting ChatGPT's stable callback. Client registration accepts public
clients only, with those exact callbacks. Extension metadata is ignored and is
never fetched or trusted. Registrations are reused for an identical approved callback set; changing the
untrusted display name cannot allocate another row. There are only three possible
callback sets under the current allowlist. The durable registry also has a ceiling
of 32 entries for future policy changes; it never evicts an existing entry. Client
IDs are public identities shared by those callback sets, while every approved
connection receives its own grant and workspace.

Discovery currently defaults to dynamic client registration. Claude selects
client-metadata discovery when advertised, but its exact hosted metadata URL has
not been confirmed in a live connection, so that mode is not advertised. The
verified ChatGPT metadata URL, `https://chatgpt.com/oauth/client.json`, can identify
a client directly. Only that exact URL is fetched: no redirects, proxy environment,
internal IP addresses, logos or keys supplied by a client. Fetches have a five-second
limit and 32 KiB response limit, with two slots and a one-hour cache. These limits
bound slow discovery and storage while allowing normal small metadata documents.
Actual hosted connections still require a live verification at deployment; local
tests do not prove vendor interoperability.

Sources checked 15 October 2026:
[EXTERNAL · Claude authentication documentation ↗](https://claude.com/docs/connectors/building/authentication),
[EXTERNAL · OpenAI authentication documentation ↗](https://developers.openai.com/plugins/build/auth),
[EXTERNAL · MCP authorization specification ↗](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

## Limits, revocation and evidence

**The loopback port is not authenticated.** The server listens on a loopback TCP port
(`PLIMSOLL_MCP_LISTEN`), the kind of backend a local reverse proxy forwards to, and nothing
proves to the proxy which local process holds that port. While the server is stopped,
another user of the same machine can bind the port, and a proxy that still forwards public
traffic to it hands that process what connected apps send: their access credentials on
`/mcp`, and refresh credentials on `/oauth/token`, which it could keep and use once the real
server is back. So run the server on a machine no other user can log in to, or keep the public
route on only while the server runs: start the tunnel after the server reports it is listening,
and stop it before the server stops (one service unit owning both does this). A batch of
JSON-RPC messages in one request is refused (400): each request is admitted and rate limited
as one call.

Access credentials last 15 minutes to limit theft. A refresh family lasts at most
30 days, with seven days since its latest refresh as the idle limit, to bound old
and abandoned grants. A refresh rotates its credential atomically and remembers
all consumed hashes for that family, up to 4,096 entries: a family refreshing once
per 15-minute access lifetime uses 2,880 in its 30 days, and one that uses them all
is revoked and must reconnect. Reusing any consumed credential revokes the entire
family, including its current access credentials, with one exception: a client that
lost a refresh's answer may retry with the same credential for 30 seconds (the
default Okta documents for the same window). The retry, like a second refresh racing
the first with the same credential, gets the same answer, which is held in memory
for that window and never written to disk. After a restart the retry rotates again
and retires the credential whose answer was lost, so presenting that one later is
reuse. The window costs some theft detection: inside it, whoever presents the
credential the last rotation consumed gets the client's current answer, so a thief
holding that credential and retrying within 30 seconds of each rotation goes
unnoticed, while a retry outside a window revokes the family. Binding refresh
credentials to a key the client holds would close this, for clients that support it.
A refresh
may omit its scope, or name the granted scope or a subset of it in any order
(RFC 6749 section 6). A fault on the server's side (storage, audit) answers 503,
never `invalid_grant`, so a client keeps a refresh credential that is still valid.
Authorization codes last one minute; approval transactions and local enrollment
codes last five minutes, limiting the time a copied or abandoned request is usable.

State allows 16 grants, 64 authorization codes, 4,096 access credentials and eight
passkeys. These are ceilings for a personal server, not per-token quotas. A grant
without a refresh credential is pruned once its access credential expires. When all
16 grants are taken, a new owner approval retires the least recently refreshed grant
holding no live access credential and closes its sandboxes, once that change is
written. This is retirement for capacity, not proof the client left: a client used
now and then holds no live access credential yet keeps a valid refresh credential.
The server retains at most 256 workspace contexts, including revocation tombstones;
a tombstone revoked at least a minute ago whose cleanup has finished is forgotten
when room is needed. A request's authorization names the workspace it was issued
for, so a request that authenticated before a revocation is never admitted into a
later workspace registered under the same ID. Active credentials
expire at the state check; sandbox cleanup checks expiry every 30 seconds to limit
idle resource retention without continuous filesystem work. Inactive grant rows
are pruned on the next durable transition.

There are 128 network connections; 16 admitted tool calls, of which one approved app
holds at most eight however many grants it has; for the unauthenticated routes 32
anonymous places (below) and eight processing slots, taken once a request's bounded
body has arrived; and a shared 64 MiB body budget, which a tool body takes as it
arrives and holds for its call, of which one approved app holds at most half, so its
requests cannot refuse another app's. A tool body is at most 32 MiB, allowing the existing
5 MiB decoded input limit even with worst-case JSON escaping. Owner JSON and approval
forms are at most 64 KiB (an approval form carries its sealed approval); token,
revocation and registration forms are at most 8 KiB.

No unauthenticated route draws on a shared rate budget that an anonymous client
could empty, because any such budget would let one client cut off the owner's
token refresh. Metadata, CORS preflights and 401 challenges are static. A token
request is metered against the grant its credential names (a burst of four, then one
per 10 seconds, against one rotation per 15 minutes) only after a read-only lookup
finds that grant, and a request naming no grant writes nothing. An approval stores
nothing until a passkey verifies. Failed anonymous attempts are audited up to a
burst of 30 and one per two seconds; the rest are counted onto the next audited
refusal, so a flood cannot rotate earlier audit history away. Authenticated traffic
shares a burst of 64 and two per second, with a burst of 16 and one per second per
grant.

Requests to the OAuth and owner routes, the only ones whose bodies are read before
a credential is checked, each hold an anonymous place from the moment their headers
arrive until they are answered, so through a slow body too, in one of three lanes:
token requests, a connected app renewing its access (8 places); the owner's approval
page and passkey steps (16); registration and revocation (8). A flood of one kind
therefore cannot take the places another needs. Past its lane's places a request is
refused at once (429, `Retry-After: 1`). With `PLIMSOLL_MCP_VISITOR_HEADER` set, one
visitor holds at most two places of the token lane, four of the owner lane and two of
the last: its address is the last in that header, an IPv6 address counted by its /64,
the block one home connection gets. `/mcp` reads no body before its access token checks out, so it
takes no place: an anonymous request there gets its 401 at once, and signed-in calls
are bounded by the tool-call slots and grant meters above. A response sent before
its request body was read closes the connection, so a held-back body cannot keep
it. The listener holds 128 connections, four times the anonymous places.

What this leaves: without the visitor header, this process sees only the proxy's
address, so one visitor can fill a lane and delay token refreshes or sign-ins (never
calls with a live token) for as long as it keeps sending; set the header when serving
publicly. With it, many visitors at once can still do the same,
and a sustained flood of refused requests costs each one a connection for up to half
a second. Volume from many addresses needs a front door with request limits; some
tunnels offer only a bandwidth cap.

Host and Origin checks use fixed configuration, never forwarded headers. Owner
POSTs additionally require the exact public Origin, a Secure/HttpOnly host-only
cookie named for that approval (two approvals in one browser keep separate
bindings) and the approval's anti-forgery value. An approval is sealed into its page
with a key held only in this process's memory and is stored nowhere, so a restart or
a disable ends every open approval. A passkey challenge is sealed into its options
answer and consumed once it verifies. A failed attempt may be retried until the
approval's five minutes end: recording failures would let anonymous requests fill
memory, and retrying cannot forge an assertion. One approval yields at most one
code: once approved, its page cannot verify again, and once the passkey has verified
it, approving and denying exclude each other, so a denial is final. Concurrent logins never move a
passkey's stored signature counter back. Enrolling another passkey excludes
the enrolled ones, so an authenticator that already holds one refuses instead of
replacing it. Unknown routes, encoded path variants,
method overrides and daemon/admin paths cannot reach the tools.

`audit.jsonl` and one preceding file are each capped at 1 MiB, keeping two bounded
local files for recent metadata. They contain event categories, internal grant
identifiers and checked record digests, never request URLs, credentials, source or
output. An audit write failure blocks new execution. There is no HTTP access log
in this process; configure the reverse proxy to omit credentials, queries and bodies.
Signed receipts remain the evidence of checked exchanges, subject to their separate
quota. They are not hardware attestation or proof that printed output is true.

## Local verification

From the repository root, `make mcp-suite` vets, lints, race-tests the complete
module and runs the vulnerability scanner. Tests use signed virtual passkey
responses, a real RPC handler over a fake sandbox provider, and real HTTPS/MCP
transports. They do not contact hosted clients, start a public proxy, use a paid
provider, or spend AI credits. `make audit` checks the root module and export guards.
