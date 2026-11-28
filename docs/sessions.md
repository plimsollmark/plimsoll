# Sessions

A <dfn>*session*</dfn> keeps one sandbox open for many calls. The files a call writes
are there for the next call; the processes a call leaves behind are killed by a cleanup
that runs after its answer goes back, and the next call starts only once that cleanup has
finished. The exception is the interpreter a session can keep for code it runs as notebook-style
[cells (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#cell)
([below](#interpreters-state-between-calls)). An agent that edits,
builds and tests in a loop pays for one sandbox instead of one per step, and its later
steps see what its earlier steps wrote. Each call gets everything a single run gets:

- a typed result, with fixed fields rather than text to parse;
- its <dfn>*floor*</dfn>, the weakest sandbox strength the request accepts, checked
  before <dfn>*dispatch*</dfn>, the moment the code is handed over to start running;
- bounded output;
- one line in the daemon's audit log;
- a <dfn>*run record*</dfn>, the daemon's statement of what was sent, what came back and
  where it ran ([run-records.md](run-records.md)), here chained to the record of the call
  before it.

A working example with a signed chain of records:
[One sandbox, five calls ↗](https://plimsollmark.github.io/plimsoll/examples/sessions/index.html),
written by `go run ./examples/sessions`.

## Who may share a session

A session is one trust domain. Everything a call does is there for every later call of
the session: the files it wrote, the functions it redefined, the data it loaded into the
interpreter, a timer it left running. Use a session only where every call in it may see
and change what every earlier call did, because they all act for the same person or job.

- **plimsoll ties a session to the authenticated caller, not to that caller's own
  customers.** Only the credential that opened a session can call it, close it or take it
  over from another process ([below](#carrying-a-session-on-from-another-worker)), and an
  unknown session ID and another caller's get the same refusal. If your service sends many
  customers' code through one plimsoll credential, plimsoll cannot tell those customers
  apart: keeping each customer in a session of their own is your service's job.
- **The credential is the only gate on a takeover.** A session's run records name the
  session and its latest call, so anyone who holds the caller's credential and has a
  session's records can take the session over. An application that
  shares one credential among its users, and shows them run records, must keep the takeover
  behind its own authorization, keyed by identities it verified. Open development mode (no
  callers file, no token) refuses every takeover.
- **Key sessions by identities you verified, never by a string your users or a model
  choose.** Derive the key from the customer and the conversation (or job) your own
  authentication established. A key built from user or model input lets one user's call
  land in another user's sandbox, with that user's files and variables. The TypeScript
  client's `CodeSandboxes` takes the key it is given; its Mastra add-on runs a call that
  has no `resourceId` (Mastra's user) in a fresh sandbox rather than in one shared by every
  user without one.
- **The strongest setup is one plimsoll credential per customer** ([callers.md](callers.md)),
  with `SANDBOX_MAX_SESSIONS_PER_CALLER` bounding each, and one session per conversation or
  job inside it. An app that serves many users on one credential names each session's user
  (`owner`) and sets `SANDBOX_MAX_SESSIONS_PER_OWNER`, so one user cannot take every place
  of the credential.
- **A sandbox that has run code is never used for anyone else.** Closing a session, or its
  end, deletes its sandbox. plimsoll keeps no pool that hands a used sandbox to another
  session, and the cleanup between calls is not a way to make a used sandbox clean.
- **Do not use a session** for code from different customers or users, for code you grade
  whose result must not depend on earlier code (run each check fresh), or before a call
  whose API access the earlier calls must not share ([below](#what-a-session-gives-up)).

## What a session gives up

A session trades the fresh sandbox of every run for speed and kept state. The wall around
the code does not change: the same isolation, no network, and the same memory, CPU and
process limits, all enforced from outside the sandbox. Disk differs on `openshell`: a run's
`/tmp` is capped by `SANDBOX_DISK_MB`, but a session's files are measured against
`SANDBOX_SESSION_DISK_MB` only after each call, so one call can write past that budget
before the session is ended for it ([openshell.md](openshell.md#sessions)). On docker every
writable directory of a session has the same size cap as a run's. What changes is how
separate one call is from the next.

- **Earlier calls shape later ones.** Code a call runs can change the interpreter (replace
  a function, patch a library), leave a timer running, or rewrite files, and every later
  call of the session runs with those changes. A call's result is only as trustworthy as
  every call before it in the session. If one call ran code you do not trust, such as code
  an agent wrote after reading an untrusted web page, treat the rest of the session the same
  way, or open a new one. A run record proves what was sent and what came back, not that
  the interpreter was untouched.
- **API access is shared with what is already running.** A <dfn>*grant*</dfn>, the
  permission that lets a call reach chosen routes of an HTTP API without the credential
  entering the sandbox, can be used while its call runs by anything an earlier call of the
  session left running. So a session refuses a call with a grant, before anything runs,
  unless the grant allows sessions: `allow_in_sessions` on its profile
  ([capability-grants.md](capability-grants.md)), `HostAPIGrant.AllowInSessions` in Go.
  The refusal is `PermissionDenied`, marked not dispatched with reason `permission`
  (`sandbox.ErrGrantNotForSessions`). Turn it on only for an API whose access may be shared
  with every call of the session. The grant ends with its call; a request plimsoll had
  already checked when the call ended can still reach the API, and it is in that call's
  trace. A `route_max_calls` cap counts every granted call of the session together, so a
  cap of two jobs is two jobs per session; the `max_calls` budget is each call's own.
- **A longer foothold.** Code has the session's lifetime (30 minutes by default, 12 hours
  at most) to probe the sandbox, instead of one run's timeout, so for code you do not trust
  choose the strongest sandbox you can run.
- **The cleanup between calls is housekeeping.** It runs inside the sandbox, where the
  session's own code can interfere with it, and the interpreters it keeps run between calls
  by design. It keeps a session tidy; it is not part of the isolation.

## Which providers

A <dfn>*provider*</dfn>, the backend that actually runs the code, offers sessions
through the optional `sandbox.SessionProvider` interface. It states that it has them only
once it passes the shared test suite in [sandbox/sessiontest](../sandbox/sessiontest/),
which every implementation runs. The suite checks that:

- files persist across calls, including between a snippet call and a project call, and
  every call runs in the same work directory, so a snippet finds a project's files by
  their relative paths;
- sessions share nothing;
- no process a call leaves behind reaches the next call: not a detached child, not a
  `setsid` grandchild, not a background child (the cleanup kills them after the answer,
  before the next call starts);
- a call's deadline ends the call and not the session;
- a call whose output a leftover process holds open still returns (whether at its
  deadline or earlier is the provider's choice, and is logged rather than checked), and
  the process holding the output dies;
- a suspend keeps the files;
- a floor above the session's <dfn>*isolation tier*</dfn> (how strong its sandbox's walls
  are: `process`, `container`, `kernel` or `vm`) is refused before dispatch;
- close and the lifetime end the session.

| Provider | Sessions |
|---|---|
| `openshell` | Yes. How it keeps the boundary between calls: [docs/openshell.md](openshell.md#sessions). |
| `docker` | Yes, with a project image configured, under either runtime: <dfn>*runc*</dfn>, docker's default, which shares the machine's kernel, or <dfn>*gVisor*</dfn>, which puts a kernel of its own between the code and the machine's. How: [Docker](#docker) below. |
| `e2b` | Yes. <dfn>*E2B*</dfn> is a hosted service that runs each sandbox in a small virtual machine of its own. How it keeps the boundary between calls: [E2B](#e2b) below. |
| `dockercloud` | Not yet. Docker Cloud sessions are held back until the open's check can read every listener inside Docker's machine. |
| `wasm` | No. The engine runs in the daemon's own process, and keeping hostile code's state there between calls is the wrong direction. |
| `wslc` | No. The WSL containers provider runs each snippet or project in a fresh container, in its per-run mode inside a fresh virtual machine as well, and keeps none open between calls ([wslc.md](wslc.md#what-it-does-not-do)). |

**File calls** (one operation on a session's files, such as a read, a write or a
listing, carried out inside the sandbox by plimsoll's native helper) are stated per scope:
`docker` and `e2b` sessions take them in both scopes (on a docker host before Linux 5.8, the
sandbox scope alone), `openshell` sessions in the sandbox scope alone. What they are, what each provider states and why: [Files](#files) below.

## Turning them on

Sessions are off unless the operator enables them, because a session holds a sandbox
between calls. The daemon refuses to start when they are enabled for a provider that
does not support them, and when one real session, opened at startup, does not keep what a
session promises: a process its first call leaves running is gone by the next call (the
sweep killed it), a file survives calls and a suspend, a cell's interpreter keeps what an
earlier cell defined or says it is new, a call whose code fails comes back as a result with
its exit code rather than an error, and closing ends the session. The provider's own
startup check proves its runs; this one proves what only a session does, on this host.

| Setting | Meaning |
|---|---|
| `SANDBOX_MAX_SESSIONS` | Open sessions at once, daemon-wide. Default 0: sessions off. |
| `SANDBOX_MAX_SESSIONS_PER_CALLER` | Open sessions one caller may hold, suspended ones included. Default 0: no cap beyond `SANDBOX_MAX_SESSIONS`. `PLIMSOLL_HARDENED=1` requires it with sessions on: a suspended session holds no concurrency slot, so without it one caller with a short idle timeout could hold every place. With docker, keep `SANDBOX_MAX_SESSIONS` below `SANDBOX_MAX_CONCURRENT` (the daemon warns otherwise): a paused docker session keeps its slot. |
| `SANDBOX_MAX_SESSIONS_PER_OWNER` | Open sessions one owner of one caller may hold: the end user an open names (`OpenSessionRequest.owner`, an opaque `[A-Za-z0-9._:-]{1,64}` name; anything else is refused, since dropping it would lift the cap). Default 0: no per-owner cap; an open with no owner counts against none. At the cap, the open closes that owner's least recently used session with no call in progress (a suspended one included) and takes its place, so a full daemon still serves it (the closed session stays closed if the new open then fails); the closed session's later calls are refused, not dispatched, with the end `replaced`. When every one is running a call, the open is refused, not dispatched, reason `capacity`. The official clients send hex(HMAC-SHA256(key = SHA-256(`"plimsoll session owner key v2\n"` + the caller's token), message = `"plimsoll session owner v2\n"` + owner)), never the name, and the daemon never logs it. The key is derived rather than the token itself because HMAC replaces a key longer than 64 bytes with its SHA-256, which for a long imported token is exactly the `token_sha256` the daemon's clients file holds; derived, it is 32 bytes and keyed by the token alone. Closing rather than refusing: a refused user would be locked out of new conversations until an old session expired. Counted per daemon, in memory: behind [placement](placement.md) across several daemons, one owner can hold that many on each. The open's rate and concurrency slot are checked before anything is closed, so a refused open closes nothing, and a victim whose close fails stays open and the open is refused. `Describe` states the cap as `max_sessions_per_owner` (with `max_sessions_per_caller`), so an app relying on it can check. |
| `SANDBOX_SESSION_POOL` | `docker` and `openshell`: sandboxes kept ready for sessions, each never used and with its interpreters already running ([Docker](#docker), "A warm pool"; [openshell.md](openshell.md#sessions) for what differs there), and for a `Run` cell that asks for one ("A cell for one call"). Default 0: none. At most `SANDBOX_MAX_SESSIONS`; startup fails when it is set for another provider. |
| `SANDBOX_SESSION_LIFETIME` | Absolute lifetime from open. Default `30m`, at most `12h`. A request may ask for less. |
| `SANDBOX_SESSION_IDLE` | A session with no call for this long is suspended: its sandbox is stopped (`openshell`) or paused (`docker`, `e2b`). Default `5m`; `0` never suspends, which the daemon refuses with a provider billed by the second (`e2b`), since such a session would bill until its lifetime. A request may ask for less, but not under 1 s. A session no request has named by its first idle timeout is closed instead, with the end `unclaimed` ([what the daemon guarantees](#what-the-daemon-guarantees)). |
| `SANDBOX_SESSION_DISK_MB` | A call that leaves more than this in the session's files ends the session. Default 1024; 0 means no bound, and nothing is measured. It is measured after each call, not enforced during one ([openshell.md](openshell.md#sessions) says why the `openshell` provider's per-run disk cap does not apply to sessions). On docker it is the used space of the session's three size-capped in-memory filesystems, a file deleted while a process holds it open included. On `openshell` it is a walk of the session's files, which stops at 200,000 entries (counted as over the budget) and which code of the session can hide files from (a deleted file still held open, a directory swapped for a link during the walk), so there it is an estimate, not a bound. |

The defaults are starting points, not measurements of real use:

- 30 minutes bounds how long a session's sandbox lives after its daemon crashes: a
  running daemon's cleanup of leftover sandboxes deletes it once the lifetime plus a
  5-minute margin has passed.
- 5 minutes is long enough for a slow model's turn between <dfn>*tool*</dfn> calls (a tool is one named action the
  model can call, such as run_code), and short enough
  that an abandoned session gives back its slot soon.
- 1 GiB leaves room for a `node_modules` tree and a build's output.

`Describe`, the procedure that reports what a daemon offers, states `supports_sessions`,
the lifetime and the idle timeout.

## The API

Four procedures beside `Run`, which also runs a cell by itself (below, "A cell for one
call"):

- `OpenSession` returns a session ID (128 random bits), the session's
  <dfn>*fingerprint*</dfn> (the SHA-256 hash of the ID), the tier measured at open, and
  when the session expires. The request's floor is checked twice: against the tier the
  provider states, before anything is made, and against the tier the opened session
  measured, before the open answers. An opened session below the floor is closed and the
  open refused, `FailedPrecondition`, marked not dispatched, reason `isolation`: an open
  carries none of the caller's code, so nothing of the caller's has run in it. The request may name the languages the session's cells will
  use (`languages`), as a hint: a daemon with a warm pool then hands over a
  sandbox with those interpreters already running ([Docker](#docker), "A warm pool"). A
  hint changes how fast the first cell answers, never what runs: a cell in any language
  the daemon states still runs, a language the session's image does not run is dropped
  from the hint, and only a name plimsoll does not know (a typo) is refused, marked not
  dispatched. An open may also be `warm_only`: it is handed a waiting pool sandbox or
  nothing. With none it may hand over (no pool, none waiting, or none that may live as
  long as the session asks), it is refused, marked not dispatched, reason `capacity`,
  and no sandbox is made, so a caller that would rather run fresh than wait for a
  session's sandbox to be made can do so; every provider without a pool, the ones
  billed by the second included, refuses it the same way, and it never closes another
  session of the owner to make room. `Describe` states the pool's size
  (`session_pool`, 0 when there is none), so a client knows when a warm-only open can
  succeed. A daemon that predates `warm_only` would ignore it and make a sandbox (on
  `e2b` one billed by the second), so the field came with protocol 5,
  which such a daemon refuses before it reads the open: no client has to ask `Describe`
  first. A session that finishes opening after its caller gave up
  is closed at once, since nobody holds its ID. An answer already on its way when the
  caller gives up is still lost, and that session holds its place until it expires; the
  per-caller session cap bounds how many such places one caller can leave behind.
- `SessionRun` is a `Run` request with the session ID: a snippet, a project, or a
  cell, code for the session's interpreter (below). A
  <dfn>*module run*</dfn>, which runs a compiled simulator once per row of a parameter
  table, has no session form; a cell runs by itself through `Run` too (below). `SessionRun` answers a `RunResponse` and, when the session
  ended during the call, why. A session that the cleanup after a call ends is reported to
  the next call.
- `CloseSession` ends the session, or collects one that ended by itself. It states how
  many calls ran and the <dfn>*digest*</dfn> (the SHA-256 hash) of the last call's record.
  Closing a session again in any of the official clients, once the daemon has answered a
  close with that count, returns the first close's answer and sends nothing, while a close
  that got no count back (lost on the way, timed out, or refused) is sent again.
- `AttachSession` lets another process take an open session over
  ([below](#carrying-a-session-on-from-another-worker)). It runs no code.

Every `CloseSession` carries the session's <dfn>*ownership generation*</dfn>, a number
that starts at 1 when the session opens and goes up by one each time a process takes the
session over. Every `SessionRun` carries the <dfn>*session head*</dfn> as the client last
saw it: the generation, the number of calls the session has answered or ended, and the
digest of the last call's record. A request with an older generation is refused before
anything runs (`FailedPrecondition`, marked not dispatched, reason `permission`); one with no
head, a zero generation or a malformed head is refused as malformed (`InvalidArgument`,
marked). A call whose count or digest is not the session's is refused under the session's
turn, before anything runs (`FailedPrecondition`, marked, reason `request`), with the
daemon's head attached as a `SessionHeadMismatch` detail; nothing moves. The official
clients track the head exactly, so they take that refusal to mean another writer or a bug,
and stop the session. Because a daemon that predates the head would ignore it and run a
call this one refuses, the head came with protocol 8.

Each request carries the <dfn>*protocol number*</dfn>, the protocol version the client
speaks, and gets the same check as `Run`: a daemon serving a different version refuses it
before reading the payload. A daemon that knows sessions but has none to offer
(its provider keeps none, or `SANDBOX_MAX_SESSIONS` is unset) answers `OpenSession`
`Unimplemented`, marked not dispatched; `SessionRun` and `CloseSession` then name a session
it does not have, and get `NotFound`, also marked. A daemon that predates sessions also answers
`Unimplemented`, since it has no such procedure, and nothing ran, but it cannot attach
the mark, so the client sees an unmarked error. Placement never reaches that case: it
opens a session only on a daemon whose `Describe` states session support, which an
older daemon never does. Session calls use a request message
of their own, so an older daemon can never drop the session ID and run the payload as a
fresh run.

From Go:

```go
remote, _ := client.New(url, client.WithToken(token))
s, err := remote.OpenSession(ctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
res, err := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("/tmp/a", "1")`})
res, err = s.RunJavaScript(ctx, sandbox.Request{Code: `console.log(require("fs").readFileSync("/tmp/a", "utf8"))`})
summary, err := s.Close(ctx)
```

**A cell for one call (`prefer_warm`).** `Run` takes a cell too: code for an interpreter
of its language, its files written into the work directory first, its final expression's
value printed, in a sandbox of its own that keeps nothing after the call (the result
states `interpreter_started` and `interpreter_ended`). With `prefer_warm` set on the
request, a daemon that keeps a warm pool runs it in a waiting pool sandbox, which has run
only plimsoll's own programs and already has the cell's interpreter running, claimed for
this call alone and deleted after it, so the call answers without a sandbox being made for
it. Otherwise, and whenever none fits (no pool, none waiting, a session image that does not
run the language or meet the request's software rule), the daemon runs the cell in a
sandbox made for it: as a project of one step, the cell's files, its code and a runner that
runs it as a session's interpreter does, or on a daemon that runs no projects (`wasm`) as a
JavaScript snippet. A miss is never a refusal. `RunResponse.warm` says which sandbox ran
it. The call goes through everything a `Run` does, before either sandbox is touched: the
isolation floor, the software rule, the ship scan, the caller's limits and, on a provider
billed by the second, the paid-time reservation. A call canceled before its pool sandbox
was claimed is answered as canceled and marked not dispatched, and is not run fresh
instead; one canceled during the cell is unmarked, since the code may have run. The pool
sandbox is deleted on every path. Files under `.plimsoll/`, where a fresh cell's code and
runner go, are refused on both paths, and a cell a daemon has no way to run fresh is
refused whether or not a pool sandbox is waiting, so the pool's state never decides a
refusal. `prefer_warm` on any other payload is refused, not dispatched.

Measured through plimsolld on a laptop (2026-10-29), a cell served by a pool sandbox answered
in 35 ms (Python) and 42 ms (JavaScript) under runc, against 320 to 690 ms for the same call
in a sandbox made for it, and in 51 and 78 ms under gVisor, against 570 to 993 ms. The low
end of each range is a fresh call within 5 seconds of the docker provider's last <dfn>*Preflight*</dfn>,
its check of the docker daemon, the runtime and the images; a fresh call later than that runs
the check first, and a pool sandbox never does. The method, the spread and a call that finds
no pool sandbox free are on the
[warm pool page (INTERNAL · plimsoll site →)](https://plimsollmark.github.io/plimsoll/measurements/warm-pool/index.html).

The official clients use it for every call that keeps nothing: the Go client's
`Remote.RunCell(ctx, cell, client.CellOptions{PreferWarm: true})`, the Python client's
`Client.run_cell(..., prefer_warm=True)` (and the async client's), the TypeScript client's
`runCell(cell, { preferWarm: true })`, which `CodeSandboxes` uses for a call that names no
conversation (no key) unless `sessions` is `"never"`, and the
[MCP (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#mcp)
server's `run_code` without a sandbox handle. What it costs: a pool sandbox runs the cell in
the session image (on docker the project image, which a fresh cell uses too), in a sandbox
that waited up to the pool's 30-minute bound with plimsoll's interpreters running in it.
The record is a single run's on either path, with no session fields, and from record
version 5 it covers `warm`: which sandbox ran the call is stated in the answer and signed in
the record. A deterministic cell answers the same on both paths with two exceptions:
a traceback names the cell's file `cell` in a fresh sandbox and `<cell 1>` in a pool one,
and a fresh cell passes on an exit code its code chose (`sys.exit(3)` is 3), where a pool
sandbox's interpreter reports 1. The Python client's `CodeExecutor` does not use the path:
its fresh run is a script (Python through `runpy`, JavaScript as an ES module), not a cell.

## Carrying a session on from another worker

A worker here is any process of your application that sends plimsoll calls:
a job runner, a web server, a durable workflow's step. A session belongs to the worker that
opened it until another worker of the same caller takes it over with `AttachSession`; the
first one's later calls and close are then refused, so two workers never run code in one
session at once. This is for a job that moves: a workflow step retried on another machine,
a conversation picked up by another server.

**What the second worker needs: a checkpoint.** A <dfn>*session checkpoint*</dfn>, or
checkpoint for short, is what the first worker saves after each call: the session's fingerprint, its ownership generation, the
number of calls it has seen, the digest of the last call's record, and the policy the
session stated at open (provider, tier, the sentence beside the tier, software, the floor
and software rule the open asked for, the lifetime and idle timeout), plus the
application's own short name for the daemon. The daemon's own count and last digest are the
session's head. A checkpoint holds no secret: not the session ID, not the
credential. Keep it where only your application can write, because a checkpoint someone
else wrote could point your worker at the wrong session. The three official clients read
and write one JSON form of it, so a checkpoint a Python worker saved can be used by a Go or
TypeScript worker.

**What the daemon checks.** The attach names the session by its fingerprint and sends the
checkpoint's generation, count and last digest. Under the session's turn (the same one
calls wait for, so an attach waits for a call in flight), the daemon compares them with its
own. An equal generation and head takes the session over: the generation goes up by one,
and the answer returns the session ID, for use in memory only, with the session's policy.
A generation that is not the current one is refused as a stale owner
(`FailedPrecondition`, marked not dispatched, reason `permission`); a head that is not the
checkpoint's is a checkpoint mismatch (`FailedPrecondition`, marked, reason `request`).
Neither moves anything. An unknown session, another caller's, a closed one, an ended one and
one past its lifetime all get the same `NotFound`, with the same text. Every attach costs
one of the caller's rate tokens, a refused one included.

**What the client checks.** The answer must repeat the checkpoint exactly: the
fingerprint (and the SHA-256 of the returned session ID), a generation one past the
checkpoint's, the checkpoint's head, and every policy field. Any difference is data loss,
and the client does not close the session: a bad answer gives it no right to destroy a
session another worker may be using. A failed or canceled attach is never retried, since the
daemon may have taken the session over already.

**A call whose answer was lost.** An <dfn>*explained gap*</dfn> is a
takeover across one call whose answer never reached its worker, which the attach names. A
worker that sends a call and then
dies, is canceled or times out leaves the daemon one call ahead of its last checkpoint:
the call may have run. A plain attach from that checkpoint is a mismatch, and nothing moves.
If the attach names the call, by the digest of its request (the request digest every run
record carries), the daemon takes the session over when, and only when, the checkpoint is
exactly one call behind, the session's last record follows the checkpoint's last record,
and that record carries the named request digest. It returns that record, and the call's answer
when the daemon still keeps it ([what the daemon keeps of an answer](#what-the-daemon-keeps-of-an-answer)): the call was
dispatched once. The record says whether the daemon answered it: a
result digest when the daemon answered (the answer then never reached the worker), which
does not show that the call ran to its end (a step stopped at its time limit and a setup
that failed are answers too), or an unanswered code when the call ended without an answer
(for example `canceled`, when the worker that sent it went away), which does not show that
it started: it may have done none, part or all of its work.
The client checks the record itself (its own digest, its version, that it states a result
digest or an unanswered code and not both, a code from the closed set, the session, its
place right after the checkpoint, the named request digest and the evidence the session
stated at open) and refuses an answer that carries such a record unasked. Every other gap,
a digest named or not, stays a mismatch, so a gap nobody can explain never moves ownership. A digest named when the head equals the checkpoint attaches
as usual: the call never ran.

**A returned answer is checked like any other.** The client refuses, as data loss, an
attach answer that carries an answer with no lost record, and an answer whose record is not
the lost record, whose result's digest is not the record's result digest, or whose evidence
differs from the session's. A checked answer is the call's real output, so the application
can carry on from it instead of guessing whether to run the call again.

**Recovery after a takeover.** A session taken over across an explained gap is
<dfn>*recovering*</dfn>: every call is refused before anything is sent (all three clients use
the same words: Go `ErrRecovering`, Python and TypeScript `RecoveringError`; the refusal is
marked not dispatched, reason `request`) until the application says it has handled the
lost call. It reads the lost call from the session (Go `Session.LostCall()`, Python
`Session.lost_call`, TypeScript `session.lostCall`, each holding the request digest, the
record and the checked answer when one came back, or nothing when the session is not
recovering) and then resolves it (`Session.ResolveLostCall()` in Go,
`Session.resolve_lost_call()` in Python, awaited on the asynchronous client,
`session.resolveLostCall()` in TypeScript). A Python session that keeps its record in the application's store (below)
writes that record ready without the lost call before it resolves, so a worker that
attaches from the store later is not recovering. Carrying on the head does not resolve it,
and neither does any call an adapter or a framework sends of its own, a stat or a
working-directory check included: the recovering state refuses those too. A checkpoint
saved while recovering carries the lost call's request digest (`recovering_request_sha256`),
so a worker that takes the session over from it is recovering as well, with the digest but
not the record or the answer; all three clients save and read it so. The PydanticAI and
Deep Agents adapters resolve on the model's next tool call, whichever tool it is: that call
is not run, and its result tells the model what the lost call's record says and the lost
call's output when the daemon kept its answer (cut to the adapter's output limit); the
tool call after it runs, the lost command sent again on purpose included.

What the recovering state does not stop: an application that resolves and then sends the
lost call again. That is its choice, made after it has seen the outcome; plimsoll does not
know which calls are safe to repeat. A program that does not use the official clients can
skip the recovering state, since it is the clients' rule; what the daemon enforces on every
caller is the head, so a call sent from a stale view of the session never runs.

**The Python client keeps a store; the Go and TypeScript clients do not.** A Python
session opened or taken over with a <dfn>*checkpoint store*</dfn>, an object of your
application's with `load` and an atomic `compare_and_set`, passes every call through it: before
the call the stored record is marked pending with the call's request digest, after a
checked answer it is set ready at the new head, after a refusal ready as it was. A worker
that dies mid-call leaves a pending record, and the next worker's attach sends its
checkpoint and names its call, so the daemon's comparison decides: the call was never
dispatched (the heads match), or it was dispatched and is the explained gap. No timeout ever clears a pending record.
The Go and TypeScript clients take an explicit checkpoint and the store is the
application's. Their limit: a Go or TypeScript worker can name a lost call only when the
answer was lost in the same process (`Session.LostRequestSHA256` in Go,
`session.lostRequestSha256` in TypeScript), so a worker that died mid-call leaves a gap the
next worker cannot explain unless the application recorded the request digest before
sending.

From Go, two workers:

```go
remote, _ := client.New(url, client.WithToken(token), client.WithDaemonName("prod"))
s, _ := remote.OpenSession(ctx, client.SessionOptions{})
s.RunCell(ctx, sandbox.CellRequest{Language: sandbox.LanguagePython, Code: "x = 1"})
cp, _ := s.Checkpoint() // save cp where only the application can write
// In another process, with the same token and daemon name:
t, err := other.AttachSession(ctx, cp, client.AttachOptions{})
```

From Python, with a store:

```python
from plimsoll_client import Client, MemoryCheckpointStore

store = MemoryCheckpointStore()  # for tests only: use storage only your app can write
key = f"{user_id}/{thread_id}"   # from identities your app verified, never model or user text
c = Client(url, token, daemon_name="prod")
s = c.open_session(checkpoint_store=store, checkpoint_key=key)
s.run_cell("x = 1")
# In another process, with the same token, store and daemon name:
t = Client(url, token, daemon_name="prod").attach_session(key, store=store)
t.run_cell("x")  # the same interpreter
```

**What taking a session over does not do.** It does not survive a daemon restart, or
recover an output the daemon did not keep (an unanswered call has none; see
[what the daemon keeps](#what-the-daemon-keeps-of-an-answer)).

**No call runs exactly once, at plimsoll's layer or any other, when its answer was lost.**
An unanswered call may have done none, part or all of its work, and nothing in the
sandbox can tell which. When a call has an effect outside the sandbox (a charge, a message,
a write to another service), put that service's own <dfn>*idempotency key*</dfn> (a
label sent with the request so the service does the work only once for that label) into the
code or its arguments, chosen by your application for that one operation, for example the
order's ID. A repeat of the call is then byte for byte the same request, and the outside
service does the work once: a granted call that sends a payment provider
`Idempotency-Key: charge-<order ID>` charges once however many times it runs.

Do not pass the key through an environment variable: environment variables are a channel
into the sandbox that plimsoll keeps closed.

A takeover also does not
extend the session's lifetime or wake a suspended sandbox (the next call does,
as always), and it does not move a session between copies of the daemon. A client with a
signing recorder cannot take a session over, since the recorder cannot resume a chain it
did not sign from the first call. An attach whose answer was lost (a dropped connection, a
cancel, a timeout) may still have taken the session over, and then no official client can
use or close it: the old worker's calls are refused as stale, and the new worker never
learned the session ID. The attach claimed it, so it is not closed as unclaimed: until its
lifetime runs out (or an open for the same end user at `SANDBOX_MAX_SESSIONS_PER_OWNER`
replaces it) it keeps its place under the session caps, and until a suspend its concurrency
slot and any paid time.

## What the daemon keeps of an answer

After each answered call the daemon keeps that call's answer in its own memory, beside the
last record it already keeps, so a worker that takes the session over across an explained
gap gets the output back. It is never written to disk and never logged (the audit line says
only whether an attach returned one). It is dropped when the next call starts, when the
session's idle timer fires, at close and when the session ends, so no answer outlives the
next call or the idle timeout. A session whose idle timeout is 0 has no idle timer once
claimed, so its answer lives until the next call, close or end.

`SANDBOX_SESSION_KEPT_ANSWER_BYTES` caps one kept answer (default 4 MiB, measured as the
answer's encoded size on the wire; 0 keeps none; at most 16 MiB, so the attach answer that
carries it stays under the clients' 32 MiB limit on an answer read as JSON): above it the
daemon keeps the record only. `SANDBOX_SESSION_KEPT_ANSWERS_TOTAL_BYTES` bounds every
session's kept answers together (default 64 MiB; 0 keeps none): an answer that would take
the total past it is not kept, its record still is, and a dropped answer gives its bytes
back. A caller
that promises its users no retention opens the session with `keep_no_answer` (Go
`SessionOptions.KeepNoAnswer`, Python `open_session(keep_no_answer=True)`, TypeScript
`openSession({ keepNoAnswer: true })`), and the daemon keeps none for that session. An answer can
hold whatever the code in the sandbox printed, a secret included, which is why it lives only as long as
it can still be asked for.

## Interpreters: state between calls

A snippet or a project starts its programs fresh on every call, so an agent that loads a
large file has to load it again in its next call. A cell does not: the session keeps one
interpreter per language, a Python or Node.js process that stays alive between calls, and runs each cell's code in it, the way a notebook runs its cells.

- **The request** names the language (`javascript` or `python`), the code, and optional
  files. The files are written into the session's work directory, which is also the
  interpreter's working directory, before the code runs: this is how a caller hands a
  cell data it got from somewhere else, such as another tool's output. Files follow the
  project limits (200 files, 4 MiB in all, UTF-8 text). A cell whose files cannot all be
  written (a directory in the way, a full disk) is refused, marked not dispatched with
  reason `request` and naming the file and the system's error code: its code does not
  run and its interpreter keeps its state. Files written before the failing one stay.
- **What a cell sees.** Variables, functions and imports from earlier cells of the same
  language. The value of the cell's last expression is printed, as a notebook shows it.
  In JavaScript, top-level `let`, `const` and `class` behave as in a notebook (a later
  cell may declare the same name again) and top-level `await` works; in Python,
  top-level `await` works.
- **The result** is a snippet's (stdout, stderr, the truncation flags) with an exit code
  of 0 when the code ran, 1 when it raised (the error is on stderr) and 124 when the
  call's deadline ended it, plus two flags: `interpreter_started` (this call started a
  fresh interpreter, so nothing an earlier cell defined exists) and `interpreter_ended`
  (the interpreter ended during this call). A cell's time budget is a project's.
- **What survives.** Only the interpreter process, as of the sweep after each call. A
  process a cell starts, a child of the interpreter, is killed by the sweep after the call
  like every other process the call left. The interpreter itself runs between calls
  (a timer that fires later, a thread), so it can start a process after the sweep; that
  process lives until the sweep after the next call, inside the session's limits, and can
  do nothing the interpreter could not. Output the interpreter writes between calls is
  dropped.
- **What ends an interpreter.** The call's deadline (the interpreter is killed, since a
  cell stuck in a loop cannot be trusted to stop), code that exits it or kills it, and
  anything that stops the sandbox: an `openshell` suspend or recovery, or an `e2b`
  suspend (its pause cuts the relays). A docker pause keeps it. The next cell then starts a fresh one and says so.
- **No API access.** A cell carries no grant: the interpreter outlives the call, and its
  code with it. A snippet or project call in the same session can carry one if the grant
  allows sessions ([above](#what-a-session-gives-up)).
- **Which languages.** `Describe` states the languages its startup checks proved, on the
  project environment (`languages`). JavaScript is always there; Python needs `python3` in
  the image, as `plimsoll/sandbox-python` has (with NumPy and SciPy). A cell in a language
  `Describe` does not state is refused before anything starts, `Unimplemented`, marked not
  dispatched with reason `unsupported`, in words that name what the image runs and the
  program it lacks: `the session's image is stated to run javascript, not python: a python
  cell needs python3 in the image, which plimsoll's startup check did not show there`. An interpreter that could not start in a session
  whose image has the language (one docker command or the identity check failed) is refused
  with reason `environment`, never as unsupported, since the next cell starts it again.
- **Records.** A cell's record has its own kind ([run-records.md](run-records.md)). A
  cell's result depends on the cells before it, so a cell is replayed only as part of its
  session, in order.

What changes for the boundary: while an interpreter lives, code of the session can run
between its calls (a timer or a thread inside the interpreter), within the session's own
memory, CPU and process limits. It is the session's own code; it reaches nothing outside
the sandbox that its calls could not reach, and it cannot forge the sweep's verdict, an
exit status, which still kills everything else after every call. What the sweep keeps it
takes from the identities the interpreters and their relays print as they start. On docker,
where code of the session can write into a process's output while it starts (below), an
identity is kept only once its command line is the very program plimsoll started and a
check run as a second user confirms it: a relay must be a process with no parent in the
container, which only `docker exec` and the container's process 1 have (the command line
rules out process 1), and an interpreter must be the only live process with its command
line. Otherwise the cell is refused before
its code is sent, marked not dispatched. A session that never runs a cell keeps no
process between calls, as before.

The interpreters and the programs that drive them are in
[sandbox/internal/sessionkit](../sandbox/internal/sessionkit/); every provider with sessions
runs them. Beside each interpreter the session keeps a relay: a small process attached to
the daemon through one exec held open (`docker exec` on docker, an exec stream on
`openshell`, a process stream through E2B's in-sandbox agent on `e2b`), which writes a cell's files, hands its code to the interpreter and streams its
output back. A warm cell's code therefore reaches its interpreter without a new process;
the call still runs the docker read-back on the host and, after the answer, the sweep. With the sweep after answering
too, a warm cell took about 5 ms on `openshell`, 14 ms under runc and 15 ms under gVisor,
against 73 to 107 ms with a process per cell and the sweep before answering (measured
2026-10-01; every operation, with the data and the program, on the
[session latency page](https://plimsollmark.github.io/plimsoll/measurements/session-latency/index.html)). The sweep keeps the relay as it keeps the interpreter.

What the relay says is not trusted with anything that matters, because code of the session
can reach it on docker. The relay loads the same small library as the sweep, which makes it
unreadable to other processes of the session once it has started, but in the moment it
starts, an interpreter the session keeps could open its input and output: a timer polling
every millisecond did in 3 of 3 tries (2026-10-01), and could then read later cells' code
and write their answers. What follows is what keeps that
from mattering, and it holds whether or not anything of the session's is running. The interpreters' own pipes and control socket, under
`/tmp/.plimsoll-interp`, belong to the session's user, so every process of the session can
reach them at any time. On `openshell` the relay cannot load the library (the gateway then
refuses its connection to the interpreter), but the `openshell` sandbox walls each exec's processes off
from the others': a cell could not open its relay's output, nor any process outside its own
exec (measured on v0.1.2, 2026-10-01). The daemon's startup check of sessions tries exactly
that and refuses sessions on a gateway or provider where a call can open a running relay. Against all of this, a cell is two steps. The relay
first writes the cell's files and connects to the interpreter, and only then is the code
sent; a refusal (files that could not be written, an interpreter that cannot be reached,
or the call's deadline passing before the code was sent, which is `DeadlineExceeded`
marked not dispatched) can come only from the first step, so a call refused as not run
never ran. Code of the session can also forge the first step's "no interpreter" answer,
which makes plimsoll start the interpreter again: the cell then runs in a fresh one and
says so (`interpreter_started`), the state earlier cells left gone. After the code
is sent, nothing the relay writes can turn the call into a refusal or send the code again.
Every line the relay writes carries the cell's random nonce, and one that does not belong
to the cell ends the interpreter, with the cell's result unknown. So code of the session can
spoil its own later cells' answers, as an interpreter it changed already could, but it
cannot make a call that ran look like one that did not, or run one twice.

A new interpreter gets a new relay; a relay lost during a cell takes the interpreter with
it, since that cell's outcome is unknown; code that kills only the relay between calls
costs a new relay, not the interpreter's state. Python starts in isolated mode (`-I`), so a
module file an earlier call left in the work directory (a `json.py`) does not run as the
interpreter starts; a cell's own `import` still finds the work directory.
The conformance suite checks state surviving calls, an error keeping the state, a deadline ending the interpreter, the interpreter's children dying with the call,
files landing in the work directory, a killed interpreter being started again, forged relay
lines neither marking a cell that ran nor running it twice, a forged relay identity not being
kept, and modules in the work directory not running as Python starts.

A single run with no session can run Python too, when the project image has it: a project
whose step is `python3 main.py`.

## Files

A **file call** is one operation on a session's files (a read, a write, a
listing), carried out inside the sandbox by plimsoll's own helper program, started as the
[guest (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#guest)'s
own user. It is a session call like a snippet, a project or a cell (`SessionRun` with a
`files` payload), so it gets what every session call gets: the head, the floor, the software
rule and the request ID's echo are checked, it is one call in the session's chain, and it has
a run record. What differs is the answer: typed fields (a kind, a size, the bytes read, an
error code), never text written inside the sandbox, so a client never parses a shell's words to
learn that a file is missing. The helper's side of it (its commands, how it opens each path, its
exit codes) is [session-files.md](session-files.md).

### The eight operations

| Operation | What it does | What it answers |
|---|---|---|
| `stat` | looks at one path; a link at the path is reported as a link, not followed | the kind (`file`, `dir`, `link`, `other`), the size, the permission bits |
| `read` | reads up to `max_bytes` (1 byte to 8 MiB) from `offset` | the bytes, and the file's size as its open saw it, so a reader of many pieces checks each piece against it with no extra call |
| `write` | writes `content` (at most 4 MiB): `replace` (the file at the name is then all of the new content, or as it was), `create_only` (refuses a name already there) or `append`; `make_parents` makes the folders on the way | the bytes written |
| `list` | a folder's entries, or with `recursive` every entry below it, only those matching the glob `match` when one is given; one page per call | per entry its path from the folder, its kind and its size (a folder a recursive listing could not enter is listed with the kind `unreadable`, and the walk goes on); `more` when the page ended at its budget |
| `read_many` | up to 16,384 files in order, each up to `max_bytes_each` | per path its bytes and size at open, or its own error code (one file's error does not fail the call); `more` when the next did not fit |
| `make_dir` | makes a folder; with `parents`, the folders on the way too | nothing |
| `remove` | removes a file or a link (never its target), or with `dir` an empty folder | nothing |
| `rename` | moves `from` to `to` in one step; without `replace`, a name already at `to` is refused by the rename itself | nothing |

There is no recursive remove, copy, change of owner or mode, watch, or search of contents: a
session's shell has `rm -r`, `cp` and `grep` for those. A listing's next page is asked for with
`after`, the last path of the page before; entries come sorted by their bytes, folders depth
first. `match` is matched by the helper, part by part: `*`, `?` and `[...]` within one part,
`**` as a whole part for any number of parts, and a leading dot is not special, so `*` matches
`.env` ([the rule and its shared test vectors](session-files.md#glob)).

Every answer carries an `outcome`: `completed` when the helper answered, else `timed_out`,
`protocol_error` (an answer the daemon could not read) or `runner_failed` (the helper ended
without one). A completed call that failed carries an `error` from a closed set (`NOT_FOUND`,
`IS_DIR`, `NOT_DIR`, `EXISTS`, `SYMLINK`, `NOT_REGULAR`, `PERMISSION_DENIED`, `TOO_LARGE`,
`NO_SPACE`, `READ_ONLY`, `NOT_EMPTY`, `SCAN_LIMIT`, `OTHER`) and the name of the system error it
came from (`ENOENT` and so on). A file that is not there is such an answer, as a nonzero exit
code is for a command, not a transport error. Paths are bytes on the wire, not text: a file's name
may hold any byte but `/` and the zero byte, which is not always UTF-8, so a name a listing
returns is named back by the same bytes.

### Scopes, and which providers state them

A file call names its paths in one of two scopes:

- **The work scope**: a path relative to the session's work folder (`/work` on docker and E2B),
  at most 4,096 bytes, its parts separated by `/`, none empty, `.` or `..`. The kernel resolves it
  beneath the work folder in one step, and a symbolic link is followed only while it stays inside
  (a virtual environment's `bin/python`); one that leads out is refused, `SYMLINK`. This promise
  needs a work folder that is a mount of its own, since otherwise a process of the session could
  move a folder out of the work folder while a call holds it open
  ([why](session-files.md#scopes)). For the same reason the work scope never crosses a mount
  below the work folder (an image or template that mounts another folder at `/work/shared`): a
  path across one is refused, `PERMISSION_DENIED`, and a recursive listing lists its folder as
  `UNREADABLE`; the sandbox scope reaches it.
- **The sandbox scope**: an absolute path, resolved as the guest's own shell resolves it, links
  followed. The sandbox's walls, not the work folder, are the boundary.

| Provider | Scopes its sessions state |
|---|---|
| `docker` | both: `/work` is a size-capped in-memory filesystem of its own. The work scope needs Linux 5.8 or later, or gVisor ([why](session-files.md#scopes)); the startup check starts it once, and where the kernel is older the sessions state the sandbox scope alone |
| `e2b` | both: the open bind-mounts the machine's `/work` on itself, as root, before any of the session's code, and puts the helper in the machine, since E2B's templates do not carry it ([E2B](#e2b) below). No startup check reads E2B's kernel: on one before Linux 5.8 every work-scope call would answer a file error whose errno is `ENOSYS` |
| `openshell` | the sandbox scope alone (below) |
| the rest | none: they keep no sessions, and Docker Cloud's sessions are not offered |

A session states its scopes in `Describe` and in the open's answer (`file_scopes`, beside
`work_dir`, the work folder's absolute path), and the daemon refuses a call in a scope the
session does not state before anything runs (marked
[not dispatched (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#dispatch),
reason `unsupported`), whatever the client believed. The scope is part of the request's
[digest (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#digest),
the hash a run record carries of it, so each call's record states the scope it used and no
record claims the work scope's confinement for a call made in the other. Each provider passes
the conformance suite's file cases for the scopes it states.

**Why the `openshell` provider states the sandbox scope alone.** An
[OpenShell (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#openshell)
session's work folder,
`/tmp/work`, is not a mount of its own, and nothing stops a move out of it. Two measurements on
OpenShell v0.1.2 with its docker driver (2026-11-27): `/tmp/work` is a plain folder on the
container's own writable layer, whose only mounts are `/proc`, `/dev`, `/sys` and a few files and
folders of docker's and OpenShell's own, and the code in the sandbox runs as an ordinary user that
cannot make one; and the sandbox's Landlock policy (a Linux facility that limits which files a
process may reach) grants `/tmp` every right, the right to move a folder to another parent
included, so a process of the session moved a folder out of `/tmp/work`, and `/tmp/work` itself,
with no refusal. The one mount the provider could ask for there, a size-capped in-memory
filesystem through the sandbox's driver settings, is discarded when the sandbox stops, which a
suspend does. So the provider states the sandbox scope alone, and a confined `Workspace` there
checks its paths by name: a path whose `..` or absolute form leads out of the work folder is
refused before any call, but a link inside the work folder that points out of it is followed,
bounded by the sandbox's walls ([openshell.md](openshell.md#sessions)).

### What a call proves, and what one that failed may have left

A completed call proves what the helper did at that call, and its record states the request the
daemon sent and the answer it got: a read's bytes are what the file held when it was read, and a
successful write's bytes were written, synced and published at the name. It does not prove that
the file still holds them later: code in the session owns its files and may change them between
calls or during one, so a sequence of reads is no snapshot of a file at one moment. A call
answered with an error, and one that got no answer (its deadline passed, the helper was killed,
the connection went), may each have left a change behind, which differs by operation; the helper's
contract has the table ([what a success proves, what a failure leaves](session-files.md#writes-how-they-publish-what-a-success-proves-what-a-failure-leaves)).
A call with no answer gets a record with no result, and the session goes on
([run-records.md](run-records.md#a-session-call-that-may-have-run-but-got-no-result)). No
official client repeats a `write`, `make_dir`, `remove` or `rename` after it got no answer: a
request ID makes an answer trustworthy, not a call repeatable.

### Limits

| Limit | Value | Why |
|---|---|---|
| One write's content | 4 MiB | the files a project call may carry, and well inside the daemon's 8 MiB request cap once base64 makes it a third larger on the wire. `Workspace.write` of more writes the first 4 MiB in place of the file, then appends the rest, so it is not atomic: a failure partway leaves the first pieces |
| One read, and one `read_many` file | 8 MiB | the most one answer takes; a longer file is read in pieces, each checked against the size its open stated |
| Paths in one `read_many` | 16,384 | the helper's own bound. The 8 MiB request cap bounds the paths' bytes too, since they travel in base64, so `Workspace.read_many` and the Agent Framework file store send at most 4 MiB of path bytes a call |
| A `list` or `read_many` page (`budget_bytes`) | 8 KiB to 8 MiB | the least page (8,192 bytes) holds the largest entry a listing can answer, a path of 4,096 bytes with its kind and size, so a page that ends with `more` always holds at least one entry and asking again always makes progress |
| One path | 4,096 bytes | Linux's own bound on a path |

A recursive listing also stops at bounds of its own (entries read, names held, depth), past which
the call answers `SCAN_LIMIT` rather than a cut list ([paging](session-files.md#paging)); list a
folder further down.

A file call carries no [capability grant (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#grant),
so it reaches no network. Every path it names, a write's content, a listing's glob and cursor,
and a rename's target pass the [ship scan](ship-scan.md#what-it-reads-and-when) as a project's
files do. Its audit line names the operation, the scope, the bytes sent in and returned, the
entry count, the error and the outcome, never a path, a name from a listing, a glob or content,
and `/metrics` counts file calls by operation, outcome and error. On every provider the cleanup
between calls is skipped after a call the helper answered that cannot add to the disk (it started
only the helper, which has exited), and runs after any other call: after an answered `write` or
`make_dir` too, since that cleanup is where the session's disk is measured.

### From the clients

- **Python**: `Session.run_files(op)`, `op` one of the classes of `plimsoll_client.files`
  (`FilesStat`, `FilesRead`, `FilesWrite`, `FilesList`, `FilesReadMany`, `FilesMakeDir`,
  `FilesRemove`, `FilesRename`, each with a `scope` of `"work"` or `"sandbox"`), answering a
  `FilesResult` (`outcome`, `error`, `answer`); `AsyncSession.run_files` for the async client;
  `Session.file_scopes` and `Session.work_dir` as the open stated them. `Workspace`
  (`plimsoll_client.workspace`) builds an agent's file tools on them and raises Python's own
  errors (`FileNotFoundError`, `IsADirectoryError`, `PermissionError` and so on): `stat`, `read`,
  `read_pieces`, `read_whole`, `read_head`, `write`, `edit`, `list`, `glob`, `read_many`,
  `make_dir`, `remove` and `rename`, each a file call or a few, never shell text.

  ```python
  from plimsoll_client import files as fs

  session.run_files(fs.FilesWrite("notes.txt", b"hello\n"))
  r = session.run_files(fs.FilesRead("notes.txt"))
  print(r.error, r.answer.content)   # none b'hello\n'
  ```
- **Go**: `(*client.Session).RunFiles(ctx, sandbox.FilesRequest{FilesCall: sandbox.FilesCall{Op: sandbox.FilesRead, Scope: sandbox.FilesScopeWork, Path: []byte("notes.txt"), MaxBytes: 1 << 20}})`,
  answering a `sandbox.FilesResult`; `Session.FileScopes()` and `Session.WorkDir()`.
- **TypeScript**: `session.runFiles(op)`, and one method per operation: `stat`, `readFile`,
  `writeFile`, `list`, `readMany`, `makeDir`, `removeFile` and `rename`; `session.fileScopes` and
  `session.workDir`.

Each client recomputes a file call's record like any other call's, follows the chain, checks the
request ID's echo and refuses an answer whose outcome, error and answer disagree
([a file call's answer](run-records.md#a-file-calls-answer)).

## What the daemon guarantees

- **One owner.** The session belongs to the <dfn>*principal*</dfn> that opened it: the
  authenticated caller, as the daemon's clients file names it. An unknown ID and another
  principal's ID get the same `NotFound`, so an ID's existence never leaks. The ID works
  like a password for the session, so it is never logged or recorded; audit lines and
  records carry the fingerprint instead. With no auth configured (open dev mode, which the
  daemon warns about at startup) every caller is the same anonymous principal, so there a
  session is protected by its ID alone.
- **One call at a time, in order.** Calls run one after another, never at once. While
  one runs, one more call (or the close) may wait for its turn; any further one is refused
  at once, `ResourceExhausted` marked not dispatched (reason `capacity`), since a client
  makes one call at a time and a parked request holds a handler and a connection. Each
  call's record names the digest of the previous call's record and its own number,
  counting from 1. The Go, Python and TypeScript clients check every record against the
  chain they have seen, so a call made by anyone else holding the ID shows as a gap at the
  next call and at the close (`DataLoss` wrapping `record.ErrChain` in Go). The chain counts
  every call that may have run: one that ended in an error not marked not dispatched gets a
  record with no result and the error's code, and the session goes on
  ([run-records.md](run-records.md#a-session-call-that-may-have-run-but-got-no-result)). A call
  whose answer never arrived leaves the client unable to follow the chain, so it sends
  nothing more on that session.
- **The end has its own error.** A call on an ended session is refused
  `FailedPrecondition`, marked not dispatched, with a `SessionEnded` detail; the Go client
  restores it as `sandbox.SessionEndedError` (`errors.Is(err, sandbox.ErrSessionEnded)`).
  The detail is believed whatever the code: a call answered `Canceled` or
  `DeadlineExceeded` with a `SessionEnded` detail was canceled or ran out of time, and its
  session ended too, and every client reports both (in Go, `errors.Is` matches the context
  error and `sandbox.ErrSessionEnded`).
  A session ends when it is closed, when its lifetime runs out, when its files pass the disk
  budget, when its sandbox's main process ends, when the provider cannot give the next call
  a clean sandbox, when the sandbox changed under it, when the daemon closed it for a newer
  session of its owner (`replaced`) or because nobody claimed it (`unclaimed`, below), or
  when the daemon shuts down. The daemon keeps the final count of a session that ended by
  itself for 10 minutes, so its owner's `CloseSession` still gets it.
- **A session nobody claimed is closed.** If no request names a session before its first
  idle timeout (a call, even one refused before it ran, or a close), the daemon closes it
  instead of suspending it, with the end `unclaimed`. That is what a session looks like
  when the answer to its open never reached the client (the connection dropped, the client
  refused an answer that did not carry its request's ID back, the client crashed after
  sending): nobody can then use or close it, and it would hold its place under the session
  caps, and until a suspend its concurrency slot and any paid time, for its whole lifetime.
  The daemon cannot tell that from a client that opened ahead of calls that have not come. A session that
  never suspends (`SANDBOX_SESSION_IDLE=0`) waits 5 minutes, the idle timeout's default.
  The cost falls on a client that opens a session ahead of use and makes its first call
  after the idle timeout: that call is refused, not dispatched, with the end `unclaimed`.
  A close the provider fails is tried again (below, "A close the daemon makes by itself"),
  and the session stays unclaimed meanwhile, so the answer is the same.
  Nothing ran in the closed session, so a new one loses nothing; `CodeSandboxes` opens it
  by itself, so a `warm` that its conversation does not use within the idle timeout costs
  one more open.
- **A close the daemon makes by itself is tried again until it takes.** The daemon closes
  a session by itself when nobody claimed it, when it could neither suspend nor pay for
  another idle period (E2B, below), when its open cannot hand it over (the caller gave up,
  or what opened does not meet the floor or the software rule), and when a pool sandbox
  has served its one call. Each close gets a time budget of its own (90 seconds), never
  one a caller or a pause has spent. A close the provider fails, with the session still
  open, is logged as a failed close naming the provider, never as a close, and counted in
  `plimsoll_session_close_failures_total`; it is tried again after 10 seconds, then 20,
  40, 80 and 160, and after six failed tries the daemon logs an error, counts it in
  `plimsoll_session_close_gave_up_total` and leaves the session to the provider's lifetime
  for it. While the session may still bill, its paid time is held to the end of that
  lifetime ("Its time is paid", below), and settled, when it is gone, to the time it was
  running.
- **Capacity.** A running session holds one of the daemon's concurrency slots (the runs
  allowed at once), and with it its share of the total memory budget,
  `SANDBOX_TOTAL_MEMORY_MB`. A suspended session whose sandbox was stopped holds none; the
  call that resumes it takes a slot first, and a capacity refusal there ran nothing and is
  safe to retry. A paused docker session keeps its slot, because a paused container keeps
  its memory. A session that ends keeps its slot until its sandbox is deleted, since the
  sandbox holds its memory until then; the call that ended it says so in its own answer
  at once. Every call
  is charged to the caller's rate limit. Opening a session is charged like a run. A call
  gets the daemon's own five-minute timeout ceiling, exactly as a run does.

## Docker

A docker session is the container a project run gets, kept for the session:

- **The same walls.** The project image, launched by the content ID the startup checks
  inspected, with the run's flags: a read-only root, no network, every writable directory
  (`/tmp`, `/dev/shm`, `/work`) a size-capped in-memory filesystem on which a stored file
  cannot be started as a program (the session's code cannot mount another without that mark,
  under `runc` or gVisor: the <dfn>*guest guard*</dfn>, plimsoll's own filter in front of every
  command started in the container, refuses it, [seccomp.md](seccomp.md#the-guest-guard-a-second-filter-in-front-of-every-program)),
  all capabilities dropped, the process limit, plimsoll's fixed read-only `/etc/resolv.conf` (so no
  resolver setting of the host, such as its search domains, reaches the session's
  code), and gVisor when `SANDBOX_DOCKER_RUNTIME=runsc`.
- **What that mark means for the session's work.** A program built or written in the
  session is stored under `/work` or `/tmp`, so the kernel refuses to start it. Measured
  2026-11-19: `cargo test` on a Rust crate (a Rust package) with a build script or a derive
  macro (both are small programs Cargo compiles and then starts during the build), a C
  build that runs what it compiled, and `./script.sh` are refused in a docker session. Go
  tests work when they are built to <dfn>*WebAssembly*</dfn> (a portable program format: a runner reads
  the `.wasm` file as data, so the kernel is never asked to start it).
- **A main process that does nothing.** The guest guard runs as process 1, in its process-1
  mode, in place of docker's own init (`--init`), which docker started outside the guest guard
  and which plimsoll no longer uses ([seccomp.md](seccomp.md#the-guest-guard-a-second-filter-in-front-of-every-program)).
  It puts its filter on itself and starts `sleep` as its child, so every process in the
  container runs behind the guest guard. Process 1 matters: a process killed between calls
  whose parent is gone becomes process 1's child, and a process 1 that never collects its dead
  children would keep them, each counting against the process limit, for the session's whole
  life; the guest guard collects every one. It passes no signal on to any process, and it ends
  the container when `sleep` ends or on a signal recorded as coming from outside the container,
  such as the one `docker stop` sends. Code of the session can still end or stall its own
  session, as it always could by ending `sleep`: it can cause a signal recorded as from outside
  (the I/O signal of a descriptor it makes process 1 the owner of, or the signal that follows a
  CPU limit it sets on process 1); under gVisor it can stop process 1, which then collects
  nothing, or end it; and while it keeps sending process 1 a stop signal, an outside `docker
  stop` waits its whole timeout before docker kills the container. plimsoll's own close removes
  the container (`docker rm -f`) and does not wait. A session refuses to open unless process 1
  has exactly the command line plimsoll started it with.
- **Every call is a `docker exec`** into the container, in `/work`.
- **Over the memory limit.** Under runc the kernel kills the one process over the limit and
  the session goes on; under gVisor the whole sandbox dies, and the session ends
  (`main_process_ended`) naming the limit, except that docker sometimes records no
  out-of-memory kill there (1 container in 40, measured 2026-11-21, [the outside fact](../internal/outsidefacts/facts.json)
  `docker-oomkilled-under-runsc`), so an exit status of 137 with none recorded is reported as
  probably the memory limit, not certainly, since any forced kill gives 137.
- **After every call, the sweep** kills every process the call left behind, by the same
  program the `openshell` provider runs, and measures the session's files against
  `SANDBOX_SESSION_DISK_MB`. It runs after the answer has gone back: the next call or a
  suspend waits for it (a close does not: it removes the container, sweep and all), and an agent's thinking time between tool calls usually
  hides it (a warm call took about 95 ms under runc instead of about 180 ms, measured
  2026-10-01). So a session that the sweep ends, over its disk budget for instance, is
  reported to the next call rather than in the answer of the call that caused it. Its verdict is its exit status, which another process could
  change only by attaching to the sweep as a debugger does, a request the guest guard refuses
  the session's code; the sweep also loads a small library
  that forbids that once it has started, and in the moment before, only a host whose Yama
  `ptrace_scope` is 0 lets a process attach to one it did not start, and a session does not
  open on such a host (gVisor keeps its own setting, 1, whatever the host's). In that moment
  code of the session can open the sweep's input and output, which carry nothing plimsoll
  reads: the verdict is the exit status alone. When it cannot prove the boundary, the session ends: the one
  recovery that kills everything, a restart, would erase the files.
- **A project call in a session starts with nothing of the session's running.** Every
  program of plimsoll's starts in the container as the user the session's code runs as,
  and until it has loaded the small library that makes it unreadable, a process of that
  same user can open its input and its output (its memory too, on a host whose Yama
  `ptrace_scope` is 0, where a session does not open); a descriptor opened in that
  moment keeps working afterwards. A project call's input carries the plan, with the key
  the runner signs its report with. So before a project call, plimsoll kills every
  process of the session's, the interpreters it keeps included. **An interpreter is
  killed, not paused: a session that runs cells loses their state at the next project
  call,** and the next cell starts a fresh interpreter and says so
  (`interpreter_started`); files in the work directory are untouched. Pausing them would
  not do, because a paused process can arrange its own resume before it is paused (an
  asynchronous notification on a descriptor of its own, a timer), and no filter can tell
  that use apart from a language runtime's. If a process can be neither killed nor
  accounted for, the project call does not start (nothing is dispatched) and the session
  ends, as it does when the sweep cannot prove the boundary. A session with no
  interpreter alive keeps no process of its own, so a session that runs only project
  calls pays nothing for this and loses nothing.
- **A snippet or a cell in a session is not protected that way,** and does not need to
  be: neither carries a key. What the session's own code can do to its own later calls'
  output is above, under what a cell's relay is trusted with. A grader whose verdict the
  graded code must not be able to forge runs as a project call of its own, in a session or
  a single run, never as a later step of the call that runs the graded code. Within one
  call nothing is killed between steps, so a process an earlier step leaves running can
  write into a later step's output, kill it, or stop it until the call's deadline
  (measured 2026-11-24 under `runc` and gVisor, in a run and in a session), and an earlier
  step can rewrite the files a later one runs ([run-results.md](run-results.md#did-anything-run-the-error-says-so)).
- **A suspend is a pause.** `docker pause` freezes every process; the files and the
  processes' memory stay. That is why a paused session keeps its concurrency slot.
  Resuming takes about 20 milliseconds (measured 2026-10-01 under runc and gVisor).
  A paused session that ends (closed, at its lifetime, at shutdown) has its container
  removed as any other, in about 0.2 s. Under gVisor plimsoll unpauses it first: docker
  cannot kill a paused gVisor container and waits 10 seconds before ending it another
  way. So under gVisor the session's code runs again for a moment before the kill (about
  22 milliseconds, measured 2026-11-20), after its relays and the socket its host API
  calls went through have been closed, with no network and nothing it writes surviving
  the removal. Under runc
  the kill reaches the paused processes and nothing runs again.
- **A read-back before every call.** Anyone who can reach the docker daemon can change a
  running container, for example raise its memory limit with `docker update`. Before each
  call the session compares the container's security settings (image, resource limits,
  mounts, capabilities, networks, user) with what they were at open, and ends the session
  on any difference. The call is refused, marked not dispatched. A read-back docker does
  not answer refuses the call too (reason `environment`), and the session goes on. After a
  call whose exit status may be docker's rather than the code's, a container found paused,
  stopped or gone ends the session; docker's exit status is never reported as the call's.
  A read-back after a call that docker does not answer ends the session (`boundary_failed`):
  what the code left running cannot be proved contained, so the session is not kept.
- **A command the guest guard refuses.** The guest guard writes one line naming the step that
  failed when it refuses to start a command. At open, plimsoll reads that line from `docker run`,
  which it keeps attached only until the main process has started (the container still keeps no
  output), so a refused open names the guest guard's own step; no code of the caller's exists yet, so
  it is marked not dispatched. In a session a caller holds, a call's own command (the snippet's
  program, or the runner a project's steps run under) that ends as the guest guard ends when it
  refuses ends the session (`boundary_failed`), and the call is not marked: what shows that
  refusal is the command's standard error and exit code, and code of the session can shape
  both (under `runc` a thread left in a kept interpreter can read the start marker off the new
  command's standard error before docker does, and the call's own code then writes the
  guest guard's line), so the end says whether the call ran is not known. Only a call whose own command
  plimsoll refused before docker started is marked (reason `environment`). A refusal after the
  call's code started, such as of the sweep that follows it, leaves the call unmarked, and the
  session's end reaches the next call. A project's steps all run inside
  the runner, so a step that fails after another ran is part of the runner's report, never a
  refusal.
- **API access.** A grant reaches its API routes through the <dfn>*broker*</dfn>, a part of plimsoll outside the sandbox that adds the
  credential, so the credential never enters the sandbox. A running container cannot gain
  a mount, so the session mounts the broker's socket at open. It serves a call's grant
  only while that call runs; between calls, and in a call without a grant, the socket
  answers 503. While it serves a grant it serves anything in the container, so code an
  earlier call left running (a timer in an interpreter, a process started after the
  sweep) can use a later call's grant. That is why a granted call needs a grant that
  allows sessions ([What a session gives up](#what-a-session-gives-up)). The socket
  takes at most 32 connections at once, so code left running can also hold them all and
  delay or block a later call's API requests. Only the session's own calls are affected:
  everything in the container is the same caller, and no socket can tell one of its
  processes from another.
- **Cleanup.** The container is removed when the session ends. The session's end, and
  with it the return of its concurrency slot and memory share, waits until the removal is
  confirmed: a container whose removal fails stays counted, and the daemon retries the
  removal on every orphan pass until the container is gone (plimsolld runs the pass,
  `ReconcileOrphans`, every minute; a program that embeds the provider and bounds its own
  concurrency must call it too, or a session whose removal failed keeps its slot and memory
  share for good). The same holds for a one-shot
  run's container on docker and for every `openshell` and `agentsandbox` sandbox. A container
  a crashed daemon left behind carries its lifetime as a label, and a running daemon removes it once
  that lifetime plus 5 minutes has passed. The broker's socket directory on the host is
  removed with its session; one a crashed daemon left is removed by a running daemon once
  it is a minute old and its socket has no listener. At shutdown the daemon refuses new
  sessions, waits for the ones still opening, and ends them all.
- **A warm pool, when `SANDBOX_SESSION_POOL` is set.** The daemon keeps that many
  containers ready. Each is created and read back exactly as a session's container is, with
  an interpreter already started and its relay attached for a set of the languages the
  image runs: every language, until language hints say otherwise (below). `OpenSession`
  hands one over instead of creating a container, so the first cell sends its code at
  once. On a laptop (measured 2026-10-02), opening a session and running its first
  cell took 22 ms (JavaScript) and 18 ms (Python) under runc instead of 740 and 789 ms, and
  51 and 32 ms under gVisor instead of 817 and 891 ms
  ([warm pool page](https://plimsollmark.github.io/plimsoll/measurements/warm-pool/index.html),
  with the data and the programs).
  - A waiting container has run only plimsoll's own programs: the guest guard as process 1, `sleep`, and the
    interpreters with their relays. It goes to one session, or to one cell a `Run` asked
    for it ("A cell for one call"), and its first cell in each language still says its
    interpreter is new. Closing that session, or that cell's answer, removes the
    container. Nothing goes back into the pool or is reused, so
    [Who may share a session](#who-may-share-a-session) holds unchanged.
  - A container is handed over only while it matches the image, runtime and isolation the
    daemon last verified, and while its relays are still attached. Any other is removed and
    replaced, and so is one that has waited 30 minutes. Its lifetime label covers those 30
    minutes plus `SANDBOX_SESSION_LIFETIME`, which bounds how long a crashed daemon's waiting
    containers outlive it.
  - A claim skips the check of the docker daemon, runtime and images that creating a
    container repeats once its result is 5 seconds old. The container was checked when it
    was made, and it is read back before every call like any session.
  - The cost is memory. A waiting container held 39 MiB under runc and 66 MiB under gVisor
    with both interpreters running, against 0.5 and 18 MiB for a bare one. That memory counts
    inside its session's limit, including the interpreter of a language the session never
    uses. A waiting container holds no concurrency slot until it is claimed, but each is
    charged one run's memory against `SANDBOX_TOTAL_MEMORY_MB` (its container's limit is
    one run's), so with a budget set, a pool of 2 leaves room for two runs fewer. A
    container the pool removes (waiting too long, made under an older image, or moved to
    another language) counts toward the pool's size until docker has removed it, so its
    replacement never runs beside it outside that charge.
  - **Language hints decide which interpreters wait.** A session opened with a hint is
    handed the waiting container that runs the most of its hinted languages, then the one
    running the fewest others, then the oldest; any waiting container beats creating one,
    since the container is most of the cold cost. A session without a hint counts as
    wanting every language.
  - **A pool of 4 or fewer does not split.** Every waiting container warms every
    language the image runs, so every session handed a waiting container finds its
    languages warm whatever callers ask for, as before hints existed. Opens that find no
    container waiting, as a burst larger than the pool can, create their containers as
    they would without a pool. Splitting so few containers cost more than it
    saved: in simulation, a split pool of 1 to 3 found a language fewer than a quarter
    of sessions asked for, or a burst of opens, warm 75 to 91% of the time, to save at
    most a few idle interpreters.
  - **A pool of 5 or more divides its size across language sets** by what sessions ask
    for. Each open the daemon does not refuse first shrinks every set's weight by a small
    rate and then adds that rate to its own set; a refused open counts for nothing. The
    rate is 1/(4 x pool size), so one open moves a set's share by about a quarter of a
    container at most and the split follows roughly the last 4 x pool size sessions. A
    set whose weight falls below a quarter of one open's is forgotten.
  - Claims and refills follow the split by themselves: a claim takes the waiting container
    closest to its hint, and its replacement warms the set furthest below its share. A
    language fewer than a quarter of recent sessions ask for may wait for its
    interpreter, which starts when the session asks, in a container that is already
    running. Concurrent opens that empty the pool create their containers as they would
    without one.
  - A container of a set fewer than a quarter of recent sessions ask for is one claims
    seldom take, so the pool also replaces such containers itself: at most one a minute,
    and only when the shift is clear (what the set furthest below its share lacks and
    what the set furthest above its share holds beyond it add up to more than 1.75
    containers, a share counting fractions of a container). Rebalancing therefore costs
    at most one container start a minute whatever callers ask for, and demand that takes
    turns (two or three sets in turn, or runs of up to five sessions each) costs nothing
    beyond the claimed container's replacement. In simulation at sizes 5 to 32, sessions
    alternating or rotating found their languages warm every time, and random hints (one
    session a second) cost under 0.02 extra container starts per session. Hints move
    containers between sets and never add any: `SANDBOX_SESSION_POOL` still bounds how
    many wait, and so the memory. Callers that send no hints see every container warm
    every language.
  - At startup, the session check runs on a container from the pool, so the warm path is
    the one startup proves.
  - `openshell` keeps the same pool, with gateway sandboxes for containers
    ([openshell.md](openshell.md#sessions), "A warm pool").

A session's snippets run in the project image, not the snippet image, because one
container runs every call. The answer to `OpenSession` and every call's record state the project image.

## E2B

An E2B session is one E2B sandbox, booted from the configured template, kept for the
session. **It needs a template whose node is v22.14.0 or later** (v23.7.0 or later in the
23 line, or any v24): plimsoll's own programs in the session start with node's
`--disable-sigusr1` option, so the session's code cannot open their debugger (the part of
node that runs whatever code it is sent to it) with a signal, and an older node refuses
the option. E2B's own `base` template carried node v20.9.0 when a live check read it on
2026-11-20; on a template whose node is that old a session is refused at its open as
unsupported, marked as never run, in words that name the version needed, before any of the
session's code runs; when
the daemon's startup check has already read the version, no sandbox is made for the
refused open. Single runs, which start none of plimsoll's own programs inside the machine,
work on `base`. **It also needs a node outside `/usr/local`.** E2B's template build leaves
`/usr/local` and everything in it writable by every user in the machine (measured on
2026-11-20, on `base` and on a template built from plimsoll's recipe), and node's own
images and `base` keep node there, so the session's code could replace it. plimsoll's own
programs in an E2B session therefore look for `node`, `sh`, `setpriv` and `python3` only in
`/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`; on a template with no node there (`base` is
one) a session is refused at its open as unsupported, marked as never run, in words that
say so.
[e2b/README.md](../e2b/README.md) builds a template that serves both single runs and
sessions, with node 24 (and a copy of it in `/usr/bin`), util-linux's `setpriv` and
`python3`.

E2B's base template gives its default user `sudo` without a password and leaves
root reachable, so before any of the session's code runs, the open makes the machine one
where that code cannot become root:

- **The code runs as a user no account has.** Every call's code runs as uid and gid
  61000, which the template's account files must not name (the open refuses one that
  does), through util-linux's `setpriv` with the kernel's no-new-privileges flag set, under
  which no setuid program, `sudo` and `su` included, can raise its privileges. The
  open also locks the template's empty passwords, stops and masks its ssh server, refuses
  the machine if anything still listens on port 22, and then proves from inside, as that
  user, that `sudo`, `su` and an ssh login to root all fail, and that E2B's agent inside
  the machine, through which plimsoll's own programs run as root, refuses that user a
  process start and a reset of its access token at every address the machine has (or
  listens at none of them). A template whose `setpriv` is not util-linux's is refused at
  open (BusyBox's cannot change user).
- **The session's code cannot write `/usr/local`.** E2B's template build ends by making
  `/usr/local` and everything in it writable by every user in the machine (mode 777, the
  permission setting that lets any user write a file or a folder), and programs that run
  as root live and look there: E2B's own helper programs are in `/usr/local/bin`, and the
  system's usual search path (the list of folders a program's name is looked up in)
  starts with `/usr/local`. Code that could replace such a program could make itself root
  in its machine. So the open, as root and before any of the session's code runs, takes
  the write permission for each file's group and for every other user off every file and
  folder under `/usr/local` (the reverse of E2B's step; a link is left as it is, since the
  folder that holds a link decides whether it can be replaced). Then a process dropped
  exactly as the session's code is asks the kernel, for each of those and for every folder
  above `/usr/local`, whether it may write it. If it may write any, because the template
  made something there that a permission change cannot close (a file owned by the
  session's uid, a mount that ignores permissions), the session is refused at its open as
  unsupported, marked as never run, in words that name the first such path. The session's
  code still reads and runs everything there (node, the TypeScript tools of plimsoll's
  recipe); what it can no longer do is install into it (`npm install -g`, a `pip install`
  that writes there): install into `/work` instead. What it costs per open, measured
  2026-11-20 on containers of plimsoll's recipe image with its 4,605 files and folders
  under `/usr/local`: about 70 ms where a permission change is written in place (28 ms
  for the changes, 40 to 90 ms for the check), and 4.4 to 5.2 s on a fresh container under
  docker's ordinary runtime, whose storage copies each file whole the first time its
  permissions change (0.5 to 0.8 s under gVisor). E2B's own time is not measured yet: the
  open reports it, and the paid live suite logs it. plimsoll's own
  programs still never look in `/usr/local` (below), so they do not rest on this alone.
  A single run is not a session and is left as E2B builds it: its code runs as E2B's own
  default user, `user`, which can write `/usr/local`, and its machine is deleted after it.
- **A program the session writes can be started.** An E2B session's work folder `/work` is
  on the machine's own disk, which carries no no-execute mark (the mark that makes the
  kernel refuse to start any file stored in a folder, as on a docker session's `/work`),
  so a program the session builds or writes there can be started. Measured 2026-11-20 on a
  template built from plimsoll's recipe: as the session's user, a program copied into
  `/work` and a shell script written there both ran. plimsoll's recipe carries no Rust or C
  toolchain (the compilers and build tools for those languages), so such builds need a
  template of the operator's own that has one, and plimsoll has not measured such a build.
- **plimsoll's own programs run as root.** The process lister, the sweep after every call
  and the check of each relay's identity run as root through the agent E2B runs
  inside each machine, out of reach of the session's code. The sweep spares every
  process the machine had when the session opened (its system services, E2B's agent included;
  the open refuses a listing with a process already running as the session's user) and
  the interpreters the session keeps, kills the rest, and skips kernel threads.
- **plimsoll's own programs start where the session's files cannot reach them.** On
  E2B the work folder `/work` carries no no-execute mark (a mark on a folder that stops
  the kernel from running or loading any file in it), so a program that goes looking for
  a file to load could find one the session's code put there. So every program of
  plimsoll's in the machine (the open, the stager, the process lister, the sweep, the
  identity check, the relays, the artifact reader, the interpreter launcher, and the
  `setpriv` that drops to the session's user) is started three ways. It starts in `/`,
  which the session's user cannot write, so a library folder a template names
  relatively (`lib` rather than `/usr/lib`, read against the folder a program starts in)
  is a folder of the root, never one of `/work`. It starts with an empty environment
  (the variables a program reads when it starts): E2B's agent hands every process its
  own `PATH`, `HOME`, `USER`, `LOGNAME`, the sandbox's environment variables and the
  request's, and plimsoll's programs start through `/usr/bin/env -i`, which clears all of
  them and sets only plimsoll's fixed `PATH`, plus `OPENSSL_CONF=/dev/null`, an empty
  settings file for OpenSSL (the cryptography library node uses, whose settings file can
  name a module, a library it then loads, by its path). And it is named by its full
  path, never found through a search: before any of the session's code runs, the open
  finds `node`, `sh`, `setpriv` and, where the template has it, `python3` in the root's
  system folders (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; never `/usr/local`, which E2B's
  template build leaves writable by every user), follows every link on the way to each, and refuses the session when
  any folder, link or file on the way is one the session's user could change, so a link
  into a folder the session writes is refused, not followed later. Every later start
  names the path the open found. The session's own code still runs with the template's
  environment: the open reads the agent's environment once, and each call's processes
  are handed it and change into `/work` themselves, as the session's user. The docker
  suite writes two such routes into its stand-in for E2B as a template could carry them
  (a library folder named relatively, and an OpenSSL settings file naming a module in
  `/work`), puts the session's own library where they lead, shows each route is taken by
  the session's own `node`, and fails if any program of plimsoll's takes one;
  `make e2b-session-live`, which is paid, has the same check for E2B itself. What
  plimsoll does not check is the template itself
  ([limitations.md](limitations.md)).
- **Files are written as the session's user.** A call's files go into a staging
  directory only root can read, and a helper that has dropped to the session's user
  writes them under `/work`, refusing a path that leads out of it through a link, as
  docker's runner does. A project's artifacts are read back as that user too. Because the
  helper is the session's user while it writes, code of the session can read a call's
  files as they land, stop the helper and run them; so a call is marked not dispatched only
  when it failed before the helper started, and never for anything the helper did or
  suffered.
- **A relay belongs to root until it drops.** A cell's relay starts as root and changes
  to the session's user itself; the kernel then marks it as a process another process of
  the same user cannot inspect, so the session's code cannot open its pipes or read its
  memory. Its identity is kept only when its parent is E2B's agent.
- **A suspend is a pause, and it ends the interpreters.** E2B saves the machine, memory
  included, and stops billing it, so the session gives back its concurrency slot. A pause
  cuts every connection into the machine, the relays' included, so the session forgets
  its interpreters first and the sweep after the resume kills them: files survive a
  suspend, a cell's state does not, and the next cell says its interpreter is new.
  Measured on 2026-10-07 on E2B's base template: an open took about 2.2 s, a call on a
  running session about 0.4 to 0.5 s, a pause about 0.3 s, and the call that resumed a
  paused session about 0.8 s.
- **A read-back before every call.** Before each call the session reads the sandbox's
  record from E2B and compares it, apart from its state, with the record at open: network
  traffic out denied, no public traffic in, no proxy, and no allowed addresses or rules
  other than, with `E2B_SESSION_GRANTS=session`, exactly the host and header rule a granted
  call needs; no automatic resume. A difference, or a sandbox E2B no longer has, ends the session.
- **Its time is paid.** E2B bills a running sandbox by the second, so a session draws on
  the daily paid allowances (`SANDBOX_PAID_SECONDS_PER_DAY`, and a caller's
  `paid_seconds_per_day`) for the time its sandbox runs: from the open, or the call that
  resumes it, to its next suspend or its end. It reserves ahead the call's timeout, the
  idle timeout and the time a delete takes; a call the allowances cannot cover is refused,
  not dispatched, reason `capacity`, and the session goes on; a session that can neither
  suspend nor pay for another idle period is closed, and its calls are refused from then
  on, not dispatched, with the end `closed`. Should that close fail (it is tried again,
  above, "A close the daemon makes by itself"), the session's time from then to the end of
  its lifetime and its delete is charged at once, past the allowance if need be, since a
  sandbox nothing has closed bills whether or not an allowance has room; when it is gone
  the charge comes down to the time it ran.
- **Grants are off unless chosen; both ways pass against the live service.** With
  `E2B_GUARD_URL` and `E2B_SESSION_GRANTS` set, a granted call reaches its grant through
  the [guard (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#guard),
  as a run's does. `session` creates the sandbox with the guard's rule and one
  credential for the session's life that serves only the grant of the call in progress:
  between calls the guard is reachable and refuses, as docker's broker socket answers 503.
  `call` creates it [deny-all (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#deny-all) and, for each granted call, puts the rule on with a fresh
  credential through E2B's network update and takes it off after: between calls the guard
  is unreachable, and each granted call costs two more requests to E2B. Unset, a call with
  a grant is refused, not dispatched, reason `unsupported`. The live run (2026-10-08)
  showed that a rule made at create survives a pause and that E2B's record of a sandbox
  shows the rule's header.
- **What a crash leaves.** Each session's sandbox declares its lifetime in its metadata,
  and E2B's own timeout for it is that lifetime plus a minute. E2B kills a running
  sandbox at its timeout, but never expires a paused one, and a sandbox that was paused
  and then resumed goes back to its paused copy at its timeout instead of going away
  (seen 2026-10-07). So a running daemon's cleanup deletes any plimsoll session sandbox
  more than 5 minutes past its declared lifetime, paused ones included, whichever daemon
  opened it.
- **The account's plan can be shorter.** E2B caps how long a sandbox may run at a stretch
  by plan (an hour on its Hobby plan when this was written). A session lifetime longer than
  the cap was not tested: the open may be refused, or the sandbox may stop at the cap, and
  then the session ends at its next call, which finds the sandbox gone.

The conformance suite runs against E2B itself with `make e2b-session-live`, which spends
money (it opens about 30 short-lived machines), and, for free, against a
stand-in for E2B's agent that runs processes in a local container, in the docker suite.

## What sessions do not do

- **Keep a process running between calls, other than the interpreters.** A development
  server inside a session is not supported: every process a call starts, an interpreter's
  children included, is killed by the cleanup after the call's answer, before the next call
  starts.
- **Survive a daemon restart.** Session state lives in one daemon's memory. After a
  restart, the cleanup of leftover sandboxes removes the old sessions' sandboxes once their
  declared lifetime plus the 5-minute margin has passed.
- **Spread across several copies of the daemon.** A session lives in one daemon. Several
  copies behind one address need session affinity: every call of a session must reach the
  daemon that opened it. The <dfn>*guard*</dfn> of the E2B provider has the
  same constraint ([limitations.md](limitations.md)): its guard, the one address an E2B
  machine may call, works only in the daemon process that started the run.
