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
  customers.** Only the credential that opened a session can call it or close it, and an
  unknown session ID and another caller's get the same refusal. If your service sends many
  customers' code through one plimsoll credential, plimsoll cannot tell those customers
  apart: keeping each customer in a session of their own is your service's job.
- **Key sessions by identities you verified, never by a string your users or a model
  choose.** Derive the key from the customer and the conversation (or job) your own
  authentication established. A key built from user or model input lets one user's call
  land in another user's sandbox, with that user's files and variables. The TypeScript
  client's `CodeSandboxes` takes the key it is given; its Mastra add-on runs a call that
  has no `resourceId` (Mastra's user) in a fresh sandbox rather than in one shared by every
  user without one.
- **The strongest setup is one plimsoll credential per customer** ([callers.md](callers.md)),
  with `SANDBOX_MAX_SESSIONS_PER_CALLER` bounding each, and one session per conversation or
  job inside it.
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
  trace.
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
| `e2b`, `dockercloud` | Not yet. Each would need its own live proof, and their live suites spend money. |
| `wasm` | No. The engine runs in the daemon's own process, and keeping hostile code's state there between calls is the wrong direction. |

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
| `SANDBOX_SESSION_POOL` | Docker only: containers kept ready for sessions, each never used and with its interpreters already running ([Docker](#docker), "A warm pool"). Default 0: none. At most `SANDBOX_MAX_SESSIONS`. |
| `SANDBOX_SESSION_LIFETIME` | Absolute lifetime from open. Default `30m`, at most `12h`. A request may ask for less. |
| `SANDBOX_SESSION_IDLE` | A session with no call for this long is suspended: its sandbox is stopped (`openshell`) or paused (`docker`). Default `5m`; `0` never suspends. A request may ask for less. |
| `SANDBOX_SESSION_DISK_MB` | A call that leaves more than this in the session's files ends the session. Default 1024; 0 means no bound, and nothing is measured. It is measured after each call, not enforced during one ([openshell.md](openshell.md#sessions) says why the `openshell` provider's per-run disk cap does not apply to sessions). On docker it is the used space of the session's three size-capped in-memory filesystems, a file deleted while a process holds it open included. On `openshell` it is a walk of the session's files, which stops at 200,000 entries (counted as over the budget) and which code of the session can hide files from (a deleted file still held open, a directory swapped for a link during the walk), so there it is an estimate, not a bound. |

The defaults are starting points, not measurements of real use:

- 30 minutes bounds how long a session's sandbox lives after its daemon crashes: a
  running daemon's cleanup of leftover sandboxes deletes it once the lifetime plus a
  5-minute margin has passed.
- 5 minutes is long enough for a slow model's turn between tool calls, and short enough
  that an abandoned session gives back its slot soon.
- 1 GiB leaves room for a `node_modules` tree and a build's output.

`Describe`, the procedure that reports what a daemon offers, states `supports_sessions`,
the lifetime and the idle timeout.

## The API

Three procedures beside `Run`, which is unchanged:

- `OpenSession` returns a session ID (128 random bits), the session's
  <dfn>*fingerprint*</dfn> (the SHA-256 hash of the ID), the tier measured at open, and
  when the session expires. The request may name the languages the session's cells will
  use (`languages`), as a hint: a daemon with a warm pool then hands over a
  container with those interpreters already running ([Docker](#docker), "A warm pool"). A
  hint changes how fast the first cell answers, never what runs: a cell in any language
  the daemon states still runs, a language the session's image does not run is dropped
  from the hint, and only a name plimsoll does not know (a typo) is refused, marked not
  dispatched. A session that finishes opening after its caller gave up
  is closed at once, since nobody holds its ID. An answer already on its way when the
  caller gives up is still lost, and that session holds its place until it expires; the
  per-caller session cap bounds how many such places one caller can leave behind.
- `SessionRun` is a `Run` request with the session ID: a snippet, a project, or a
  cell, code for the session's interpreter (below). A
  <dfn>*module run*</dfn>, which runs a compiled simulator once per row of a parameter
  table, has no session form, and a cell has no form outside a session. `SessionRun` answers a `RunResponse` and, when the session
  ended during the call, why. A session that the cleanup after a call ends is reported to
  the next call.
- `CloseSession` ends the session, or collects one that ended by itself. It states how
  many calls ran and the <dfn>*digest*</dfn> (the SHA-256 hash) of the last call's record.

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
  anything that stops the sandbox: an `openshell` suspend or recovery. A docker pause
  keeps it. The next cell then starts a fresh one and says so.
- **No API access.** A cell carries no grant: the interpreter outlives the call, and its
  code with it. A snippet or project call in the same session can carry one if the grant
  allows sessions ([above](#what-a-session-gives-up)).
- **Which languages.** `Describe` states the languages its startup checks proved, on the
  project environment (`languages`). JavaScript is always there; Python needs `python3` in
  the image, as `plimsoll/sandbox-python` has (with NumPy and SciPy). A cell in a language
  the image lacks is refused, marked not dispatched.
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
container, which only `docker exec` and the container's own init have (the command line
rules out the init), and an interpreter must be the only live process with its command
line. Otherwise the cell is refused before
its code is sent, marked not dispatched. A session that never runs a cell keeps no
process between calls, as before.

The interpreters and the programs that drive them are in
[sandbox/internal/sessionkit](../sandbox/internal/sessionkit/); every provider with sessions
runs them. Beside each interpreter the session keeps a relay: a small process attached to
the daemon through one exec held open (`docker exec` on docker, an exec stream on
`openshell`), which writes a cell's files, hands its code to the interpreter and streams its
output back. A warm cell's code therefore reaches its interpreter without a new process;
the call still runs the docker read-back on the host and, after the answer, the sweep. With the sweep after answering
too, a warm cell took about 5 ms on `openshell`, 14 ms under runc and 15 ms under gVisor,
against 73 to 107 ms with a process per cell and the sweep before answering (measured
2026-10-01). The sweep keeps the relay as it keeps the interpreter.

What the relay says is not trusted with anything that matters, because code of the session
can reach it on docker. The relay loads the same small library as the sweep, which makes it
unreadable to other processes of the session once it has started, but in the moment it
starts, an interpreter the session keeps can open its input and output: a timer polling
every millisecond did in 3 of 3 tries (2026-10-01), and could then read later cells' code
and write their answers. The interpreters' own pipes and control socket, under
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
  version 3 record with the error, and the session goes on
  ([run-records.md](run-records.md#a-session-call-that-may-have-run-but-got-no-result)). A call
  whose answer never arrived leaves the client unable to follow the chain, so it sends
  nothing more on that session.
- **The end has its own error.** A call on an ended session is refused
  `FailedPrecondition`, marked not dispatched, with a `SessionEnded` detail; the Go client
  restores it as `sandbox.SessionEndedError` (`errors.Is(err, sandbox.ErrSessionEnded)`).
  A session ends when it is closed, when its lifetime runs out, when its files pass the disk
  budget, when its sandbox's main process ends, when the provider cannot give the next call
  a clean sandbox, when the sandbox changed under it, or when the daemon shuts down. The
  daemon keeps the final count of a session that ended by itself for 10 minutes, so its
  owner's `CloseSession` still gets it.
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
  (`/tmp`, `/dev/shm`, `/work`) a size-capped in-memory filesystem, all capabilities
  dropped, the process limit, and gVisor when `SANDBOX_DOCKER_RUNTIME=runsc`.
- **A main process that does nothing.** Docker's own init runs as process 1 and starts
  `sleep`. The init matters: a process killed between calls whose parent is gone becomes
  process 1's child, and a process 1 that never collects its dead children would keep
  them, each counting against the process limit, for the session's whole life.
- **Every call is a `docker exec`** into the container, in `/work`.
- **After every call, the sweep** kills every process the call left behind, by the same
  program the `openshell` provider runs, and measures the session's files against
  `SANDBOX_SESSION_DISK_MB`. It runs after the answer has gone back: the next call or a
  suspend waits for it (a close does not: it removes the container, sweep and all), and an agent's thinking time between tool calls usually
  hides it (a warm call took about 95 ms under runc instead of about 180 ms, measured
  2026-10-01). So a session that the sweep ends, over its disk budget for instance, is
  reported to the next call rather than in the answer of the call that caused it. Its verdict is its exit status, which another process could
  change only by attaching to the sweep as a debugger does; the sweep loads a small library
  that forbids that once it has started, and in the moment before, only a host whose Yama
  `ptrace_scope` is 0 lets a process attach to one it did not start. When it cannot prove the boundary, the session ends: the one
  recovery that kills everything, a restart, would erase the files.
- **A project's report can be forged inside a session.** A project call runs the same
  runner as a run, and the runner signs its report with a key from the plan it reads on its
  input. In a run nothing else is in the container, but in a session an interpreter it keeps
  can open the runner's input and output while the runner starts, as with the relay above,
  read the key and write a report of its own. So a grader whose verdict the graded code
  must not be able to forge runs it in a single run, not in a session that also ran that
  code's cells.
- **A suspend is a pause.** `docker pause` freezes every process; the files and the
  processes' memory stay. That is why a paused session keeps its concurrency slot.
  Resuming takes about 20 milliseconds (measured 2026-10-01 under runc and gVisor).
- **A read-back before every call.** Anyone who can reach the docker daemon can change a
  running container, for example raise its memory limit with `docker update`. Before each
  call the session compares the container's security settings (image, resource limits,
  mounts, capabilities, networks, user) with what they were at open, and ends the session
  on any difference. The call is refused, marked not dispatched. A read-back docker does
  not answer refuses the call too (reason `environment`), and the session goes on. After a
  call whose exit status may be docker's rather than the code's, a container found paused,
  stopped or gone ends the session; docker's exit status is never reported as the call's.
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
- **Cleanup.** The container is removed when the session ends. A container a crashed
  daemon left behind carries its lifetime as a label, and a running daemon removes it once
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
  51 and 32 ms under gVisor instead of 817 and 891 ms.
  - A waiting container has run only plimsoll's own programs: init, `sleep`, and the
    interpreters with their relays. It goes to one session, and its first cell in each
    language still says its interpreter is new. Closing that session removes the
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

A session's snippets run in the project image, not the snippet image, because one
container runs every call. The answer to `OpenSession` and every call's record state the project image.

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
  daemon that opened it. The <dfn>*guard*</dfn> of the <dfn>*E2B*</dfn> provider has the
  same constraint ([limitations.md](limitations.md)): E2B is a hosted service that runs each
  sandbox in a small virtual machine, and its guard, the one address such a machine may
  call, works only in the daemon process that started the run.
