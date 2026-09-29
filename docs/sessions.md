# Sessions

A <dfn>*session*</dfn> keeps one sandbox open for many calls. The files a call writes
are there for the next call; no process a call starts outlives it. An agent that edits,
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

## Which providers

A <dfn>*provider*</dfn>, the backend that actually runs the code, offers sessions
through the optional `sandbox.SessionProvider` interface. It states that it has them only
once it passes the shared test suite in [sandbox/sessiontest](../sandbox/sessiontest/),
which every implementation runs. The suite checks that:

- files persist across calls, including between a snippet call and a project call;
- sessions share nothing;
- no process outlives its call: not a detached child, not a `setsid` grandchild, not a
  background child;
- a call's deadline ends the call and not the session;
- output held open by a leftover process ends at the deadline, and the process holding it
  dies;
- a suspend keeps the files;
- a floor above the session's <dfn>*isolation tier*</dfn> (how strong its sandbox's walls
  are: `process`, `container`, `kernel` or `vm`) is refused before dispatch;
- close and the lifetime end the session.

| Provider | Sessions |
|---|---|
| `openshell` | Yes. How it keeps the boundary between calls: [docs/openshell.md](openshell.md#sessions). |
| `e2b`, `dockercloud` | Not yet. Each would need its own live proof, and their live suites spend money. |
| `docker` | Not yet: a container would need a supervisor process inside it to find and kill leftover processes between calls. |
| `wasm` | No. The engine runs in the daemon's own process, and keeping hostile code's state there between calls is the wrong direction. |

## Turning them on

Sessions are off unless the operator enables them, because a session holds a sandbox
between calls. The daemon refuses to start when they are enabled for a provider that
does not support them.

| Setting | Meaning |
|---|---|
| `SANDBOX_MAX_SESSIONS` | Open sessions at once, daemon-wide. Default 0: sessions off. |
| `SANDBOX_SESSION_LIFETIME` | Absolute lifetime from open. Default `30m`, at most `12h`. A request may ask for less. |
| `SANDBOX_SESSION_IDLE` | A session with no call for this long is suspended. Default `5m`; `0` never suspends. A request may ask for less. |
| `SANDBOX_SESSION_DISK_MB` | A call that leaves more than this in the session's files ends the session. Default 1024; 0 means no bound. It is measured after each call, not enforced during one ([openshell.md](openshell.md#sessions) says why the `openshell` provider's per-run disk cap does not apply to sessions). |

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
  when the session expires.
- `SessionRun` is a `Run` request with the session ID: a snippet or a project. A
  <dfn>*module run*</dfn>, which runs a compiled simulator once per row of a parameter
  table, has no session form. `SessionRun` answers a `RunResponse` and, when the session
  ended during or after the call, why.
- `CloseSession` ends the session, or collects one that ended by itself. It states how
  many calls ran and the <dfn>*digest*</dfn> (the SHA-256 hash) of the last call's record.

Each request carries the <dfn>*protocol number*</dfn>, the protocol version the client
speaks, and gets the same check as `Run`: a daemon serving a different version refuses it
before reading the payload. A daemon that predates sessions answers the new procedures
`Unimplemented`, marked not dispatched (nothing ran). Session calls use a request message
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

## What the daemon guarantees

- **One owner.** The session belongs to the <dfn>*principal*</dfn> that opened it: the
  authenticated caller, as the daemon's clients file names it. An unknown ID and another
  principal's ID get the same `NotFound`, so an ID's existence never leaks. The ID works
  like a password for the session, so it is never logged or recorded; audit lines and
  records carry the fingerprint instead. With no auth configured (open dev mode, which the
  daemon warns about at startup) every caller is the same anonymous principal, so there a
  session is protected by its ID alone.
- **One call at a time, in order.** Calls run one after another, never at once. Each
  call's record names the digest of the previous call's record and its own number,
  counting from 1. The Go client checks every record against the chain it has seen, so a
  call made by anyone else holding the ID shows as a gap at the next call and at the close
  (`DataLoss` wrapping `record.ErrChain`). The chain covers calls that returned a result; a
  call that failed after dispatch returns no record.
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
  `SANDBOX_TOTAL_MEMORY_MB`. A suspended session holds none; the call that resumes it takes
  a slot first, and a capacity refusal there ran nothing and is safe to retry. Every call
  is charged to the caller's rate limit. Opening a session is charged like a run. A call
  gets the daemon's own five-minute timeout ceiling, exactly as a run does.

## What sessions do not do

- **Keep a process running between calls.** A development server inside a session is not
  supported: every call's processes die at its end.
- **Survive a daemon restart.** Session state lives in one daemon's memory. After a
  restart, the cleanup of leftover sandboxes removes the old sessions' sandboxes once their
  declared lifetime plus the 5-minute margin has passed.
- **Spread across several copies of the daemon.** A session lives in one daemon. Several
  copies behind one address need session affinity: every call of a session must reach the
  daemon that opened it. The <dfn>*guard*</dfn> of the <dfn>*E2B*</dfn> provider has the
  same constraint ([limitations.md](limitations.md)): E2B is a hosted service that runs each
  sandbox in a small virtual machine, and its guard, the one address such a machine may
  call, works only in the daemon process that started the run.
