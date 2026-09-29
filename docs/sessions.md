# Sessions

A **session** keeps one sandbox for many calls. The files a call writes are there for
the next call; no process a call starts outlives it. An agent that edits, builds and
tests in a loop pays for one sandbox instead of one per step, and its later steps see
what its earlier steps wrote. Each call keeps a run's contract: a typed result, the
floor checked before dispatch, bounded output, one audit line, and a
[run record](run-records.md), chained to the call before it.

A working example with a signed chain of records:
[One sandbox, five calls ↗](https://plimsollmark.github.io/plimsoll/examples/sessions/index.html),
written by `go run ./examples/sessions`.

## Which providers

A provider offers sessions through the optional `sandbox.SessionProvider` interface
and states them only once it passes the conformance suite in
[sandbox/sessiontest](../sandbox/sessiontest/), which every implementation runs:
files persist across calls and payload kinds, sessions share nothing, no process
outlives its call (a detached child, a `setsid` grandchild, a background child), a
call's deadline ends the call and not the session, output held open by a leftover ends
at the deadline and the holder dies, a suspend keeps the files, a floor above the
session's tier is refused before dispatch, and close and the lifetime end the session.

| Provider | Sessions |
|---|---|
| `openshell` | Yes. How it keeps the boundary between calls: [docs/openshell.md](openshell.md#sessions). |
| `e2b`, `dockercloud` | Not yet. Each would need its own live proof, and their live suites spend money. |
| `docker` | Not yet: a container would need a supervisor inside it to sweep processes between calls. |
| `wasm` | No. The engine runs in the daemon's own process, and keeping hostile code's state there between calls is the wrong direction. |

## Turning them on

Sessions are off unless the operator enables them, because a session holds a sandbox
between calls. The daemon refuses to start when they are enabled for a provider
without them.

| Setting | Meaning |
|---|---|
| `SANDBOX_MAX_SESSIONS` | Open sessions at once, daemon-wide. Default 0: sessions off. |
| `SANDBOX_SESSION_LIFETIME` | Absolute lifetime from open. Default `30m`, at most `12h`. A request may ask for less. |
| `SANDBOX_SESSION_IDLE` | A session with no call for this long is suspended. Default `5m`; `0` never suspends. A request may ask for less. |
| `SANDBOX_SESSION_DISK_MB` | A call that leaves more than this in the session's files ends the session. Default 1024; 0 means no bound. |

The defaults are starting points, not measurements of real use: 30 minutes bounds how
long a crashed daemon's session sandbox lives (the lifetime plus the reaper's 5-minute
margin), 5 minutes is long enough for a slow model's turn between tool calls and short
enough that an abandoned session gives back its slot soon, and 1 GiB leaves room for a
`node_modules` tree and a build's output.

`Describe` states `supports_sessions`, the lifetime and the idle timeout.

## The API

Three procedures beside `Run`, which is unchanged:

- `OpenSession` returns a session ID (128 random bits), the session's fingerprint (the
  SHA-256 of the ID), the tier measured at open, and when it expires.
- `SessionRun` is a `Run` request with the session ID: a snippet or a project (a module
  run has no session form). It answers a `RunResponse` and, when the session ended during
  or after the call, why.
- `CloseSession` ends the session, or collects one that ended by itself, and states how
  many calls ran and the last call's record digest.

Each request states the protocol number and gets `Run`'s check. A daemon that predates
sessions answers the new procedures `Unimplemented`, marked not dispatched. Session
calls use a request message of their own, so an older daemon can never drop the session
ID and run the payload as a fresh run.

From Go:

```go
remote, _ := client.New(url, client.WithToken(token))
s, err := remote.OpenSession(ctx, client.SessionOptions{MinimumIsolation: sandbox.IsolationContainer})
res, err := s.RunJavaScript(ctx, sandbox.Request{Code: `require("fs").writeFileSync("/tmp/a", "1")`})
res, err = s.RunJavaScript(ctx, sandbox.Request{Code: `console.log(require("fs").readFileSync("/tmp/a", "utf8"))`})
summary, err := s.Close(ctx)
```

## What the daemon guarantees

- **One owner.** The session belongs to the principal that opened it. An unknown ID and
  another principal's ID get the same `NotFound`, so an ID's existence never leaks. The ID
  is a capability: it is never logged or recorded; audit lines and records carry the
  fingerprint. With no auth configured (open dev mode, which the daemon warns about at
  startup) every caller is the same anonymous principal, so there a session is protected by
  its ID alone.
- **One call at a time, in order.** Calls are serialized, and each call's record names
  the previous call's record digest and its own number from 1. The Go client checks every
  record against the chain it has seen, so a call made by anyone else holding the ID shows
  as a gap at the next call and at the close (`DataLoss` wrapping `record.ErrChain`). The
  chain covers calls that returned a result; a call that failed after dispatch returns no
  record.
- **The end is typed.** A call on an ended session is refused `FailedPrecondition`,
  marked not dispatched, with a `SessionEnded` detail; the Go client restores it as
  `sandbox.SessionEndedError` (`errors.Is(err, sandbox.ErrSessionEnded)`). A session ends
  when it is closed, at its lifetime, past its disk budget, when its sandbox's main process
  ends, when the provider cannot give the next call a clean sandbox, when the sandbox
  changed under it, or at shutdown. A session that ended by itself stays collectable for 10
  minutes, so its owner's close still gets the final count.
- **Admission.** A running session holds one concurrency slot, and its memory share of
  `SANDBOX_TOTAL_MEMORY_MB` with it. A suspended session holds none; the call that resumes
  it takes a slot first, and a capacity refusal there ran nothing and is safe to retry.
  Every call is charged to the caller's rate limit. Opening a session is charged like a run.
  A call gets the daemon's own five-minute ceiling, exactly as a run does.

## What sessions do not do

- **Keep a process running between calls.** A development server inside a session is not
  supported: every call's processes die at its end.
- **Survive a daemon restart.** Session state lives in one daemon's memory. After a
  restart the reaper removes the old sessions' sandboxes once their declared lifetimes
  pass.
- **Spread across replicas.** A session lives in one daemon. Several replicas behind one
  address need session affinity, the same constraint the E2B guard documents.
