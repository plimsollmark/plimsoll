# What comes back, and what it means

In short: a failed run is a normal result, an error says whether anything ran, and truncation is a field of the result rather than a note inserted into the output.

Part of the [plimsoll README](../README.md).

Most sandboxes flatten every bad outcome into one error, and the caller then cannot
tell a user's broken code from a refused request from a run that may have half
happened. That distinction is the difference between retrying safely and repeating
something with side effects.

**A non-zero exit code is a normal result, not a Go error.** The user's code failed;
nothing went wrong with the sandbox. Errors cover refusals (`ErrInvalidRequest`,
`ErrUnsupported`, `ErrDisabled`, `ErrAtCapacity`, `ErrInsufficientIsolation`),
cancellation, and infrastructure faults that match none of those.

### Did anything run? The error says so

An error code alone cannot answer that. `InvalidArgument` is usually a request that
failed validation, but a simulation worker (the program that runs a compiled
simulator once per row of a parameter table) can also refuse a table after its
container started. A capacity refusal can come from the daemon's limiter or from the
<dfn>*provider*</dfn>, the backend that runs the code. So a refusal raised before any
code was <dfn>*dispatched*</dfn>, handed to the provider to run, is **marked**, and the
mark carries a reason:

```go
if reason, ok := sandbox.NotDispatchedReason(err); ok {
	// Nothing ran. Safe to retry, or to send the same request to another daemon
	// when the reason allows it.
}
```

| Reason | Raised when | Worth retrying elsewhere |
|---|---|---|
| `request` | the request is malformed or out of bounds | no, every daemon refuses it |
| `permission` | missing or unknown token, missing scope, or the caller is not allowed the <dfn>*grant*</dfn> it named (permission to call listed routes of one API, stored on the server as a <dfn>*grant profile*</dfn>); or the run's grant could not be issued (an invalid grant, or its credential could not be made) | no, the caller's identity or the daemon's grant setup is the problem |
| `protocol` | the daemon serves another <dfn>*protocol number*</dfn>, the protocol version every request states | only on a daemon that speaks yours |
| `unsupported` | this provider cannot do the operation, or execution is disabled | yes |
| `isolation` | the provider's current isolation is below the request's <dfn>*floor*</dfn>, the weakest isolation it accepts | yes, on a stronger provider |
| `environment` | the selected software identity (the exact hash of the image the run would use) is unknown or outside the caller's required set; or, in a [session (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#session), the sandbox could not be confirmed (an interpreter could not start, or docker did not answer the read-back before the call) | yes, on a backend with an approved image; a session call can be sent to the same session again |
| `capacity` | <dfn>*admission*</dfn> (the daemon's capacity check just before a run starts) or the rate limit <dfn>*shed*</dfn> the run: refused it at once instead of queueing it | yes, later or elsewhere |

**No mark means the run may have executed**, whatever the error code, so it is never a
safe automatic retry. That is the conservative default: a refusal path that forgot to
mark its error reads as "may have run", never as "safe to repeat". The same call works
on a local provider and through the Go client: on the wire the mark is the
`plimsoll.v1.NotDispatched` error detail, a typed message attached to the RPC error,
and the client turns it back into the same Go error. A failure while authenticating
that is not a refusal (the caller cancelled, the token verifier was unreachable) is not
marked either.

A few refusals happen before the daemon's own code sees the request: the RPC library
refuses a body it cannot parse, one over its size cap, or an unsupported content type,
and the HTTP server answers 404 for a procedure it does not serve. Nothing can have run
for any of them, but they carry no error detail, so the daemon marks them with the
`Plimsoll-Not-Dispatched` response header instead (`unsupported` for a 404, `request`
otherwise). The clients read the header when the error has no detail.

**A mark counts only if the answer is the one to your request.** A proxy or cache that
gets confused and serves one request's answer for another would otherwise make a call
that ran read "nothing ran", and a retry would run it twice. So every official client
sends a fresh random `Plimsoll-Request-Id` (32 lowercase hex digits) with each request,
and the daemon copies it onto every answer. An answer without your ID, or with another
one, is believed in nothing. A success becomes a data-loss error (the code may have run;
Go: `client.ErrAnswerNotBound`), and an error keeps its code but loses its mark, its
session end and anything else it said about the call. A daemon older than protocol 3
does not echo the ID, and protocol 3 is what makes it refuse a newer client before
running anything.

For projects, per-step failures live in `Steps` and the run's conclusion is a typed
`ProjectResult.Outcome`, a stable value to decide retries on rather than a message to
match with a regular expression:

| Outcome | What happened | Retryable |
|---|---|---|
| `completed` | every step ran; read `Steps` for pass or fail | no, the answer is in the result |
| `setup_failed` | preparing the project never got as far as your code | yes, nothing of yours ran |
| `timed_out` | the run exceeded its deadline | with care; side effects may exist |
| `protocol_error` | the runner (the program inside the sandbox that runs the steps) and the host disagreed | no, this is a bug to report |

For a grader (code that scores a run), treat `protocol_error` as a failed attempt.
No authenticated step result is available, and the <dfn>*guest*</dfn> (the code in
the sandbox) may already have run. Do not accept the attempt, retry it automatically,
or turn it into a passing score.
Report the protocol error to the operator separately.

Read the isolation errors the same way. `ErrInsufficientIsolation` is marked
`isolation`: **no code ran**. `ErrIsolationEvidenceMismatch` is raised by the client
after a run returned weaker evidence than the floor required, so execution **may
already have happened**; it is never marked and never a safe automatic retry.

### Output comes back exactly as the guest wrote it

Guest output is `bytes` on the wire, not a string, so arbitrary bytes survive verbatim
instead of being lossily repaired into UTF-8. If your agent emits a binary blob, a lone
surrogate (half of a UTF-16 character pair), or invalid UTF-8, you receive what it
actually wrote.

**Truncation is a field, never a marker injected into your data.** Results carry
`StdoutTruncated`, `StderrTruncated` and `ArtifactsTruncated`, and the output that is
kept has no note written into it. Nothing appends `...[truncated]` into a stream you
are about to parse, so a run that produces JSON still produces parseable JSON right up
to the cut.

Flooding is classified as what it is. A guest on <dfn>*E2B*</dfn> (a hosted service
that runs each sandbox in its own small virtual machine) that pushes its output past
the transfer budget, the cap on how much output comes back, is a **failed user run**
(exit 153, both streams flagged truncated), not an infrastructure error, so it does
not page anyone and it does not get retried as though the platform failed.

## Why a snippet and a project are separate contracts

`RunJavaScript` and `RunProject` are two operations rather than one with a mode flag,
and the reason is visible in what each one can answer.

- **The answers have different shapes.** A snippet's whole story fits in one exit
  code. A project's story is an ordered list of steps plus a verdict about the list,
  which is what `ProjectResult.Outcome` carries. Forcing both into one response type
  means every caller starts by asking which kind of answer it is holding.
- **Stopping at the first failing step is a contract, not an optimisation.** A caller
  never has to reason about whether a later step ran against a broken artifact.
- **Providers differ in what they can do.** The `wasm` provider is a small interpreter
  with no compiler, no package manager and no useful file system: it genuinely cannot
  build a project, and it says so with `ErrUnsupported` rather than failing halfway.
  `Describe`, the RPC that reports what a daemon can do, reports `supports_project` so
  a gateway can advertise only what it will actually run. A tool that appears in the
  menu and then refuses half its requests teaches an agent to distrust the whole menu.
- **They cost differently.** A snippet is small and fast; a project starts a larger
  image, writes files and runs a compiler. Measured through the docker provider on one
  machine (24 cores, Linux 6.6 under WSL2, Docker 29.1.3, local images, median of 20
  runs, 2026-09-29): a one-line snippet took 0.40 s under <dfn>*runc*</dfn> (the program
  Docker uses by default to start containers) and 0.45 s under <dfn>*gVisor*</dfn> (a
  replacement for runc that puts its own kernel between the code and the host's), and a
  one-file TypeScript project (compile with `tsc`, then run with `node`) took 1.95 s and
  4.1 s, five and nine times as long. A bigger build costs more. The number of runs
  that can be in progress at once is the smaller of the concurrency cap and the number
  of per-run memory allowances that fit in the total memory budget, so a heavy
  operation removes admission slots from everyone, not just its own caller.

Merging them would not remove that asymmetry. It would move it into a mode flag and
make every caller rediscover it at runtime.
