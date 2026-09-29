# What comes back, and what it means

Result semantics: a failed run is a normal result, an error says whether anything ran, and truncation is machine-readable rather than annotated in the output.

Part of the [plimsoll README](../README.md).

Most sandboxes flatten every bad outcome into one error, and the caller then cannot
tell a user's broken code from a refused request from a run that may have half
happened. That distinction is the difference between retrying safely and repeating
something with side effects.

**A non-zero exit code is a normal result, not a Go error.** The user's code failed;
nothing went wrong with the sandbox. Errors cover refusals (`ErrInvalidRequest`,
`ErrUnsupported`, `ErrDisabled`, `ErrAtCapacity`, `ErrInsufficientIsolation`),
cancellation, and unmatched infrastructure faults.

### Did anything run? The error says so

An error code alone cannot answer that. `InvalidArgument` is usually a request that
failed validation, but a simulation worker can also refuse a table after its container
started; a capacity refusal can come from the daemon's limiter or from the provider.
So a refusal raised before any code was dispatched is **marked**, and the mark carries
a reason:

```go
if reason, ok := sandbox.NotDispatchedReason(err); ok {
	// Nothing ran. Safe to retry, or to send the same request to another daemon
	// when the reason allows it.
}
```

| Reason | Raised when | Worth retrying elsewhere |
|---|---|---|
| `request` | the request is malformed or out of bounds | no, every daemon refuses it |
| `permission` | missing or unknown token, missing scope, caller not allowed the grant profile | no, the caller's identity is the problem |
| `protocol` | the daemon serves another protocol number | only on a daemon that speaks yours |
| `unsupported` | this provider cannot do the operation, or execution is disabled | yes |
| `isolation` | the provider's current isolation is below the request's floor | yes, on a stronger provider |
| `capacity` | admission or the rate limit shed the run | yes, later or elsewhere |

**No mark means the run may have executed**, whatever the error code, so it is never a
safe automatic retry. That is the conservative default: a refusal path that forgot to
mark its error reads as "may have run", never as "safe to repeat". The same call works
on a local provider and through the Go client: on the wire the mark is the
`plimsoll.v1.NotDispatched` error detail, and the client turns it back into the same
Go error. A failure while authenticating that is not a refusal (the caller cancelled,
the token verifier was unreachable) is not marked either.

For projects, per-step failures live in `Steps` and the run's conclusion is a typed
`ProjectResult.Outcome`, which is a stable retry classification rather than a message
to regex:

| Outcome | What happened | Retryable |
|---|---|---|
| `completed` | every step ran; read `Steps` for pass or fail | no, the answer is in the result |
| `setup_failed` | staging the project never got as far as your code | yes, nothing of yours ran |
| `timed_out` | the run exceeded its deadline | with care; side effects may exist |
| `protocol_error` | the runner and the host disagreed | no, this is a bug to report |

For a grader (code that scores a run), treat `protocol_error` as a failed attempt.
No authenticated step result is available, and the guest may already have run.
Do not accept the attempt, retry it automatically, or turn it into a passing score.
Report the protocol error to the operator separately.

Read the isolation errors the same way. `ErrInsufficientIsolation` is marked
`isolation`: **no code ran**. `ErrIsolationEvidenceMismatch` is raised by the client
after a run returned weaker evidence than the floor required, so execution **may
already have happened**; it is never marked and never a safe automatic retry.

### Output comes back exactly as the guest wrote it

Guest output is `bytes` on the wire, not a string, so arbitrary bytes survive verbatim
instead of being lossily repaired into UTF-8. If your agent emits a binary blob, a lone
surrogate, or invalid UTF-8, you receive what it actually wrote.

**Truncation is a field, never a marker injected into your data.** Results carry
`StdoutTruncated`, `StderrTruncated` and `ArtifactsTruncated`, and the retained output
is not annotated in-band. Nothing appends `...[truncated]` into a stream you are about
to parse, so a run that produces JSON still produces parseable JSON right up to the
cut.

Flooding is classified as what it is. An E2B guest that pushes its output past the
transfer budget is a **failed user run** (exit 153, both streams flagged truncated),
not an infrastructure error, so it does not page anyone and it does not get retried as
though the platform failed.

## Why a snippet and a project are separate contracts

`RunJavaScript` and `RunProject` are two operations rather than one with a mode flag,
and the reason is visible in what each one can answer.

- **The answers have different shapes.** A snippet's whole story fits in one exit
  code. A project's story is an ordered list of steps plus a verdict about the list,
  which is what `ProjectResult.Outcome` carries. Forcing both into one response type
  means every caller starts by asking which kind of answer it is holding.
- **Stopping at the first failing step is a contract, not an optimisation.** A caller
  never has to reason about whether a later step ran against a broken artifact.
- **Providers differ in what they can do.** The WASM provider is a small interpreter
  with no compiler, no package manager and no useful file system: it genuinely cannot
  build a project, and it says so with `ErrUnsupported` rather than failing halfway.
  `Describe` reports `supports_project` so a gateway can advertise only what it will
  actually run. A tool that appears in the menu and then refuses half its requests
  teaches an agent to distrust the whole menu.
- **They cost differently by an order of magnitude.** A snippet is small and fast; a
  project starts a large image, writes files and runs a compiler. Effective capacity
  is the smaller of the concurrency cap and what the aggregate memory budget can hold,
  so a heavy operation removes admission slots from everyone, not just its own caller.

Merging them would not remove that asymmetry. It would move it into a mode flag and
make every caller rediscover it at runtime.
