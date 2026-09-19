# What comes back, and what it means

Result semantics: a failed run is a normal result, an error means nothing ran, and truncation is machine-readable rather than annotated in the output.

Part of the [plimsoll README](../README.md).

Most sandboxes flatten every bad outcome into one error, and the caller then cannot
tell a user's broken code from a refused request from a run that may have half
happened. That distinction is the difference between retrying safely and repeating
something with side effects.

**A non-zero exit code is a normal result, not a Go error.** The user's code failed;
nothing went wrong with the sandbox. Errors are reserved for pre-dispatch failures
(`ErrInvalidRequest`, `ErrUnsupported`, `ErrDisabled`, `ErrAtCapacity`), cancellation,
and unmatched infrastructure faults.

For projects, per-step failures live in `Steps` and the run's conclusion is a typed
`ProjectResult.Outcome`, which is a stable retry classification rather than a message
to regex:

| Outcome | What happened | Retryable |
|---|---|---|
| `completed` | every step ran; read `Steps` for pass or fail | no, the answer is in the result |
| `setup_failed` | staging the project never got as far as your code | yes, nothing of yours ran |
| `timed_out` | the run exceeded its deadline | with care; side effects may exist |
| `protocol_error` | the runner and the host disagreed | no, this is a bug to report |

Read the isolation errors the same way. `ErrInsufficientIsolation` means **no code
ran**. `ErrIsolationEvidenceMismatch` means execution **may already have happened**,
which is why it is never a safe automatic retry. `ErrAtCapacity` is the one that is
cleanly retryable with backoff, because admission refused the run before it started.

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

