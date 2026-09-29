# Run records

Every answered `Run` carries a **run record**: the daemon's statement of what the
caller sent, what came back, the evidence the run executed under, and when. It is a
set of SHA-256 digests plus a few plain fields, small enough to store beside every
result.

The daemon computes the record and **holds no key**. A harness outside the daemon
recomputes the digests from its own copy of the request and the result, refuses a
record that does not match, and signs the ones that do. The split is deliberate: the
daemon runs hostile code (on the wasm tier, in its own process), so a signing key
inside it would be one engine escape away from forging every record.

What a record proves, and what it does not:

- The two content digests prove that the request and result the caller holds are the
  ones the daemon states it received and returned. A changed byte anywhere in the code,
  a file, a step, the output or an artifact changes a digest.
- The evidence fields (provider, tier, environment, policy) are the daemon's
  statement, with the same qualification as the tier everywhere else in plimsoll:
  configuration and provider evidence, **never runtime attestation**. A compromised
  daemon can state anything.
- A deterministic workload can be checked a stronger way: run the stored request
  again, on the same backend or another, and compare result digests. The physics
  oracle's trajectory already reproduces to the bit on five providers
  ([the providers example](example-programs.md)).
- A refused or failed run returns an error, not a response, so it has no record. A
  refusal marked not-dispatched ran nothing ([run results](run-results.md)).

The Go client checks every record it receives against the request it sent and the
response it got (`record.Check`); a mismatch is `DataLoss` wrapping
`record.ErrMismatch`, with the result still returned, because the run may have
executed. A response with no record is refused the same way (`DataLoss` wrapping
`record.ErrNoRecord`): every daemon answer carries one. `Result.Record`,
`ProjectResult.Record` and `ModuleResult.Record` hold the checked record; they are nil
only from an in-process provider, which has no daemon to state one. Nothing a daemon
executes depends on the record, so it did not move the protocol number.

## Fields

| Field | Meaning |
|---|---|
| `version` | The encoding version, `1`. A verifier refuses a version it does not know. |
| `request_sha256` | Digest of what the caller sent: protocol number, floor, timeout, payload. |
| `result_sha256` | Digest of the result as sent: exit codes or outcome, output, truncation flags, steps, artifacts, module rows. |
| `provider` | The provider that ran it (the response's `sandbox`). |
| `isolation` | The tier the response states, verbatim. |
| `environment` | The payload kind's content-addressed identity as `Describe` states it (a verified image ID, an image digest, the embedded interpreter's hash); empty when none is stated. |
| `policy` | The sandbox policy the provider verified before the run, by digest (`openshell-policy:sha256:...` is the hash OpenShell's gateway itself reports); empty for providers without one. |
| `started_unix_ms`, `ended_unix_ms` | When the daemon received the request and when it finished the result. |
| `session`, `sequence`, `previous_sha256` | A session call's place in its chain: the SHA-256 of the session ID (the ID is a capability and is never recorded), the call's number from 1, and the previous call's `record_sha256`. Empty or zero for a single run. |
| `record_sha256` | Digest of every field above. |

Left out on purpose: the **trace id** (the caller's correlation key; it changes
nothing that runs, and leaving it out keeps one request's digest the same on every
attempt), **durations** (they differ on every run, so a replay could never match),
and **advice** (analysis of the run's host-API calls, not its output).

## The encoding

Every digest is lowercase hex SHA-256 over a length-prefixed byte string, not over
protobuf or JSON bytes, so any language reproduces it with a hash function alone.

- A **value** is its length as an unsigned 64-bit big-endian integer, then its bytes.
- A **field** is its name encoded as a value, then its content encoded as a value.
- A **digest** is SHA-256 over the domain string encoded as a value, then the fields
  in the order listed below.
- Integers are decimal ASCII, with a leading `-` when negative (`124`, `-3`).
  Booleans are `true` or `false`. Floating-point numbers are their IEEE 754 binary64
  bits, 8 bytes big-endian each, concatenated when a field holds several. Strings are
  their UTF-8 bytes; output and artifact contents are their raw bytes.
- A repeated group is preceded by its count, so moving a boundary (a byte from one
  file's path into its content, two steps joined into one) always changes the digest.

### Request: domain `plimsoll.run-request.v1`

`protocol`, `minimum_isolation` (empty when none), `timeout_ms` (as sent), `kind`
(`javascript`, `project` or `module`), then by kind:

- javascript: `code`, `grant_profile`
- project: `grant_profile`; `files` (count), then per file `file_path`,
  `file_content`; `steps` (count), then per step `step_command`; `artifacts`
  (count), then per path `artifact_path`
- module: `model`, `end_time`, `step`, `rows` (count), then per row `row_values`

### Result: domain `plimsoll.run-result.v1`

`kind`, then by kind:

- javascript: `exit_code`, `timed_out`, `stdout`, `stderr`, `stdout_truncated`,
  `stderr_truncated`
- project: `outcome` (the `ProjectOutcome` number), `outcome_detail`,
  `artifacts_truncated`; `steps` (count), then per step `step_command`,
  `step_exit_code`, `step_timed_out`, `step_stdout`, `step_stderr`,
  `step_stdout_truncated`, `step_stderr_truncated`; `artifacts` (count), then per
  artifact `artifact_path`, `artifact_content`
- module: `outcome`, `outcome_detail`, `width`, `stdout`, `stderr`; `runs` (count),
  then per row `run_status`, `run_outputs`

### Record: domain `plimsoll.run-record.v1`

The domain ends in the record's `version` (`plimsoll.run-record.v<version>`), so the
digest covers the version without a field of its own: a record read under another
version's encoding cannot keep its digest.

`request_sha256`, `result_sha256`, `provider`, `isolation`, `environment`, `policy`,
`started_unix_ms`, `ended_unix_ms`, `session`, `sequence`, `previous_sha256`.

## Reference implementation

This Python computes a JavaScript request digest from the specification alone. It
gives `585a1b46c55ebacc1dfdd4336e302328c32ed3e2e7e8a8b460d252d0454be8fc`, the first
golden vector in `record/record_test.go`, where the other kinds' vectors are pinned
too (all of them were cross-checked against an independent Python implementation of
this page).

```python
import hashlib, struct

def digest(domain, fields):
    h = hashlib.sha256()
    def value(b):
        h.update(struct.pack(">Q", len(b)))
        h.update(b)
    value(domain.encode())
    for name, v in fields:
        value(name.encode())
        value(v if isinstance(v, bytes) else str(v).encode())
    return h.hexdigest()

print(digest("plimsoll.run-request.v1", [
    ("protocol", 1), ("minimum_isolation", "container"), ("timeout_ms", 5000),
    ("kind", "javascript"), ("code", "console.log(1+1)"), ("grant_profile", ""),
]))
```

(`str()` suits integers and strings here; booleans must be written `true` or
`false`, and floats packed with `struct.pack(">d", v)`.)

## Signing, verifying and replaying

Package [attest](../attest/) is the harness's half. It runs outside the daemon and
uses the standard library only (Ed25519, SHA-256, JSON).

- **Sign.** The harness checks the record against its own copy of the request and the
  response (`record.Check`), then signs it as a
  [DSSE envelope (EXTERNAL · official docs ↗)](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)
  around an
  [in-toto Statement v1 (EXTERNAL · official docs ↗)](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):
  payload type `application/vnd.in-toto+json`, one subject named `run-record` whose
  `sha256` is the record's own digest (over the encoding above, not over a file), and
  predicate type `https://plimsollmark.github.io/plimsoll/run-record/v1` with the
  record's fields as the predicate. A record whose digest does not match its fields is
  never signed. The key ID is the hex SHA-256 of the public key's PKIX encoding.
- **Close.** When a session ends, the daemon states how many calls it executed and the
  last record's digest; the harness signs that as a statement with predicate type
  `https://plimsollmark.github.io/plimsoll/session-close/v1`.
- **Verify.** A bundle is JSON Lines: each call is its stored request and response (their
  binary protobuf encodings, base64 in the line) and its envelope; a close is an envelope
  alone. The messages are stored binary because protobuf JSON writes every NaN as `"NaN"`
  and reads it back as one particular NaN, so a module output holding any other NaN
  would no longer match its signed digest. Verification checks
  every signature, recomputes both content digests from the stored messages, requires
  the record the stored response carries to equal the signed one in every field, and
  checks each session's chain: calls numbered from 1 with no gap, each naming the
  record before it, and a close whose count and last record match. A chain without a
  close fails, because a cut tail looks exactly like an ended session. A session closed
  before any call is its close alone, with a count of zero and no last record. A call another
  holder of the session ID made shows up as a gap, since the daemon numbers the calls
  it executed.
- **Replay.** The bundle is verified first, and nothing is sent unless it verifies.
  Each stored single run is then sent again and its result digest compared with the
  signed one. It is meaningful for deterministic workloads; one that reads the
  clock or random numbers differs by design.

From Go, one client option signs every run a client makes:

```go
signer := attest.NewSigner(key) // the key stays in the harness process
remote, err := client.New(url, client.WithRecorder(attest.NewHarness(signer, bundleFile)))
```

A failure to keep a record returns the executed result with `client.ErrNotRecorded`.
The command-line harness does the same from files:

```sh
go run ./cmd/plimsoll-attest keygen -out harness          # harness.key (0600), harness.pub
PLIMSOLL_CALLER_TOKEN=... go run ./cmd/plimsoll-attest run \
  -daemon http://127.0.0.1:8746 -key harness.key -bundle runs.jsonl request.json
go run ./cmd/plimsoll-attest verify -pub harness.pub runs.jsonl
go run ./cmd/plimsoll-attest replay -daemon http://127.0.0.1:8746 -pub harness.pub runs.jsonl
```

`request.json` is a `plimsoll.v1.RunRequest` in protobuf JSON, such as
`{"protocol": 1, "javascript": {"code": "console.log(1)"}}`. The token comes from the
environment and the key from a file or `PLIMSOLL_ATTEST_KEY`, so neither appears in a
process listing.
