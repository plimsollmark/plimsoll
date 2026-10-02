# Run records

Every answered `Run` carries a <dfn>*run record*</dfn>: the daemon's statement of what
the caller sent, what came back, the evidence the run executed under, and when. It is a
set of SHA-256 <dfn>*digests*</dfn> (hashes of content, each used as the content's name:
the same digest always means the same bytes) plus a few plain fields, small enough to
store beside every result.

The daemon computes the record and **holds no key**. A <dfn>*harness*</dfn>, a program
outside the daemon that drives runs and checks their results, recomputes the digests from
its own copy of the request and the result, refuses a record that does not match, and
signs the ones that do. The split is deliberate: the daemon runs hostile code (the
`wasm` <dfn>*provider*</dfn>, one of the backends that can run the code, runs it inside
the daemon's own process), so a signing key inside the daemon would be one engine
<dfn>*escape*</dfn> (a bug that lets code act outside its sandbox) away from forging
every record.

What a record proves, and what it does not:

- The two content digests prove that the request and result the caller holds are the
  ones the daemon states it received and returned. A changed byte anywhere in the code,
  a file, a step, the output or an artifact changes a digest.
- The evidence fields are the daemon's statement: the provider (the backend that ran
  the code), the <dfn>*isolation tier*</dfn> (how strong the sandbox's walls
  are), the outer image, the selected software image, the caller's software rule and the
  sandbox policy. They carry the same qualification as the tier everywhere else in
  plimsoll: configuration and provider evidence, **never runtime
  <dfn>*attestation*</dfn>** (cryptographic proof, usually rooted in the hardware, of what
  software a machine is actually running). A compromised daemon can state anything.
- A deterministic workload, one that gives the same output for the same input every
  time, can be checked a stronger way: run the stored request again, on the same backend
  or another, and compare result digests. The <dfn>*physics oracle*</dfn> example, which
  tests agent-written code that balances a simulated pole, already reproduces its
  <dfn>*trajectory*</dfn> (the record of every step of the simulation) to the bit on five
  providers ([the providers example](example-programs.md)).
- A refused or failed run returns an error, not a response, so it has no record. A
  refusal marked as not <dfn>*dispatched*</dfn>, meaning the code was never handed over
  to start running, ran nothing ([run results](run-results.md)).

The Go client checks every record it receives against the request it sent and the
response it got (`record.Check`); a mismatch is `DataLoss` wrapping
`record.ErrMismatch`, with the result still returned, because the run may have
executed. A response with no record is refused the same way (`DataLoss` wrapping
`record.ErrNoRecord`): every daemon answer carries one. `Result.Record`,
`ProjectResult.Record` and `ModuleResult.Record` hold the checked record. They are nil
from an in-process provider, which has no daemon to state one, and when the check
failed: the result then comes back with the `DataLoss` error, and no record, since
the one the daemon sent did not check. Nothing a daemon
executes depends on the record, so adding it did not change the <dfn>*protocol
number*</dfn>: the version every request states, which goes up only when a new request
field changes what a daemon may execute.

## Fields

| Field | Meaning |
|---|---|
| `version` | The encoding version: `2` for an answered call, `3` for a call that may have run but ended in an error (below). New signers sign versions `2` and `3`; verifiers still accept existing version `1` signed records. A verifier refuses an unknown version. |
| `request_sha256` | Digest of what the caller sent: protocol number, isolation <dfn>*floor*</dfn> (the weakest tier the caller accepts), timeout, software rule and payload. Version 1 omits the software rule. |
| `result_sha256` | Digest of the result as sent: exit codes or outcome, output, truncation flags, steps, artifacts, module rows. |
| `provider` | The provider that ran it (the response's `sandbox`). |
| `isolation` | The tier the response states, verbatim. |
| `environment` | The exact outer image artifact or embedded interpreter selected for the run. For Docker this is the image index ID (the ID of the list that points to the image for each platform), which may include fresh build metadata even when the executable image is unchanged. Empty when none is stated. |
| `software_identity` | The <dfn>*manifest*</dfn> (the file listing one image's configuration and layers) of the executable image selected, with its platform, for example `oci-manifest:linux/amd64@sha256:<digest>`. Empty when the provider cannot establish which image it selected. |
| `software_rule_id` | The software rule the caller required, which the daemon checks before the run starts: `exact:<identity>` or `approved:sha256:<digest of approved identities>`. Empty when the caller set no rule. The request digest covers the complete approved list. |
| `policy` | The sandbox policy the provider verified before the run, by digest. For <dfn>*OpenShell*</dfn>, NVIDIA's agent sandbox runtime, it is the policy that sets the sandbox's network and filesystem rules, and `openshell-policy:sha256:...` is the hash its gateway itself reports. Empty for providers without one. |
| `started_unix_ms`, `ended_unix_ms` | When the daemon received the request and when it finished the result. |
| `session`, `sequence`, `previous_sha256` | A call's place in its <dfn>*session*</dfn> (one sandbox kept open for many calls) and its chain: the SHA-256 of the session ID (the ID works like a password for the session, so it is never recorded), the call's number counting from 1, and the previous call's `record_sha256`. Empty or zero for a single run. |
| `unanswered` | Version 3 only: the status code of the error the call ended with (`unknown`, `deadline_exceeded`, `unavailable`, ...), the daemon's own word, never error text. `result_sha256` is then empty. |
| `record_sha256` | Digest of every field above. |

Left out on purpose: the **trace id** (the caller's own ID for matching this run to
its logs; it changes nothing that runs, and leaving it out keeps one request's digest the
same on every attempt), **durations** (they differ on every run, so a replay could never match),
and **advice** (analysis of the run's host-API calls, not its output).

## The encoding

Every digest is lowercase hex SHA-256 over a byte string in which each piece is
preceded by its length. It is not computed over the bytes of a
<dfn>*protobuf*</dfn> message (protobuf is the binary format plimsoll's requests and
responses travel in) or over JSON, so any language reproduces it with a hash function
alone.

- A **value** is its length as an unsigned 64-bit big-endian integer, then its bytes.
- A **field** is its name encoded as a value, then its content encoded as a value.
- A **digest** is SHA-256 over the domain string encoded as a value, then the fields
  in the order listed below. The domain string names what is hashed, for example
  `plimsoll.run-result.v1`.
- Integers are decimal ASCII, with a leading `-` when negative (`124`, `-3`).
  Booleans are `true` or `false`. Floating-point numbers are their IEEE 754 binary64
  bits (a Go `float64` or a JavaScript number), 8 bytes big-endian each, concatenated
  when a field holds several. Strings are their UTF-8 bytes; output and artifact
  contents are their raw bytes.
- A repeated group is preceded by its count, so moving a boundary (a byte from one
  file's path into its content, two steps joined into one) always changes the digest.

### Request: domains `plimsoll.run-request.v1` and `.v2`

Protocol 1 uses the `.v1` domain and the original fields. Protocol 2 uses the
`.v2` domain and adds, after `timeout_ms`, `software_mode` (`""`, `exact` or
`approved`), `software_identities` (count) and each `software_identity` in the
order sent. Then both versions encode `kind`
(`javascript`, `project`, `module` or `cell`), then by kind:

- javascript: `code`, `grant_profile`
- project: `grant_profile`; `files` (count), then per file `file_path`,
  `file_content`; `steps` (count), then per step `step_command`; `artifacts`
  (count), then per path `artifact_path`
- module: `model`, `end_time`, `step`, `rows` (count), then per row `row_values`
- [cell (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#cell) (a session call to the session's interpreter, [sessions.md](sessions.md)):
  `language`, `code`; `files` (count), then per file `file_path`, `file_content`

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
- cell: `exit_code`, `timed_out`, `stdout`, `stderr`, `stdout_truncated`,
  `stderr_truncated`, `interpreter_started`, `interpreter_ended`

A cell's result depends on what earlier cells of its session left in the interpreter,
so a cell is replayed only as part of its session's chain, in order, never alone.

### Record: domains `plimsoll.run-record.v1`, `.v2` and `.v3`

The domain ends in the record's `version` (`plimsoll.run-record.v<version>`), so the
digest covers the version without a field of its own: a record read under another
version's encoding cannot keep its digest.

Version 1 encodes `request_sha256`, `result_sha256`, `provider`, `isolation`,
`environment`, `policy`, then `started_unix_ms`, `ended_unix_ms`, `session`,
`sequence`, `previous_sha256`. Version 2 inserts `software_identity` and
`software_rule_id` after `policy`; every other field stays in the same order.
Version 3 is version 2 with `unanswered` inserted after `result_sha256`.
The approved-set rule ID is SHA-256 over its unique identities sorted in byte
order and joined with a zero byte. Identity syntax excludes zero bytes. The
`RunResponse` repeats the outer environment and selected software identities,
and the official client checks that both agree with the record. It also checks
that the selected software is in the rule the request sent, that the record's tier
meets the request's `minimum_isolation`, and that a version 1 or 2 record names no
`unanswered` code (a field those versions' digests do not cover).

## Reference implementation

This Python computes a version 1 JavaScript request digest from the specification alone. It
gives `585a1b46c55ebacc1dfdd4336e302328c32ed3e2e7e8a8b460d252d0454be8fc`, the first
golden vector (a fixed input kept in a test with the digest it must produce) in
`record/record_test.go`, where the other kinds' vectors are fixed too (all of them were
cross-checked against an independent Python implementation of this page).

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

## A session call that may have run but got no result

A session call can end in an error that does not say nothing ran: an exec stream that
broke after the code started, a cell whose relay was lost. Its code may have run, so it is
part of the session, and its record says so. The daemon numbers it in the chain like any
call, writes a version 3 record (no result digest, the error's status code in
`unanswered`, and as evidence what the session stated when it opened, since there is no
response to read it from), and sends that record with the error as the
`plimsoll.v1.UnansweredCall` error detail. The next call chains after it, and
`CloseSession` counts it. A call refused before it ran (an error marked not dispatched)
gets no record and is not counted.

The official clients check that record (version 3, no result, a status code, the digest
of the request they sent, its software rule and that its software is in it, its tier
against the call's floor, its own digest, its place in the chain, and that its provider,
tier and software are what the session stated at open), keep it in their chain, and
return the error: the session goes on, and the call's outcome
stays unknown. A call whose answer never arrived (a dropped connection) carries no
record, so the client cannot follow the daemon's chain any more, and it refuses every
later call of that session before sending it, marked not dispatched. The Go client's
recorder signs a version 3 record like any other; a bundle stores it as the request
alone, with no response. A Go client whose Recorder cannot keep a whole chain (one that
is not also an `UnansweredRecorder` and a `SessionRecorder`) refuses to open a session,
before anything is sent, rather than drop those records.

Before 2026-10, such a call returned no record: the next call chained cleanly, the close
count matched the client's, and a verified chain could hide a call that ran.

## Signing, verifying and replaying

Package [attest](../attest/) is the harness's half. It runs outside the daemon and
uses the standard library only (Ed25519, SHA-256, JSON).

- **Sign.** The harness checks the record against its own copy of the request and the
  response (`record.Check`), then signs it. A record whose digest does not match its
  fields is never signed, and neither is one whose isolation is below the request's
  `minimum_isolation`, or an answered call's record (version 1 or 2) that names an
  unanswered code, a field its version's digest does not cover. The signed form is a <dfn>*DSSE*</dfn> envelope (Dead Simple
  Signing Envelope, a small standard format that wraps a payload together with its
  signatures:
  [DSSE envelope (EXTERNAL · official docs ↗)](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md))
  around an <dfn>*in-toto*</dfn> statement (a standard format for signed statements about
  software:
  [in-toto Statement v1 (EXTERNAL · official docs ↗)](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)).
  In in-toto's terms, the subject is what a statement is about and the predicate is what
  it says about it. Here:
  - the payload type is `application/vnd.in-toto+json`;
  - there is one subject, named `run-record`, whose `sha256` is the record's own digest
    (over the encoding above, not over a file);
  - the predicate type is `https://plimsollmark.github.io/plimsoll/run-record/v1`, and
    the predicate is the record's fields.

  The key ID is the hex SHA-256 of the public key's PKIX encoding (the standard DER
  encoding of a public key).
- **Close.** When a session ends, the daemon states how many calls it executed and the
  last record's digest; once the client has compared that with the chain it saw, the
  harness signs it as a statement with predicate type
  `https://plimsollmark.github.io/plimsoll/session-close/v1`. A close that does not
  match (some call ran that this client did not make) is `DataLoss` and is not signed,
  and neither is the close of a session the client refused at open.
- **Verify.** A bundle is the file of signed records the harness keeps, in JSON Lines
  (one JSON object per line). A call's line is its stored request and response (their
  binary protobuf encodings, in base64) and its envelope; a close's line is an envelope
  alone. The messages are stored binary because protobuf JSON writes every NaN as `"NaN"`
  and reads it back as one particular NaN, which in Go is not the one the daemon sends
  (every NaN of a module output goes out as the quiet NaN with no sign or payload, so a
  JSON client in Python or TypeScript reads back the bits it hashed), so a stored JSON
  message would no longer match its signed digest. Verification:
  - checks every signature;
  - checks each stored exchange exactly as the client checked it live: both content
    digests recomputed from the stored messages, the provider, tier, environment and
    selected software the stored response states, the request's software rule, and
    that the tier meets the request's floor;
  - requires the record the stored response carries to equal the signed one in every
    field;
  - checks each session's chain: one record version throughout (one daemon served it),
    calls numbered from 1 with no gap, each naming the record before it, and a close
    whose count and last record match.

  A chain without a close fails, because a chain whose last calls were cut off looks
  exactly like an ended session. A session closed before any call is its close alone,
  with a count of zero and no last record. A call another holder of the session ID made
  shows up as a gap, since the daemon numbers the calls it executed.
- **Replay.** The bundle is verified first, and nothing is sent unless it verifies.
  Each stored single run is then sent again and its result digest compared with the
  signed one. It is meaningful for deterministic workloads; one that reads the
  clock or random numbers differs by design.

From Go, one client option signs every run a client makes:

```go
signer := attest.NewSigner(key) // the key stays in the harness process
remote, err := client.New(url, client.WithRecorder(attest.NewHarness(signer, bundleFile)))
```

If the harness fails to keep a record, the client returns the executed result together
with `client.ErrNotRecorded`. The record and the evidence are checked before the harness
sees the exchange, so a failing harness never hides evidence below the floor: that is
`DataLoss` wrapping `sandbox.ErrIsolationEvidenceMismatch`, and the harness is not called.
The command-line harness does the same from files:

```sh
go run ./cmd/plimsoll-attest keygen -out harness          # harness.key (0600), harness.pub
PLIMSOLL_CALLER_TOKEN=... go run ./cmd/plimsoll-attest run \
  -daemon http://127.0.0.1:8746 -key harness.key -bundle runs.jsonl request.json
go run ./cmd/plimsoll-attest verify -pub harness.pub runs.jsonl
go run ./cmd/plimsoll-attest replay -daemon http://127.0.0.1:8746 -pub harness.pub runs.jsonl
```

`request.json` is a `plimsoll.v1.RunRequest` in protobuf JSON, such as
`{"protocol": 2, "javascript": {"code": "console.log(1)"}}`. The token comes from the
environment and the key from a file or `PLIMSOLL_ATTEST_KEY`, so neither appears in a
process listing.
