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
the daemon's own process), so a <dfn>*signing key*</dfn> (a private key whose signatures anyone holding the
public key can check) inside the daemon would be one engine
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
- A nonzero exit from code sent by the caller is an answered result with a record. A refusal marked
  as not <dfn>*dispatched*</dfn> has no record, because the code was never handed over
  to start running ([INTERNAL · run results →](run-results.md)). An independent run that ends in an
  infrastructure error has no answered result to record. A call in a <dfn>*session*</dfn>
  (one sandbox kept for many calls) that may have
  run but ended without an answer instead has a record with no result and its outcome
  marked unknown ([INTERNAL · unanswered session calls →](#a-session-call-that-may-have-run-but-got-no-result)).

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
number*</dfn>: the version every request states, which goes up when a new request field
changes what a daemon may execute, or when clients start requiring something new of
answers. Protocol 4 (2026-10-23) came with record version 4. Protocol 5 came with
`RunRequest.prefer_warm` and `OpenSessionRequest.warm_only`, which an older daemon would have
ignored, making a sandbox the caller asked it not to. Protocol 6 came with record version 5,
which every client now requires of a live answer: an older daemon refuses the request before
anything runs, instead of running it and giving an answer the client would have to reject.
Protocol 7 (2026-11-21) came with the provider name's character rule (below): every client
refuses a record whose provider holds a control or bidirectional format character, which a
client of protocol 6 accepted, so a daemon of either number refuses a client of the other
before anything runs. Protocol 8 (2026-11-24) came with the head every session call states
(`SessionRunRequest.head`), which an older daemon would ignore. Protocol 9 (2026-11-26) came
with record version 6 and the request domain `plimsoll.run-request.v3`, both for the
`files` kind (one operation on a session's files, [sessions.md](sessions.md)): every client
requires version 6 of a live answer, so a daemon of protocol 8, which writes version 5,
and a client of protocol 9 refuse each other before anything runs.

What a files call's record proves: the request the daemon sent into the sandbox and the answer
the helper gave at that call, no more. A write's record does not prove that the file still holds
the content later (code running in the sandbox owns it and may change it between calls or during one), and a
sequence of read records is no snapshot of a file at one moment; [session-files.md](session-files.md#writes-how-they-publish-what-a-success-proves-what-a-failure-leaves)
states per operation what a successful, a failed and an unanswered call may have done. The
call's scope (the work folder, or the whole sandbox) is part of the request digest, so a record
states which confinement its call had, and no record of a sandbox-scope call, the only scope an
`openshell` session takes, can be read as one confined to the work folder ([sessions.md](sessions.md#files)).

## Fields

| Field | Meaning |
|---|---|
| `version` | The encoding version. A daemon writes `6`, for every record, a call answered or one that may have run but ended in an error (below), and signers sign `6` only; a live answer must carry it. A verifier of stored evidence (`attest`, `record.CheckExchange`) also reads every version an earlier release wrote, by that version's own layout and result domain (below): `1` (v0.10.0 to v0.11.1), `2` (answered calls, v0.12.0 to v0.22.0), `3` (unanswered session calls, v0.15.0 to v0.22.0), `4` (v0.23.0 to v0.27.x) and `5` (v0.28.0 to v0.29.x), so evidence signed under an older release checks without its release's binary. A version no release wrote is `record.ErrVersion`: upgrade the verifier, not "forged". |
| `request_sha256` | Digest of what the caller sent: protocol number, isolation <dfn>*floor*</dfn> (the weakest tier the caller accepts), timeout, software rule and payload. |
| `result_sha256` | Digest of the result as sent: exit codes or outcome, output, truncation flags, steps, artifacts, module rows. |
| `provider` | The provider that ran it (the response's `sandbox`). It is shown to a reader beside the tier, so it holds to the qualification's character rule (below) in every version: valid UTF-8 with no control character and none of the bidirectional controls or line and paragraph separators. A record whose provider holds one is refused, and a daemon refuses every call, before anything runs, when its provider's name holds one. Since 2026-11-21; before, such a name passed every reader's check and was signed. |
| `isolation` | The tier the response states, verbatim: one of `none`, `process`, `container`, `kernel` or `vm` ([INTERNAL · isolation tiers →](isolation-tiers.md)). A record that names anything else, another spelling, `unknown` or nothing at all, is refused, whatever floor the request named. plimsolld writes none: a run whose provider's result names no tier is answered as an internal error, unmarked since the code may have run, and logged as a failed run naming the provider; a session whose provider states no tier for it is refused at the open, marked not dispatched. |
| `isolation_qualification` | The sentence the provider's vendor or its design requires beside the tier, as the response states it (`RunResponse.isolation_qualification`, the same sentence `Describe` states), or empty when the provider states none. Only the [WSL containers (INTERNAL · operator guide →)](wslc.md) provider states one so far: Microsoft's statement that WSL is not a security sandbox for running untrusted code, and, when the operator turns it on, the place of the user-space kernel that also runs inside each run's virtual machine. At most 1024 bytes of UTF-8 with no control character (U+0000 to U+001F, U+007F to U+009F) and none of U+061C, U+200E, U+200F, U+2028, U+2029, U+202A to U+202E or U+2066 to U+2069: Unicode's bidirectional controls, which show text in another order than it is stored, and its line and paragraph separators. A record outside that is refused. Other invisible characters, such as the zero-width space, are not refused. From version 5. |
| `environment` | The exact outer image artifact or embedded interpreter selected for the run. For Docker this is the image index ID (the ID of the list that points to the image for each platform), which may include fresh build metadata even when the executable image is unchanged. Empty when none is stated. |
| `software_identity` | The <dfn>*manifest*</dfn> (the file listing one image's configuration and layers) of the executable image selected, with its platform, for example `oci-manifest:linux/amd64@sha256:<digest>`. Empty when the provider cannot establish which image it selected. |
| `software_rule_id` | The software rule the caller required, which the daemon checks before the run starts: `exact:<identity>` or `approved:sha256:<digest of approved identities>`. Empty when the caller set no rule. The request digest covers the complete approved list. |
| `policy` | The sandbox policy the provider verified for the run, by digest. For <dfn>*OpenShell*</dfn>, NVIDIA's agent sandbox runtime, it is the policy that sets the sandbox's network and filesystem rules, and `openshell-policy:sha256:...` is the hash its gateway itself reports. For docker it is the <dfn>*seccomp*</dfn> profile (the kernel's list of the operations a program may ask it for) this run applied: `seccomp:sha256:...` names the file by the SHA-256 of its bytes (the default, or the variant a run gets when its API permission asked for the local address for client libraries, `sdk_env`, [seccomp.md](seccomp.md)), `seccomp:docker-default` and `seccomp:unconfined` the two docker keywords, and `seccomp:skipped:runsc` a run under the `runsc` runtime, where no host profile is applied. Then, under either runtime, one space and `guest-guard:sha256:...` name the <dfn>*guest guard*</dfn> the run's commands started behind, plimsoll's own filter in front of every program it starts in the container, by the SHA-256 of its program ([seccomp.md](seccomp.md#the-guest-guard-a-second-filter-in-front-of-every-program)): so a docker policy is one of those four seccomp forms, then one space and the guest guard's word, such as `seccomp:sha256:... guest-guard:sha256:...`, and a docker record with no guest guard word comes from a daemon from before the guest guard. A call in a session names the profile its session's container applies for its life, which the session states when it opens: the default (a session never applies the variant), on the record of a call that ended without an answer too. Empty for providers without one. |
| `instance` | The sandbox instance that ran the call, as the response states it: a typed reference, a kind of lowercase letters, digits and `-`, a colon, and an ID of letters, digits and `. _ : -`, at most 160 bytes in all, such as `k8s-pod-uid:` and the UID the Kubernetes API server gave the pod. Empty when the provider names none (so far every provider but the [agent-sandbox (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#agent-sandbox) one). It is an opaque join key, never a name or a path: it lets evidence kept outside plimsoll, such as a log of everything the pod's code asked its kernel to do, be tied to this run. |
| `warm` | `true` when a waiting pool sandbox ran the call (a `Run` of interpreter code with `prefer_warm`, [sessions.md](sessions.md)), as the response states it; `false` otherwise, and on every unanswered call's record. From version 5. |
| `daemon_version` | The answering daemon's plimsoll module version, from the build information Go writes into the binary, as the response states it: a release tag such as `v0.28.0`, a Go pseudo-version for a build from a commit no tag names (the next patch version above the latest release tag the commit's repository holds, then `-0.`, a time and the commit), or `(devel)` when the build states none, as `go test` and a build from a directory replacement do. A repository without plimsoll's release tags gives a pseudo-version above whatever tags it does hold. The example programs and the steps that regenerate their published pages build plimsolld with `-buildvcs=false`, so their records state `(devel)`; the pull-request recipe does the same except when it builds from the top of a plimsoll clone, unchanged, whose checkout holds a release tag naming its commit, where its daemon states that release: the tag itself must be in the checkout (the recipe's workflow fetches the release tags that name the one commit it is set to use), and a checkout without it states `(devel)`. Empty when the daemon could read no build information, or when the version it read is outside the form below. It must be `(devel)` or a `v` and three numbers with optional `-` and `+` parts of letters, digits, `.` and `-`, at most 128 bytes. The daemon's own statement about itself, like every evidence field, and only as true as Go's build stamping: a daemon built inside a git worktree nested in another checkout can state that outer checkout's commit, and `modified` false, as its pseudo-version (seen 2026-11-17). A release built from its tag states its tag. From version 5. |
| `started_unix_ms`, `ended_unix_ms` | When the daemon received the request and when it finished the result. A record that ends before it starts is refused, whether or not the call was answered; for a version 1 or 2 record that reading was retired on 2026-11-21 (below). |
| `session`, `sequence`, `previous_sha256` | A call's place in its session and its chain: the SHA-256 of the session ID (the ID works like a password for the session, so it is never recorded), the call's number counting from 1, and the previous call's `record_sha256`. Empty or zero for a single run. |
| `unanswered` | On the record of a call that may have run but got no answer: the status code of the error it ended with (`unknown`, `deadline_exceeded`, `unavailable`, ...), the daemon's own word, never error text. `result_sha256` is then empty. |
| `record_sha256` | Digest of every field above. |

**Retired on 2026-11-21: version 1 and 2 records that end before they start.** Daemons v0.10.0 to v0.12.0 read a record's start and its end from the wall clock separately, so a clock step between the two readings could write a genuine record whose end is before its start (from v0.13.0 the end is the start plus the time measured on a monotonic clock). A version 2 record does not say which daemon wrote it, so the retirement covers all of versions 1 and 2. From v0.28.0 every verifier (`record`, `attest` and `plimsoll-attest verify-record`, the Python and TypeScript clients; the bill of materials checker reads no version below 4) refuses such a record, with the text "the record ends before it starts, and that reading is retired by the decision of 2026-11-21" (`record.ErrRetired`, which `attest` does not call an invalid statement), so the refusal reads as a retirement, not as a forgery. Every other version 1 and 2 record still verifies, and a record of version 3 or later that ends before it starts is refused as before.

Left out on purpose: the **trace id** (the caller's own ID for matching this run to
its logs; it changes nothing that runs, and leaving it out keeps one request's digest the
same on every attempt), **durations** (they differ on every run, so a replay could never match),
**advice** (analysis of the run's host-API calls, not its output), and for a
[cell (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#cell)
`Run` runs by itself (code for a Python or JavaScript interpreter, its last value printed), **`prefer_warm`** on the request
(whether a waiting pool sandbox may run it, [sessions.md](sessions.md), "A cell for one
call"): it chooses which sandbox runs the cell, not what runs. The answer's `warm`, which
states which did, is signed from record version 5 on. Such a cell's record is a single
run's on either path, with no session fields.

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

A domain string names one encoding for good. Any change to what it covers, a new payload
kind included, takes a new domain string, so a digest under a given domain string always
means one byte layout. Nothing in a result says which result domain hashed it: the
record's version fixes that, so a new result domain comes with a new record version.
Records of versions 1 to 5 state results hashed under `plimsoll.run-result.v1`, which
covers the four kinds listed under it and no other (the `cell` kind joined it on
2026-10-01, before this rule was written down); records of version 6 state results hashed
under `plimsoll.run-result.v2`, which covers those four and `files`. A request's domain is
fixed the same way by the protocol number it states: `plimsoll.run-request.v1` below 2,
`plimsoll.run-request.v2` from 2 to 8, `plimsoll.run-request.v3` (the same encoding with
the `files` kind) from 9. Under a domain that does not cover the `files` kind, a files
payload or result is encoded as no kind (`kind` empty, nothing after it), and every
verifier refuses a record of a files call stated under a version before 6 or a protocol
before 9, whatever its digests. `TestResultDomainCoversItsKinds` in `record/` fails if a
kind appears that the current result domain does not list.

### Request: domain `plimsoll.run-request.v3`

From protocol 9. `protocol`, `minimum_isolation`, `timeout_ms`, `software_mode` (`""`,
`exact` or `approved`), `software_identities` (count) and each `software_identity` in the
order sent, then `kind` (`javascript`, `project`, `module`, `cell` or `files`), then by
kind:

- javascript: `code`, `grant_profile`
- project: `grant_profile`; `files` (count), then per file `file_path`,
  `file_content`; `steps` (count), then per step `step_command`; `artifacts`
  (count), then per path `artifact_path`
- module: `model`, `end_time`, `step`, `rows` (count), then per row `row_values`
- [cell (INTERNAL · trainer site →)](https://plimsollmark.github.io/plimsoll/trainers/glossary.html#cell) (a session call to the session's interpreter, [sessions.md](sessions.md)):
  `language`, `code`; `files` (count), then per file `file_path`, `file_content`
- files (one operation on a session's files, `FilesRun`): `scope` (the `FilesScope`
  number: 1 the work folder, 2 the whole sandbox), then `op`, the operation's word, then
  its fields. Every path, `match` and `after` is raw bytes, not text: a file's name may
  hold any byte but `/` and zero, which is not always UTF-8.
  - stat: `path`
  - read: `path`, `offset`, `max_bytes`
  - write: `path`, `content`, `write_mode` (the `FilesWriteMode` number: 1 replace,
    2 create only, 3 append), `make_parents`
  - list: `path`, `recursive`, `match`, `after`, `budget_bytes`
  - read_many: `paths` (count), then each `path`; `max_bytes_each`, `budget_bytes`
  - make_dir: `path`, `parents`
  - remove: `path`, `dir`
  - rename: `from_path`, `to_path`, `replace`
  - none (an empty operation, which no daemon runs): `op` empty and nothing after it

`plimsoll.run-request.v2` (protocols 2 to 8) is the same encoding without the `files`
kind.

### Result: domain `plimsoll.run-result.v2`

From record version 6. `kind`, then by kind:

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
- files: `outcome` (the `ProjectOutcome` number), `error` (the `FilesError` number, 0 for
  none: one of a closed set, such as 1 not found or 5 a link where the work folder's scope
  follows none), `errno` (the name of the system error it came from, such as `ENOENT`, or
  empty), then `op`, the word of the operation the answer names (empty when there is no
  answer: an error, a timeout), then the answer's fields. Contents and paths are raw
  bytes.
  - stat: `type` (the `FilesEntryType` number: 1 file, 2 folder, 3 link, 4 other),
    `size`, `mode` (the permission bits)
  - read: `content`, `size_at_open` (the file's size when the read opened it, which says
    nothing of its length later)
  - write: `written`
  - list: `entries` (count), then per entry `entry_path`, `entry_type`, `entry_size`;
    `more`
  - read_many: `items` (count), then per item `item_error`, `item_errno`,
    `item_content`, `item_size_at_open`; `more`
  - make_dir, remove, rename: nothing after `op`

### A file call's answer

A files result holds one operation's answer or none, and every verifier (Go's `record`
package, the Python and TypeScript clients) checks that its outcome, error and answer agree
before it believes the result, since a part the digest does not cover, or covers in a shape
no daemon writes, is something a reader could act on that the record does not prove:

- `completed` with no error: exactly one answer, of the operation the request asked, and an
  empty `errno`;
- `completed` with an error: no answer (`errno` may name the system error);
- `timed_out`, `protocol_error` and `runner_failed`: no answer, no error and no `errno`;
- any other outcome (unspecified, `setup_failed`) is not a file call's;
- in a `read_many` answer, each item holds its bytes or its error, never both, and no
  `errno` without an error.

A result holding two answers is malformed: the protobuf oneof cannot carry two, but the JSON
form can, and a verifier that hashed the first would leave the second unproven. The Python
and TypeScript clients refuse it while computing the result digest, and Go's JSON decoder
refuses it. So is a field of another JSON type than its own (a flag that is not `true` or
`false`, such as the string `"false"`; a number that is not an integer in its range): a verifier
that hashed `"false"` by its truthiness as `true` and handed its caller the string would prove
one value and give another. Each verifier decodes a files result once into typed values, and the
digest covers, and the caller gets, those same values; an integer may come as a JSON number or a
decimal string, as proto3 JSON allows, and either reaches the caller as the integer. A call that
breaks the rule is refused as a mismatch, like a result of another kind. An attach that returns a lost call's answer checks all of the rule but the operation:
the attach has the lost call's request digest, not its request. The shared cases of the
`files-answer` family (`internal/clientcases/testdata/records.json`) hold one case for each
shape refused and every client runs them.

`plimsoll.run-result.v1` (records of versions 1 to 5) is the same encoding without the
`files` kind.

A cell's result depends on what earlier cells of its session left in the interpreter,
so a cell is replayed only as part of its session's chain, in order, never alone.

### Record: domain `plimsoll.run-record.v6`

The domain ends in the record's `version` (`plimsoll.run-record.v<version>`), so the
digest covers the version without a field of its own: a record that names another version
cannot keep its digest.

Version 6 encodes every field, every time, empty strings, zeros and `false` included:
`request_sha256`, `result_sha256`, `unanswered`, `provider`, `isolation`,
`isolation_qualification`, `environment`, `policy`, `software_identity`,
`software_rule_id`, `instance`, `warm`, `daemon_version`, `started_unix_ms`,
`ended_unix_ms`, `session`, `sequence`, `previous_sha256`. An answered call's record has
an empty `unanswered`; an unanswered call's has an empty `result_sha256`. Its
`result_sha256` is over `plimsoll.run-result.v2`.

The earlier versions, which verifiers still read, state results hashed under
`plimsoll.run-result.v1`, and record no files call. Version 5 encodes the same fields as
version 6, in the same order (v0.28.0 to v0.29.x; its vectors are frozen in
`record/testdata/published/v0.29.0-golden.json`). The ones before it encode fewer fields,
in this order, and a record of one may state no field its version leaves out (so no record
before version 5 states a qualification, `warm` as `true` or a daemon version):

- version 1: `request_sha256`, `result_sha256`, `provider`, `isolation`, `environment`,
  `policy`, `started_unix_ms`, `ended_unix_ms`, `session`, `sequence`, `previous_sha256`.
  Answered calls only; its `environment` was never checked against the response's.
- version 2: version 1's fields with `software_identity` and `software_rule_id` after
  `policy`. Answered calls only.
- version 3: version 2's fields with `unanswered` after `result_sha256`. Unanswered
  session calls only.
- version 4: `request_sha256`, `result_sha256`, `unanswered`, `provider`, `isolation`,
  `environment`, `policy`, `software_identity`, `software_rule_id`, `instance`,
  `started_unix_ms`, `ended_unix_ms`, `session`, `sequence`, `previous_sha256`. Both kinds
  of call. Published version 4 evidence (bundles, the bills of materials on the example
  pages) is read as it is and not remade.

A request sent under protocol 1 (the records of version 1) has domain
`plimsoll.run-request.v1` and no software fields; every later protocol has the encoding
above. The approved-set rule ID is SHA-256 over its unique identities sorted in byte
order and joined with a zero byte. Identity syntax excludes zero bytes. The
`RunResponse` repeats the outer environment and selected software identities,
and the official client checks that both agree with the record. It also checks
that the selected software is in the rule the request sent, that the record's tier
is one of the five and meets the request's `minimum_isolation`, that an answered call's record names no
`unanswered` code, that the record's `instance` is the response's and has the typed
form, and, from version 5, that its `isolation_qualification`, `warm` and
`daemon_version` are the response's and in their bounds.

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

Floats have vectors of their own in `record/testdata/float-bits.json`, written by
`record/testdata/float_bits.py` from this page alone and checked against the Go
implementation: a module result whose one output is +0, -0, 0.1, the NaN the daemon sends
or a NaN with a payload, each with its digest, and three wrong computations a conforming
implementation must not reproduce (the sign of -0 dropped, the payload of a NaN dropped, a
float written as decimal text). The +0 and -0 pair is the one a JSON digest cannot tell
apart: RFC 8785, the JSON canonicalization scheme, writes both as `0`. The daemon sends
every NaN as `7ff8000000000000`, so the payload pair tests the encoding, not a result
plimsoll returns. A JavaScript number need not keep a NaN's payload, so an implementation in
JavaScript passes that vector only by taking each float as its 64-bit pattern.

## A session call that may have run but got no result

A session call can end in an error that does not say nothing ran: an exec stream that
broke after the code started, a cell whose relay was lost. Its code may have run, so it is
part of the session, and its record says so. The daemon numbers it in the chain like any
call, writes its record (no result digest, the error's status code in
`unanswered`, and as evidence what the session stated when it opened, since there is no
response to read it from), and sends that record with the error as the
`plimsoll.v1.UnansweredCall` error detail. The next call chains after it, and
`CloseSession` counts it. A call refused before it ran (an error marked not dispatched)
gets no record and is not counted.

The official clients check that record (version 6, no result, a status code, the digest
of the request they sent, its software rule and that its software is in it, its tier
against the call's floor, its own digest, its place in the chain, and that its provider,
tier, the tier's qualification and software are what the session stated at open), keep it in their chain, and
return the error: the session goes on, and the call's outcome
stays unknown. A call whose answer never arrived (a dropped connection) carries no
record, so the client cannot follow the daemon's chain any more, and it refuses every
later call of that session before sending it, marked not dispatched. The Go client's
recorder signs such a record like any other; a bundle stores it as the request
alone, with no response. A Go client whose Recorder cannot keep a whole chain (one that
is not also an `UnansweredRecorder` and a `SessionRecorder`) refuses to open a session,
before anything is sent, rather than drop those records.

Before 2026-10, such a call returned no record: the next call chained cleanly, the close
count matched the client's, and a verified chain could hide a call that ran.

## Signing, verifying and replaying

Package [attest](../attest/) is the harness's half. It runs outside the daemon and
uses the standard library only (Ed25519, SHA-256, JSON).

- **Sign.** The harness checks the record against its own copy of the request and the
  response (`record.CheckExchange`, after refusing any record version but the current
  one), then signs it. A record whose digest does not match its
  fields is never signed, and neither is one whose isolation is below the request's
  `minimum_isolation`, or an answered call's record that names an unanswered code, or
  one whose instance is not the response's. The signed form is a <dfn>*DSSE*</dfn> envelope (Dead Simple
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
- **A close that could not be collected.** Sometimes the daemon can never answer a
  close with its count: it restarted (sessions live only in its memory), the close came
  more than 10 minutes after the session ended by itself (the daemon keeps an ended
  session's count that long), another holder of the session ID already closed it, the
  close reached a daemon that never had it (a load balancer in front of several daemons,
  where the session may still be alive on another), or another worker took the session
  over. The daemon then refuses the close, as `NotFound` marked not dispatched ("no such
  session for this caller", which is all it says, whichever of those happened) or as a
  stale owner (`client.ErrStaleOwner`). On
  exactly those two refusals, and on no other failure, the Go client's `Close` has a
  recorder that implements `client.CloseNotCollectedRecorder` (`attest.Harness` does)
  sign the harness's own statement that the close could not be collected, with predicate
  type `https://plimsollmark.github.io/plimsoll/session-close-not-collected/v1`. Its
  fields are `session` (the SHA-256 of the session's ID, as its records name it), `calls_seen` (how many of the session's calls
  this client saw), `last_record_sha256` (the last of those calls' record digest),
  `unanswered_request_sha256` (below), `reason` (`not_found` or `stale_owner`) and
  `noted_unix_ms` (the harness's clock when it signed, its word only).
  `unanswered_request_sha256` is the request digest (what `request_sha256` in a run record
  would say) of a call this client sent after the ones it saw and got no answer for, as
  when a daemon restart drops the connection in the middle of a call: that call may have
  run, changed files or called the caller's own API through the sandbox, and no line of
  the bundle holds it, so the
  statement names it. It is `""` when there was none, and there is never more than one:
  a session's calls go one at a time, and the first that ends with no answer the client
  can check stops the session, so every later call is refused before it is sent. (A call
  that ended with the daemon's record of a call that may have run is in the session's
  chain itself, among the calls seen.) The harness signs it with its own key; the daemon signs nothing
  and holds no key. It ends the session in the bundle, as a close does, and `Close`
  returns `client.ErrCloseNotCollected` wrapping the daemon's refusal: the client sends
  nothing more on that session, its close included, and the harness writes no second
  ending for it. A timeout, a dropped connection or any error without the daemon's mark
  signs nothing, since the close may still be collected by trying again. A client
  process that died signs nothing either: no client is left that saw the calls. Nor is
  anything signed for a session the client had already stopped because an answer failed
  its check (a call came back numbered after a gap, so another holder of the session ID
  ran a call between two of this client's; or a record did not match the call sent): the
  client then holds proof that something it did not send ran, so the session keeps no
  ending, its bundle fails `verify` as an unfinished session's does, and `Close`'s error
  says why.
- **Verify.** A bundle is the file of signed records the harness keeps, in JSON Lines
  (one JSON object per line). A call's line is its stored request and response (their
  binary protobuf encodings, in base64) and its envelope; a close's line is an envelope
  alone; every line also carries its link, and a checkpoint's line is its link alone (see
  below). The messages are stored binary because protobuf JSON writes every NaN as `"NaN"`
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
  - checks each session's chain: calls numbered from 1 with no gap, each naming the
    record before it, and a close whose count and last record match. Records may be
    any published version, each read by its own layout; an unknown one is
    `record.ErrVersion`.

  A chain without a close fails, because a chain whose last calls were cut off looks
  exactly like an ended session. A close's line (and the line of the statement that a
  close could not be collected, below) is its envelope alone: one that also stores a
  request or a response is refused, by `verify` and by `verify-entry` alike, so it is
  never counted as a call. A session closed before any call is its close alone,
  with a count of zero and no last record. A call another holder of the session ID made
  shows up as a gap, since the daemon numbers the calls it executed.

  The harness's statement that a close could not be collected (above) also ends a
  session, under the same rules: its `calls_seen` and last record must be the chain's,
  and nothing of the session may follow it. Such a session is reported as **not proven
  complete**: `verify` exits 0, its first words are "verified, NOT PROVEN COMPLETE:"
  (never a plain "verified", so a reader who stops there is not misled), and it says, for
  the session, "N calls (the session's first N, none between them), NOT PROVEN COMPLETE:
  its close could not be collected (the daemon that answered the close said it has no
  such session for this caller); the harness signed that the client saw these N calls in
  this order, and the daemon's own count of the session's calls is unknown", then what
  that means. What is proven: these are the session's first N calls, in order, none
  removed and none between them, since the chain numbers calls from 1 with no gap and
  each names the one before, and the links catch any line removed or added. What is not:
  that the daemon ran no call after the last (made by another holder of the session ID,
  by the worker that took the session over, or a call this program sent whose answer was
  lost), which only the daemon's count shows, and that the close truly could not be collected, which is the
  harness's word (the daemon's own log line for each close it answers is where an operator
  checks it). When the statement names a call sent with no answer, `verify` and
  `verify-entry` add "and one more call was sent after them with no answer (request R): it
  may have run", R being its full request digest, so a caller can find that call in its
  own log. `-require-close` makes `verify` fail instead unless every session ends in the
  daemon's close (`attest.Report.Complete` in Go, `attest.ErrNotProvenComplete`); use it
  where the daemon's count is required. The Go library is stricter by default than the
  command: `attest.VerifyBundle` and `attest.VerifyExpected` refuse such a session with
  `attest.ErrNotProvenComplete` (`VerifyBundle` returns its report beside the error), so a
  program that checks only the error never takes the session for a closed one; a program
  that accepts it passes `attest.AcceptNotProvenComplete` and must say "not proven
  complete" where it reports the session, as `plimsoll-attest verify` does. Resuming a
  bundle (`attest.ResumeHarness`) and replaying one accept it, since neither claims
  anything about calls the bundle lacks. `-expect` and `-expect-count` (below) show the
  harness was handed every call the caller made, not that the daemon ran no other. A call
  sent with no answer returned no record and is in no line, so it is counted apart, and
  only if the caller says so: in the `-expect` file as a line `unanswered DIGEST`, and as
  a number with `-expect-unanswered M`, each matched against the statements alone
  (`attest.Expected.Unanswered` in Go). Left out, such a call is shown and required of
  nothing. It never makes up for a line: a digest listed without the mark, and
  `-expect-count`, are matched against the bundle's call lines exactly, so an answered
  retry of the lost call cut off with the bundle's tail is found missing. A session with
  neither ending still fails.

  A verifier from v0.18.0 to v0.27.2 refuses a bundle holding this statement: it stops at
  the bundle's first record, of version 5, which those releases do not read, and past that
  it would read the statement as "not a valid run-record statement", since they read any
  line they do not know as a run record. Verify such a bundle with v0.28.0 or
  later. From v0.28.0 on, a line the bundle's key signed
  whose statement is plimsoll's (its predicate type starts
  `https://plimsollmark.github.io/plimsoll/`) but of a kind the verifier does not read is
  refused as `attest.ErrUnknownStatement`: "a kind of plimsoll statement this release does
  not read as a bundle line: a newer release may have written it (upgrade the verifier); if
  none has, plimsoll writes no such line". A later kind of line then does not read as a
  forged one, while the words stay true of the other case: plimsoll also signs statements
  with a harness key that never belong in a bundle (`sign-statement`, below), and only the
  key's holder could put one in a line, since every line's link is checked first.

  - follows the bundle's links: every line carries a second envelope the harness signed,
    a link (`https://plimsollmark.github.io/plimsoll/bundle-link/v1`, one signature, the
    harness's) stating the line's position, the SHA-256 of the line before it and the
    SHA-256 of its own entry; and the last line must be a checkpoint, a link alone that
    states how many lines come before it, which the harness writes when it finishes
    (`Harness.Checkpoint`). The digests are over stored bytes: a line's is the SHA-256
    of the line as stored, without its newline, and an entry's is the same bytes with
    the line's `link` member, always its last, removed. A line must be exactly the
    encoding the harness gives its entry (members in the order `request`, `response`,
    `envelope`, `link`, standard padded base64, no whitespace, no escape the encoder
    would not write, nothing after the object), and a payload exactly the base64 of
    what it decodes to, so no reader finds more in a line than the verifier did.

  So a bundle with a line removed, moved, added or changed anywhere in it, single runs and
  whole sessions included, or with its end cut off, fails: the verified bundle is the
  whole file the harness wrote. Two things it still cannot show. A harness resumed on a
  bundle (`plimsoll-attest run` appends one run per invocation, each ending with a
  checkpoint) leaves earlier checkpoints in the file, and a bundle cut back to one of them
  verifies as whole. And the file being whole says nothing about whether the harness was
  handed every run the caller made. Both take a record kept outside the file: the
  caller's own list of the request digests of its calls, which `plimsoll-attest verify
  -expect FILE` (or `-expect-count N`) holds the bundle to (`attest.VerifyExpected`),
  or an entry in an append-only log such as a transparency log. A call's request digest
  is `request_sha256` in its run record (`Result.Record.RequestSHA256` in Go), which the
  client has already checked against the request it sent; every call that returned a
  record counts, an unanswered session call's included. The bundle must hold exactly
  those requests, each as many times as the list names it, so a call missing, a call
  added, or a call whose request is not the one the caller sent fails. Two calls with
  one digest sent the same request (the digest leaves out only the `trace_id`), so
  counting them is exact and no ID has to be unique. Each line of the file is one
  digest; anything after it on the line, such as the call's `trace_id`, is a label the
  check ignores. The list binds what was sent, not what came back: a caller that also
  needs a result proven compares that call's `result_sha256` with its own log. A call the
  client sent and got no answer for goes on a line of its own as `unanswered DIGEST`
  (above); `-expect-count N` counts the calls that returned a record, and
  `-expect-unanswered M` the calls sent with no answer.
- **Replay.** The bundle is verified first, and nothing is sent unless it verifies.
  Each stored single run is then sent again, and each recorded session's calls in
  their order into a fresh session, and every result digest is compared with the
  signed one. A request recorded with permission for its code to call the caller's own
  API is reported and not sent, since sending it would call that API again
  (`-with-grants` sends it), and a request recorded under another protocol number is
  never sent, since the fields that number governs may run differently now. It is meaningful for deterministic workloads; one
  that reads the clock or random numbers differs by design.

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
go run ./cmd/plimsoll-attest verify-entry -pub harness.pub -line 3 runs.jsonl
go run ./cmd/plimsoll-attest verify-record -pub harness.pub -line 1 old-runs.jsonl
go run ./cmd/plimsoll-attest replay -daemon http://127.0.0.1:8746 -pub harness.pub runs.jsonl
```

What the command prints of a daemon's answer, a bundle or a file (a provider's name, an
isolation tier, an error's text) shows each control character (escape, carriage return and
line feed among them, and the C1 range), line or paragraph separator and bidirectional
control as a visible escape, such as `\x1b` or `\u202e`, so a hostile daemon cannot
rewrite the screen or forge a line of the command's own. JSON it prints (`open-statement`,
`verify-receipt`) carries the same characters as JSON escapes, which read as the same
value. `plimsoll-clients`, `plimsoll-withheld` and the daemon's log lines do the same.

`verify-entry` checks one call line on its own (`attest.VerifyEntry`): its signature, its
stored request and response against the signed record, and its link at the place it
states. It is for a line whose bundle is not whole yet, such as a call of a session still
open, whose chain has no close statement and so fails `verify`. It says what it does not
establish: that the line is in the bundle its holder names, that the bundle around it is
whole, and, for a session call, that its session's chain is. `verify` is unchanged.
On a session's ending line (the daemon's close, or the harness's statement that the close
could not be collected) it checks the line's link and the statement (`attest.VerifyEnding`)
and prints what the statement says, naming the second as the harness's word and not the
daemon's.

`verify-record` checks one call line with no link at all (`attest.VerifyCall`): its
signature, and its stored request and response against the signed record. It is how a
record from before links (v0.10.0 to v0.17.x, whose bundles no reader accepts whole) is
still checked, one line at a time. It proves the recorded exchange, not the line's place:
a holder could have dropped or reordered such lines unseen, which is what links were
added to prevent.

```sh
go run ./cmd/plimsoll-attest sign-statement -key harness.key \
  -type https://in-toto.io/attestation/test-result/v0.1 -out test-result.intoto.json statement.json
go run ./cmd/plimsoll-attest open-statement -pub harness.pub \
  -type https://in-toto.io/attestation/test-result/v0.1 test-result.intoto.json
```

`sign-statement` signs an in-toto statement the harness makes about evidence it has checked
(`attest.SignStatement`): `statement.json` holds `{"subject": [...], "predicate": {...}}`, and
the envelope is the standard signed form, so anything that reads a standard predicate (in-toto's
test-result, OpenVEX) takes it as it is. It refuses the run record, link and close types and
the statement that a close could not be collected, which are signed only through their own
checked paths. `open-statement` checks the signature and the
type and prints `{"keyid", "subject", "predicate"}`. A signature says who made the statement,
not that the predicate is true: the harness signs what it is given, so a reader rebuilds the
predicate from the evidence it names and compares, as `examples/pr-receipt/verify.py` does.

`request.json` is a `plimsoll.v1.RunRequest` in protobuf JSON, such as
`{"protocol": 9, "javascript": {"code": "console.log(1)"}}`. The token comes from the
environment and the key from a file or `PLIMSOLL_ATTEST_KEY`, so neither appears in a
process listing. A bundle holds every run's request and response in full, the submitted
code and its output included, so on Unix `run` creates it readable by its owner only
(0600), and refuses, before the run, to add to an existing bundle its group or others
can read or write unless `-shared-bundle` says it is shared on purpose; it never changes
an existing bundle's mode. On Windows, where access is a matter of ACLs, a new bundle
takes the ACL its directory passes on and no access is checked, so keep bundles in a
directory only you can read.
An append that fails part way is cut back and the cut synced to disk, so the bundle is
left as it was and the next run continues it; the record it could not append goes to a
new owner-only side file (`runs.jsonl.unsealed-<UTC time>-<random>.jsonl`), never into
an existing one. If the cut or its sync fails too, the error says so: the bundle may then
hold part of a line after a crash, so verify it before the next run.

## Timestamped assertions about an artifact

For separately configured signer roles and outside timestamps over complete signed
envelopes, see the <dfn>*receipt*</dfn> profile, which groups signed claims about a file,
and its [INTERNAL · offline verification guide →](receipt-verification.md).
That optional checker verifies artifact bytes and authenticated assertions without
independently repeating an application's tests or proving organizational independence.
