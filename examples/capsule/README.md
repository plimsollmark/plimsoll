# capsule: plimsoll run records as Agent Action Capsules

An Agent Action Capsule is a signed JSON record of one action an automated system took:
why it ended as it did, what is known about its effect, and who vouches for that
([EXTERNAL · specification draft ↗](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/),
[EXTERNAL · reference implementations ↗](https://github.com/action-state-group/agent-action-capsule)).
This program states each call in plimsoll's published session bundle
(`docs/examples/sessions/bundle.jsonl`) as a capsule, under draft -05, and writes
[the page](../../docs/examples/capsule/index.html) with every capsule ID and each
verifier's result.

It trusts nothing it has not verified. plimsoll's own verifier (`attest.VerifyBundle`)
checks the bundle's signatures, records and chain first, and only a record it accepted
becomes a capsule. The capsules are then checked by the capsule project's Go verifier and
by its independent Python reference verifier, including copies broken on purpose.

## Run it

```sh
cd examples/capsule
go run .                                                  # writes ../../docs/examples/capsule/
go run . -aac "$(command -v agent-action-capsule)"        # also runs the Python verifier
AAC_VERIFIER="$(command -v agent-action-capsule)" go test ./...
```

The Python verifier is `pip install "agent-action-capsule[envelope]==0.6.0"`, the version
the published page was checked with; the `envelope` extra brings scitt-cose, which
`verify_envelopes.py` uses to check every signature independently of the Go signer
(`requirements.txt` pins it and its dependencies by hash; `make capsule-suite` at the
repository root installs it from that lockfile and runs this module's tests with it,
which is what CI does). With no flags, the program reproduces every published
capsule ID: an ID depends only on the capsule's content, and on the published bundle
the operator, developer and import time default to the published ones. The signatures
differ on each run, because each run makes its own key and writes only the public half
(`producer.pub`).

Any other bundle (`-bundle`, with its harness key in `-pub`) must be given `-operator`,
`-developer` and `-imported-at`: the published defaults name the sessions example and an
import in the past, which would be false of someone else's records, so the program
refuses to apply them. Such a bundle gets its capsules, their envelopes, the producer key and
every check, printed, but no page: the page tells the published session's story.

**This is its own Go module.** The capsule emitter needs Go 1.27 and brings dependencies
(COSE and CBOR libraries) that plimsoll's own module does not take on: plimsoll is a
hostile-code trusted computing base, and every module that imports it would inherit them.
Nothing in plimsoll's `go.mod` changes, and `go build ./...` at the repository root does not
see this directory.

Its own `toolchain` line selects Go 1.27.2, which patches the Go 1.27 standard-library
advisories reported on October 8. The root module's compiler selection does not apply
here. To scan this module, the scanner must also be built with a compiler that supports
Go 1.27; from this directory, use the repository's pinned scanner without replacing the
installed one:

```sh
GOTOOLCHAIN=go1.27.2 go run golang.org/x/vuln/cmd/govulncheck@"$(sed -n 's/^govulncheck=//p' ../../gate-tools.versions)" ./...
```

[EXTERNAL · Go security advisory ↗](https://pkg.go.dev/vuln/GO-2026-6599)
lists Go 1.27.2 as the patched version for the template-execution issue this program's
page renderer reaches. Scanner reachability alone does not establish an exploitable
input to this offline example.

## The mapping

| plimsoll outcome | `verdict_class` | `effect.status` | derived `effect_mode` | `reason_digest` |
|---|---|---|---|---|
| `completed`, any exit code (a snippet, a cell or a project) | `executed` | `confirmed` | `confirmed` | absent |
| `timed_out` | `timeout` | `dispatched` | `dispatched_unconfirmed` | the outcome |
| `setup_failed` | `errored` | `dispatched` | `dispatched_unconfirmed` | the outcome |
| `protocol_error` | `errored` | `dispatched` | `dispatched_unconfirmed` | the outcome |
| a session call that may have run but got no answer (a version 3 record) | `errored` | `dispatched` | `dispatched_unconfirmed` | the error's status code |

The table is `verdicts` in [mapping.go](mapping.go); a snippet and a cell read as
`timed_out` or `completed`, and a call that got no answer, whose bundle entry stores a
request and a signed record but no response, is `unanswered` there. A completed run is
`confirmed` whatever its exit code: plimsoll observed the result, and the exit code is
inside the digested response. `setup_failed` and `protocol_error` share a class and a
status and may carry no response digest, so the reason digest, over
`{"plimsoll_outcome": ...}` (or `{"plimsoll_unanswered": ...}` for a lost answer), is
what keeps them apart. Session calls chain with `relation: follows`.

Every row uses `effect_attestation: runtime_claimed`: the capsule records the daemon's
statement, checked against the stored bytes by the harness that signed it, not an
observation this program made. The stronger grade, `gate_executed`, is for a producer that
observed the effect boundary itself. Whether a collector restating a gate's signed record
may carry it was put to the draft's author (Q1 of the implementation report) and is not
answered, so the capsules claim what this program can vouch for; the draft reads an
unrecognized grade as no stronger than `runtime_claimed` anyway, so a consumer loses
nothing it could have relied on. Every row also states `irreversibility_class: two_way`,
the lowest of the draft's four classes, because every call stated here ran with no
host-API grant, so whatever it did stayed inside the sandbox.

Two kinds of call are refused, not mapped. A **granted** call (a `grant_profile` on its
snippet or project request) could have reached a host API with PUT, POST or DELETE, and
the response carries no call trace (it stays in the daemon), so what the call did outside
the sandbox is unknown; the class vocabulary has no value for "unknown", so the program
stops rather than guess. A **module** run (a compiled simulator run once per parameter row)
has a request (`end_time`, `step`) and outputs that are doubles, and draft -05 forbids JSON
floating-point values in digest-bearing material (Section 2). The emitter refuses most of
them but digests `-0` as `0`, as RFC 8785 requires (its Appendix B), so a JSON digest could not
bind the sign of a zero output either. plimsoll's own record digest keeps every float's 64
bits ([docs/run-records.md](../../docs/run-records.md#the-encoding)), and the
capsule's `source_ref` cites that record, but -05 has no place to put the result digest
itself.

The published bundle exercises only the first row. `TestEveryVerdictRowVerifies` builds a
capsule for every row from one identical record, the unanswered row included, so it passes
only if the capsule's own fields tell the outcomes apart, and checks each with both
verifiers; `TestSessionWithCellAndUnansweredCall` states a freshly signed bundle holding a
cell and a lost answer, whole.

The capsule's `request_digest` and `response_digest` are the draft's JSON digests over the
protobuf JSON mapping of each message, as the Go protobuf library writes it for the schema
this program was compiled with. They are reproducible with this program, not from a
specification; plimsoll's own record digests, which the capsule cites through `source_ref`,
are the specified ones ([docs/run-records.md](../../docs/run-records.md)).

## What the capsules claim

- **Backfilled.** `provenance_mode: backfilled`, `time_rung: self_attested`, `source_ref`
  the plimsoll run record by the SHA-256 plimsoll's verifier checks, and `import_batch` the
  SHA-256 of the bundle file. An import must come strictly after its record's time; one at
  the same instant is the shape the capsule verifier refuses as laundering.
- **Collected.** `provenance: collector`: this program read signed records afterwards, so
  the effect grade is `runtime_claimed`, a recorded claim, not an observation of its own.
- **No model identity.** The session's calls were written by hand, and an execution layer
  never learns which model wrote the code it runs.
- **`code_execution` is an unregistered effect type**, reported by the verifier as
  informational, as the specification requires.
- **No refusals.** The specification asks for a capsule on every verdict. plimsoll answers
  a refused run with an error that carries no record, so no `blocked` or `denied` capsule
  can be stated from one.
- **Not registered anywhere.** No capsule was sent to a transparency service, so a missing
  last capsule is invisible to a store check. plimsoll's bundle catches that case on its own:
  its links and closing checkpoint, and the session's signed close statement, each refuse
  it, and the page shows both results.
