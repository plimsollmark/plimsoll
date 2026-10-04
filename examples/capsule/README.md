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
`verify_envelopes.py` uses to check every signature independently of the Go signer. With no flags, the program reproduces every published
capsule ID: an ID depends only on the capsule's content, and the default import time is
the published one. The signatures differ on each run, because each run makes its own key
and writes only the public half (`producer.pub`).

**This is its own Go module.** The capsule emitter needs Go 1.27 and brings dependencies
(COSE and CBOR libraries) that plimsoll's own module does not take on: plimsoll is a
hostile-code trusted computing base, and every module that imports it would inherit them.
Nothing in plimsoll's `go.mod` changes, and `go build ./...` at the repository root does not
see this directory.

## The mapping

| plimsoll outcome | `verdict_class` | `effect.status` | derived `effect_mode` | `reason_digest` |
|---|---|---|---|---|
| `completed`, any exit code | `executed` | `confirmed` | `confirmed` | absent |
| `timed_out` | `timeout` | `dispatched` | `dispatched_unconfirmed` | the outcome |
| `setup_failed` | `errored` | `dispatched` | `dispatched_unconfirmed` | the outcome |
| `protocol_error` | `errored` | `dispatched` | `dispatched_unconfirmed` | the outcome |

The table is `verdicts` in [mapping.go](mapping.go); a snippet reads as `timed_out` or
`completed`. Every row uses `effect_attestation: gate_executed` (the engine observed the
effect boundary directly), since plimsoll ran the code. A completed run is `confirmed`
whatever its exit code: plimsoll observed the result, and the exit code is inside the
digested response. `setup_failed` and `protocol_error` share a class and a status and may
carry no response digest, so the reason digest, over `{"plimsoll_outcome": ...}`, is what
keeps them apart. Session calls chain with `relation: follows`.

The published bundle exercises only the first row. `TestEveryVerdictRowVerifies` builds a
capsule for every row from one identical record, so it passes only if the capsule's own
fields tell the outcomes apart, and checks each with both verifiers.

## What the capsules claim

- **Backfilled.** `provenance_mode: backfilled`, `time_rung: self_attested`, `source_ref`
  the plimsoll run record by the SHA-256 plimsoll's verifier checks, and `import_batch` the
  SHA-256 of the bundle file. An import must come strictly after its record's time; one at
  the same instant is the shape the capsule verifier refuses as laundering.
- **Collected.** `provenance: collector`: this program read signed records afterwards. The
  `gate_executed` grade is the gate's, carried from the cited record.
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
