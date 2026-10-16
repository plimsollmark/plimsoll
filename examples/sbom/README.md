# Signed project-run evidence as CycloneDX

This separate Go module converts verified plimsoll bundles into CycloneDX 1.6 JSON
bills of materials (BOM, a parts list), one per single project run. Each BOM holds the
program's file fingerprints, the image the run executed in, the executed steps and
three claims linked to signed evidence; where the platform signed a qualification
statement for the run, a fourth claim carries its verdict with a conformance score. It
does not scan the image's installed packages, discover dependencies, or provide
vulnerability coverage.

The checked-in example contains six real runs. Four are an invoice reconciliation
program: two under gVisor (tier `kernel`), the second with one failed network attempt,
and the same two requests, byte for byte, sent again to a Docker Cloud Sandboxes
microVM (tier `vm`), so the pairs share a request fingerprint and differ in the room.
Two are adapter runs from [the adapter example](../adapter/), each with the platform's
signed verdict: `adapter-v2.js` in the nominal scenario (every rule held, conformance
1) and `adapter-v1.js` in the lost-acknowledgement scenario (one rule broken,
conformance 0). A generated
[INTERNAL · example page →](../../docs/examples/sbom/index.html) presents all six,
explains the verdict in plain words with a diagram, and labels the outside comparison
transcript as unsigned.

From this directory:

```sh
go run .
go run . -check ../../docs/examples/sbom/run-c7e245a369dd.cdx.json \
  -trusted-pub ../../docs/examples/sbom/harness.pub
go run . -check ../../docs/examples/sbom/run-40a5c260c313.cdx.json \
  -check-bundle ../../docs/examples/adapter/bundle.jsonl \
  -check-qualification ../../docs/examples/adapter/qualification.jsonl \
  -trusted-pub ../../docs/examples/adapter/harness.pub
```

Generation reads no clock or environment. It verifies each complete bundle, including
the signed chain of entries and checkpoint, and every qualification statement against
its bundle, before writing outputs. A cyclonedx-go version bump can change the
published bytes; the reproduction test will report the difference. Each file is named
`run-<first 12 hex of record digest>.cdx.json`. Reproduction does not create a sandbox
or call a hosted service. Go may download the pinned dependencies on first use; all
evidence and schema checks themselves are offline.

Flags: `-bundle`, `-pub`, `-name`, `-image-name`, `-operator`, `-pages`, `-out`,
`-outside`, `-image-bom`; for the verdicts `-qualified-bundle`, `-qualified-pub`,
`-qualification`, `-qualified-runs` (bundle line numbers, default `10,4`) and
`-qualified-pages` (where that bundle and its statements are published; an empty
`-qualified-bundle` writes no verdict BOMs); for checking `-check`, `-trusted-pub`,
`-check-bundle` and `-check-qualification`; for one run `-line`. `go run . -h` prints
defaults. `-line N` (with `-bundle`, `-pub`, and an explicit `-out` and `-pages`) writes only
the BOM of the bundle's line N and prints the checks it passed, the refusals of altered copies
included, with no page; the other lines need not be runs it can map. It is the path for a
caller that converts runs as they happen: give it the signed file up to that run's checkpoint,
so the bundle digest the BOM cites never moves as later runs are appended. On the published
bundle it writes the published BOMs byte for byte (the reproduction test checks). `-outside`
optionally names an unsigned comparison transcript; without it, a file named
`outside-plimsoll.txt` beside the bundle is included if present. Missing explicit
inputs fail. Session bundles, non-project runs and runs whose record states no image
identity are refused. Granted runs are accepted: the `plimsoll:grant` property names
the profile and the tier claim says the grant's routes were the run's only way out.
OCI means Open Container Initiative, the standard container image format. The image
identity is docker's selected OCI manifest (the containerd image store), or the
linux/amd64 manifest Docker Cloud reported it booted; other providers are refused
while their records state neither. `-image-name` is a simple lowercase display name;
the image digest supplies identity. Inputs are capped at 32 MiB to cover the
request/result budgets plus base64 attachment expansion while bounding parsing.

The file-set digest is independent of the request's execution settings: sort files
by path; concatenate SHA-256(path) followed by SHA-256(content), each as 32 raw
bytes, for each file; hash that concatenation with SHA-256. A file's length is the
number of bytes, not characters. The run-record digest seeds a deterministic UUID
for the BOM's serial number. Times are taken from the record, formatted in UTC
with milliseconds.

## Evidence by line, bundle by fingerprint

Each BOM attaches its own line of the bundle, `entry.json`: the exact binary protobuf
request and response as base64, the record's Dead Simple Signing Envelope (DSSE, the
signed record wrapper) and the harness's signed link placing the line at its index. It
also attaches `envelope.json`, the public key and `exchange.json`, a plain JSON copy of
the messages checked against the protobuf bytes before publication. The whole bundle
is referenced by URL and SHA-256 (the `attestation` reference and the
`plimsoll:bundle_sha256` property; `plimsoll:bundle_line` is the line's index), never
attached, so a BOM stays small however many runs its bundle holds: the adapter bundle
is 1.8 MB and each verdict BOM about 150 KB. `attest.VerifyEntry` checks a line on its
own (the record's signature, the stored bytes against the signed digests, the link's
seal over the line's content). The chain around the line, and the checks across runs,
need the whole bundle: `-check` runs them when it has it (an explicit `-check-bundle`,
or a sibling `bundle.jsonl` whose digest is the referenced one) and prints a LIMIT line
saying so when it does not. Generation always has the bundle and always runs them.

A verdict BOM adds a second evidence item, `evidence-qualification`, with the
platform's statement as `statement.json` (an in-toto statement, predicate type
`https://plimsollmark.github.io/plimsoll/examples/adapter/qualification/v1`, subject
the run's record), a fourth claim `claim-verdict` whose text names every rule with
held or broken and the ledger's words, requirement R4 "the program met the platform's
rules", and a conformance score of 1 when every rule held or 0 with the broken rules
named. The file of all statements is referenced by URL and SHA-256
(`plimsoll:qualification_sha256`). `-check` verifies the statement's seal under the
attached key, its subject against the record, its files, step, report and exit code
against the stored request and response, and re-evaluates the verdict from its
evidence (`qualify.VerifyOne`); with `-check-qualification` and the bundle it also runs
the checks across runs (every run has one statement, no credential served two). The
statement is the platform's own signed account of a run against a simulated vendor,
re-evaluated here; it is not an independent audit.

`-check` rebuilds the full mapped BOM, checking files, hashes, steps, results, image,
claims, references and limitations. Duplicate JSON keys and unknown content are
refused. It accepts whitespace and object-key order differences. It is a checker for
this emitter's mapping, not an arbitrary CycloneDX verifier.

An attached public key alone establishes internal consistency. An attacker can
replace both evidence and key. `-trusted-pub` compares with a key obtained
independently and refuses another signer. The example's adjacent keys are illustrative
pins, not independent proof of a publisher's identity. Names, the page URL and
assessor label remain unsigned presentation. Agent authorship is supplied context, not
something the execution record proves. The record states what the daemon reported; it
is not hardware attestation. A conformance or confidence score of 1 means the
deterministic consistency check passed, not perfect isolation or a probability that an
assertion is true. The BOM itself and its affirmation are unsigned; only the attached
run evidence and statement are signed.

The public evidence cannot be edited to fix a check. The optional evidence
classification is omitted: `cyclonedx-go` v0.12.0 models it as an object although
the pinned 1.6 schema requires a string. The description identifies this as
public example evidence. The library also omits `thirdParty: false`, so after
its JSON encoding the emitter restores that explicit self-assessment value.
No invalid unsigned signatory is added to the affirmation. Workflow outputs
reference the evidence because the schema requires an output resource or data.

From the repository root, run the same offline suite the separate CI job uses:

```sh
make sbom-suite
```

The target vets and race-tests this module and fails on a skipped test. The root
module takes no new dependencies and its `make audit` does not reach this nested
module. Tests reproduce all six BOMs and the page byte for byte, validate against
the embedded schemas, verify attachments, reject single-byte changes, a flipped
verdict word or score, an edited statement with its signature kept, another run's
statement, and coordinated file substitution, check other mapped fields and
trusted-key mismatches, and refuse session bundles. Tests create scratch files only
inside the repository's ignored `tmp/`. `make audit` then `make sbom-suite` is the
gate for every change to this example.

Platform ingestion and declaration rendering have not been tested. Schema
validity alone cannot guarantee either. The BOM is intentionally a run-evidence
proof of concept, not a claim of adoption or commercial demand.

References:

- [EXTERNAL · official CycloneDX 1.6 JSON reference ↗](https://www.cyclonedx.org/docs/1.6/json/)
- [EXTERNAL · official attestations documentation ↗](https://cyclonedx.org/use-cases/attestations/)
- [EXTERNAL · in-toto statement specification ↗](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [INTERNAL · pinned schema provenance →](schema/README.md)
- [INTERNAL · the adapter example, where the verdicts come from →](../adapter/)

The page inlines `check.js`, also run by `check_test.mjs` under Node 22 or later
from `go test`. A missing Node executable fails the suite. The browser recomputes
request, result, record and file fingerprints, verifies the Ed25519 seals on the
record, on the line's link and on the statement with its built-in crypto, and checks
that the verdict claim and score say what the statement says. Its `exchange.json`
attachment is a plain JSON copy, checked against the signed bundle's protobuf messages
before publication. Go also checks the complete bundle chain and re-runs the rules;
the browser checks the selected receipt.

The selected image can carry an ingredients label of its own. `-image-bom`
accepts a local CycloneDX 1.6 or 1.7 image label. Without it, generation and
`-check` look for `image-<first 12 manifest hex>.cdx.json` beside their input.
When present, its root version must equal the recorded manifest digest. The run
BOM links to the file by URL plus SHA-256 and to its root by BOM-Link. A referenced
file that is absent, changed or joined to another image fails `-check`. No URL is
fetched. Images without a supplied label get no ingredient claim; the Docker Cloud
runs' public node image has none here. The pinned example was scanned by syft
1.54.1 from the OCI layout, with 694 components; the page states the exact command
and why the legacy-daemon scan cannot be substituted. The label's random serial stays
pinned, so tests copy its bytes without regenerating it.
