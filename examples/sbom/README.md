# Signed project-run evidence as CycloneDX

This separate Go module converts a verified plimsoll bundle into one CycloneDX
1.6 JSON bill of materials (BOM, a parts list) per single project run. It includes
the program's file fingerprints, the selected container image, the executed
steps and three claims linked to signed evidence. It does not scan the image's
installed packages, discover dependencies, or provide vulnerability coverage.

The checked-in example contains two real runs of an invoice reconciliation
program. The second adds one failed network attempt. A generated
[INTERNAL · example page →](../../docs/examples/sbom/index.html) presents both
runs and labels the outside comparison transcript as unsigned.

From this directory:

```sh
go run .
go run . -check ../../docs/examples/sbom/run-c7e245a369dd.cdx.json
go run . -check ../../docs/examples/sbom/run-af0fa2597b81.cdx.json \
  -trusted-pub ../../docs/examples/sbom/harness.pub
```

Generation reads no clock or environment. It verifies the complete bundle,
including the signed chain of entries and checkpoint, before writing outputs.
A cyclonedx-go version bump can change the published bytes; the reproduction
test will report the difference.
Each file is named `run-<first 12 hex of record digest>.cdx.json`. Reproduction
does not create a sandbox or call a hosted service. Go may download the pinned
dependencies on first use; all evidence and schema checks themselves are offline.

Flags: `-bundle`, `-pub`, `-name`, `-image-name`, `-operator`, `-pages`, `-out`,
`-check`, `-trusted-pub`, `-outside`, `-image-bom`. `go run . -h` prints defaults. `-outside`
optionally names an unsigned comparison transcript; without it, a file named
`outside-plimsoll.txt` beside the bundle is included if present. Missing explicit
inputs fail. Session bundles, non-project runs, granted runs and missing selected
OCI image identities are refused. OCI means Open Container Initiative, the
standard container image format. Today this means docker on the containerd image
store; other providers are refused when the selected identity is missing.
`-image-name` is a simple lowercase display name; the image digest supplies identity. Inputs are capped at 32 MiB to cover
the request/result budgets plus base64 attachment expansion while bounding parsing.

The file-set digest is independent of the request's execution settings: sort files
by path; concatenate SHA-256(path) followed by SHA-256(content), each as 32 raw
bytes, for each file; hash that concatenation with SHA-256. A file's length is the
number of bytes, not characters. The run-record digest seeds a deterministic UUID
for the BOM's serial number. Times are taken from the record, formatted in UTC
with milliseconds.

The evidence attachments are the Dead Simple Signing Envelope (DSSE, the signed
record wrapper), the public key and the original complete bundle. The bundle
holds the exact binary protobuf request and response as base64, not protobuf
JSON. Its signed entry links bind even fields outside the run-record digests,
such as trace identifiers and durations. `-check` verifies those sources and
rebuilds the full mapped BOM, checking files, hashes, steps, results, image,
claims, references and limitations. Duplicate JSON keys and unknown content are
refused. It accepts whitespace and object-key order differences. It is a checker
for this emitter's mapping, not an arbitrary CycloneDX verifier.

Each BOM embeds the complete input bundle. For a batch of N runs, writing N BOMs
repeats that evidence N times, so this proof of concept has quadratic batch-output
growth. A production extension should attach each selected entry with its signed
content link and refer to a shared bundle by digest, while preserving the same
request/result checks. Independent verification of a selected entry and its
completeness claim needs its own contract and equivalence tests; that extension
is deferred. The 32 MiB input limit is also an explicit prototype limit, not a
claim of unrestricted batch support.

An attached public key alone establishes internal consistency. An attacker can
replace both evidence and key. `-trusted-pub` compares with a key obtained
independently and refuses another signer. The example's adjacent key is an
illustrative pin, not independent proof of a publisher's identity. Names, the
page URL and assessor label remain unsigned presentation. Agent authorship is
supplied context, not something the execution record proves. The record states
what the daemon reported; it is not hardware attestation. A conformance or
confidence score of 1 means the deterministic consistency check passed, not
perfect isolation or a probability that an assertion is true. The BOM itself and
its affirmation are unsigned; only the attached run evidence is signed.

The public evidence cannot be edited to fix a check. The emitter intentionally
includes a bundle attachment because an envelope of digests alone would not
bind an internally consistent substituted file list. The optional evidence
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
module. Tests reproduce both BOMs and the page byte for byte, validate against
the embedded schemas, verify attachments, reject three single-byte changes and
coordinated file substitution, check other mapped fields and trusted-key
mismatches, and refuse session bundles. Tests create scratch files only inside
the repository's ignored `tmp/`. `make audit` then `make sbom-suite` is the gate
for every change to this example.

Platform ingestion and declaration rendering have not been tested. Schema
validity alone cannot guarantee either. The BOM is intentionally a run-evidence
proof of concept, not a claim of adoption or commercial demand.

References:

- [EXTERNAL · official CycloneDX 1.6 JSON reference ↗](https://www.cyclonedx.org/docs/1.6/json/)
- [EXTERNAL · official attestations documentation ↗](https://cyclonedx.org/use-cases/attestations/)
- [EXTERNAL · in-toto statement specification ↗](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [INTERNAL · pinned schema provenance →](schema/README.md)

The page inlines `check.js`, also run by `check_test.mjs` under Node 22 or later
from `go test`. A missing Node executable fails the suite. The browser recomputes
request, result, record, file and bundle fingerprints and verifies the Ed25519
seal with its built-in crypto. Its `exchange.json` attachment is a plain JSON
copy, checked against the signed bundle's protobuf messages before publication.
Go also checks the complete bundle chain; the browser checks the selected receipt.

The selected image can carry an ingredients label of its own. `-image-bom`
accepts a local CycloneDX 1.6 or 1.7 image label. Without it, generation and
`-check` look for `image-<first 12 manifest hex>.cdx.json` beside their input.
When present, its root version must equal the recorded manifest digest. The run
BOM links to the file by URL plus SHA-256 and to its root by BOM-Link. A referenced
file that is absent, changed or joined to another image fails `-check`. No URL is
fetched. Images without a supplied label get no ingredient claim. The pinned
example was scanned by syft 1.54.1 from the OCI layout, with 694 components; the
page states the exact command and why the legacy-daemon scan cannot be substituted.
The label's random serial stays pinned, so tests copy its bytes without regenerating it.
