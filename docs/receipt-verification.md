# Check a timestamped receipt offline

A <dfn>*receipt*</dfn> is a signed claim about a particular file. Think of an inspection slip
stapled to a box: the file's hash identifies the box, the signature identifies the
<dfn>*signing key*</dfn> (a private key whose matching public key checks its signatures), and an outside timestamp witnesses the signed slip. None of those
checks independently repeats the inspection.

This optional profile groups existing standard objects: <dfn>*DSSE*</dfn> (Dead Simple Signing Envelope, a signed envelope),
an <dfn>*in-toto*</dfn> Statement (the standard layout for its subject and assertion), and an RFC 3161
timestamp response. The grouping JSON is a Plimsoll profile, not a new signature
or timestamp standard. It complements the
[INTERNAL · signed test-report example →](../examples/pr-receipt/README.md).
The existing run-bundle verification commands are unchanged.

## Try the invented example

From the repository root, run:

```sh
go run ./cmd/plimsoll-attest verify-receipt \
  -policy attest/receipt/testdata/policy.json \
  -artifact attest/receipt/testdata/widget.txt \
  attest/receipt/testdata/valid.json
```

Success exits zero and prints two authenticated assertions, with
`distinct_signing_keys: 2`, their timestamp authority's claimed time, its stated
one-second accuracy and root-certificate hashes. Both assertions say `example_only`.
The keys and authority are invented, and their private keys were discarded when
the fixtures were made. These files demonstrate the check, not a real inspection.

For a failure, replace `valid.json` with `changed-envelope.json`. It contains the
same signed assertion with an extra space in its envelope file. The command exits
nonzero and reports that the timestamp covers another <dfn>*digest*</dfn>, a content hash. Replacing the
policy with `untrusted-policy.json` also fails: its invented keys did not sign the
receipt. Changing the artifact file fails its SHA-256 check.

No command here contacts a model, timestamp service, daemon or network endpoint.
Go may download the exact configured toolchain and build dependencies if they are uncached.

**Verification runs offline**, on a machine with no network connection at all: build the
binary where there is a network (`go build ./cmd/plimsoll-attest`) and carry it over with the
evidence and a policy you obtained separately. On 2026-10-28 the example above,
`plimsoll-attest verify` on a whole published run bundle and `verify-entry` on one of its lines
all passed inside a Linux network <dfn>*namespace*</dfn> (a separate copy of the kernel's network
stack, seen only by the processes started in it) whose only interface was a loopback that was
down (`unshare -rn`; a connection even to 127.0.0.1 was refused as unreachable), and the changed
envelope still failed there. This covers checking evidence only: running plimsolld, or
signing, without a network is another matter.

## The trust boundary

The consumer must obtain and authenticate its policy separately. A receipt sender
can invent a matching key and root, so accepting a policy merely because it came
beside that receipt defeats identity verification. The example policy is trusted
only for the invented example. Real deployments configure authorized role keys,
acceptable timestamp roots, assertion types, and the expected artifact digest
through their own authenticated release or configuration process.

Two roles can use one key. Two different keys can belong to one person. The report
counts distinct signing keys; organizational independence requires separate
evidence about who controls them. Roles are labels such as `builder` and `reviewer`,
not identities proven by the labels themselves.

## Profile version 1

Both inputs are UTF-8 JSON objects. Schema names are case-sensitive. Duplicate or
unknown schema fields, trailing JSON and versions other than `1` are rejected.
Each input is limited to 1 MiB to bound decoding. There are 1 to 8 roles, enough
for ordinary approval groups while bounding signature and certificate work.

The **trusted policy** has exactly these fields:

| Field | Meaning |
|---|---|
| `version` | Integer `1`. This profile version is separate from the daemon RPC protocol. |
| `subject` | Exactly `name` (a nonempty label) and `digest`, an object containing only `sha256`, 64 lowercase hex digits. |
| `roles` | Required role objects, each with `name`, `predicate_type`, `public_key_pem`, `timestamp_roots_pem`. Names are unique, 1 to 64 lowercase letters, digits, `_` or `-`. |

Each role specifies one Ed25519 public key in PKIX PEM, one absolute assertion-type URI,
and a PEM bundle of acceptable timestamp root certificates. There is no built-in
vendor trust list, system-root fallback, receipt-supplied root override or URL
lookup. In a real deployment, the expected subject digest must come from a trusted
source, not simply be copied from the untrusted receipt.

The **receipt** has exactly `version` and `endorsements`. Each endorsement has
exactly `role`, `envelope`, and `timestamp`. The last two are standard JSON base64
strings containing exact bytes:

| Object | Required interpretation |
|---|---|
| `envelope` | A UTF-8 DSSE envelope file with `payloadType`, `payload`, and exactly one `signatures` entry (`keyid`, `sig`). The payload is an in-toto Statement v1. |
| Signed statement | Exactly `_type`, `subject`, `predicateType`, `predicate`. It names exactly the configured subject and SHA-256 digest, and the configured assertion type. The application-specific predicate must be a present JSON object. |
| `timestamp` | A DER-encoded RFC 3161 **TimeStampResp**, not a bare CMS token. Its SHA-256 message imprint covers the exact decoded envelope-file bytes, including the signature and any whitespace. |

There must be exactly one endorsement for every policy role, with no additional
or repeated roles. Evidence order does not matter; reports follow policy order.
An assertion signed under another role's key or assertion type is rejected.
Predicates remain authenticated opaque JSON. The checker does not interpret their
application-specific fields or turn an assertion of `pass` into an independently
reproduced test result.

## Signing and timestamp binding

Use the existing `sign-statement` command or `attest.Signer.SignStatement` to make
a generic assertion. See
[INTERNAL · signing and execution evidence →](run-records.md).
Finalize its envelope file first, then request an outside timestamp over SHA-256
of **that entire file**. Preserve its bytes. Hashing the unsigned predicate or
statement payload proves only content existence, not existence of the signature.
Reformatting the envelope after timestamping deliberately invalidates this
profile's timestamp check. No canonical JSON re-encoding is performed.

The public request encoder can prepare an RFC 3161 SHA-256 request with a random
nonce. Its nonce matches the response to the original request; it does not hide
predictable content. `tsa.Verify` checks an expected nonce when a requester supplies
one. This offline receipt profile checks the artifact binding and signature-bearing
bytes, without claiming to validate an original request's nonce.

## Timestamp support and limits

The verifier bounds responses at 64 KiB, checks the signed content and certificate
identifier, and checks a chain to explicitly configured roots at the token's own
claimed time. The signing certificate must have critical, exclusively timestamping
extended key usage. SHA-256 message imprints and SHA-256/384/512 digest algorithms
are supported, with RSA PKCS#1 v1.5, ECDSA and Ed25519 signatures. Ed25519 requires
SHA-512. RSA-PSS is rejected because this implementation does not validate its
parameters. Exactly one CMS signer is accepted. Unsigned CMS attributes and
unknown critical timestamp extensions are rejected. This is a bounded profile,
not a verifier for every CMS encoding.

The timestamp is a trusted authority's claim, not an independent measurement of its
clock. Its accuracy matters: an asserted one-second accuracy means a one-second
uncertainty either side of its time. Omitted accuracy means no accuracy bound is
asserted by this report. No deadline, timestamp ordering, freshness, historical
revocation or long-term archival policy is enforced. The offline check makes no
revocation-network requests, and does not establish a signer's human identity or
the fairness, completeness or secrecy of private tests. Hashes of predictable
documents can be guessed and compared; hashing is not encryption.

The timestamp verifier has focused regression tests and source review. That is
not an independent security audit or production clearance. Applications that need
deadline decisions or historical revocation checks must supply those policies.

## Reference code and checks

`attest/receipt.Verify` takes receipt bytes and independently trusted policy bytes,
returning no partial report on failure. It checks signatures, role expectations,
subject identifiers and timestamps. Its caller must also hash the actual artifact
file and compare the expected digest. The CLI performs that file check itself.

```sh
go test ./attest/receipt ./attest/tsa ./cmd/plimsoll-attest
```

Tests generate private keys in memory, use an invented authority and exercise
substituted trust, changed bytes, wrong subjects/types, missing roles and malformed
inputs. To deliberately replace the invented fixture files, run
`go test ./attest/receipt -run TestInventedExample -args -write-example`.
No private keys are written by that fixture generator.

The formats and trust separation follow
[EXTERNAL · in-toto Statement specification ↗](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[EXTERNAL · DSSE protocol specification ↗](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
[EXTERNAL · RFC 3161 timestamp standard ↗](https://www.rfc-editor.org/rfc/rfc3161.html),
[EXTERNAL · CMS standard ↗](https://www.rfc-editor.org/rfc/rfc5652.html),
[EXTERNAL · Sigstore timestamp guidance ↗](https://docs.sigstore.dev/cosign/verifying/timestamps/), and
[EXTERNAL · SLSA verification guidance ↗](https://slsa.dev/spec/v1.2/verifying-artifacts).
