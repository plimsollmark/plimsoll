# A receipt for a pull request

This copyable example runs a JavaScript project's test command in plimsoll under
gVisor, a separate user-space kernel. It asks for the `kernel` isolation floor,
checks the returned record, signs it and emits a CycloneDX bill of materials
(BOM, an ingredients label with the signed receipt attached). The tier is
configuration and provider evidence plus startup checks, never hardware attestation.
The receipt covers the command and files that ran, and names the repository, commit and
pull request they came from: the request carries a file of its own,
`.pr-receipt/subject.json`, inside what the run record signs. It does not cover a later
merge, prove who wrote the files, or promise that the tests catch every defect.

Copy [INTERNAL · workflow template →](workflow.yml) to
`.github/workflows/pr-receipt.yml` in the target project. It runs on `pull_request`,
posts no comment and needs no repository secret. Set repository variable
`PLIMSOLL_RECEIPT_REF` to a full 40-character public plimsoll commit SHA containing
this example and `examples/sbom`. A mutable tag or empty pin is refused. At this
example's local build on 2026-10-13, the public repository did not contain the
converter yet; the template cannot run there until the export publishes it.
No future release hash is invented here.

The workflow builds trusted tools and the trusted project image from that pin,
installs gVisor using plimsoll's checksum-verified installer, and starts its own
loopback daemon. Project code is never run directly on the host. The workflow
checks out the PR head, includes its changed files and the rest of its tracked
text files as test context, then runs `npm test` inside the sandbox. Override
`PLIMSOLL_TEST_COMMAND` with the project's command. The default image provides
Node and a toolchain, without runtime dependency downloads; projects needing
packages must bake them into a trusted derived image and set `PROJECT_IMAGE`.
The files are read from the commit's own git objects, never the working tree, so an
uncommitted edit is not what runs and cannot change between a check and the read.
Binary files, links, submodules, oversized projects, projects with no tracked files or
more than 199 (the subject is the 200th file, plimsoll's limit) and a tracked file under
`.pr-receipt/` are refused rather than silently omitted or misnamed. The test command can read the subject file like any other. Deleted files are absent from the tested
head. The unsigned context file lists changed surviving files; the signed request
contains the exact files that ran. A test failure still creates and uploads its
receipt, then leaves the workflow red.

The template pins Docker 29.9.0 and turns on its containerd image store while
keeping the runtime configuration produced by the gVisor installer. The runner
image list checked on 2026-10-13 had Docker 28.0.4, below plimsoll's 28.1 minimum
for selected manifest inspection. The pin was verified against Docker's stable
release listing. These are setup choices, not a claim of a hosted exercise.
See [EXTERNAL · official image-store docs ↗](https://docs.docker.com/engine/storage/containerd/)
and [EXTERNAL · runner image source ↗](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md).

The toolchain image must be present on a containerd image store with selected
manifest identities. A classic Docker image store cannot produce a compatible
BOM. The converter fails clearly there. This template is not enabled in plimsoll's
own workflows. See the working image/install recipe in
[INTERNAL · gVisor workflow →](../../.github/workflows/gvisor.yml) and the offline
converter checks in [INTERNAL · receipt converter →](../sbom/README.md).

To exercise the script locally, provide a new output directory outside the target
project. The daemon and signing key belong to the script; it stops its own daemon
and deletes the key at exit. The key lives under the user's cache, never in a
web-served directory. Ordinary logs stay in the source checkout's ignored `tmp/`.

```sh
TEST_COMMAND='npm test' PR_NUMBER=0 PR_REPOSITORY=example/project \
  examples/pr-receipt/receipt.sh /path/to/committed/project "$PWD/tmp/pr-receipt-output"
```

`PR_REPOSITORY` is the CI platform's name for the repository (the workflow passes
GitHub's `owner/name`); a verifier compares it with the name its own platform gives.

By default the run is signed with a throwaway key made for it, which shows that the
receipt is consistent with itself, not who made it: anyone can make a key and sign a
receipt of their own. To sign with a key a verifier already trusts, set
`PLIMSOLL_HARNESS_KEY` to the `.key` file of a pair made by `plimsoll-attest keygen`, with
its `.pub` beside it. The script refuses a key inside the project, whose files go into
the sandbox, leaves it in place at exit, and copies only the public half into the output. A verifier
checks the receipt against that public key, given to it separately, never against the
`harness.pub` in the output. Keep the private key where the pull request's author cannot
use it: a workflow that a pull request can edit can also sign with any key it can read.

## The JUnit file

Every output holds a `junit.xml`, the test-report format CI systems and evidence stores
read (it has no official specification; [EXTERNAL · community format notes, a GitHub repository ↗](https://github.com/testmoapp/junitxml)). Set
`JUNIT_PATH` to the file the test command writes (for node's own runner,
`TEST_COMMAND='node --test --test-reporter=junit --test-reporter-destination=junit.xml'`
and `JUNIT_PATH=junit.xml`; the workflow reads it from the repository variable
`PLIMSOLL_JUNIT_PATH`). The sandbox returns that file inside the signed result, so
`junit.xml` is the framework's own report, byte for byte, and cannot be edited afterwards
without failing the run record. The path must be plain relative names, and not a tracked
file: the report has to be one the run wrote. Without `JUNIT_PATH`, `junit.xml` is built
from the signed result alone, one test case per step, so anyone can rebuild it
([INTERNAL · junit.py →](junit.py)). Either way the report is only as honest as the tests,
which belong to the pull request; pass or fail is decided from the signed exit codes,
never from the report.

## Standard formats: a signed test-result statement and Cobertura coverage

Evidence stores and policy engines read a few standard formats. Every output also holds
`test-result.intoto.json`, an in-toto test-result statement
([EXTERNAL · in-toto predicate specification, a GitHub repository ↗](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md))
in the standard signed envelope, signed with the same key as the run
(`plimsoll-attest sign-statement`). Its subject is the repository and commit the signed
request names; its result is `PASSED` only when every step exited 0 without timing out
and a readable JUnit report lists no case failures, errors or nonzero failure/error
summary counters; its test names come from `junit.xml`. A missing requested report,
malformed XML, an unsupported root element or invalid failure/error counters produces
`FAILED`: the evidence could not establish a passing test report. Without `JUNIT_PATH`,
the report is constructed from the signed command results. A valid report with zero
tests can pass, which does not prove any tests were run. The predicate has
no field for where the tests ran, so the run record's entry in `configuration` carries the
isolation tier, provider and environment as annotations, the specification's own extension
point. Set `COVERAGE_PATH` beside `JUNIT_PATH` to the lcov file the test command writes and
the output also holds `coverage.cobertura.xml`, the Cobertura form of that file as the
run returned it (for node's own runner, add `--experimental-test-coverage
--test-reporter=lcov --test-reporter-destination=lcov.info` and set
`COVERAGE_PATH=lcov.info`; the workflow reads the repository variable
`PLIMSOLL_COVERAGE_PATH`). Both are derived from the checked receipt alone
([INTERNAL · formats.py →](formats.py)), so a reader rebuilds them and compares; neither adds
anything the run record does not hold, and the coverage is only as honest as the tests.

## Coding-agent sessions

Some session recorders mark each commit a coding agent made with a commit trailer, a
`Key: value` line at the end of the message, naming the session IDs. Set `SESSION_TRAILER`
to that trailer's key (the workflow reads it from the repository variable
`PLIMSOLL_SESSION_TRAILER`) and the subject file lists the IDs as `agent_sessions`, sorted,
each once, inside the signed request, where a policy reading the receipt finds them beside
the session evidence they name. With `PR_BASE_SHA` (the workflow passes the pull request's
base) every commit after the base counts and the base is named in the subject; without it,
the head commit alone. A commit's message is fixed by its ID, which the subject already
names, so the list adds nothing a commit could change afterwards; a trailer holding
anything but session IDs is refused. The list says which sessions the commits name, not
that those sessions wrote them: anyone can type a trailer.

## Checking a receipt someone else made

When the same job runs `receipt.sh` and is required to pass, that is already a merge gate:
the job fails from the signed result. [INTERNAL · verify.py →](verify.py) is for a receipt
made by an operator outside the pull request's control, checked by the repository's own
required check before anything believes it. With the operator's public key, given to it
separately and never taken from the receipt, it checks in order: the signature and that
every field of the receipt equals the signed run record (by `examples/sbom -check`); that the
signed request is exactly what `prepare.py` builds for this repository, head commit, pull
request number, base (`--base`), test command, JUnit path and session trailer
(`--session-trailer`), so a receipt for another commit or repository is refused; with `--junit`, that the JUnit file equals the signed result's; with
`--test-result` (and `--attest`, the built `plimsoll-attest`), that the statement is signed with
the operator's key and equals the one the signed result gives; with `--coverage` (and
`--coverage-path`), that the Cobertura file equals the one converted from the signed lcov file; and that the run
completed behind the kernel tier or stronger with every step exiting 0. Nothing after a
failed signature is judged.

```sh
go -C examples/sbom build -o "$PWD/tmp/sbom" .
python3 -I examples/pr-receipt/verify.py --sbom tmp/sbom \
  --receipt RECEIPT_DIR/run-*.cdx.json --trusted-pub OPERATOR.pub \
  --repo /path/to/clone --repository owner/name --head HEAD_SHA --pr NUMBER \
  --command 'npm test' --junit RECEIPT_DIR/junit.xml \
  --attest "$PWD/tmp/plimsoll-attest" --test-result RECEIPT_DIR/test-result.intoto.json
```

Build the attest tool first with `go build -o "$PWD/tmp/plimsoll-attest" ./cmd/plimsoll-attest`.

It prints a JSON report naming the SHA-256 of the receipt it checked (hand that file, and no
other, to whatever reads the receipt next) and exits 0 when every check passes, 1 when the
receipt is refused or its tests failed, 2 on a usage error and 3 when the check could not
run (an unusable key is never a pass). Its own git calls use git's defaults, never the
machine's settings; the clone it reads must be checked out with git's defaults too.

## The receipt challenge: does your gate refuse these?

A merge gate that only checks that a receipt exists, or only that it is signed, or only reads
the JUnit file beside it, waves through things it should not. [INTERNAL · challenge/ →](challenge/)
holds one honest receipt and six that a correct gate refuses, all made by this recipe under
gVisor ([INTERNAL · generate.sh →](challenge/generate.sh)), with a three-commit project to check
them against ([INTERNAL · cases.json →](challenge/cases.json) names each case, the commit a gate
would be checking it for, and the right answer):

| Case | What it is | A correct gate |
|---|---|---|
| honest | the receipt for the commit under review, signed by the operator, tests passed | accepts |
| another signer | a genuine receipt for the same commit, signed by a key that is not the operator's | refuses at the signature |
| edited result | the honest receipt with one exit code changed inside it | refuses at the signature |
| failing tests | a genuine, correctly signed receipt for a run whose tests failed | refuses at the result |
| passing report beside a failing run | the failing run's receipt with a passing JUnit file put next to it | refuses at the JUnit check |
| wrong commit | the honest receipt presented for a later commit it never tested | refuses at the head |
| wrong repository | the honest receipt presented for another repository | refuses at the head |

```sh
go -C examples/sbom build -o "$PWD/tmp/sbom" .
python3 -I examples/pr-receipt/challenge/check.py --sbom "$PWD/tmp/sbom"
```

`check.py` runs every case through `verify.py` and prints what it decided beside what
`cases.json` expects; run your own gate on the same files and compare. The operator's
public key is [INTERNAL · operator.pub →](challenge/operator.pub); its private key was made
for the run and deleted.

`PLIMSOLL_PAGES` is the absolute URL, ending in `/`, where the output directory will be
published; the BOM's attestation reference and the page's file links are built from it.
It defaults to the raw GitHub URL of this example's `evidence/` directory, which is
right for the committed artifact and wrong for anyone else's run, so set it.

Local execution leaves `PLIMSOLL_REF` unset when testing an unpublished working
copy. The workflow always supplies and verifies the pin. The output contains the
signed bundle, public key, request, BOM, `junit.xml`, page and check logs. The signing key is
not an artifact. Each workflow artifact is labelled `plimsoll-pr-<number>`.
The program limit is 30 seconds, enough for the small demonstration while keeping
a slow command bounded; longer suites need an explicit timeout extension.

[INTERNAL · one real local run →](evidence/README.md) holds the signed receipt of the
small sum program in [INTERNAL · fixture →](fixture/test.mjs), run by this script under
gVisor on 2026-10-21. `make receipt-suite` runs the script the same way and fails if its
output names a directory of the machine that made it; the script then moves that output aside
and leaves the output directory empty, so a workflow that uploads it after a failure publishes
nothing. The number 0 labels the local
exercise; no actual pull request or hosted workflow is asserted here.
