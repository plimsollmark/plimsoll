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
receipt, then leaves the workflow red. Every output also holds `states.json`, which says
plainly what the receipt covers, and the job summary shows it one line per state
([INTERNAL · receipt states →](#receipt-states-what-a-receipt-covers-said-plainly)).

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
The daemon's own temporary directory, where the docker provider makes its Unix sockets, is
never under the checkout: Linux refuses a socket path over 107 bytes, and a GitHub runner's
checkout path (`/home/runner/work/<repository>/<repository>/tools/plimsoll`) holds the
repository's name twice. The script makes a new private directory (a random name, mode
0700) under `$RUNNER_TEMP`, the runner's temporary directory that it empties at each job's
start and end, or under `/tmp` when that is unset or too long, and removes it at exit. On a
hosted Linux runner, whose `RUNNER_TEMP` is `/home/runner/work/_temp`
([EXTERNAL · official docs ↗](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)),
the longest socket path is then 84 bytes whatever the repository is called
([INTERNAL · receipt_test.go →](receipt_test.go) runs the script from a checkout under a
100-character repository name and fails if a socket would not fit).

```sh
TEST_COMMAND='npm test' PR_NUMBER=0 PR_REPOSITORY=example/project \
  examples/pr-receipt/receipt.sh /path/to/committed/project "$PWD/tmp/pr-receipt-output"
```

`PR_REPOSITORY` is the CI platform's name for the repository (the workflow passes
GitHub's `owner/name`); a verifier compares it with the name its own platform gives.
`PR_HEAD_SHA`, when set, is the commit the run is for (the workflow passes the pull
request's head from the event); the receipt's states compare the commit that ran with it,
and a different one fails the job. Unset, the project's own `HEAD` stands in.

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
which belong to the pull request.

The job fails when a step exits nonzero or times out, from the signed exit codes. With
`JUNIT_PATH` set it also fails, though every step exited 0, when the report the run
returned is missing or not JUnit, lists a failure or error, or lists fewer tests that ran
than the minimum: 1 by default, so a report of zero tests, or of skipped tests only, fails.
A test command can exit 0 with every test skipped, or with a failure its runner did not
turn into an exit code; a green check over either says the tests passed when none did. Set
`PLIMSOLL_MIN_TESTS` to raise the minimum (the workflow reads the repository variable
`PLIMSOLL_MIN_TESTS`); it needs `JUNIT_PATH`, since without a report there is nothing to
count. These are read from the report as the run returned it inside the signed result,
never from a `junit.xml` beside the receipt or from printed text.

## Standard formats: a signed test-result statement and Cobertura coverage

Evidence stores and policy engines read a few standard formats. Every output also holds
`test-result.intoto.json`, an in-toto test-result statement
([EXTERNAL · in-toto predicate specification, a GitHub repository ↗](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md))
in the standard signed envelope, signed with the same key as the run
(`plimsoll-attest sign-statement`). Its subject is the repository and commit the signed
request names; its result is `PASSED` only when every step exited 0 without timing out
and a readable JUnit report lists at least one test that ran and passed, and no case
failures, errors or nonzero failure/error summary counters; its test names come from
`junit.xml`. A missing requested report, malformed XML, an unsupported root element,
invalid failure/error counters, or a report in which no test ran (none listed, or only
skipped ones) produces `FAILED`: the evidence could not establish a passing test report.
Without `JUNIT_PATH`, the report is constructed from the signed command results. A
minimum above one (`PLIMSOLL_MIN_TESTS`) is the job's setting, not the signed result's,
so the statement does not carry it; it lists the passed tests, which a policy can count. The predicate has
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

## Beside an AI reviewer's required check

An AI reviewer's own merge check can pass with no review behind it: CodeRabbit's
`CodeRabbit` check counts as passing for a required check when the review was skipped or
rate limited ([EXTERNAL · official docs ↗](https://docs.coderabbit.ai/pr-reviews/status-check)).
The receipt job answers a different question, whether these tests ran on this exact commit
and passed, and it does not pass by being skipped. GitHub turns a skip into a pass in two
cases ([EXTERNAL · official docs ↗](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks)):
a job skipped by its own `if:` reports Success, and a job that needs a failed job may not
block merging. A workflow skipped by a path, branch or commit-message filter leaves its
required check pending, which blocks the merge. This workflow has one job, with no job-level
condition, no `needs` and no event filter, and
[INTERNAL · workflow_test.go →](workflow_test.go) fails if one is added. Require both
checks: the receipt shows the tests ran on the head commit even when the reviewer skipped
it, and it does not show that anyone reviewed the change.

What it does not cover: the pull request's head commit is what runs, not the later merge
commit; the workflow handles `pull_request` only, so in a merge queue its required check
never reports and the queued merge fails (add `merge_group` once you have decided what a
queued commit must prove); and without `JUNIT_PATH` the job knows the exit codes, not how
many tests ran, so a test command that runs no test and exits 0 passes it (set
`JUNIT_PATH`, above).

One limit stands. On `pull_request`, GitHub runs the workflow file as the pull request has
it, so a pull request can rewrite the receipt job to pass, and sign with any key the job can
read. Three ways to keep the check out of its author's hands:

- Require a code owner's review for `.github/workflows/` (a `CODEOWNERS` entry and "Require
  review from Code Owners"), so a rewritten job is seen before it merges. Every plan has it.
- Have an operator outside the pull request's control make the receipt with a key the author
  cannot read, and report it as a status from a GitHub App chosen as the required check's
  expected source, which a ruleset can name
  ([EXTERNAL · official docs ↗](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)).
  `verify.py` checks such a receipt (next section).
- On GitHub Enterprise Cloud, require the workflow through an organization ruleset, "Require
  workflows to pass before merging", pinned to a commit in another repository
  ([EXTERNAL · official docs ↗](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)).

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
`--coverage-path`), that the Cobertura file equals the one converted from the signed lcov file; that the run
completed behind the kernel tier or stronger with every step exiting 0; and, when the
receipt asks for a test report (or with `--min-tests N`), that the report the run returned
lists no failure or error and at least N tests that ran (1 by default). Nothing after a
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

With `--self-consistent` instead of `--trusted-pub`, it reads a receipt signed with a key
made for the run (the template's default): every check runs against the key the receipt
carries, and the result is never verified, since anyone can make a key and sign a receipt.
For the same reason the JUnit report inside a receipt is read only when it is at most 8 MiB
(the most a run returns in artifacts) and declares no DOCTYPE or entity: Python's
`xml.etree` expands the entities a DOCTYPE declares, and nested ones take any amount of
memory ([EXTERNAL · official docs ↗](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)).
A test framework's report needs neither, and one that has either reads as not JUnit XML.

It prints a JSON report naming the SHA-256 of the receipt it checked (hand that file, and no
other, to whatever reads the receipt next), with the receipt's states (next section), and
exits 0 when every check passes against the operator's key, 1 when the receipt is refused,
its tests failed or it was read as self-consistent only, 2 on a usage error and 3 when the
check could not run (an unusable key is never a pass). Its own git calls use git's defaults, never the
machine's settings; the clone it reads must be checked out with git's defaults too.

## Receipt states: what a receipt covers, said plainly

A receipt that checks is not the same as tests that passed. A run can end at its time
limit, a test report can list no tests, a receipt can be for the commit before a later push,
and a receipt signed with a key made for the run shows only that it agrees with itself. So
every reading of a receipt says where it stands, each state in one word from a fixed list.
`verify.py` puts them in its report as `states`, each an object with a `value` and a
one-sentence `detail` built from signed values and the verifier's own words, never from text
the tests printed. `receipt.sh` writes that report on the receipt it just made to
`states.json` and prints one line per state; the workflow writes the same lines to the job
summary (`$GITHUB_STEP_SUMMARY`, the page GitHub shows for the run) after the upload step.
[INTERNAL · states.py →](states.py) derives them. What cannot be established is `unknown`,
and an unknown never counts toward a pass.

| State | Its values, in plain words |
|---|---|
| `signer` | `trusted_key`: the signature checks against a public key given to the checker separately (`--trusted-pub`). `self_consistent`: it checks only against the key the receipt carries (`--self-consistent`), which shows the receipt agrees with itself, not who made it. `refused`: it does not check, and nothing in the receipt is read. `unknown`: the check could not run. |
| `covers` | `known`: the repository, commit, pull request and base that the signed subject file names, given as fields. `unknown`: the signed request names none. |
| `candidate` | Whether the receipt is evidence for the head the checker was given (`--head`, read when the check runs). `current`: that commit, and the signed request is exactly what the recipe builds there. `stale`: another commit of the same repository and pull request, such as the one before a later push. `mismatch`: the head's commit, but other files, command, base or sessions than this configuration gives. `other`: another repository or pull request, or no subject. `unknown`: the request for the head could not be rebuilt (the clone lacks the commit), or no head was given. |
| `run` | The signed outcome: `completed` (the run reached its end, a failing step included), `setup_failed` (no step began), `timed_out` (the time limit ended it), `protocol_error` (the sandbox gave no readable result), `runner_failed` (the runner failed after a step began), or `unknown` (an outcome this reader does not know, or a call that got no answer). Its fields give the isolation tier and how many of the requested steps ran. |
| `steps` | `passed`: every requested step ran and exited 0 without timing out. `failed`: one exited nonzero or timed out. `not_run`: not every step ran, and none failed. `unknown`: the result does not say. |
| `tests` | Read only from the JUnit report the run returned inside the signed result (`JUNIT_PATH`), so it is the test framework's own count, written by the project's code. `discovered`: the report lists at least one test that ran (fields: cases, passed, failed, skipped). `zero`: it lists none, or only skipped ones. `unknown`: no report was requested, none came back, or it is not JUnit XML this reads (over 8 MiB, or declaring a DOCTYPE). Never counted from the steps or from printed text. Its field `minimum` is the fewest tests that ran the job requires: 1 whenever a report was requested, unless `PLIMSOLL_MIN_TESTS` (`--min-tests`) says more, and none when no report was requested. |
| `evidence` | `complete`: every file the run was asked to return came back, and no output was cut. `partial`: a requested file is missing, or the returned files or a step's output went over its budget (fields: `missing`, `cut`). `unknown`: the run gave no readable result. |
| `verdict` | One reading of the rest, by the first rule that matches: `unknown` when the signature check could not run; `refused` when the signature does not check, the candidate is `stale`, `mismatch` or `other`, or a file given beside the receipt differs from it; `failed` when the run did not complete, a step failed or did not run, it ran below the kernel tier, the returned report lists failures, or a run that completed was asked for a report and that report did not come back readable or lists fewer tests that ran than the minimum (zero tests included), or the repository's own policy (`--policy`, next section) refused it; `unknown` when the candidate, run or steps are unknown; `incomplete` when every check that ran passed but the signer is only self-consistent, no report was requested so how many tests ran is unknown, or part of the evidence did not come back; `passed` otherwise. |
| `stored` | The job summary only, from GitHub's outcome of the upload step: `uploaded` (kept as the workflow artifact), `not_uploaded` (the upload failed or did not run, and the runner holding the receipt is discarded with the job), or `unknown`. A verifier holding a receipt has it, so its report has no such state. |

Beside the states, `unverified` lists by code what the receipt does not show: always
`merge_result` (the commit a merge would make), `authorship` (who wrote the files) and
`test_quality` (whether the tests check the change); when they apply, `signer_identity`,
`test_count`, and `junit_file`, `test_result_statement` or `coverage_file` for a file beside
the receipt the verifier was not given; or `everything` alone when the signature was not
established.

The verdict is stricter than `verified` and does not replace it. `verified` and the exit
codes decide from the signature, the head, the signed exit codes and, when the receipt asks
for a test report, that report's failures and count (the `tests` check). So a receipt with
no test report verifies (exit 0) while its verdict says `incomplete`, and one whose report
lists zero tests is refused (exit 1) and its verdict says `failed`. The template's default
key is made for the run, so its job
summary reads `self_consistent` and at best `incomplete`. The job fails when the signed
result fails, and also when its own check of the receipt refuses it: a head other than the
event's (`PR_HEAD_SHA`), a file beside the receipt that differs from it, or a returned test
report that is missing, lists a failure or error, or lists fewer tests that ran than the
minimum. The job writes the summary, so the summary is out of the pull request's hands only
as far as the job is (above).

## A policy of your own

`--policy FILE` (repeatable) adds the repository's own rules, written in Rego, the policy
language of Open Policy Agent ([EXTERNAL · official docs ↗](https://www.openpolicyagent.org/docs/policy-language)).
`--opa` names the `opa` binary that evaluates them. The verifier hashes that binary before it
runs it and runs a private copy of exactly the bytes it hashed, so a binary that is not the
release [INTERNAL · policy/opa.version →](policy/opa.version) pins (or the SHA-256 given with
`--opa-sha256`) is never run, however it was found. The policy runs only after the signature
and head checks pass, as the last check, over facts from the signed run: the subject
(repository, commit, pull request, agent sessions), the request (isolation floor, steps), the
result (tier, provider, outcome, each step's exit code and timeout, the returned files by
digest), the record's own fields, every check before it (the tests check included) and
`signer`, which says whether the signature checked against the operator's key or only against
the one the receipt carries (`--self-consistent`). [INTERNAL · policy/input.schema.json →](policy/input.schema.json)
lists every field. No step's output reaches it: what a step printed is the tested code's to
write.

It evaluates `data.plimsoll.receipt.deny`, a set of strings; each string is a refusal, listed
in the report's `policy` check (`refusals`), and an empty set adds none. A refusal makes the
receipt's `verdict` state `failed`, which names how many refusals there were but not their
text, so the states and the exit code agree. [INTERNAL · policy/receipt.rego →](policy/receipt.rego) is
an example to copy: tier at or above the floor and at least kernel, every verifier check
passed, the runner did not fail, the run completed and every step exited 0.

```sh
python3 -I examples/pr-receipt/verify.py ... --opa "$(sh examples/pr-receipt/policy/opa.sh "$PWD/tmp/tools")" \
  --policy /path/to/a-checkout-of-the-base-branch/receipt.rego
```

What it guarantees, and what it does not:

- **A policy can only refuse.** The verifier's own checks still decide, so a mistaken policy
  cannot accept a receipt they refuse.
- **A policy that is wrong stops the check (exit 3), never passes.** OPA is handed the input
  schema, and OPA's type checker treats a field the schema does not name as an error
  ([EXTERNAL · official docs ↗](https://www.openpolicyagent.org/docs/policy-language#translating-schemas-to-rego-types-and-dynamicity)),
  so a misspelled field stops the check rather than becoming a rule that never fires; a
  policy in another package, a deny set that is not strings, and a built-in function that
  errors stop it too.
- **The decision repeats offline.** The policy runs with no built-in that reaches the network
  (`http.send`, or the JSON schema matchers, which fetch remote references), reads the
  environment (`opa.runtime`, which would hand it the CI job's secrets) or reads the clock or
  a random source (certificate verification against today's date included), and with no host
  OPA may reach; a policy that calls one does not compile. The same receipt, policy and OPA
  release give the same answer later, anywhere.
- **Where the policy comes from is yours to decide.** Read it from the base branch or another
  repository, never from the pull request's own checkout, whose author could rewrite it.
- `--policy-input FILE` writes the input your policy reads, for writing and testing one with
  `opa eval` or `opa test`.

The gate is pinned to Open Policy Agent v1.21.4, its SHA-256 in
[INTERNAL · policy/opa.version →](policy/opa.version); `make policy-suite` downloads that
release once into `tmp/tools`, checks the digest before it runs, and runs the example
policy's own tests and every refusal above on it.

## The receipt challenge: does your gate refuse these?

A merge gate that only checks that a receipt exists, or only that it is signed, or only reads
the JUnit file beside it, waves through things it should not. [INTERNAL · challenge/ →](challenge/)
holds one honest receipt and eight that a correct gate refuses, all made by this recipe under
gVisor ([INTERNAL · generate.sh →](challenge/generate.sh)), with a five-commit project to check
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
| every test skipped | a genuine, correctly signed receipt for a run in which every step exited 0 and the returned report lists only skipped tests | refuses at the test count |
| timed out | a genuine, correctly signed receipt for a run the 30-second limit ended, its report cut off mid-write | refuses at the result |

```sh
go -C examples/sbom build -o "$PWD/tmp/sbom" .
python3 -I examples/pr-receipt/challenge/check.py --sbom "$PWD/tmp/sbom"
```

`check.py` runs every case through `verify.py` and prints what it decided beside what
`cases.json` expects, which also names each case's states (the verdict reads `passed` for
the honest receipt alone); run your own gate on the same files and compare. The operator's
public key is [INTERNAL · operator.pub →](challenge/operator.pub); its private key was made
for the run and deleted.

`PLIMSOLL_PAGES` is the absolute URL, ending in `/`, where the output directory will be
published; the BOM's attestation reference and the page's file links are built from it.
It defaults to the raw GitHub URL of this example's `evidence/` directory, which is
right for the committed artifact and wrong for anyone else's run, so set it.

Local execution leaves `PLIMSOLL_REF` unset when testing an unpublished working
copy. The workflow always supplies and verifies the pin. The output contains the
signed bundle, public key, request, BOM, `junit.xml`, `states.json`, page and check logs. The signing key is
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
