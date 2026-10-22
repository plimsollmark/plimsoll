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
Binary files, links, oversized projects, projects with no tracked files or more than
199 (the subject is the 200th file, plimsoll's limit), a tracked file under
`.pr-receipt/`, and tracked files that differ from the commit are refused rather than
silently omitted or misnamed. The test command can read the subject file like any other. Deleted files are absent from the tested
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

`PLIMSOLL_PAGES` is the absolute URL, ending in `/`, where the output directory will be
published; the BOM's attestation reference and the page's file links are built from it.
It defaults to the raw GitHub URL of this example's `evidence/` directory, which is
right for the committed artifact and wrong for anyone else's run, so set it.

Local execution leaves `PLIMSOLL_REF` unset when testing an unpublished working
copy. The workflow always supplies and verifies the pin. The output contains the
signed bundle, public key, request, BOM, page and check logs. The signing key is
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
