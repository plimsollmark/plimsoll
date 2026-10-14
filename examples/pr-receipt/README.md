# A receipt for a pull request

This copyable example runs a JavaScript project's test command in plimsoll under
gVisor, a separate user-space kernel. It asks for the `kernel` isolation floor,
checks the returned record, signs it and emits a CycloneDX bill of materials
(BOM, an ingredients label with the signed receipt attached). The tier is
configuration and provider evidence plus startup checks, never hardware attestation.
The receipt covers the command and files that ran. It does not cover a later merge,
prove who wrote the files, or promise that the tests catch every defect.

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
Binary files, links, oversized projects and projects with no tracked files are
refused rather than silently omitted. Deleted files are absent from the tested
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
TEST_COMMAND='npm test' PR_NUMBER=0 \
  examples/pr-receipt/receipt.sh /path/to/tracked/project "$PWD/tmp/pr-receipt-output"
```

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

[INTERNAL · dated local exercise status →](evidence/README.md) records the
2026-10-13 attempt with the small sum program in
[INTERNAL · fixture →](fixture/test.mjs). Startup refused the isolated process-ID
namespace before code was sent, because the host process-limit check could not
read Docker's host cgroup. No new signed run was obtained. The dated instructions
let a host-side agent finish it without weakening that check. The number 0 labels
the local exercise; no actual pull request or hosted workflow is asserted here.
