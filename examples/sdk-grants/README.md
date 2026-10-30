# The OpenAI and Anthropic libraries in a sandbox that never holds the key

`go run ./examples/sdk-grants` runs agent-style Python code that uses the OpenAI and
Anthropic client libraries, unmodified, in plimsoll docker sandboxes whose grant profile
sets `sdk_env`, and writes the page that shows what happened:
[INTERNAL · the SDK grants page →](https://plimsollmark.github.io/plimsoll/examples/sdk-grants/index.html)
(source: `docs/examples/sdk-grants/index.html`).

**The API is a stub, not OpenAI's or Anthropic's.** `stub.go` listens on two loopback
ports, answers like a small part of each API (a chat or messages call, the same call
streamed as server-sent events, a multipart file upload, and an embeddings route the
profile does not allow) and writes down every request it receives, headers included. No
model API is called and nothing is paid for.

## What it runs

Three project runs through `plimsolld` on the docker provider, with
`SANDBOX_DOCKER_SECCOMP=docker/seccomp.json` and `SANDBOX_DOCKER_SECCOMP_SDK=derived`:

- `guest/openai_main.py` under the `openai` profile: a chat call with an
  `OpenAI-Organization` header the profile does not pass, the same call streamed, an 8 MiB
  `files.create` upload on a route raised to 16 MiB for `multipart/form-data`, and
  `embeddings.create` on a route the profile does not allow;
- `guest/anthropic_main.py` under the `anthropic` profile, which passes
  `anthropic-version`: a messages call with an `anthropic-beta` header the profile does
  not pass, and the same call streamed;
- `guest/plain_main.py` with no grant, the control run.

Each guest also prints its whole environment, the environment of every process it can
see, and what happens when it opens an IPv4 TCP, UDP or IPv6 socket or connects to an
outside address (`guest/report.py`).

The image is plimsoll's Python image plus the two libraries, installed by
`sdk.Dockerfile` from `requirements.txt`: every wheel pinned by version and SHA-256 and
installed with `--require-hashes --no-deps --only-binary=:all:`. Building it uses the
network; a run never does. Nothing under `docker/` changes.

## What it writes

Beside the page in `docs/examples/sdk-grants/`:

- `bundle.jsonl` and `harness.pub`: every run's request, answer and run record, signed by
  a key made for the run (`go run ./cmd/plimsoll-attest verify -pub harness.pub bundle.jsonl`);
- `observations.dsse.json`: the harness's signed statement of what it saw outside the
  runs (the daemon's Describe, its audit lines and `/metrics` host-call series, the
  image, the keys it gave the daemon, the SHA-256 of each file below), naming the three
  records as its subjects;
- `stub.jsonl`: the stub's log; `grants.json`: the grants file the daemon read;
- `seccomp-default.json` and `seccomp-sdk.json`: the default profile and the variant the
  daemon derived, as it pinned them (read from its private directory by the digest its
  policy names);
- `evidence.json`: everything the page states, derived from the files above by
  `derive.go`, with each claim computed as a check. The socket, version, stream timing and
  sent-header claims are the guest code's own report from inside the sandbox, so `derive.go`
  takes a run only when its signed request carries this program's `main.py` and `report.py`
  byte for byte, and its one step.

## Run it

From the repository root, with docker and the images `make docker-images` builds:

```sh
go run ./examples/sdk-grants           # build the image, run everything, write docs/examples/sdk-grants/
go run ./examples/sdk-grants -verify   # recheck the published files; starts nothing
go run ./examples/sdk-grants -render   # rewrite index.html from evidence.json
go run ./examples/sdk-grants -derive   # rebuild evidence.json and index.html from the published raw files
```

`-build=false` skips the image build; `-work` moves the scratch directory (default
`tmp/sdk-grants-example/`, holding plimsolld, its log and the grants file; never published).
The run fails if any check the page states does not hold, after writing the page so the
evidence can be read.

## What it does not show

- How OpenAI's or Anthropic's servers answer: the stub stands in for them.
- E2B and Docker Cloud, where a standard client reaches the broker through the guard's raw
  route; `sdk_env` is not built on those providers.
- That a chat API's own server-side tools are safe to grant: the broker never reads a
  body ([docs/capability-grants.md](../../docs/capability-grants.md), "A grant to a chat
  API is a grant to the internet through the API's own tools").
- Sessions, snippets, or a library in another language.

## Tests

`go test ./examples/sdk-grants` verifies the published directory and every claim, refuses
a copy with one byte changed in the stub's log, the bundle, the variant profile, the
grants file, the evidence or the page, and checks that each check can say no: a stream
buffered whole, a header that reached the API unlisted, a dummy key in a header, a body or
an upload, a request off the allow list, a policy naming other profiles. It needs no
docker and no network.
