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

## Against the real APIs (`-live`)

`-live` runs the same unmodified libraries against real services, and it spends: the OpenAI
library against Nebius Token Factory's OpenAI-compatible API (model
`nvidia/Nemotron-3_5-Lightning`), and the Anthropic library against Anthropic's API (model
`claude-haiku-5-5`). Each makes one plain call and one streamed call with a short fixed prompt
and `max_tokens=64`, then a call to a route its profile does not allow, which the broker refuses.
No test or gate reaches it.

It needs `NEBIUS_API_KEY` and `ANTHROPIC_API_KEY` in its environment. It hands them to the daemon
alone, removes them from its own environment before any other child starts, and the grants file
names the variables, never the values. `-anthropic-workspace ID` sets the
`anthropic-workspace-id` header, which a key not scoped to one workspace needs.

```sh
go run ./examples/sdk-grants -live
```

The spend is held three ways: the guest's fixed calls with retries off; each profile's
`route_max_calls`, which the broker enforces whatever the guest does; and a check that refuses to
start if the calls at list price could pass $0.25 (they cannot: about $0.00013). It writes
`docs/examples/sdk-grants/live/` only if every check holds, and the page gains a section drawn
from `live/live.json`. Without that directory the page does not change.

It can show less than the stub run, because a real API keeps no log for it to read. It shows
that each API answered, that a stream arrived in pieces, that the broker refused the route off
the list, and that neither key is in what the run sent or answered, or in the sandbox's
processes and files. That last check works from a salted SHA-256 of each key, hashing every
window of the key's length, so `-verify` and any reader can rerun it on the published files
without holding the key. It finds a key's exact bytes, not an encoded copy. It cannot show what
the API received.

`PLIMSOLL_SDK_GRANTS_LIVE_STUB=1 go test ./examples/sdk-grants -run TestLivePlumbing -v` runs this
whole path against the local stub with canary keys, under docker, and spends nothing.

## What it does not show

- How OpenAI's or Anthropic's servers answer: the stub stands in for them, except in the live
  section, once a `-live` run sits beside the page.
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
docker and no network. `live_test.go` holds the guest code to the numbers the budget check
uses, refuses a run over budget or without a key before anything starts, and refuses a stub
run's results as a real run's.
