# A Nemotron coding agent whose every run is signed

`go run ./examples/nemotron-agent` gives an NVIDIA Nemotron model on
[Nebius Token Factory](https://tokenfactory.nebius.com/) (EXTERNAL · product page ↗) a
task and one tool, `run_code`, which runs code in a plimsoll session behind gVisor. The
model writes code, the code runs, the real output goes back to the model, and it fixes and
reruns until it answers. Every run leaves a signed run record, and the page the program
writes shows the conversation, each run with its record, and the verifier's verdict on the
bundle beside it.

What this proves: which code ran, what came back, in which sandbox at which tier, in what
order, signed by a key the daemon never held, and checkable offline by anyone with the
public key. What it does not prove: that the guest's output is true, or anything about
hardware (the tier is configuration and provider evidence plus the daemon's startup checks).

## Run it

From the repository root, with docker and gVisor (`runsc`) installed and the images from
`make docker-images`:

```sh
NEBIUS_API_KEY=... go run ./examples/nemotron-agent -task "Write and test a function that ..."
```

The key is read from the environment and never written. Flags: `-model` (default
`nvidia/Nemotron-3_5-Lightning`), `-base` (the OpenAI-compatible API,
`https://api.tokenfactory.nebius.com/v1`), `-runtime` (`runsc` or `runc`), `-image` (the
session image, default `plimsoll/sandbox-python:latest`), `-max-turns` (8), `-daemon` (a
running plimsolld to use instead of starting one, its token in `PLIMSOLL_TOKEN`), `-out`.

It writes `docs/examples/nemotron-agent/index.html` and, beside it, `bundle.jsonl` (the
signed records), `harness.pub` (the public key) and `transcript.json`. Check the bundle:

```sh
go run ./cmd/plimsoll-attest verify -pub docs/examples/nemotron-agent/harness.pub docs/examples/nemotron-agent/bundle.jsonl
```

## What the model is given

The model sees the task and the tool's description; after each run it sees the exit code,
stdout and stderr (8 KiB each at most), whether the run timed out, and the SHA-256 of the
signed record. The system prompt asks it to run its code, read the output, and never claim a
result it did not run. The page states nothing about a run on the model's say-so: every
number comes from the daemon's answer, checked by the client and signed.

## Tests

`go test ./examples/nemotron-agent` runs the loop against a scripted model and an in-memory
daemon with sessions, and verifies the bundle the program wrote, then refuses it with one
byte of a response changed. It spends nothing and needs no key.

## Verify in the browser

The page carries the same verification compiled to WebAssembly (`verifier/`, built by
`make nemotron-verifier` into `docs/examples/nemotron-agent/verify.wasm.gz`, about 3.7 MB,
decompressed in the page). Its two buttons verify the bundle beside the page and verify a
copy with one byte of a response changed, which is refused. The bundle and the key never
leave the browser.
