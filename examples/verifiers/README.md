# verifiers on plimsoll: an outside task, every call on the record

`go run ./examples/verifiers` runs Prime Intellect's verifiers library
([EXTERNAL · source repo ↗](https://github.com/PrimeIntellect-ai/verifiers)) on plimsoll docker
sessions through plimsoll's runtime plugin, `plimsoll_client.verifiers_runtime`, and writes the
page that shows what happened:
[INTERNAL · verifiers on plimsoll →](https://plimsollmark.github.io/plimsoll/examples/verifiers/index.html)
(source: `docs/examples/verifiers/index.html`).

**The model is a script, not an AI.** A loopback server answers each of verifiers' model requests
from a fixed list of moves (`clients/python/frameworks/verifiers/scripted_model.py` and
`attempt/policies.py`). It drives verifiers' real loop, interception server and runtime calls, so
every number measures verifiers, plimsoll and the task, never a model's skill. Nothing is paid
for.

## What it runs

Each configuration runs fresh, through the Python harness in
`clients/python/frameworks/verifiers/`:

- `vf-validate` of `plimsoll-sum`, plimsoll's tiny test environment, under runc and under gVisor:
  the same check `make docker-suite` runs (`docker_check.py`). The gold answer must pass, and the
  untouched task must score 0.0 when graded in a fresh sandbox.
- Prime's `uuid_ctf` task from prime-envs, unmodified, through `vf-eval`
  (`attempt/run_attempt.py`): the `plimsoll-bash` harness on plimsoll under runc and under gVisor
  with the solving script, under runc with a wrong answer, verifiers' shipped `bash` harness on
  plimsoll (it stops in its own setup: it installs itself from the network), and the shipped
  harness on verifiers' own docker runtime as the baseline.
- Each runtime call timed through verifiers' runtime API (`attempt/measure_calls.py`): 5 fresh
  runtimes per configuration, 20 commands each, a 1 KiB write and read.
- Terminal-Bench 2 read as data: each task's `task.toml`, grading script and Dockerfile matched
  against the rules in `census.go`. Nothing in it runs.

The two outside repositories are fetched at pinned commits, and any other commit is refused:
prime-envs at `e221a6514f2e8317af7922649a0d528aea5d087f`, whose task package must also match
every file's SHA-256 in `run.go` (its scoring code runs in the evaluator's Python, as verifiers
runs every task's), and Terminal-Bench 2 at `2fd12b88aafdd04a52c298e3940bcb189f9766d6`.

Every record log is rechecked twice: by the Python client's `check_record_log` when the run
ends, and by this program's Go checker (`recordlog.go`, over the `record` package's
`CheckStored`), and the run fails if the two disagree on any count. The logs are published
beside the page; a log is not signed, so rechecking shows the records agree with each other, not
who wrote the file.

## Run it

From the repository root, with docker, gVisor installed as docker's `runsc` runtime, and
Python 3.12:

```sh
make docker-images                         # plimsoll's sandbox images
make py-frameworks PY_FRAMEWORKS=verifiers # the hash-locked verifiers environment
go run ./examples/verifiers                # every configuration, fresh; writes docs/examples/verifiers/
go run ./examples/verifiers -verify        # recheck the published files; starts nothing
go run ./examples/verifiers -render        # rewrite index.html from evidence.json
go run ./examples/verifiers -assemble      # rebuild evidence.json and the page from the last run's raw output
```

It builds `plimsolld` and the session image `plimsoll-wip/verifiers-agent:dev`
(`attempt/agent.Dockerfile`: plimsoll's Python image plus `bash` and a `/workspace` link to
`/work`), and pulls `python:3.11-slim` for the baseline if it is missing. A full run takes a few
minutes. `-runsc=false` runs the runc configurations alone, without the call timing. Flags
`-python`, `-prime-envs`, `-terminal-bench` and `-work` move the interpreter, the two checkouts
and the scratch directory (default `tmp/verifiers-example/`).

It writes `docs/examples/verifiers/index.html`, `evidence.json` (every number the page states)
and `records/*.jsonl` (the record logs). Raw output (verifiers' traces, the daemons' logs) stays
in the scratch directory and is never published: a trace holds the evaluator's paths.

## A real model

`attempt/run_attempt.py --model NAME --upstream-base URL --upstream-key-stdin` (the key as one line on stdin, so it is in no environment; `--upstream-key-var VAR` reads a variable instead and leaves it readable in `/proc/<pid>/environ`) runs uuid_ctf with
a real language model instead of the script, and spends. It is run by hand, never by this program
or by any test.

`vf-eval` imports the outside task's code into its own process, which is started without the API key: it
calls a relay on loopback (`attempt/model_relay.py`) with a token made for the run, and the relay,
inside the driver, adds the real key and forwards one route to one host. The relay holds a dollar
budget for the run (at most $0.96), at list prices with cached input at its cached price, by
reserving an upper bound before each call and settling it from the answer's `usage` field; token
budgets stay as a backstop that the dollars always reach first. verifiers' own `max_total_tokens` is not a spending
limit: it counts each input token once, and an API bills the whole conversation again on every turn.
After the run every file under the output directory, any `--scan-file` (the driver's own log) and the child processes' environments are checked for the key. The
relay also refuses a request carrying one of the task's hidden values in a system message or before
the model's first turn.

`--fake-upstream POLICY` is the same run against a scripted server on loopback with a random canary
as the key, and spends nothing; its results say `dry_run` and cannot be published.

```sh
go run ./examples/verifiers -real-model DIR   # gather a run's output beside the page and rewrite it
```

That writes `docs/examples/verifiers/real-model/` and adds a section to the page. Without that
directory the page does not change. It refuses a dry run, a key found anywhere, or a hidden value
that reached the model. The section's score is the task's own grader's, read from verifiers' trace.
uuid_ctf is one small task, so that score says little about a model's skill, and the section says so.

## What it does not show

- Anything about an AI model, in the runs this program makes: the moves are scripted.
- verifiers' runtime conformance suite: it lives in verifiers' repository, not in the installed
  package, and was not run.
- That most hub environments run on plimsoll: a plimsoll server serves one image, and most
  environments name their own. The page's census shows what that means for Terminal-Bench 2.

## Tests

`go test ./examples/verifiers` rechecks a made-up log and refuses each change to it (a changed
digest, a dropped call, a miscounted close, a tier below the floor), checks the census rules and
the transcript comparison on made-up inputs, refuses a task package that is not the pinned one,
and verifies the published directory, then refuses a copy with one byte of one record changed.
`real_test.go` draws the real-model section from made-up results and refuses each thing that must
not reach the page. It needs no docker and no network. The relay's tests are
`clients/python/frameworks/verifiers/test_model_relay.py`, against local servers with canary keys.
