# The ship scan, five calls

`go run ./examples/ship-scan` shows the ship scan end to end and writes the page that shows what happened:
[INTERNAL · the ship scan, five calls →](https://plimsollmark.github.io/plimsoll/examples/ship-scan/index.html)
(source: `docs/examples/ship-scan/index.html`). The reference is [INTERNAL · the ship scan reference →](../../docs/ship-scan.md).

It needs no docker, no network, no credentials and no model. Run it from the repository root: it builds
`plimsolld` and `plimsoll-withheld` from source.

```sh
go run ./examples/ship-scan            # run the calls, write the page and its evidence
go run ./examples/ship-scan -verify    # check the published files offline; starts nothing
go run ./examples/ship-scan -render    # rewrite the page from the published evidence
```

## What it runs

It writes a toy harness (one simulator file, `harness/sim.py`) and `seeds.txt` with three seeds made up for the run,
then builds the set the way docs/ship-scan.md recommends, with one command:

```sh
plimsoll-withheld build -mode refuse -file harness/ -source harness/ -source-mode refuse \
  -values seeds.txt -values-mode audit > withheld.json
```

The harness's files are `refuse`: shipping them is the harness developer's mistake. The seeds are `audit`: a refusal
is an answer, so an agent that put a guessed seed in its code and saw the call refused would know the guess was
right; in audit mode the call runs, the agent learns nothing, and the operator's log names the seed's label.

It starts plimsolld with `SANDBOX_PROVIDER=wasm` and `PLIMSOLL_WITHHELD_FILE`, and sends five calls through the Go
client, each with its own trace id:

| Call | What it carries | Outcome |
|---|---|---|
| `clean` | a controller snippet with nothing withheld | runs; its run record is rechecked |
| `harness-file` | the simulator as a project file, byte for byte | refused, not dispatched (`permission`) |
| `harness-edited` | the simulator with a function renamed and its indents changed | refused (the source entry) |
| `harness-archive` | the simulator inside a `.tar.gz`, as base64 text | refused; the refusal never names the member |
| `seed-in-code` | a snippet with the second seed as a constant | runs; only the operator's log names `seeds.txt:2` |

The project calls are refused by the scan before the WASM provider, which runs snippets only, is asked. Then
`plimsoll-withheld scan` runs the same set over two folders offline.

## What is published, and what is not

`docs/examples/ship-scan/` holds `evidence.json`, the set (`withheld.json`), the clean call's request and response, the seed call's
response, and the page. The evidence is an allowlist: each call is described by text this program wrote, the daemon's log
lines are reduced to the fields `LogLine` lists and matched to the call by trace id, and an answer keeps only what the
caller was told. The seed call's request is not published (it holds a seed); its response is, so `-verify` recomputes that record's
result digest and checks the answer shown, and the request digest is the one the client checked.

The seeds are made up for each run, used nowhere else, and deleted with the run's work directory when it ends, which
is the only reason the set is published: a ten-digit
seed's digest is found by trying every ten-digit number, so a set of real seeds is as secret as the seeds.

## Checks

- Before it publishes, the program checks every claim the page makes (`checkEvidence`) and that no seed and no
  distinctive line of the simulator is in the daemon's whole log, the evidence, the clean exchange or the page.
- `-verify` repeats the claims against the published files, checks the set's SHA-256 on every log line, recomputes
  the clean call's run record from its exchange, and checks the page is what the evidence renders.
- `go test ./examples/ship-scan`: the published files verify; 23 alterations of the evidence each fail it; the two
  lines the page quotes from `examples/squeeze/argon-scan.txt` are still there; and the whole run, end to end on
  WASM, with fresh random seeds, so it is a canary run as well.

## What it does not show

The scan's limits are in [INTERNAL · the ship scan's limits →](../../docs/ship-scan.md#limits). Here: the provider is WASM (process
tier: it runs inside the daemon's own process, with no operating-system isolation boundary, so it is not for
hostile code in production), so no project runs; the run record of a call that ran does not
state that it was scanned, so the operator's log is the evidence; and the harness is a toy, the hackathon case on the
page an offline reconstruction (`examples/squeeze/argon-scan.sh`).
