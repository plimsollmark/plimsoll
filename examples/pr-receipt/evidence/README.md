# One real pull-request receipt, 2026-10-13

The artifact of one real run of `receipt.sh` on a developer machine with docker and
gVisor (`runsc`), using the fixture project beside it (`sum.mjs`, `test.mjs`,
`package.json`) with `PR_NUMBER=0` and `TEST_COMMAND='npm test'`. The script built
plimsolld, plimsoll-attest and the converter from this checkout, started the daemon on a
loopback port of its own with the docker provider under `runsc` and the shipped seccomp
allowlist at a `kernel` floor, sent the three tracked files and the one command, sealed
the run into `bundle.jsonl` with a key made for the run and deleted afterwards (only
`harness.pub` is here), verified the bundle, wrote the BOM and its page, and checked the
BOM from its own attached evidence against that public key.

What each file is: `request.json` (the request as sent), `context.json` (the unsigned
pull-request context: number, tested commit, changed files, command), `bundle.jsonl` (the
signed exchange and its checkpoint), `harness.pub` (the run's public key),
`run-26e4dd7e7e7b.cdx.json` (the BOM, named by the record digest), `index.html` (the page
for that one run), `run.log`, `verify.log`, `emit.log`, `check.log` (what each tool
printed) and `status.txt` (`PASS`: the outcome was completed and every step exited 0).

The BOM, its page, `emit.log` and `check.log` were re-derived once from this same
bundle and public key after the run, with the pages option set to this directory's raw
GitHub URL so the BOM's attestation reference and the page's links name this run's own
evidence (the first derivation used the main example's default). The run's originals,
`bundle.jsonl`, `harness.pub`, `request.json`, `context.json`, `run.log` and
`verify.log`, are untouched, and the record digest in the BOM's file name is the same.

`verify.log`: "verified 2 entries … whole to its last checkpoint: 1 single runs".
`check.log`: seven PASS lines and the standing LIMIT line; no image label was supplied, so
the image link check does not appear. The run's times are the daemon's own clock. The
earlier attempt inside a process-isolated session was refused by the daemon's startup
check (it could not read the host cgroup that proves the process limit); that refusal was
kept, and this run on the host is the evidence.
