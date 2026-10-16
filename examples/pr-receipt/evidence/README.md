# One real pull-request receipt, 2026-10-16

The artifact of one real run of `receipt.sh` on a developer machine with docker and
gVisor (`runsc`), using the fixture project beside it (`sum.mjs`, `test.mjs`,
`package.json`) with `PR_NUMBER=0` and `TEST_COMMAND='npm test'`. The script built
plimsolld, plimsoll-attest and the converter from this checkout, started the daemon on a
loopback port of its own with the docker provider under `runsc` and the shipped seccomp
allowlist at a `kernel` floor, sent the three tracked files and the one command, sealed
the run into `bundle.jsonl` with a key made for the run and deleted afterwards (only
`harness.pub` is here), verified the bundle, wrote the BOM and its page, and checked the
BOM from its own attached evidence against that public key. No file the run wrote was
edited after it.

What each file is: `request.json` (the request as sent), `context.json` (the unsigned
pull-request context: number, tested commit, changed files, command), `bundle.jsonl` (the
signed exchange and its checkpoint), `harness.pub` (the run's public key),
`run-4e72b664433b.cdx.json` (the BOM, named by the record digest), `index.html` (the page
for that one run), `run.log`, `verify.log`, `emit.log`, `check.log` (what each tool
printed) and `status.txt` (`PASS`: the outcome was completed and every step exited 0).

`verify.log`: "verified 2 entries … whole to its last checkpoint: 1 single runs".
`check.log`: eight PASS lines and the standing LIMIT line; no image label was supplied, so
the image link check does not appear. The run's times are the daemon's own clock.

This run replaces one of 2026-10-13, whose `run.log` named the bundle by an absolute path
on the machine that made it. The script now runs its tools from the output directory with
relative names and refuses to finish if any output file names a directory of the machine
(the checkout, the project, the output, the home); `make receipt-suite` runs it end to end
and checks the same. The request is byte-identical to the earlier run's.
