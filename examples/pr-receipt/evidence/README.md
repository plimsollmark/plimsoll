# One real pull-request receipt, 2026-10-23

The artifact of one real run of `receipt.sh` on a developer machine with docker and
gVisor (`runsc`), using the fixture project beside it (`sum.mjs`, `test.mjs`,
`package.json`), committed once with a fixed author and date (commit `627534fc71de`), with
`PR_NUMBER=0`, `PR_REPOSITORY=example/pr-receipt-fixture` and `TEST_COMMAND='npm test'`. The script built
plimsolld, plimsoll-attest and the converter from this checkout, started the daemon on a
loopback port of its own with the docker provider under `runsc` and the shipped seccomp
allowlist at a `kernel` floor, sent the three tracked files, the subject file `.pr-receipt/subject.json` naming the
repository, commit and pull request, and the one command, sealed
the run into `bundle.jsonl` with a key made for the run and deleted afterwards (only
`harness.pub` is here), verified the bundle, wrote the BOM and its page, and checked the
BOM from its own attached evidence against that public key. No file the run wrote was
edited after it.

What each file is: `request.json` (the request as sent), `context.json` (the unsigned
pull-request context: number, tested commit, changed files, command), `bundle.jsonl` (the
signed exchange and its checkpoint), `harness.pub` (the run's public key),
`run-edfbd999f17d.cdx.json` (the BOM, named by the record digest), `index.html` (the page
for that one run), `junit.xml` (the test report: the run asked for no JUnit file, so the
script built it from the signed result alone, one test case for the one step, and anyone gets
the same bytes from the same BOM; `verify.py --junit` checks it), `test-result.intoto.json`
(an in-toto test-result statement about the commit, signed with the run's key, which
`verify.py --test-result` checks), `run.log`, `verify.log`, `emit.log`, `check.log`,
`statement.log` (what each tool printed) and `status.txt` (`PASS`: the outcome was completed
and every step exited 0).

`verify.log`: "verified 2 entries … whole to its last checkpoint: 1 single runs".
`check.log`: eight PASS lines and the standing LIMIT line; no image label was supplied, so
the image link check does not appear. The run's times are the daemon's own clock.

This run, made with record version 4 and protocol 4, replaces one of 2026-10-21 on the same
commit, whose record was version 2. That one replaced one of 2026-10-16, whose request named no repository or commit, so its
receipt would also have passed for another commit or repository with the same files. That
one replaced a run of 2026-10-13 whose `run.log` named the bundle by an absolute path on the
machine that made it; the script now refuses to finish if any output file names a directory
of the machine (the checkout, the project, the output, the home), and `make receipt-suite`
runs it end to end and checks the same.
