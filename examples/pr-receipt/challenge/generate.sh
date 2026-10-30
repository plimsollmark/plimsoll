#!/usr/bin/env bash
# Regenerate the receipt challenge: one honest pull-request receipt and the receipts and
# claims a merge gate must refuse, each made by the real recipe under gVisor. Run from the
# repository root with docker, runsc and the containerd image store (what make receipt-suite
# needs). Writes examples/pr-receipt/challenge/{project.bundle,operator.pub,receipts/}; the
# operator's private key is made for the run in a scratch directory and deleted with it.
set -euo pipefail
here=examples/pr-receipt/challenge
scratch="$(mktemp -d "$PWD/tmp/receipt-challenge.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
command_line='node --test --test-reporter=junit --test-reporter-destination=reports.xml test.mjs'

# The project: five commits with fixed authors and dates, so their IDs are the same on
# every regeneration. main: the fixture, then a README. The branch "broken": a sum that
# drops the last value, whose tests fail. The branch "skipped": every test marked to skip,
# so every step exits 0 and no test runs. The branch "hangs": a test that waits an hour, so
# the recipe's 30-second limit ends the run.
project="$scratch/project"
mkdir -p "$project"
cp examples/pr-receipt/fixture/{package.json,sum.mjs,test.mjs} "$project/"
export GIT_AUTHOR_NAME='Receipt Challenge' GIT_AUTHOR_EMAIL='challenge@example.invalid'
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
g() { git -C "$project" -c init.defaultBranch=main -c commit.gpgsign=false "$@"; }
at() { export GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1"; }
g init -q
g add -A; at '2026-10-01T12:00:00Z'; g commit -q -m 'Sum a list of numbers'
tested=$(g rev-parse HEAD)
g checkout -q -b broken
printf '%s\n' 'export const sum = values => values.slice(0, -1).reduce((total, value) => total + value, 0);' > "$project/sum.mjs"
g add -A; at '2026-10-02T12:00:00Z'; g commit -q -m 'Sum a list of numbers, faster'
broken=$(g rev-parse HEAD)
g checkout -q main
printf '%s\n' '# sum' > "$project/README.md"
g add -A; at '2026-10-03T12:00:00Z'; g commit -q -m 'Add a README'
later=$(g rev-parse HEAD)
g checkout -q -b skipped "$tested"
cat > "$project/test.mjs" <<'JS'
import test from 'node:test';
import assert from 'node:assert/strict';
import {sum} from './sum.mjs';
test.skip('adds three numbers', () => assert.equal(sum([10, 20, -5]), 25));
test.skip('sums an empty list to 0', () => assert.equal(sum([]), 0));
JS
g add -A; at '2026-10-04T12:00:00Z'; g commit -q -m 'Skip the sum tests for now'
skipped=$(g rev-parse HEAD)
g checkout -q -b hangs "$tested"
cat > "$project/test.mjs" <<'JS'
import test from 'node:test';
test('waits for a reply that never comes', () => new Promise(resolve => setTimeout(resolve, 3600000)));
JS
g add -A; at '2026-10-05T12:00:00Z'; g commit -q -m 'Test against the reply service'
hangs=$(g rev-parse HEAD)
g checkout -q "$tested"
g bundle create "$scratch/project.bundle" --all 2>/dev/null

# Two operator keys: the one a gate trusts, and another.
go run ./cmd/plimsoll-attest keygen -out "$scratch/operator" >/dev/null
go run ./cmd/plimsoll-attest keygen -out "$scratch/other" >/dev/null

receipt() { # $1 out dir, $2 key, $3 commit
  g checkout -q "$3"
  TEST_COMMAND="$command_line" JUNIT_PATH=reports.xml PR_NUMBER=7 PR_REPOSITORY=example/receipt-challenge \
    PLIMSOLL_HARNESS_KEY="$2.key" bash examples/pr-receipt/receipt.sh "$project" "$1" >/dev/null
}
receipt "$scratch/honest" "$scratch/operator" "$tested"
receipt "$scratch/other-signer" "$scratch/other" "$tested"
receipt "$scratch/failing" "$scratch/operator" "$broken" || true # the run fails; its receipt is still made
receipt "$scratch/skipped" "$scratch/operator" "$skipped" || true # every step exits 0; the job fails at its tests check
receipt "$scratch/timed-out" "$scratch/operator" "$hangs" || true # the time limit ends the run; its receipt is still made

rm -rf "$here/receipts" && mkdir -p "$here/receipts"
cp "$scratch/project.bundle" "$here/"
cp "$scratch/operator.pub" "$here/operator.pub"
for d in honest other-signer failing skipped timed-out; do
  mkdir -p "$here/receipts/$d"
  cp "$scratch/$d"/run-*.cdx.json "$here/receipts/$d/receipt.cdx.json"
  # A run that did not return its report has no junit.xml (junit.py says why).
  if [ -f "$scratch/$d/junit.xml" ]; then cp "$scratch/$d/junit.xml" "$here/receipts/$d/junit.xml"; fi
done

# Two forgeries: the honest receipt with one exit code changed inside the signed exchange,
# and the failing run's receipt with a passing JUnit report put beside it.
mkdir -p "$here/receipts/altered-result" "$here/receipts/altered-junit"
python3 -I - "$here/receipts" <<'PY'
import base64, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
raw = (root / 'honest/receipt.cdx.json').read_text()
bom = json.loads(raw)
for d in bom['declarations']['evidence'][0]['data']:
    if d['name'] != 'exchange.json':
        continue
    old = d['contents']['attachment']['content']
    x = base64.b64decode(old).decode()
    changed = x.replace('"exit_code":0', '"exit_code":1', 1)
    assert changed != x and raw.count(old) == 1
    (root / 'altered-result/receipt.cdx.json').write_text(raw.replace(old, base64.b64encode(changed.encode()).decode(), 1))
(root / 'altered-result/junit.xml').write_text((root / 'honest/junit.xml').read_text())
# A passing JUnit report beside the failing run's genuine receipt: what a gate that reads
# the report instead of the signed result would wave through.
(root / 'altered-junit/receipt.cdx.json').write_text((root / 'failing/receipt.cdx.json').read_text())
(root / 'altered-junit/junit.xml').write_text((root / 'honest/junit.xml').read_text())
PY

cat > "$here/commits.json" <<JSON
{"tested": "$tested", "later": "$later", "broken": "$broken", "skipped": "$skipped", "hangs": "$hangs"}
JSON
echo "challenge regenerated: tested $tested, later $later, broken $broken, skipped $skipped, hangs $hangs"
