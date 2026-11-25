#!/bin/sh
# The canary run on a stand-in harness: the transcript the squeeze page shows, canary-demo.txt.
#
# The stand-in harness is the few lines of Python below. It puts the markers canary make writes
# where a real harness would keep its secrets, and records the requests it would send: one clean,
# one with the reference's step time leaked into the prompt, one with a planted clip uploaded
# under its plan name. It is not a real evaluation; it shows what the check prints when it passes
# and when it fails. The markers are random, and the check never prints one, so every run prints
# the same transcript.
#
# Run from the repository root. Needs Python 3; runs this checkout's Python client
# (clients/python/src), the same code as python3 -m plimsoll_client.tripwire with the client
# installed, and writes only under tmp/canary-demo/:
#
#	examples/squeeze/canary-demo.sh | diff - examples/squeeze/canary-demo.txt
set -eu
ROOT=$(pwd)
[ -f "$ROOT/clients/python/src/plimsoll_client/tripwire.py" ] || { echo "run from the plimsoll repository root" >&2; exit 2; }
W=tmp/canary-demo
rm -rf "$W"
mkdir -p "$W"

tripwire() {
  (cd "$W" && PYTHONPATH="$ROOT/clients/python/src" python3 -m plimsoll_client.tripwire "$@")
}
show() {
  echo "\$ python3 -m plimsoll_client.tripwire $*"
  set +e
  tripwire "$@" 2>&1
  rc=$?
  set -e
  echo "(exit $rc)"
}

echo "# The canary run on a stand-in harness, a few lines of Python in canary-demo.sh written for this page."
echo "# Not a real evaluation: it shows what the check prints when it passes and when it fails."
show canary make truth reference-times plan-names -o canary.json
(cd "$W" && python3 -I - <<'PY'
import json, os
v = {x["id"]: x for x in json.load(open("canary.json"))["values"]}
os.makedirs("hidden/clips")
for d in ("run-1", "run-2", "run-3", "not-planted"):
    os.makedirs(d)
# The hidden places get the markers in place of the real values.
json.dump({"clip-07": v["truth/text"]["text"]}, open("hidden/truth.json", "w"))
json.dump({"step-3-start": float(v["reference-times/number"]["number"])}, open("hidden/reference.json", "w"))
open("hidden/clips/%s.mp4" % v["plan-names/text"]["text"], "wb").write(b"\0" * 16)
# What the harness sends the model under test.
ask = "Here is a worker's video of the procedure. Which steps are missing or out of order?"
leak = "Here is a worker's video of the procedure. The expert starts step 3 at %s s. Which steps are missing or out of order?"
def request(path, text):
    json.dump({"model": "model-under-test", "messages": [{"role": "user", "content": text}], "max_tokens": 1024}, open(path, "w"))
request("run-1/0001.json", ask)
request("run-2/0001.json", leak % v["reference-times/number"]["number"])
request("run-3/0001.json", ask)
open("run-3/%s.mp4" % v["plan-names/text"]["text"], "wb").write(b"\0" * 16)
PY
)
echo "# hidden/ now holds the markers where the secrets live: the truth labels (truth.json), the reference's step times (reference.json) and a planted clip named by its plan (clips/)."
echo "# run-1/ is the harness as it should be: one request, a prompt that holds none of them."
show canary check --sealed canary.json --planted hidden --requests run-1
echo "# run-2/: the same request, with one leak put back on purpose: the reference's step time in the prompt."
show canary check --sealed canary.json --planted hidden --requests run-2
echo "# run-3/: the clean request, and the planted clip uploaded under its plan name."
show canary check --sealed canary.json --planted hidden --requests run-3
echo "# not-planted/ is what a harness that forgot to plant leaves behind: nothing."
show canary check --sealed canary.json --planted not-planted --requests run-1
