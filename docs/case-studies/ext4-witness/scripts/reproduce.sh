#!/bin/sh
# reproduce.sh: rerun one part of the ext4 case study on your own machine, in a throwaway Debian container.
#
#   sh reproduce.sh PART [OUTDIR]      PART: merge | config | masking | fixes
#
# Needs Docker and about 4 GB of disk. Nothing leaves your machine but two git fetches of public trees (GitHub and
# git.kernel.org). The first run fetches the kernel history into OUTDIR/work and builds; later runs reuse both.
# Results land in OUTDIR/PART/: one NAME.result.json per job (every test's status with and without the fix) and
# kunit.py's own output beside it (NAME.log; for plain runs also the kernel's log and the generated .config).
set -eu
PART="${1:?usage: sh reproduce.sh merge|config|masking|fixes [OUTDIR]}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mkdir -p "${2:-$PWD/ext4-witness-out}" && cd "${2:-$PWD/ext4-witness-out}" && pwd)"
mkdir -p "$OUT/work"
python3 "$HERE/queues.py" "$PART" > "$OUT/queue-$PART.json"
# The same Debian release the cloud runs used (trixie), pinned by digest.
IMAGE=debian:trixie@sha256:1c2fd3096624441883bc13fd646c376664b3ee8a990fde0f6246e567349512e9
docker run --rm -v "$HERE:/scripts:ro" -v "$OUT:/out" -e WITNESS_WORK=/out/work -e PART="$PART" \
  -e HOST_IDS="$(id -u):$(id -g)" "$IMAGE" sh -c '
    sh /scripts/setup.sh > /out/setup.log 2>&1 || { echo "setup failed: see /out/setup.log"; exit 3; }
    python3 /scripts/witness.py /out/queue-$PART.json /out/$PART; code=$?
    chown -R "$HOST_IDS" /out
    exit $code'
echo "done: $OUT/$PART"
python3 - "$OUT/$PART" <<'SUMMARY'
import glob, json, os, sys
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.result.json"))):
    r = json.load(open(p))
    if r.get("watched"):  # the masking check: the watched line decides, and every failed expectation is listed
        detail = "; ".join("%s: %s" % kv for kv in r["watched"].items())
        detail += " (failed without the fixes: %s)" % (", ".join(r.get("before_failed_at") or []) or "none")
    elif "outcome" in r:  # a plain run of the whole suite
        detail = "%d tests: %s" % (r.get("ran", 0), r.get("status_counts"))
    else:
        detail = ", ".join(r.get("witnesses") or []) or (r.get("before_note") or "").strip()[:80]
    # With a watched line the verdict is the line's (witnessed only when it fails without the fixes).
    status = r["verdict"] if r.get("watched") else (r.get("outcome") or r.get("category", "-"))
    print("%-26s %-17s %s" % (r["job"]["id"], status, detail))
SUMMARY
