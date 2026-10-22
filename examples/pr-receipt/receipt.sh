#!/usr/bin/env bash
# Build trusted tools, then run only the project request inside the sandbox.
set -euo pipefail
if [ "$#" -ne 2 ]; then echo 'usage: receipt.sh PROJECT_DIRECTORY OUTPUT_DIRECTORY' >&2; exit 2; fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${PLIMSOLL_SOURCE:-$(cd "$script_dir/../.." && pwd)}"
project_dir="$(realpath "$1")"
output_dir="$(realpath -m "$2")"
case "$output_dir/" in "$project_dir/"*) echo 'Output must be outside the target project' >&2; exit 2;; esac
if [ -e "$output_dir" ]; then echo 'Use a new output directory; evidence is never overwritten' >&2; exit 2; fi
# An operator key a verifier already trusts, or (unset) a throwaway key made for this run.
operator_key=''
if [ -n "${PLIMSOLL_HARNESS_KEY:-}" ]; then
  case "$PLIMSOLL_HARNESS_KEY" in *.key) ;; *) echo 'PLIMSOLL_HARNESS_KEY must name a .key file made by plimsoll-attest keygen' >&2; exit 2;; esac
  operator_key="$(realpath -m "$PLIMSOLL_HARNESS_KEY")"
  [ -f "$operator_key" ] && [ -f "${operator_key%.key}.pub" ] || { echo 'PLIMSOLL_HARNESS_KEY needs the .key file and the .pub beside it' >&2; exit 2; }
  case "$operator_key" in "$project_dir/"*) echo 'The operator key must be outside the project, whose files go into the sandbox' >&2; exit 2;; esac
fi
if [ -n "${PLIMSOLL_REF:-}" ]; then
  [[ "$PLIMSOLL_REF" =~ ^[a-f0-9]{40}$ ]] || { echo 'PLIMSOLL_REF must be a full commit SHA' >&2; exit 2; }
  [ "$(git -C "$source_dir" rev-parse HEAD)" = "$PLIMSOLL_REF" ] || { echo 'Source checkout differs from PLIMSOLL_REF' >&2; exit 2; }
  [ -z "$(git -C "$source_dir" status --porcelain)" ] || { echo 'Pinned source checkout must be clean' >&2; exit 2; }
fi
[ -f "$source_dir/examples/sbom/main.go" ] || { echo 'Pinned source does not include the receipt converter yet' >&2; exit 2; }
mkdir -p "$source_dir/tmp"
work_dir="$(mktemp -d "$source_dir/tmp/pr-receipt.XXXXXXXX")"
umask 077
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}"
mkdir -p "$cache_dir"
key_dir="$(mktemp -d "$cache_dir/plimsoll-pr-key.XXXXXXXX")"
daemon_pid=''
cleanup() {
  if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
    if tr '\0' ' ' < "/proc/$daemon_pid/cmdline" | grep -Fq "$work_dir/plimsolld"; then
      kill -TERM "$daemon_pid"
      wait "$daemon_pid" || true
    fi
  fi
  rm -rf "$key_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Local-only. No project file is built or executed on the runner itself.
go -C "$source_dir" build -o "$work_dir/plimsolld" ./cmd/plimsolld
go -C "$source_dir" build -o "$work_dir/plimsoll-attest" ./cmd/plimsoll-attest
go -C "$source_dir/examples/sbom" build -o "$work_dir/sbom" .
# Choose an unused loopback port. Bind failure is still fatal if another process
# claims it before the daemon; readiness also requires our own child to stay alive.
port="$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0))
    print(s.getsockname()[1])
PY
)"
docker_resolution=()
for setting in DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG XDG_RUNTIME_DIR; do
  if [[ -v "$setting" ]]; then docker_resolution+=("$setting=${!setting}"); fi
done
env -i PATH="$PATH" HOME="$HOME" TMPDIR="$work_dir" "${docker_resolution[@]}" \
SANDBOX_PROVIDER=docker SANDBOX_DOCKER_RUNTIME=runsc \
SANDBOX_DOCKER_IMAGE="${PROJECT_IMAGE:-plimsoll/sandbox:latest}" \
SANDBOX_DOCKER_PROJECT_IMAGE="${PROJECT_IMAGE:-plimsoll/sandbox:latest}" \
SANDBOX_DOCKER_SECCOMP="$source_dir/docker/seccomp.json" \
SANDBOX_MIN_ISOLATION=kernel PLIMSOLL_INSECURE=1 PLIMSOLL_METRICS_ADDR=off \
PLIMSOLL_ADDR="127.0.0.1:$port" \
  "$work_dir/plimsolld" > "$work_dir/daemon.log" 2>&1 &
daemon_pid=$!
ready=0
for ((i=0; i<120; i++)); do
  kill -0 "$daemon_pid" 2>/dev/null || { cat "$work_dir/daemon.log" >&2; exit 1; }
  if curl --fail --silent "http://127.0.0.1:$port/readyz" > /dev/null; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { echo 'Daemon did not become ready' >&2; cat "$work_dir/daemon.log" >&2; exit 1; }
python3 "$script_dir/prepare.py" "$project_dir" "$output_dir"
if [ -n "$operator_key" ]; then
  signing_key="$operator_key"
  cp "${operator_key%.key}.pub" "$output_dir/harness.pub"
else
  "$work_dir/plimsoll-attest" keygen -out "$key_dir/harness"
  signing_key="$key_dir/harness.key"
  cp "$key_dir/harness.pub" "$output_dir/harness.pub"
fi
# Run from the output directory with relative names: the tool prints the bundle path it
# was given, and the log is published, so an absolute path would name this machine's layout.
(cd "$output_dir" && env -u PLIMSOLL_CALLER_TOKEN -u PLIMSOLL_ATTEST_KEY "$work_dir/plimsoll-attest" run -daemon "http://127.0.0.1:$port" -key "$signing_key" \
  -bundle bundle.jsonl request.json > run.log)
"$work_dir/plimsoll-attest" verify -pub "$output_dir/harness.pub" "$output_dir/bundle.jsonl" > "$output_dir/verify.log"
# PLIMSOLL_PAGES is where this output directory will be published, so the BOM's
# attestation reference and the page's links point at this run's own evidence.
"$work_dir/sbom" -bundle "$output_dir/bundle.jsonl" -pub "$output_dir/harness.pub" \
  -pages "${PLIMSOLL_PAGES:-https://raw.githubusercontent.com/plimsollmark/plimsoll/main/examples/pr-receipt/evidence/}" \
  -name "pull-request-${PR_NUMBER}" -qualified-bundle "" -out "$output_dir" > "$output_dir/emit.log"
for bom in "$output_dir"/run-*.cdx.json; do
  "$work_dir/sbom" -check "$bom" -trusted-pub "$output_dir/harness.pub" > "$output_dir/check.log"
done
# Everything in the output directory is published: refuse it if any file names a
# directory of this machine's (the checkout, the project, the output, the home). A
# workflow may upload the output even after a failure (a failed command still gets a
# receipt), so a refused output is moved aside and the output directory left empty.
for local_path in "$source_dir" "$project_dir" "$output_dir" "$HOME"; do
  [ "${#local_path}" -gt 1 ] || continue
  if grep -rlF -- "$local_path" "$output_dir" >&2; then
    refused="$output_dir.refused.$$"
    mv -- "$output_dir" "$refused" && mkdir -- "$output_dir"
    echo "The files above name the local directory $local_path; nothing here is fit to publish (moved aside to ${refused##*/})" >&2
    exit 1
  fi
done
# A normal failed command still gets a signed receipt. Publish the artifacts,
# then fail the job from the recorded result, never from guest-printed text.
python3 - "$output_dir" <<'PY'
import base64
import glob
import json
from pathlib import Path
import sys
out = Path(sys.argv[1])
bom = json.loads(Path(glob.glob(str(out / 'run-*.cdx.json'))[0]).read_bytes())
data = bom['declarations']['evidence'][0]['data']
a = next(d for d in data if d['name'] == 'exchange.json')['contents']['attachment']
x = json.loads(base64.b64decode(a['content']))
p = x['response']['project']
passed = p['outcome'] == 'PROJECT_OUTCOME_COMPLETED' and bool(p['steps']) and all(s['exit_code'] == 0 and not s['timed_out'] for s in p['steps'])
(out / 'status.txt').write_text('PASS\n' if passed else 'FAIL\n')
print('Receipt checked; project command ' + ('passed' if passed else 'failed'))
sys.exit(0 if passed else 1)
PY
