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
# The head this run is for (the workflow passes the pull request's head from the event); the
# receipt's states compare the commit it tested with it. Unset: the project's own HEAD.
if [ -n "${PR_HEAD_SHA:-}" ]; then
  [[ "$PR_HEAD_SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'PR_HEAD_SHA must be a full commit SHA' >&2; exit 2; }
fi
# The fewest tests the returned report must list as run for the job to pass; with JUNIT_PATH
# set and this unset, 1. Without a test report there is nothing to count, so it needs one.
if [ -n "${PLIMSOLL_MIN_TESTS:-}" ]; then
  [[ "$PLIMSOLL_MIN_TESTS" =~ ^[1-9][0-9]{0,5}$ ]] || { echo 'PLIMSOLL_MIN_TESTS must be a whole number from 1 to 999999' >&2; exit 2; }
  [ -n "${JUNIT_PATH:-}" ] || { echo 'PLIMSOLL_MIN_TESTS needs JUNIT_PATH: without a test report the receipt cannot count tests' >&2; exit 2; }
fi
mkdir -p "$source_dir/tmp"
work_dir="$(mktemp -d "$source_dir/tmp/pr-receipt.XXXXXXXX")"
umask 077
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}"
mkdir -p "$cache_dir"
key_dir="$(mktemp -d "$cache_dir/plimsoll-pr-key.XXXXXXXX")"
daemon_pid=''
daemon_tmp=''
cleanup() {
  if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then
    if tr '\0' ' ' < "/proc/$daemon_pid/cmdline" | grep -Fq "$work_dir/plimsolld"; then
      kill -TERM "$daemon_pid"
      wait "$daemon_pid" || true
    fi
  fi
  rm -rf "$key_dir"
  if [ -n "$daemon_tmp" ]; then rm -rf "$daemon_tmp"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# The daemon's own temporary directory, short and private. The docker provider makes Unix
# sockets in it, and Linux refuses a socket path over 107 bytes, so it cannot sit under the
# checkout: a GitHub runner's checkout path holds the repository's name twice. It is the
# runner's RUNNER_TEMP (which the runner empties at each job's start and end) when that is
# short enough, else /tmp, in a new directory mktemp names at random with mode 0700, never a
# fixed name another local user could make first; removed at exit. socket_room is the
# longest name the daemon makes in it, plimsoll-docker-config-<up to 10 digits>/alive.sock
# (sandbox/docker_cli.go); receipt_test.go checks it against every socket the provider makes.
socket_room=44
daemon_parent="${RUNNER_TEMP:-/tmp}"
# 16 is "/plimsoll.XXXXXX", 1 the slash before the socket's own directory.
if [ $(( ${#daemon_parent} + 16 + 1 + socket_room )) -gt 107 ]; then daemon_parent=/tmp; fi
daemon_tmp="$(mktemp -d "$daemon_parent/plimsoll.XXXXXX")"
if [ $(( ${#daemon_tmp} + 1 + socket_room )) -gt 107 ]; then
  echo "The daemon's temporary directory $daemon_tmp leaves its socket paths over Linux's 107 bytes" >&2
  exit 1
fi
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
env -i PATH="$PATH" HOME="$HOME" TMPDIR="$daemon_tmp" "${docker_resolution[@]}" \
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
# The JUnit file, from the checked receipt only: the framework's own report as the run
# returned it, or one built from the signed steps (junit.py says which).
python3 -I "$script_dir/junit.py" "$output_dir"
# The same receipt in standard formats (formats.py): an in-toto test-result statement,
# signed with the same key, and Cobertura coverage when the run returned an lcov file.
python3 -I "$script_dir/formats.py" "$output_dir"
env -u PLIMSOLL_ATTEST_KEY "$work_dir/plimsoll-attest" sign-statement -key "$signing_key" \
  -type https://in-toto.io/attestation/test-result/v0.1 -out "$output_dir/test-result.intoto.json" \
  "$output_dir/test-result.statement.json" > "$output_dir/statement.log"
rm -- "$output_dir/test-result.statement.json"
# The receipt's states (states.py), in verify.py's report on the receipt just made, written to
# states.json: which commit it covers and whether that is the head this run is for, whether
# the run completed, what came back, how many tests the returned report lists, and what stays
# unverified. A key made for this run is read as self-consistent only, never as trusted.
boms=("$output_dir"/run-*.cdx.json)
[ "${#boms[@]}" = 1 ] || { echo "Expected one receipt, found ${#boms[@]}" >&2; exit 1; }
verify_args=(--sbom "$work_dir/sbom" --receipt "${boms[0]}" --repo "$project_dir" --repository "${PR_REPOSITORY:-}"
  --head "${PR_HEAD_SHA:-$(git -C "$project_dir" rev-parse --verify 'HEAD^{commit}')}" --pr "${PR_NUMBER:-}"
  --command "${TEST_COMMAND-npm test}" --attest "$work_dir/plimsoll-attest" --test-result "$output_dir/test-result.intoto.json")
if [ -n "$operator_key" ]; then verify_args+=(--trusted-pub "${operator_key%.key}.pub"); else verify_args+=(--self-consistent); fi
[ -z "${JUNIT_PATH:-}" ] || verify_args+=(--junit-path "$JUNIT_PATH")
[ -z "${PLIMSOLL_MIN_TESTS:-}" ] || verify_args+=(--min-tests "$PLIMSOLL_MIN_TESTS")
[ ! -f "$output_dir/junit.xml" ] || verify_args+=(--junit "$output_dir/junit.xml")
[ -z "${COVERAGE_PATH:-}" ] || verify_args+=(--coverage-path "$COVERAGE_PATH")
[ ! -f "$output_dir/coverage.cobertura.xml" ] || verify_args+=(--coverage "$output_dir/coverage.cobertura.xml")
[ -z "${PR_BASE_SHA:-}" ] || verify_args+=(--base "$PR_BASE_SHA")
[ -z "${SESSION_TRAILER:-}" ] || verify_args+=(--session-trailer "$SESSION_TRAILER")
verify_status=0
python3 -I "$script_dir/verify.py" "${verify_args[@]}" > "$output_dir/states.json" || verify_status=$?
if [ "$verify_status" -gt 1 ]; then
  echo "The receipt's states could not be derived (verify.py exited $verify_status)" >&2
  # A usage error prints no report; the summary then says no states were written.
  [ -s "$output_dir/states.json" ] || rm -f -- "$output_dir/states.json"
fi
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
# The summary, one line per state, for the log (the workflow writes it to the job summary).
if [ -f "$output_dir/states.json" ]; then python3 -I "$script_dir/states.py" summary "$output_dir/states.json"; fi
# A normal failed command still gets a signed receipt. Publish the artifacts,
# then fail the job from the recorded result, never from guest-printed text, and from the
# receipt's own check: every check in states.json must pass (a head other than PR_HEAD_SHA,
# a file beside the receipt that differs from it, a returned test report that lists a failure
# or fewer tests that ran than PLIMSOLL_MIN_TESTS, or no report at all fails the job).
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
ran = p['outcome'] == 'PROJECT_OUTCOME_COMPLETED' and bool(p['steps']) and all(s['exit_code'] == 0 and not s['timed_out'] for s in p['steps'])
try:
    report = json.loads((out / 'states.json').read_text())
except (OSError, ValueError):
    report = {}
checks = report.get('checks') if isinstance(report, dict) and isinstance(report.get('checks'), list) else []
refused = [c if isinstance(c, dict) else {} for c in checks if not isinstance(c, dict) or c.get('passed') is not True]
checked = bool(checks) and not refused
passed = ran and checked
(out / 'status.txt').write_text('PASS\n' if passed else 'FAIL\n')
if ran and not checked:
    names = ', '.join(str(c.get('check', 'a malformed check')) for c in refused)
    print("Receipt made, but its own check refused it at: " + (names if refused else 'nothing: the check could not run'))
    for c in refused:  # verify.py's own words, from signed values and this configuration
        print(f"  {c.get('check', 'a malformed check')}: {c.get('detail', 'no detail')}")
else:
    print('Receipt checked; project command ' + ('passed' if passed else 'failed'))
sys.exit(0 if passed else 1)
PY
