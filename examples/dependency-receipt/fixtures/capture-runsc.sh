#!/bin/sh
# Captures one fixture log under the host's own runsc, with the receipt's options, and writes
# it to ../runsclog/testdata/NAME-RELEASE.boot.json.gz. It is how the reader is checked against
# a new runsc release before that release goes into runsclog.Supported.
#
# capture.sh takes the receipt's real path (kind, containerd's runsc shim, a RuntimeClass);
# this one runs `runsc --rootless run` on the fixture image's files directly, with no
# network (--network=none), so it needs only docker (to read the image) and runsc on PATH,
# and no root. The two paths differ in what the guest sees (its network, some errors from
# /proc), never in the format of the log runsc writes.
#
# The work directory is a fresh one under /tmp, deleted afterwards: runsc writes its own
# paths into the log, and a fixture must not name the home directory of whoever captured it.
#
#   examples/dependency-receipt/fixtures/capture-runsc.sh [NAME]    (NAME defaults to canary)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
name=${1:-canary}
image=plimsoll-dependency-fixtures:dev
syscalls=$(sed -n 's/^ *strace-syscalls = "\(.*\)"$/\1/p' "$here/runsc-receipt.toml")
[ -n "$syscalls" ] || { echo "no strace-syscalls in runsc-receipt.toml" >&2; exit 1; }
release=$(runsc --version | sed -n 's/^runsc version //p')
[ -n "$release" ] || { echo "runsc --version names no release" >&2; exit 1; }
docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" "$here" >/dev/null
work=$(mktemp -d /tmp/runsc-fixture.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bundle/rootfs" "$work/log" "$work/state"
container=$(docker create "$image")
docker export "$container" | tar -x -C "$work/bundle/rootfs"
docker rm "$container" >/dev/null
# runsc's default spec, with the image's environment (its Dockerfile's ENV) and a writable
# root, as a container's is.
(cd "$work/bundle" && runsc spec -- node /driver.mjs "$name")
sed -i -e 's|"TERM=xterm"|"HOME=/tmp", "NPM_CONFIG_UPDATE_NOTIFIER=false"|' \
	-e 's|"readonly": true|"readonly": false|' "$work/bundle/config.json"
runsc --rootless --network=none --root="$work/state" \
	--debug --strace --strace-log-size=16 --strace-syscalls="$syscalls" \
	--debug-log-format=json --debug-log="$work/log/" \
	run --bundle "$work/bundle" "fixture-$name"
# runsc writes its closing line when the sandbox stops, which `runsc run` waits for.
out="$here/../runsclog/testdata/$name-$release.boot.json.gz"
cat "$work/log/"*.boot.txt | gzip -9 -n > "$out"
echo "$name under $release: $(gzip -dc "$out" | wc -c) bytes"
