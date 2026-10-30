#!/bin/sh
# Fetch the Open Policy Agent release pinned in opa.version into DIR, check its SHA-256
# against the pin, and print the binary's path. Linux amd64 only, the machines the gate
# runs on. A binary already in DIR is checked again, never trusted; one with another digest
# is removed, and nothing downloaded is made executable before its digest matches.
#
#   sh examples/pr-receipt/policy/opa.sh "$PWD/tmp/tools"
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:?usage: opa.sh DIR}
version=$(sed -n 's/^version=//p' "$here/opa.version")
want=$(sed -n 's/^sha256_linux_amd64_static=//p' "$here/opa.version")
[ -n "$version" ] && [ -n "$want" ] || { echo "opa.sh: opa.version names no version or digest" >&2; exit 1; }
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo "opa.sh: the pin is for linux amd64 only" >&2; exit 1; }
bin="$dir/opa-$version"
if [ ! -f "$bin" ]; then
  mkdir -p "$dir"
  part="$bin.part.$$"
  trap 'rm -f "$part"' EXIT
  curl -sSfL --proto '=https' -o "$part" "https://github.com/open-policy-agent/opa/releases/download/$version/opa_linux_amd64_static"
  mv "$part" "$bin"
fi
got=$(sha256sum "$bin" | cut -d' ' -f1)
if [ "$got" != "$want" ]; then
  rm -f "$bin"
  echo "opa.sh: the download has SHA-256 $got; opa.version pins $want. Removed." >&2
  exit 1
fi
chmod 0755 "$bin"
echo "$bin"
