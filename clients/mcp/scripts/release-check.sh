#!/bin/sh
# Runs the stdio tests against the release as a user gets it, after scripts/release.sh.
# First SHA256SUMS is checked. Then @plimsollmark/mcp is installed by name, as npx
# installs it, from a local registry serving only these tarballs, with a cache of its
# own, into a directory whose path has spaces: npm picks this platform's package from
# the launcher's optional dependencies itself, and nothing comes from the public
# registry. On WSL the Windows bundle's binary also runs through interop.
set -eu
cd "$(dirname "$0")/.."
here=$(pwd)
[ -f dist/SHA256SUMS ] || { echo "release-check: run scripts/release.sh first" >&2; exit 1; }
(cd dist && sha256sum --quiet -c SHA256SUMS) || { echo "release-check: SHA256SUMS does not match dist/" >&2; exit 1; }
version=$(node -p 'require("./npm/package.json").version')
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x64 ;;
  Linux-aarch64) platform=linux-arm64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  Darwin-x86_64) platform=darwin-x64 ;;
  *) echo "release-check: no build for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
work="$here/dist/release check"
rm -rf "$work" && mkdir -p "$work/npm app" "$work/registry/@plimsollmark/tarballs"

# run_tests runs the stdio tests against one command, failing the check on any failure.
run_tests() {
  if ! PLIMSOLL_MCP_COMMAND="$1" go test ./cmd/plimsoll-mcp -count=1 -v > "$work/test.log" 2>&1; then
    cat "$work/test.log" >&2
    echo "release-check: FAILED for $1" >&2
    exit 1
  fi
  grep -E '^(--- |ok)' "$work/test.log"
}

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
registry="http://127.0.0.1:$port"
# A packument per package (the registry's metadata document), at the path npm asks for.
REGISTRY="$registry" WORK="$work/registry" DIST="$here/dist/npm" node -e '
  const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
  const { REGISTRY, WORK, DIST } = process.env;
  const pkgs = [["mcp", path.join(DIST, "mcp/package.json")]];
  for (const d of fs.readdirSync(DIST)) if (d.startsWith("mcp-")) pkgs.push([d, path.join(DIST, d, "package.json")]);
  for (const [dir, file] of pkgs) {
    const p = JSON.parse(fs.readFileSync(file, "utf8"));
    const tgz = `plimsollmark-${dir}-${p.version}.tgz`;
    const bytes = fs.readFileSync(path.join(DIST, tgz));
    fs.copyFileSync(path.join(DIST, tgz), path.join(WORK, "@plimsollmark/tarballs", tgz));
    p.dist = {
      tarball: `${REGISTRY}/@plimsollmark/tarballs/${tgz}`,
      integrity: "sha512-" + crypto.createHash("sha512").update(bytes).digest("base64"),
      shasum: crypto.createHash("sha1").update(bytes).digest("hex"),
    };
    const doc = { name: p.name, "dist-tags": { latest: p.version }, versions: { [p.version]: p } };
    fs.writeFileSync(path.join(WORK, "@plimsollmark", p.name.split("/")[1]), JSON.stringify(doc));
  }'
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work/registry" > "$work/registry.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null "$registry/" && break; sleep 0.2; done

cd "$work/npm app"
echo '{"private": true}' > package.json
npm install --silent --no-audit --no-fund --userconfig=/dev/null --cache "$work/npm cache" \
  --registry "$registry" "@plimsollmark/mcp@$version"
cd "$here"
installed=$(ls "$work/npm app/node_modules/@plimsollmark")
[ "$installed" = "$(printf 'mcp\nmcp-%s' "$platform")" ] || { echo "release-check: npm installed [$installed], want the launcher and mcp-$platform alone" >&2; exit 1; }
echo "release-check: npm selected mcp-$platform from the launcher's optional dependencies"
run_tests "$work/npm app/node_modules/.bin/plimsoll-mcp"

if grep -qi microsoft /proc/version 2>/dev/null; then
  mkdir -p "$work/windows bundle"
  python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "dist/plimsoll-$version-win32-x64.mcpb" "$work/windows bundle"
  chmod +x "$work/windows bundle/server/plimsoll-mcp.exe"
  echo "release-check: the Windows bundle's binary, through WSL interop (not Claude Desktop's own install and launch)"
  run_tests "$work/windows bundle/server/plimsoll-mcp.exe"
fi
echo "release-check: OK"
