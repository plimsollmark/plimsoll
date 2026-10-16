#!/bin/sh
# Builds a release of the MCP server into dist/, publishing nothing: one binary per
# platform (static, -trimpath, no build ID, so a rebuild with the same toolchain is
# byte-identical), the npm launcher and one npm package per platform as packed
# tarballs, one Claude Desktop bundle per desktop platform (its entries' times fixed,
# so a rebuild is byte-identical too), and SHA256SUMS over all of it. Needs Go, node and npm; the bundle CLI is installed from
# scripts/tools/package-lock.json with npm ci, so every package of it is checked against
# the content hash recorded there, not only named by version.
set -eu
cd "$(dirname "$0")/.."
version=$(go run ./cmd/plimsoll-mcp --version | awk '{print $2}')
launcher=$(node -p 'require("./npm/package.json").version')
[ "$launcher" = "$version" ] || { echo "release: npm/package.json is $launcher, the server $version" >&2; exit 1; }
rm -rf dist && mkdir -p dist/bin dist/npm dist/mcpb

# goos/goarch:npm-os:npm-cpu
for target in darwin/arm64:darwin:arm64 darwin/amd64:darwin:x64 linux/arm64:linux:arm64 linux/amd64:linux:x64 windows/amd64:win32:x64; do
  goarch=${target%%:*}; rest=${target#*:}; os=${rest%%:*}; cpu=${rest#*:}
  name=$os-$cpu
  exe=plimsoll-mcp; [ "$os" = win32 ] && exe=plimsoll-mcp.exe
  mkdir -p "dist/bin/$name"
  CGO_ENABLED=0 GOOS=${goarch%/*} GOARCH=${goarch#*/} go build -trimpath -ldflags='-s -w -buildid=' -o "dist/bin/$name/$exe" ./cmd/plimsoll-mcp
  pkg=dist/npm/mcp-$name
  mkdir -p "$pkg/bin"
  cp "dist/bin/$name/$exe" "$pkg/bin/"
  cp LICENSE "$pkg/"
  NAME=$name OS=$os CPU=$cpu VERSION=$version node -e '
    const e = process.env;
    const p = { name: `@plimsollmark/mcp-${e.NAME}`, version: e.VERSION,
      description: `The plimsoll MCP server binary for ${e.NAME}; installed by @plimsollmark/mcp`,
      license: "Apache-2.0", repository: { type: "git", url: "git+https://github.com/plimsollmark/plimsoll.git", directory: "clients/mcp" },
      os: [e.OS], cpu: [e.CPU], files: ["bin"], preferUnplugged: true };
    process.stdout.write(JSON.stringify(p, null, 2) + "\n");' > "$pkg/package.json"
  (cd "$pkg" && npm pack --silent --pack-destination .. >/dev/null)
done

cp -r npm dist/npm/mcp
cp LICENSE README.md dist/npm/mcp/
(cd dist/npm/mcp && npm pack --silent --pack-destination .. >/dev/null)

npm ci --prefix scripts/tools --silent --no-audit --no-fund
mcpb=scripts/tools/node_modules/.bin/mcpb
for name in darwin-arm64 darwin-x64 win32-x64; do
  os=${name%-*}
  exe=plimsoll-mcp; [ "$os" = win32 ] && exe=plimsoll-mcp.exe
  dir=dist/mcpb/$name
  mkdir -p "$dir/server"
  cp "dist/bin/$name/$exe" "$dir/server/"
  cp LICENSE README.md "$dir/"
  OS=$os node -e '
    const m = require("./mcpb/manifest.json");
    m.compatibility.platforms = [process.env.OS];
    process.stdout.write(JSON.stringify(m, null, 2) + "\n");' > "$dir/manifest.json"
  "$mcpb" validate "$dir/manifest.json" >/dev/null
  "$mcpb" pack "$dir" "dist/plimsoll-$version-$name.mcpb" >/dev/null
  node scripts/fixed-zip-time.mjs "dist/plimsoll-$version-$name.mcpb"
done

(cd dist && sha256sum plimsoll-*.mcpb npm/*.tgz bin/*/* > SHA256SUMS)
echo "release: built $version into $(pwd)/dist"
