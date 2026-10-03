#!/usr/bin/env bash
# vendor-three.sh — vendor three.js for the forum client's 3D poker table.
#
# Fetches the pinned `three` tarball from the npm registry, checks it against
# the registry's own sha512 integrity, minifies the three files the table
# loads (the WebGPU build, the core it imports, and the RoomEnvironment
# add-on) with esbuild, rewrites their module specifiers to sibling relative
# paths so they load without an import map, and writes VENDORED.md with the
# SHA-256 of every file shipped.
#
# Usage: scripts/vendor-three.sh [version]      (default: 0.186.1)
#
# Needs: curl, node/npm (esbuild is fetched into a temporary directory and
# never added to the repository), sha256sum, python3.

set -euo pipefail

VERSION="${1:-0.186.1}"
ESBUILD_VERSION="0.25.12"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/crates/nostr-bbs-forum-client/assets/vendor/three-$VERSION"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "three@$VERSION -> $DEST"

# 1. The tarball, verified against the registry's integrity field.
META="$(curl -fsSL "https://registry.npmjs.org/three/$VERSION")"
TARBALL="$(printf '%s' "$META" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dist"]["tarball"])')"
INTEGRITY="$(printf '%s' "$META" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dist"]["integrity"])')"
curl -fsSL -o "$WORK/three.tgz" "$TARBALL"
GOT="sha512-$(python3 -c 'import base64,hashlib,sys; print(base64.b64encode(hashlib.sha512(open(sys.argv[1],"rb").read()).digest()).decode())' "$WORK/three.tgz")"
if [ "$GOT" != "$INTEGRITY" ]; then
    echo "integrity mismatch: registry $INTEGRITY, downloaded $GOT" >&2
    exit 1
fi
tar -xzf "$WORK/three.tgz" -C "$WORK"
PKG="$WORK/package"

# 2. esbuild, in the scratch directory only.
(cd "$WORK" && npm init -y >/dev/null && npm install --silent --no-audit --no-fund "esbuild@$ESBUILD_VERSION" >/dev/null)
ESBUILD="$WORK/node_modules/.bin/esbuild"

# 3. Specifier rewrite, then minify each file on its own (no bundling: the
#    three files stay separate modules and share one copy of the core).
#      three.webgpu.js:     './three.core.js'  -> './three.core.min.js'
#      RoomEnvironment.js:  'three'            -> './three.webgpu.min.js'
#    `three` must resolve to the WebGPU build, never to three.module.js:
#    a second copy of the core breaks instanceof checks and the shared
#    ColorManagement state.
mkdir -p "$WORK/src"
cp "$PKG/build/three.core.js" "$WORK/src/three.core.js"
sed "s#from './three.core.js'#from './three.core.min.js'#g" \
    "$PKG/build/three.webgpu.js" > "$WORK/src/three.webgpu.js"
sed "s#from 'three'#from './three.webgpu.min.js'#g" \
    "$PKG/examples/jsm/environments/RoomEnvironment.js" > "$WORK/src/RoomEnvironment.js"
for f in three.core three.webgpu RoomEnvironment; do
    if grep -nE "from '(three|three/[a-z]+)'" "$WORK/src/$f.js" >/dev/null; then
        echo "$f.js still has a bare specifier after the rewrite" >&2
        exit 1
    fi
done

rm -rf "$DEST"
mkdir -p "$DEST"
for f in three.core three.webgpu RoomEnvironment; do
    "$ESBUILD" "$WORK/src/$f.js" --minify --format=esm --target=es2022 \
        --legal-comments=inline --log-level=warning --outfile="$DEST/$f.min.js"
done
cp "$PKG/LICENSE" "$DEST/LICENSE"

# 4. VENDORED.md with the hashes of what ships.
{
    echo "# Vendored: three.js $VERSION"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| Upstream | https://github.com/mrdoob/three.js (npm \`three@$VERSION\`) |"
    echo "| Tarball | $TARBALL |"
    echo "| Integrity | \`$INTEGRITY\` (checked against the npm registry) |"
    echo "| Licence | MIT (\`LICENSE\`, copied from the package) |"
    echo "| Minifier | esbuild $ESBUILD_VERSION, \`--minify --format=esm --target=es2022 --legal-comments=inline\` |"
    echo "| Produced by | \`scripts/vendor-three.sh $VERSION\` |"
    echo
    echo "| File | From | SHA-256 |"
    echo "|---|---|---|"
    for pair in "three.core.min.js:build/three.core.js" \
                "three.webgpu.min.js:build/three.webgpu.js" \
                "RoomEnvironment.min.js:examples/jsm/environments/RoomEnvironment.js" \
                "LICENSE:LICENSE"; do
        file="${pair%%:*}"; from="${pair#*:}"
        echo "| \`$file\` | \`$from\` | \`$(sha256sum "$DEST/$file" | cut -d' ' -f1)\` |"
    done
    echo
    echo "## The rewrite"
    echo
    echo "Applied before minifying, so the files load as plain relative ES modules"
    echo "with no import map and no bundler:"
    echo
    echo "- \`three.webgpu.js\`: \`from './three.core.js'\` → \`from './three.core.min.js'\`"
    echo "- \`RoomEnvironment.js\`: \`from 'three'\` → \`from './three.webgpu.min.js'\`"
    echo
    echo "\`three\` resolves to the WebGPU build, as in the three.js examples' own"
    echo "import map: loading \`three.module.js\` beside it would put a second copy of"
    echo "the core on the page and break \`instanceof\` checks and the shared"
    echo "\`ColorManagement\` state. The script fails if a bare specifier survives."
    echo
    echo "## What is here and why"
    echo
    echo "- \`three.webgpu.min.js\` + \`three.core.min.js\`: \`WebGPURenderer\` (WebGPU, with"
    echo "  its WebGL 2 backend as the fallback), the node materials and the whole"
    echo "  core. TSL is reached as \`TSL\` from the WebGPU build, which is all"
    echo "  \`three.tsl.js\` re-exports, so that file is not shipped."
    echo "- \`RoomEnvironment.min.js\`: the procedural studio room PMREM-filtered into"
    echo "  the scene's environment, so the cards and the lacquer have reflections"
    echo "  without downloading an HDRI."
    echo
    echo "Nothing here is loaded until a member switches the 3D table on: the"
    echo "wasm-bindgen snippet \`js/table3d.js\` dynamic-imports \`table3d/index.js\`,"
    echo "which imports these files by relative path. See \`js/table3d/README.md\`."
    echo
    echo "## Updating"
    echo
    echo "Run \`scripts/vendor-three.sh <version>\`, delete the old \`three-<version>\`"
    echo "directory, change the version in the two \`index.html\` copy-dir links and in"
    echo "\`js/table3d/three.js\`, and check the 3D table in Chrome (WebGPU) and in"
    echo "Firefox on Linux (WebGL 2). Node-material APIs still change between"
    echo "releases, so bump deliberately."
} > "$DEST/VENDORED.md"

ls -la "$DEST"
