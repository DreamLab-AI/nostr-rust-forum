# Vendored: three.js 0.186.1

| | |
|---|---|
| Upstream | https://github.com/mrdoob/three.js (npm `three@0.186.1`) |
| Tarball | https://registry.npmjs.org/three/-/three-0.186.1.tgz |
| Integrity | `sha512-blFeqb49wRCSGUGj7gtpfnSGHy2lwDk94RhUmS1c/hTby70kvChbWpkJ4Pm1390LqzzvTmzgXKHPEafJwCb8jA==` (checked against the npm registry) |
| Licence | MIT (`LICENSE`, copied from the package) |
| Minifier | esbuild 0.25.12, `--minify --format=esm --target=es2022 --legal-comments=inline` |
| Produced by | `scripts/vendor-three.sh 0.186.1` |

| File | From | SHA-256 |
|---|---|---|
| `three.core.min.js` | `build/three.core.js` | `c001a388abbe69583ddd66e9dc18098df55fa81d06bcc5a5722efb6c7f522dc8` |
| `three.webgpu.min.js` | `build/three.webgpu.js` | `0b80bdd888481afd5160553ddb30b8fb902788a3ad0bf9002e5ccec02f81ceb1` |
| `RoomEnvironment.min.js` | `examples/jsm/environments/RoomEnvironment.js` | `2949b4e16007d17d2b870f576fc6b063b355fec1411cf9a5e3e4ba039d02a27a` |
| `LICENSE` | `LICENSE` | `8b378ebe60e2fe500158cb0ac71cb5e8b7d92953c2abcc63a0eb90499653b5bc` |

## The rewrite

Applied before minifying, so the files load as plain relative ES modules
with no import map and no bundler:

- `three.webgpu.js`: `from './three.core.js'` → `from './three.core.min.js'`
- `RoomEnvironment.js`: `from 'three'` → `from './three.webgpu.min.js'`

`three` resolves to the WebGPU build, as in the three.js examples' own
import map: loading `three.module.js` beside it would put a second copy of
the core on the page and break `instanceof` checks and the shared
`ColorManagement` state. The script fails if a bare specifier survives.

## What is here and why

- `three.webgpu.min.js` + `three.core.min.js`: `WebGPURenderer` (WebGPU, with
  its WebGL 2 backend as the fallback), the node materials and the whole
  core. TSL is reached as `TSL` from the WebGPU build, which is all
  `three.tsl.js` re-exports, so that file is not shipped.
- `RoomEnvironment.min.js`: the procedural studio room PMREM-filtered into
  the scene's environment, so the cards and the lacquer have reflections
  without downloading an HDRI.

Nothing here is loaded until a member switches the 3D table on: the
wasm-bindgen snippet `js/table3d.js` dynamic-imports `table3d/index.js`,
which imports these files by relative path. See `js/table3d/README.md`.

## Updating

Run `scripts/vendor-three.sh <version>`, delete the old `three-<version>`
directory, change the version in the two `index.html` copy-dir links and in
`js/table3d/three.js`, and check the 3D table in Chrome (WebGPU) and in
Firefox on Linux (WebGL 2). Node-material APIs still change between
releases, so bump deliberately.
