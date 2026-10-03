# Table textures: provenance and licence

All from **Poly Haven** (https://polyhaven.com), released under **CC0 1.0**
(https://polyhaven.com/license). No attribution is required; credit is
given here anyway.

| File | Source | Authors |
|---|---|---|
| `leather-albedo.webp`, `leather-normal.webp`, `leather-rough.webp` | Brown Leather, https://polyhaven.com/a/brown_leather (1k JPG: albedo, nor_gl, rough) | Rob Tuytel |
| `wood-albedo.webp` | Dark Wood, https://polyhaven.com/a/dark_wood (1k JPG: diff) | Dario Barresi, Dimitrios Savva, Rico Cilliers |

Downloaded 2026-10-03; each source JPG's MD5 matched the one the Poly Haven
API publishes. Re-encoded to 512² WebP with ImageMagick
(`-resize 512x512 -quality 80-82 -define webp:method=6`; the roughness map
in grey at quality 55). The felt has no texture: it is procedural noise in
the shader (`materials.js`), so it never tiles.

| File | SHA-256 |
|---|---|
| `leather-albedo.webp` | `adbc2b77f4c6f3ee26c048fbc24920c3f81106d2cca1fbcea557126bfe626a47` |
| `leather-normal.webp` | `c9b314ccb4107e24782e0f73c695b91658d7faf00857f2930a9aac446aaf53cc` |
| `leather-rough.webp` | `da240fa15f77855846b28cdf7133de04146abd9a972f8b436dc1ea80f86ea983` |
| `wood-albedo.webp` | `0cc6211b2332beeadd7dd647cb0d19cf5101d296250f10b0ccf634e809c0728a` |
