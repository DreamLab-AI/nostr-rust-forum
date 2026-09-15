# Evidence — EXP-FB-001 (distinct PWA icon)

## The defect, as committed at `11b674c`

`crates/nostr-bbs-forum-client/manifest.webmanifest` icon entries, before:

```json
{ "src": "/community/bbs/icons/icon-192.png", ... },
{ "src": "/community/bbs/icons/icon-512.png", ... },
{ "src": "/community/bbs/icons/icon-512-maskable.png", ... }
```

Those paths are the **retro BBS client's** icons
(`crates/nostr-bbs-bbs-client/assets/icons/`), whose mark is a `>_` terminal
glyph on `#0a0a0a`. Two consequences:

1. The installed forum PWA was visually identical to the installed BBS PWA, and
   a near-black tile on a dark home screen — the reported "can't identify it".
2. It was an absolute cross-app dependency: deploying the forum without the
   `bbs/` sub-app left the manifest pointing at 404s, and a manifest whose
   icons all 404 makes Chrome fall back to a letter-glyph tile.

`crates/nostr-bbs-forum-client/` had **no** `assets/` directory at all:

```
$ find . -name '*icon*' -not -path '*/target/*' | grep -v node_modules
./crates/nostr-bbs-bbs-client/assets/icons
./crates/nostr-bbs-bbs-client/assets/icons/icon-512.png
./crates/nostr-bbs-bbs-client/assets/icons/icon-192.png
./crates/nostr-bbs-bbs-client/assets/icons/icon-512-maskable.png
```

`index.html` also had no `<link rel="apple-touch-icon">`, so iOS screenshotted
the page for the home-screen tile.

## Generation

```
$ ./scripts/gen-pwa-icons.sh
renderer: magick
wrote:
  icon-192.png               7147 bytes
  icon-512.png               26892 bytes
  apple-touch-icon.png       6239 bytes
  icon-512-maskable.png      20164 bytes
  icon-192-maskable.png      5107 bytes
```

Drift check (regenerates to a temp dir and diffs against the committed rasters):

```
$ ./scripts/gen-pwa-icons.sh --check
renderer: magick
icons match their SVG sources
$ echo $?
0
```

## Rasteriser verification

ImageMagick 7.1.2-27 renders the SVG `linearGradient` correctly (a blank or
flat-filled PNG would be the failure mode to watch for):

```
$ magick identify crates/nostr-bbs-forum-client/assets/icons/icon-192.png
icon-192.png PNG 192x192 192x192+0+0 16-bit sRGB
```

Both rasters were inspected visually: `icon-192.png` renders the dark diamond
with the amber tick on the amber gradient field; `icon-512-maskable.png` renders
the same mark scaled to 72% about the centre, comfortably inside the 80%-diameter
adaptive-icon safe circle.

## Build wiring

`trunk build --release` asset pipeline output — the `copy-dir` directive with
`data-target-path="icons"` resolves, and the manifest's relative `icons/*` paths
now have files behind them:

```
$ find dist -name 'icon*' -o -name 'apple*' -o -name '*.webmanifest'
dist/.stage/manifest.webmanifest
dist/.stage/icons/icon-512.png
dist/.stage/icons/apple-touch-icon.png
dist/.stage/icons/icon-192-maskable.png
dist/.stage/icons/icon-maskable.svg
dist/.stage/icons/icon-192.png
dist/.stage/icons/icon.svg
dist/.stage/icons/icon-512-maskable.png
```

## Honest limits

- No device install was performed. The manifest is spec-correct and the rasters
  exist at the referenced paths, but "eye catching" is a judgement the member
  will have to confirm on their own home screen.
- `theme_color`/`background_color` deliberately unchanged — see EXP-FB-001
  "Out of scope".
