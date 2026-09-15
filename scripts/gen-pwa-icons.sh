#!/usr/bin/env bash
# Rasterise the forum PWA icon SVG sources into the PNG sizes the manifest
# and the iOS <link rel="apple-touch-icon"> reference.
#
# The SVGs in crates/nostr-bbs-forum-client/assets/icons/ are the SOURCE OF
# TRUTH; the PNGs beside them are generated artefacts that happen to be
# committed (a PWA manifest cannot reference an SVG for `maskable`, and iOS
# ignores SVG touch icons entirely, so the rasters must ship).
#
# Requires ImageMagick 7 (`magick`) or 6 (`convert`). Both rasterise SVG
# linear gradients correctly; rsvg-convert is used in preference when present
# because its SVG renderer is the more faithful of the two.
#
# Usage:  scripts/gen-pwa-icons.sh
# Verify: scripts/gen-pwa-icons.sh --check   (regenerate to a temp dir and
#         diff, so CI can prove the committed PNGs match the SVG sources)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_dir="$repo_root/crates/nostr-bbs-forum-client/assets/icons"

check_mode=0
[ "${1:-}" = "--check" ] && check_mode=1

out_dir="$src_dir"
if [ "$check_mode" -eq 1 ]; then
  out_dir="$(mktemp -d)"
  trap 'rm -rf "$out_dir"' EXIT
fi

# Pick a rasteriser once, up front, so a missing tool fails loudly rather
# than silently emitting a blank PNG.
if command -v rsvg-convert >/dev/null 2>&1; then
  render() { rsvg-convert -w "$2" -h "$2" -o "$3" "$1"; }
  renderer="rsvg-convert"
elif command -v magick >/dev/null 2>&1; then
  render() { magick -background none -density 384 "$1" -resize "${2}x${2}" -strip "PNG32:$3"; }
  renderer="magick"
elif command -v convert >/dev/null 2>&1; then
  render() { convert -background none -density 384 "$1" -resize "${2}x${2}" -strip "PNG32:$3"; }
  renderer="convert"
else
  echo "error: need rsvg-convert or ImageMagick (magick/convert) on PATH" >&2
  exit 1
fi
echo "renderer: $renderer"

# (source-svg, output-basename, size)
# 192/512 are the two sizes the Web App Manifest spec's install heuristics
# look for; 180 is the iOS apple-touch-icon size; 512-maskable backs the
# Android adaptive icon.
render "$src_dir/icon.svg"          192 "$out_dir/icon-192.png"
render "$src_dir/icon.svg"          512 "$out_dir/icon-512.png"
render "$src_dir/icon.svg"          180 "$out_dir/apple-touch-icon.png"
render "$src_dir/icon-maskable.svg" 512 "$out_dir/icon-512-maskable.png"
render "$src_dir/icon-maskable.svg" 192 "$out_dir/icon-192-maskable.png"

if [ "$check_mode" -eq 1 ]; then
  status=0
  for f in icon-192.png icon-512.png apple-touch-icon.png \
           icon-512-maskable.png icon-192-maskable.png; do
    if ! cmp -s "$out_dir/$f" "$src_dir/$f"; then
      echo "DRIFT: $f differs from its SVG source" >&2
      status=1
    fi
  done
  [ "$status" -eq 0 ] && echo "icons match their SVG sources"
  exit "$status"
fi

echo "wrote:"
for f in icon-192.png icon-512.png apple-touch-icon.png \
         icon-512-maskable.png icon-192-maskable.png; do
  printf '  %-26s %s\n' "$f" "$(wc -c <"$src_dir/$f") bytes"
done
