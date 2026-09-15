---
id: EXP-FB-001
parent_spec: forum-member-feedback-2026-09 item 1
linked_adrs: []
priority: medium
regression_critical: false
evidence_category: executable
status: accepted
authored_by: pair
---

## Expectation: the installed forum PWA is identifiable by its own distinct icon

Member feedback, verbatim: *"More eye catching logo for easy identification of pwa"*.

The forum client ships its own icon set generated from an SVG source of record.
`crates/nostr-bbs-forum-client/manifest.webmanifest` references only icons served
from the forum's OWN scope (relative `icons/*`), never the retro BBS client's
`/community/bbs/icons/*`. The set covers the two sizes the Web App Manifest
install heuristics require (192, 512), a `maskable` variant at both sizes whose
mark sits inside Android's 80%-diameter adaptive-icon safe zone, an SVG entry,
and a 180px `apple-touch-icon` linked from `index.html` (iOS ignores manifest
icons entirely and screenshots the page without it). The tab favicon, the iOS
home-screen tile and the manifest icons are all the same mark.

`scripts/gen-pwa-icons.sh` regenerates every raster from the SVG sources and
`--check` proves the committed PNGs still match them.

### In scope
- SVG sources (`any` + `maskable`), the generation script, the committed rasters
- Manifest icon entries and their relative-path scoping
- `apple-touch-icon` + iOS status-bar meta in `index.html`
- Trunk `copy-dir` wiring so the icons reach `dist/icons/`

### Out of scope (intentionally)
- `theme_color` / `background_color` were left at `#111827`. The app is
  dark-first; an amber chrome bar above a dark UI, and an amber splash that
  flashes to dark, would both look like a bug. Identification is carried by the
  icon, which is what a home screen and task switcher actually show.
- Operator re-branding of `name`/`short_name` (already handled by the deploy).

### Counter-examples (must NOT happen)
- The forum manifest referencing an icon path outside its own scope
- A maskable icon whose mark is clipped by a circular OS mask
- Committed PNGs drifting from their SVG source without the script being re-run
