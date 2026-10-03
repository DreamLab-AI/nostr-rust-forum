# The 3D poker table

A Three.js scene of the heads-up table at `/table`, for both the practice
table and the DREAM table. It renders exactly the state the flat table
renders, a `SeatView` plus the hand's log, and adds nothing to the record.
Members switch it on with the **3D table** toggle on the table page (stored
as `poker_table_3d` in the preferences store, beside `poker_table`).

## Architecture

```
src/components/table3d.rs   Leptos <Table3d>: canvas, DOM labels, lifecycle, the seam
src/pages/table.rs          <TableSurface>: 3D over the flat table, toggle, busy-gating
js/table3d.js               wasm-bindgen snippet: JSON-string seam, dynamic import
js/table3d/                 the scene (copied verbatim by Trunk to <public-url>/table3d/)
  index.js                  create(): renderer, scene, loop, beats → tweens, events
  renderer.js               WebGPURenderer on WebGPU or its WebGL 2 backend
  scene.js                  felt, racetrack, padded rail, apron, floor, lamp, PMREM room
  materials.js              TSL node materials (felt, leather, lacquer, cards, chips)
  layout.js        (pure)   every anchor on the table, in metres
  director.js      (pure)   frames → beats; table model; reconcile
  choreography.js  (pure)   beat → plan (what moves where, when); reduced motion
  timeline.js      (pure)   the tween clock and easings
  stacks.js        (pure)   amounts → chip denominations → columns
  card-faces.js    (pure + CardAtlas) 15-slot face atlas, pips, indices, back, courts
  cards.js                  one InstancedMesh for every card and the deck stub
  chips.js                  one InstancedMesh for every chip, piles and flights
  camera.js                 seated framing, limited orbit, parallax, input
  picking.js       (pure)   felt point → pick target; inspectable groups
  inspect.js       (pure)   card inspection: state machine, flourishes, face-on layout
  peek-keys.js              keyboard buttons for inspection (stand-in DOM in tests)
  overlay.js                pins the DOM labels, writes the numbers the chips reached
  quality.js       (pure)   start tier, DPR cap, adaptive pixel ratio
  three.js                  the one import of the vendored three.js
assets/vendor/three-0.186.1/ three.js, minified, specifiers rewritten (VENDORED.md)
tools/table3d-test.mjs      node tests of every pure module, on the recorded hands
```

### Loading

`index.html` carries no `<base href>` and the SPA serves deep routes
(`/community/table`), so a document-relative URL would resolve differently
on every route. Nothing here uses one:

1. `#[wasm_bindgen(module = "/js/table3d.js")]` ships the snippet to
   `<public-url>/snippets/<crate-hash>/js/table3d.js`. It is imported
   statically by the wasm glue on every page, so it imports nothing heavy:
   only `./librepoker/poker.js` (already on every page) for `bestFive`.
2. When `<Table3d>` mounts, the snippet runs
   `import(new URL('../../../table3d/index.js', import.meta.url))`, which is
   `<public-url>/table3d/index.js` under any `--public-url`.
3. The scene imports three by relative path, `../vendor/three-0.186.1/…`,
   resolved from its own URL. Trunk copies both directories
   (`<link data-trunk rel="copy-dir">` in `index.html`).

three.js (~1.1 MB minified, ~300 KB gzipped) is therefore fetched only by
members who turn the 3D table on, and only on the table page. Same origin, no
CDN, cached by the service worker like any other static file.

### The seam

Strings in, strings out, one opaque handle, as `js/poker-table.js` does for
the engine:

| Export | Rust | Notes |
|---|---|---|
| `table3dInit(canvas, optsJson)` | `async`, `catch` | Resolves to the handle; rejects with `{"error":…}` |
| `table3dUpdate(handle, frameJson)` | → `String` | `"null"` or `{"error":…}` |
| `table3dSetOptions(handle, optsJson)` | → `String` | live: `reducedMotion`, `fourColour`, `freeLook`, `maxDpr` |
| `table3dOnEvent(handle, cb)` | `Closure<dyn FnMut(String)>` | every event as JSON |
| `table3dDispose(handle)` | | from Leptos `on_cleanup` |

- **Init options:** `{backend: "webgpu"|"webgl", quality: "auto"|"low"|"high",
  reducedMotion, fourColour, freeLook, maxDpr?, theme?: {felt, rail, back,
  accent, background, floor}}`.
- **Frame:** `{handKey, view, log}` — `view` is the engine's `SeatView` and
  `log` its `LogEntry[]`, serialised by serde exactly as the engine writes
  them. `handKey` is the practice hand's seed or the DREAM hand's commitment:
  two hands can show identical views, so the key is what says a new hand
  began. `null` empties the table.
- **Events:** `{"type":"ready","backend","tier"}`, `{"type":"busy","value"}`,
  `{"type":"pick","target":"heroCards"|"pot"|"stack"|"seat","seat"}`,
  `{"type":"peek","group":"hole"|"board"|"villain","inspecting","cards"}`,
  `{"type":"quality","dpr"}`, `{"type":"lost","reason"}`. A listener added
  after start is sent `ready` and the current `busy` at once.

### Backend detection

Rust decides, from the app's render tier (`components::fx`, probed once at
start-up), in `table3d::choose_backend`:

| Render tier | WebGL 2 present | 3D table |
|---|---|---|
| `WebGPU` (`navigator.gpu` exists) | — | starts with `backend: "webgpu"` |
| `Canvas2D` | yes (`WebGL2RenderingContext`) | starts with `backend: "webgl"` (`forceWebGL`) |
| `Canvas2D` | no | toggle disabled, flat table |
| `CSSOnly` (reduced motion at start-up) | — | toggle disabled, flat table |

`navigator.gpu` existing does not guarantee an adapter, and three falls back
to WebGL 2 on its own when the adapter request fails, so the backend in the
`ready` event is read back from `renderer.backend.isWebGPUBackend` and is the
one the page shows. If `init()` rejects, or the device is lost later
(`renderer.onDeviceLost`, covering WebGPU device loss and WebGL context loss),
the page shows the flat table with a one-line note; switching the toggle off
and on again retries.

Reduced motion switched on *after* start-up (the app preference, or the OS
setting) reaches a running scene as `reducedMotion: true`: every beat becomes
a 120 ms crossfade in place, with no arcs, flights, camera springs or
parallax.

### The director

`director.js` holds a pure model of the table (stacks, bets, the middle,
cards by place, button, winners, the lit five). Each frame, the log entries
it has not seen become **beats** (`reset`, `post`, `deal`, `call`, `bet`,
`raise`, `check`, `fold`, `street`, `runout`, `refund`, `reveal`, `award`,
`clear`), each a pure step from one model to the next. `choreography.js`
turns a beat into a plan (cards from the deck in Bézier arcs, hero cards
turning over at the end of their flight, chips from stack to bet line, bets
swept to the pot, flop dealt down then turned left to right, an all-in
run-out showing both hands first with a pause before each street, the
winning five lit and the rest dimmed, the pot pushed to the winner) and
`index.js` runs plans on the timeline one beat at a time.

The view stays the truth: when the queue drains, the model the beats reached
is compared with the model read straight from the view and the scene snaps
to the view. The node tests require that comparison to find no difference at
every step of all 160 recorded hands, from both seats, and when two of every
three frames are skipped.

- **busy** is true from the first queued beat until the queue drains; the
  page disables the action buttons (and the deal/sit button and the keyboard
  shortcuts) meanwhile.
- **Fast-forward:** more than 12 queued beats, a hidden tab, or the table
  scrolled out of view jumps straight to the newest view.
- The first frame after mounting (the toggle switched on mid-hand) snaps; so
  does a log that went backwards within a hand.

### Rendering

- **Render on demand.** The loop runs only while a beat animates, the camera
  springs, or something was repainted; an idle table draws nothing.
- **Pixel ratio:** capped at 2 (1.5 on touch devices), then adaptive: a
  60-frame window whose 90th-percentile frame is over 22 ms lowers it by 0.25
  (not below 1); three comfortable windows raise it again. MSAA only when the
  cap is ≤ 1.5.
- **Tiers:** `high` (desktops): a 2048² soft spot-light shadow from the lamp,
  fibre bump on the felt. `low` (touch devices, ≤ 4 cores or < 4 GB): no
  real-time shadows; soft blob shadows under every card and pile instead.
- **Draw calls:** felt, racetrack, rail, apron, floor, cards (1 instanced),
  chips (1 instanced), button, blobs (low tier) — about ten, twice that with
  the shadow pass.
- `compileAsync` before `ready`, so the first deal never waits on pipeline
  creation; `visibilitychange` and an `IntersectionObserver` pause the loop.
- Everything is disposed in `dispose()`: geometries, materials, textures, the
  PMREM target, the atlas canvas, listeners, observers, the renderer.

### Cards

All cards are one `InstancedMesh` of an extruded rounded rectangle (63.5 ×
88.9 mm at 1.2× scale, 0.4 mm thick). The faces live in one 2048² canvas
atlas with 15 slots (the back plus 14 faces; a heads-up hand shows at most
nine), repainted as cards are dealt, so GPU memory is fixed. Pips, indices
and the back (a guilloché field and a four-suit medallion) are drawn in
code; the court figures are Fomin's (below), loaded when a court card is
first dealt, with a drawn court standing in until it arrives. The
four-colour deck is a toggle beside the 3D toggle. Hero cards are always face
up (no peek mode). Flips lift the card by half its width as it turns; a
vertex curl was left out because TSL's `positionNode` runs after the
instance transform in r186.

### Inspecting cards

Hovering a group of face-up cards lifts it to the camera for a closer look:
the hero's hole cards together, the board together, and the other seat's
cards together once they are shown (never while face down). Nothing else on
the table reacts to hover.

- **The lift.** The group rises off the felt and travels to a face-on row in
  front of the camera on a cubic ease-out (700 ms), filling about 80% of the
  canvas's shorter side where the row's shape allows (never more than 92% of
  the width), and laid out between the two seat labels; the bet and pot tags
  step aside while it is up (`data-t3d-inspecting` on the overlay). Leaving
  drops it on a cubic ease-in (500 ms) to exactly its resting pose. Every
  tween starts from where the cards are, so re-entering mid-drop reverses
  with no snap and nothing queued; durations scale with the distance left.
- **Flourishes**, one chosen uniformly per inspection, all within the travel
  time: `flip` (a tumble end over end with a glint sweeping the face), `fan`
  (the cards spread like a hand, then square up), `spin` (a full turn about
  the vertical, settling face-on), `float` (a bob and rock while the coat's
  gloss comes up), `wave` (a ripple runs along the row). Every offset is zero
  at both ends, and a drop only fades the one in progress, so the drop has no
  flourish of its own. The glint and gloss are the card material's fourth fx
  channel (`clearcoat`, `clearcoatRoughness`, a face-only emissive sweep).
- **Reduced motion:** a 140 ms crossfade from the felt to the face-on pose, no
  travel and no flourish.
- **Touch:** tap a group to inspect, tap anywhere else to drop. **Keyboard:**
  `<Table3d>` renders one `<button data-t3d-peek>` per group beside the
  canvas; `peek-keys.js` shows only the groups face up, lays each over its
  cards (its focus ring frames them as they lift), and maps Enter or Space to
  toggle and Escape, or Tab away, to drop. Those keys stop at the button, so
  the page's Enter (next hand) never sees them. The page announces each lift
  in a polite live region ("Inspecting your hole cards: A♠ K♥").
- **The view stays authoritative.** The inspection pose is composed over each
  card's resting pose when the instances are written (`CardSet.poser`), never
  stored in the card states or the director's model. A frame with new log
  entries drops the group first and the next beat waits for it to land
  (`busy` behaves as before: true only while the director has beats);
  nothing new lifts while the director is busy, and a fast-forward puts
  everything down at once. Inspection keeps render-on-demand: the loop runs
  while a group moves, or while one is up and the camera moves.

## Assets and licences

| Asset | Licence | Where |
|---|---|---|
| three.js 0.186.1 | MIT | `assets/vendor/three-0.186.1/` (`LICENSE`, `VENDORED.md`) |
| Easing curves ported from tween.js | MIT, attributed in `timeline.js` | `timeline.js` |
| Court figures, Dmitry Fomin's English-pattern deck | CC0 1.0 | `assets/cards/` (`LICENSE.md`) |
| Brown Leather, Dark Wood (Poly Haven) | CC0 1.0 | `assets/textures/` (`LICENSE.md`) |
| Everything else (pips, indices, back, chips, felt, button) | AGPL-3.0, this crate | drawn in code |

GSAP was not used: its licence is not compatible with the AGPL.

## Testing

```
node crates/nostr-bbs-forum-client/tools/table3d-test.mjs
```

Runs the director, choreography, timeline, chip breakdown, card atlas,
painter (on a recording context), picking, and card inspection (the state
machine through enter, leave, reversal, drop-on-frame, reduced motion and
dispose; the flourishes; the face-on layout; the keyboard buttons on
stand-in elements) under node, with no browser and no three.js. The Rust side's pure helpers (backend choice, frame and option
JSON, event parsing) are unit tests in `src/components/table3d.rs`.
