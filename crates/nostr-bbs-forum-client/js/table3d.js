// table3d.js — the wasm-bindgen snippet for the 3D poker table: the
// string-only seam between the forum client (Rust/WASM) and the Three.js
// scene in ../table3d/ (served at <public-url>/table3d/).
//
// This file is imported statically by the wasm-bindgen glue on every page,
// so it imports nothing heavy: the scene and three.js (~1.1 MB) are loaded
// with a dynamic import() only when a member opens the 3D table. The import
// resolves from this file's own URL — <public-url>/snippets/<crate-hash>/js/
// table3d.js — three levels up to <public-url>/table3d/index.js, so it works
// on every route and under any Trunk --public-url (the index.html carries no
// <base href>, so a document-relative URL would break on deep routes).
//
// The one static import is the poker engine, already on every page through
// poker-table.js: the scene lights a showdown's winning five with the
// engine's own bestFive().
//
// Like poker-table.js, everything crossing the seam is a JSON string, and a
// failure comes back as {"error": "…"} rather than an exception unwinding
// into wasm-bindgen; only init rejects, with that same JSON as its reason.

import { bestFive } from './librepoker/poker.js';

const SCENE = '../../../table3d/index.js';

function failure(e) {
  return JSON.stringify({ error: String((e && e.message) || e) });
}

// opts: {backend: "webgpu"|"webgl", quality, maxDpr, reducedMotion,
//        fourColour, freeLook, theme: {felt, rail, back, accent, background, floor}}
// Resolves to an opaque handle; rejects with '{"error": …}'.
export async function table3dInit(canvas, optsJson) {
  let scene;
  try {
    scene = await import(new URL(SCENE, import.meta.url).href);
  } catch (e) {
    throw failure(e);
  }
  try {
    return await scene.create(canvas, JSON.parse(optsJson), { bestFive });
  } catch (e) {
    throw failure(e);
  }
}

// frame: {handKey, view: SeatView, log: LogEntry[]} or null for an empty
// table. Returns "null", or '{"error": …}'.
export function table3dUpdate(handle, frameJson) {
  try {
    handle.update(JSON.parse(frameJson));
    return 'null';
  } catch (e) {
    return failure(e);
  }
}

// Live option changes: reducedMotion, fourColour, freeLook, maxDpr.
export function table3dSetOptions(handle, optsJson) {
  try {
    handle.setOptions(JSON.parse(optsJson));
    return 'null';
  } catch (e) {
    return failure(e);
  }
}

// cb receives each event as a JSON string: ready, busy, pick, quality, lost.
export function table3dOnEvent(handle, cb) {
  handle.onEvent((ev) => cb(JSON.stringify(ev)));
}

export function table3dDispose(handle) {
  try {
    handle.dispose();
  } catch (_e) {
    // already torn down: nothing left to release
  }
}
