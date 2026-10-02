// poker-table.js — the string-only seam between the forum client (Rust/WASM)
// and the vendored Libre Poker engine (./librepoker, AGPL-3.0, see VENDORED.md).
//
// Every export takes and returns JSON *strings*: the hand state lives in Rust
// between calls and crosses the boundary serialised, so no JS object handle is
// ever held by WASM. An engine throw (illegal action, bad seed) comes back as
// {"error":"…"} instead of unwinding into wasm-bindgen as an exception.
// Constants and pure lookups (the bot roster, card names) the Rust side binds
// from the engine files directly; see src/poker/mod.rs.

import { newHand, legal, act, seatView, evaluate, handName, rngFromSeed } from './librepoker/poker.js';
import { decide } from './librepoker/bots.js';

function guard(fn) {
  try {
    return JSON.stringify(fn());
  } catch (e) {
    return JSON.stringify({ error: String((e && e.message) || e) });
  }
}

// cfg: {seats:[{name,stack}], button, sb, bb, seedHex, limit}
export function pokerNewHand(cfgJson) {
  return guard(() => {
    const cfg = JSON.parse(cfgJson);
    return newHand({
      seats: cfg.seats, button: cfg.button, sb: cfg.sb, bb: cfg.bb,
      seedHex: cfg.seedHex, limit: cfg.limit !== false,
    });
  });
}

// The legal envelope for the seat to act, or null once the hand is over.
export function pokerLegal(hJson) {
  return guard(() => legal(JSON.parse(hJson)));
}

// action: {seat, action, amount?}. Returns the advanced hand.
export function pokerAct(hJson, actionJson) {
  return guard(() => act(JSON.parse(hJson), JSON.parse(actionJson)));
}

// A bot's decision for `seat`, from that seat's view only, deterministic in seedHex.
export function pokerBotDecide(hJson, seat, profile, seedHex) {
  return guard(() => {
    const h = JSON.parse(hJson);
    const L = legal(h);
    if (!L) throw new Error('hand is over');
    return decide(seatView(h, seat), L, profile, rngFromSeed(seedHex));
  });
}

// What `seat` may see: own hole cards, others' only at showdown.
export function pokerSeatView(hJson, seat) {
  return guard(() => seatView(JSON.parse(hJson), seat));
}

// "two pair, kings and nines" for a JSON array of card indices; "" on bad input.
export function pokerHandName(cardsJson) {
  try {
    const cards = JSON.parse(cardsJson);
    return Array.isArray(cards) && cards.length > 0 ? handName(evaluate(cards)) : '';
  } catch (_e) {
    return '';
  }
}
