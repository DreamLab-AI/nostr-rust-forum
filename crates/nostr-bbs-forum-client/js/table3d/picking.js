// picking.js — what a tap on the table means. Pure: no DOM, no three.
//
// The scene turns a pointer into a point on the felt (one ray against the
// y = 0 plane, no mesh raycasts); this file turns that point into a target.
// Only a handful of things are worth a tap in heads-up — your own cards, the
// pot, your stack, the other seat — so a few distance tests beat a raycast
// against every instance, and they run in node.

import { CARD, LAYOUT, sideOf } from './layout.js';

/** How close (metres) a tap must land to a pile's anchor to pick it. */
const PILE_RADIUS = 0.075;

const dist = (a, b) => Math.hypot(a.x - b.x, a.z - b.z);

/** Whether `p` lies within a card's footprint at `a` (yaw ignored: it is small). */
function onCard(p, a, slack = 0.01) {
  return Math.abs(p.x - a.x) <= CARD.w / 2 + slack && Math.abs(p.z - a.z) <= CARD.h / 2 + slack;
}

/**
 * The pick event for a point `{x, z}` on the felt, or `null` for empty felt.
 * Seats are the engine's seat numbers; the hero's is `model.hero`.
 */
export function pickOnFelt(p, model) {
  if (!p || !model) return null;
  const hero = model.hero | 0;
  const other = hero === 0 ? 1 : 0;
  const near = LAYOUT[sideOf(hero, hero)];
  const far = LAYOUT[sideOf(other, hero)];
  const heroSeat = model.seats[hero];
  if (heroSeat && heroSeat.cards && !heroSeat.mucked && near.hole.some((a) => onCard(p, a))) {
    return { type: 'pick', target: 'heroCards', seat: hero };
  }
  if (model.pot > 0 && dist(p, LAYOUT.pot) <= PILE_RADIUS) {
    return { type: 'pick', target: 'pot', seat: null };
  }
  if (heroSeat && heroSeat.stack > 0 && dist(p, near.stack) <= PILE_RADIUS) {
    return { type: 'pick', target: 'stack', seat: hero };
  }
  // the far seat: its cards, its stack, or the rail in front of it
  const otherSeat = model.seats[other];
  if (
    otherSeat &&
    (far.hole.some((a) => onCard(p, a, 0.02)) || dist(p, far.stack) <= PILE_RADIUS || dist(p, far.seat) <= 0.12)
  ) {
    return { type: 'pick', target: 'seat', seat: other };
  }
  return null;
}
