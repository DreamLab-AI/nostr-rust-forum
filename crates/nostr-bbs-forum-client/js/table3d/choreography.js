// choreography.js — how each beat looks. Pure: no DOM, no three.
//
// The director says *what* changed (a beat, and the table model before and
// after it); this file says how that change is shown: which card flies from
// where, which chips slide, how long it all takes. A plan is plain data, so
// node tests can check every beat of every recorded hand has one and that
// reduced motion really is short and arc-free; the scene (index.js) only
// executes plans.
//
// Cards are identified by place, not by face: `s0c1` is seat 0's second hole
// card, `b3` the turn. Chip piles likewise: `stack0`, `bet1`, `pot`.

import { CARD, LAYOUT, holeYaw, muckSpot, sideOf } from './layout.js';
import { Easing } from './timeline.js';

/** Beat timings in ms (full motion), and the reduced-motion ceiling. */
export const durations = Object.freeze({
  dealFlight: 360,
  dealStagger: 90,
  chips: 320,
  raise: 380,
  check: 260,
  fold: 380,
  sweep: 380,
  boardFlight: 300,
  boardStagger: 100,
  flip: 260,
  flipStagger: 130,
  runoutPause: 700,
  reveal: 460,
  highlightHold: 650,
  award: 650,
  resetSweep: 420,
  reduced: Object.freeze({ move: 120, max: 240 }),
});

/** Card ids in drawing order. */
export const CARD_IDS = Object.freeze(['s0c0', 's0c1', 's1c0', 's1c1', 'b0', 'b1', 'b2', 'b3', 'b4']);
/** Chip pile ids. */
export const PILE_IDS = Object.freeze(['stack0', 'stack1', 'bet0', 'bet1', 'pot']);

const HIDDEN = Object.freeze({ visible: false });

/** The resting place of every card the model shows. */
export function posesOf(model) {
  const poses = {};
  const lit = new Set(model.highlight || []);
  const anyLit = lit.size > 0;
  let mucked = 0;
  for (let seat = 0; seat < 2; seat++) {
    const s = model.seats[seat];
    const side = sideOf(seat, model.hero);
    for (let i = 0; i < 2; i++) {
      const id = `s${seat}c${i}`;
      if (!s || !s.cards) {
        poses[id] = HIDDEN;
        continue;
      }
      const card = s.cards[i] ?? null;
      if (s.mucked) {
        const p = muckSpot(mucked++);
        poses[id] = { visible: true, card, faceUp: false, x: p.x, y: p.y, z: p.z, yaw: p.yaw, glow: 0, dim: 0 };
        continue;
      }
      const a = LAYOUT[side].hole[i];
      poses[id] = {
        visible: true,
        card,
        faceUp: card != null,
        x: a.x,
        y: CARD.t / 2 + 0.0004 * i,
        z: a.z,
        yaw: holeYaw(side, i),
        glow: card != null && lit.has(card) ? 1 : 0,
        dim: anyLit && card != null && !lit.has(card) ? 1 : 0,
      };
    }
  }
  for (let i = 0; i < 5; i++) {
    const id = `b${i}`;
    if (i >= model.board.length) {
      poses[id] = HIDDEN;
      continue;
    }
    const card = model.board[i];
    const a = LAYOUT.board[i];
    poses[id] = {
      visible: true,
      card,
      faceUp: true,
      x: a.x,
      y: CARD.t / 2,
      z: a.z,
      yaw: 0,
      glow: lit.has(card) ? 1 : 0,
      dim: anyLit && !lit.has(card) ? 1 : 0,
    };
  }
  return poses;
}

/** The pose a card leaves the deck in. */
export function deckPose(n = 0) {
  return {
    visible: true,
    card: null,
    faceUp: false,
    x: LAYOUT.deck.x,
    y: CARD.t * (8 + n * 0.5),
    z: LAYOUT.deck.z,
    yaw: Math.PI / 2,
    glow: 0,
    dim: 0,
  };
}

/** Pile amounts the model shows. */
export function pileAmounts(model) {
  const s = model.seats;
  return {
    stack0: s[0] ? s[0].stack : 0,
    stack1: s[1] ? s[1].stack : 0,
    bet0: s[0] ? s[0].bet : 0,
    bet1: s[1] ? s[1].bet : 0,
    pot: model.pot,
  };
}

const card = (id, to, o = {}) => ({ kind: 'card', id, to, from: null, delay: 0, duration: 0, arc: false, lift: 0, ease: Easing.Cubic.InOut, ...o });
const chips = (from, to, amount, o = {}) => ({ kind: 'chips', from, to, amount, delay: 0, duration: durations.chips, arc: false, ease: Easing.Cubic.InOut, ...o });

/** Bet-line → middle for every seat with chips in front of it. */
function sweepMoves(m, delay) {
  const out = [];
  m.seats.forEach((s, i) => {
    if (s && s.bet > 0) out.push(chips(`bet${i}`, 'pot', s.bet, { delay, duration: durations.sweep }));
  });
  return out;
}

/** Cards present before and gone after fly to `where` (the muck or the deck). */
function collectMoves(before, after, where, delay) {
  const pb = posesOf(before);
  const pa = posesOf(after);
  const out = [];
  let n = 0;
  for (const id of CARD_IDS) {
    if (pb[id].visible && !pa[id].visible) {
      const target = where === 'deck' ? { ...deckPose(n), visible: false } : { ...pb[id], visible: false };
      out.push(card(id, target, { delay: delay + n * 25, duration: durations.resetSweep, arc: true, lift: 0.03, from: 'current' }));
      n += 1;
    }
  }
  return out;
}

/**
 * The full-motion plan for one queued beat.
 * Returns `{duration, moves, piles}`: `moves` as described above, `piles`
 * the pile amounts to show once the beat is done (always `after`'s).
 */
function fullPlan({ beat, before, after }) {
  const moves = [];
  const pa = posesOf(after);
  const t = beat.type;

  if (t === 'clear' || t === 'reset') {
    moves.push(...collectMoves(before, after, 'deck', 0));
    if (t === 'reset' && before.button !== after.button && after.button != null) {
      moves.push({ kind: 'button', seat: after.button, delay: 0, duration: durations.resetSweep, ease: Easing.Cubic.InOut });
    }
    moves.push({ kind: 'piles', delay: durations.resetSweep, duration: 0 });
  } else if (t === 'post' || t === 'call' || t === 'bet' || t === 'raise') {
    const s = beat.seat;
    const moved = before.seats[s].stack - after.seats[s].stack;
    if (moved > 0) {
      const push = t === 'raise' || t === 'bet';
      moves.push(
        chips(`stack${s}`, `bet${s}`, moved, {
          duration: push ? durations.raise : durations.chips,
          ease: push ? Easing.Back.Out : Easing.Cubic.InOut,
          arc: push,
        }),
      );
    }
  } else if (t === 'check') {
    moves.push({ kind: 'pulse', seat: beat.seat, delay: 0, duration: durations.check });
  } else if (t === 'deal') {
    beat.order.forEach(([seat, idx], k) => {
      const id = `s${seat}c${idx}`;
      if (!pa[id].visible) return;
      moves.push(
        card(id, pa[id], {
          from: deckPose(k),
          delay: k * durations.dealStagger,
          duration: durations.dealFlight,
          arc: true,
          lift: 0.05,
          ease: Easing.Quartic.Out,
          faceUp: pa[id].faceUp,
        }),
      );
    });
  } else if (t === 'fold') {
    for (const i of [0, 1]) {
      const id = `s${beat.seat}c${i}`;
      if (pa[id].visible) moves.push(card(id, pa[id], { from: 'current', delay: i * 60, duration: durations.fold, arc: true, lift: 0.02, faceUp: false }));
    }
  } else if (t === 'street' || t === 'runout') {
    let at = 0;
    const sw = sweepMoves(before, 0);
    moves.push(...sw);
    if (sw.length) at += durations.sweep;
    const from = beat.from ?? before.board.length;
    const to = after.board.length;
    // group the new cards by street: flop together, then turn, then river
    const groups = [];
    for (let i = from; i < to; i++) {
      if (i < 3) {
        if (!groups.length || groups[groups.length - 1][0] >= 3) groups.push([]);
        groups[groups.length - 1].push(i);
      } else groups.push([i]);
    }
    for (const g of groups) {
      if (t === 'runout') at += durations.runoutPause;
      g.forEach((i, k) => {
        const id = `b${i}`;
        moves.push(
          card(id, { ...pa[id], faceUp: false }, {
            from: deckPose(k),
            delay: at + k * durations.boardStagger,
            duration: durations.boardFlight,
            arc: true,
            lift: 0.03,
            ease: Easing.Quartic.Out,
            faceUp: false,
          }),
        );
      });
      at += (g.length - 1) * durations.boardStagger + durations.boardFlight;
      g.forEach((i, k) => {
        const id = `b${i}`;
        moves.push(card(id, pa[id], { from: 'current', delay: at + k * durations.flipStagger, duration: durations.flip, faceUp: true, flip: true }));
      });
      at += (g.length - 1) * durations.flipStagger + durations.flip;
    }
  } else if (t === 'refund') {
    const s = beat.seat;
    const fromBet = Math.min(before.seats[s].bet, beat.amount);
    if (fromBet > 0) moves.push(chips(`bet${s}`, `stack${s}`, fromBet));
    if (beat.amount - fromBet > 0) moves.push(chips('pot', `stack${s}`, beat.amount - fromBet, { arc: true }));
  } else if (t === 'reveal') {
    let k = 0;
    for (const seat of Object.keys(beat.cards)) {
      for (const i of [0, 1]) {
        const id = `s${seat}c${i}`;
        moves.push(card(id, pa[id], { from: 'current', delay: k * durations.flipStagger, duration: durations.reveal, faceUp: true, flip: true, lift: 0.025 }));
        k += 1;
      }
    }
  } else if (t === 'award') {
    let at = 0;
    const sw = sweepMoves(before, 0);
    moves.push(...sw);
    if (sw.length) at += durations.sweep;
    if (beat.showdown && after.highlight.length) {
      moves.push({ kind: 'highlight', delay: at, duration: 220 });
      at += durations.highlightHold;
    }
    // what the middle will hold once the bets are in
    for (const w of beat.winners) {
      if (w.amount > 0) moves.push(chips('pot', `stack${w.seat}`, w.amount, { delay: at, duration: durations.award, arc: true, ease: Easing.Cubic.InOut }));
    }
    at += durations.award;
    moves.push({ kind: 'winner', seats: beat.winners.map((w) => w.seat), delay: at - durations.award, duration: durations.award });
  }

  const duration = moves.reduce((a, m) => Math.max(a, (m.delay || 0) + (m.duration || 0)), 0);
  return { duration, moves, piles: pileAmounts(after) };
}

/**
 * The plan for one queued beat. Under reduced motion every move becomes a
 * short crossfade in place of travel: no arcs, no flights, no stagger, so
 * the state changes exactly as it would with motion, only quietly.
 */
export function planBeat(item, { reducedMotion = false } = {}) {
  const plan = fullPlan(item);
  if (!reducedMotion) return plan;
  const d = durations.reduced.move;
  const moves = plan.moves
    // a check pulse and the winner glow are pure motion: drop them
    .filter((m) => m.kind !== 'pulse')
    .map((m) => ({
      ...m,
      delay: 0,
      duration: d,
      arc: false,
      lift: 0,
      fade: m.kind === 'card',
      ease: Easing.Linear.None,
    }));
  const duration = moves.length ? Math.min(durations.reduced.max, 2 * d) : 0;
  return { duration, moves, piles: plan.piles };
}
