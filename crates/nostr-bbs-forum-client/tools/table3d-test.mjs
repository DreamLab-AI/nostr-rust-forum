// table3d-test.mjs — node tests for the 3D table's pure modules.
//
//   node crates/nostr-bbs-forum-client/tools/table3d-test.mjs
//
// Drives the director with the engine's 160 recorded hands
// (crates/nostr-bbs-poker/tests/fixtures/hands.json, every intermediate
// state included) from both seats, frame by frame as the table page would
// send them, and requires the beats to land exactly on each view with no
// reconcile drift. Also covers the timeline, the chip breakdown, the card
// atlas, the choreography's beat plans and felt picking. No browser and no
// three.js: the modules under test import nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  Director,
  applyBeat,
  beatsFor,
  dealOrder,
  diffModels,
  emptyModel,
  modelFromView,
  startStacks,
} from '../js/table3d/director.js';
import { Timeline, Easing, arc } from '../js/table3d/timeline.js';
import { DENOMS, breakdown, pileLayout, shownValue, minDenomIndex, COLUMN_MAX } from '../js/table3d/stacks.js';
import { AtlasSlots, ATLAS, cardParts, pipLayout, drawFace, drawBack } from '../js/table3d/card-faces.js';
import { planBeat, durations } from '../js/table3d/choreography.js';
import { pickOnFelt } from '../js/table3d/picking.js';
import { AdaptiveDpr, dprCap, startTier } from '../js/table3d/quality.js';
import { LAYOUT, CARD } from '../js/table3d/layout.js';
import { bestFive, newHand, act, seatView } from '../js/librepoker/poker.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(join(here, '../../nostr-bbs-poker/tests/fixtures/hands.json'), 'utf8'),
);
const testdata = (name) => JSON.parse(readFileSync(join(here, '../src/poker/testdata', name), 'utf8'));

/** Drain a director's queue the way the choreography does, checking each step. */
function drain(d) {
  let n = 0;
  for (let item = d.next(); item; item = d.next()) {
    assert.deepEqual(applyBeat(item.before, item.beat), item.after, `beat ${item.beat.type} is not pure`);
    n += 1;
  }
  return n;
}

/** The frames the page sends for one recorded hand, seen from `seat`. */
function framesOf(hand, seat) {
  const key = hand.cfg.seedHex;
  const frames = [{ handKey: key, view: seatView(hand.dealt, seat), log: hand.dealt.log }];
  for (const step of hand.steps) {
    frames.push({ handKey: key, view: seat === 0 ? step.view0 : seatView(step.after, seat), log: step.after.log });
  }
  return frames;
}

// ── director ────────────────────────────────────────────────────────────────

test('every recorded hand lands on every view, from both seats, with no drift', () => {
  assert.equal(fixtures.hands.length, 160);
  for (const seat of [0, 1]) {
    const d = new Director({ bestFive, maxQueue: 1e9 });
    assert.equal(d.update(null), 'snap');
    let beats = 0;
    for (const hand of fixtures.hands) {
      for (const frame of framesOf(hand, seat)) {
        d.update(frame);
        beats += drain(d);
        const diff = diffModels(d.model, d.target);
        assert.deepEqual(diff, [], `hand ${hand.cfg.seedHex.slice(0, 8)} seat ${seat}: ${JSON.stringify(diff)}`);
        d.reconcile();
      }
      // the last frame of the hand equals the engine's final view
      const final = modelFromView(seatView(hand.final, seat), hand.cfg.seedHex, bestFive);
      assert.deepEqual(diffModels(d.model, final), []);
    }
    assert.equal(d.drift, 0, `seat ${seat}: ${JSON.stringify(d.lastDiff)}`);
    assert.ok(beats > 160 * 5, `only ${beats} beats`);
  }
});

test('frames that skip states (only every third arrives) still land without drift', () => {
  const d = new Director({ bestFive, maxQueue: 1e9 });
  d.update(null);
  for (const hand of fixtures.hands) {
    const frames = framesOf(hand, 0);
    const sparse = frames.filter((_, i) => i % 3 === 0 || i === frames.length - 1);
    for (const f of sparse) {
      d.update(f);
      drain(d);
      assert.deepEqual(diffModels(d.model, d.target), []);
      d.reconcile();
    }
  }
  assert.equal(d.drift, 0);
});

test('the first frame snaps; a repeated frame queues nothing', () => {
  const hand = fixtures.hands.find((h) => h.steps.length >= 3);
  const frames = framesOf(hand, 0);
  const d = new Director({ bestFive });
  assert.equal(d.update(frames[2]), 'snap');
  assert.equal(d.pending, 0);
  assert.deepEqual(diffModels(d.model, modelFromView(frames[2].view, hand.cfg.seedHex, bestFive)), []);
  assert.equal(d.update(frames[2]), 'none');
  assert.equal(d.update(frames[3]), 'queued');
});

test('a log that goes backwards in the same hand snaps instead of animating', () => {
  const hand = fixtures.hands.find((h) => h.steps.length >= 3);
  const frames = framesOf(hand, 0);
  const d = new Director({ bestFive });
  d.update(null);
  d.update(frames[3]);
  drain(d);
  d.reconcile();
  assert.equal(d.update(frames[1]), 'snap');
  assert.deepEqual(diffModels(d.model, modelFromView(frames[1].view, hand.cfg.seedHex, bestFive)), []);
});

test('a deal is posted blinds, then cards to the big blind first; the hero sees only their own', () => {
  const hand = fixtures.hands[0];
  const d = new Director({ bestFive });
  d.update(null);
  d.update(framesOf(hand, 0)[0]);
  const types = d.queue.map((q) => q.beat.type);
  assert.deepEqual(types, ['reset', 'post', 'post', 'deal']);
  const deal = d.queue[3].beat;
  // button 0 is the small blind heads-up; seat 1 is dealt first
  assert.deepEqual(deal.order, [[1, 0], [0, 0], [1, 1], [0, 1]]);
  assert.deepEqual(deal.holes[0], hand.dealt.seats[0].hole);
  assert.equal(deal.holes[1], null);
  assert.deepEqual(dealOrder(1), [[0, 0], [1, 0], [0, 1], [1, 1]]);
});

test('an all-in run-out reveals both hands before the board comes', () => {
  let seen = 0;
  for (const hand of fixtures.hands) {
    if (!hand.final.log.some((e) => e.ev === 'runout')) continue;
    const d = new Director({ bestFive, maxQueue: 1e9 });
    d.update(null);
    for (const f of framesOf(hand, 0)) d.update(f);
    const types = d.queue.map((q) => q.beat.type);
    const run = types.indexOf('runout');
    const reveal = types.indexOf('reveal');
    assert.ok(run > 0);
    if (hand.final.result.showdown) {
      assert.ok(reveal >= 0 && reveal < run, types.join(','));
      assert.equal(types.filter((t) => t === 'reveal').length, 1, 'shown once, not again at showdown');
    }
    seen += 1;
  }
  assert.ok(seen > 0, 'the fixtures include all-in run-outs');
});

test('a showdown lights the winning five; a fold-out never reveals the folded hand', () => {
  const view = testdata('view_showdown.json');
  const m = modelFromView(view, 'k', bestFive);
  assert.equal(m.highlight.length, 5);
  for (const c of m.highlight) assert.ok([...view.board, ...view.seats[1].hole].includes(c));
  assert.deepEqual(m.winners, [{ seat: 1, amount: 4 }]);
  assert.equal(m.pot, 0);
  assert.deepEqual(m.seats.map((s) => s.bet), [0, 0]);

  const fold = fixtures.hands.find((h) => !h.final.result.showdown);
  const d = new Director({ bestFive, maxQueue: 1e9 });
  d.update(null);
  for (const f of framesOf(fold, 0)) d.update(f);
  assert.ok(!d.queue.some((q) => q.beat.type === 'reveal'));
  const award = d.queue.find((q) => q.beat.type === 'award').beat;
  assert.equal(award.showdown, false);
  assert.deepEqual(award.highlight, []);
});

test('start stacks are read back from any view of the hand', () => {
  for (const hand of fixtures.hands.slice(0, 40)) {
    const want = hand.cfg.seats.map((s) => s.stack);
    for (const f of framesOf(hand, 0)) assert.deepEqual(startStacks(f.view), want);
  }
});

test('a refund comes out of the bet first, then the middle', () => {
  const m = emptyModel();
  m.seats[0] = { ...m.seats[0], stack: 10, bet: 3, cards: [1, 2] };
  m.pot = 20;
  const a = applyBeat(m, { type: 'refund', seat: 0, amount: 5 });
  assert.equal(a.seats[0].bet, 0);
  assert.equal(a.pot, 18);
  assert.equal(a.seats[0].stack, 15);
});

test('clearing the table queues one clear beat and an empty target', () => {
  const d = new Director({ bestFive });
  d.update(null);
  d.update(framesOf(fixtures.hands[0], 0)[0]);
  drain(d);
  d.reconcile();
  assert.equal(d.update(null), 'queued');
  assert.equal(d.next().beat.type, 'clear');
  assert.equal(d.update(null), 'none');
});

test('a backlog is flagged past maxQueue', () => {
  const d = new Director({ bestFive, maxQueue: 3 });
  d.update(null);
  const frames = framesOf(fixtures.hands[5], 0);
  d.update(frames[frames.length - 1]);
  assert.ok(d.backlogged);
});

test('a live engine hand (fresh from poker.js) also lands', () => {
  let h = newHand({
    seats: [{ name: 'A', stack: 40 }, { name: 'B', stack: 40 }],
    button: 1, sb: 1, bb: 2, seedHex: 'c'.repeat(64), limit: true,
  });
  const d = new Director({ bestFive });
  d.update(null);
  const actions = ['call', 'check', 'check', 'check', 'check', 'check', 'check', 'check'];
  for (let i = 0; i < 20 && h.phase === 'act'; i++) {
    d.update({ handKey: 'live', view: seatView(h, 1), log: h.log });
    drain(d);
    assert.deepEqual(diffModels(d.model, d.target), []);
    d.reconcile();
    const want = actions[i] || 'check';
    const seat = h.toAct;
    const call = h.currentBet - h.seats[seat].streetCommit;
    h = act(h, { seat, action: call > 0 && want === 'check' ? 'call' : call === 0 && want === 'call' ? 'check' : want });
  }
  d.update({ handKey: 'live', view: seatView(h, 1), log: h.log });
  drain(d);
  assert.deepEqual(diffModels(d.model, d.target), []);
});

// ── choreography plans ──────────────────────────────────────────────────────

test('every beat in the recorded hands has a plan, and reduced motion is short and arc-free', () => {
  const d = new Director({ bestFive, maxQueue: 1e9 });
  d.update(null);
  const kinds = new Set();
  for (const hand of fixtures.hands.slice(0, 60)) {
    for (const f of framesOf(hand, 1)) {
      d.update(f);
      for (let it = d.next(); it; it = d.next()) {
        kinds.add(it.beat.type);
        const full = planBeat(it, { reducedMotion: false });
        const calm = planBeat(it, { reducedMotion: true });
        assert.ok(full.duration >= 0 && Number.isFinite(full.duration), it.beat.type);
        assert.ok(calm.duration <= durations.reduced.max, `${it.beat.type} reduced ${calm.duration}`);
        assert.ok(calm.moves.every((mv) => !mv.arc), `${it.beat.type} arcs under reduced motion`);
        for (const mv of full.moves) assert.ok(mv.delay >= 0 && mv.duration >= 0);
      }
      d.reconcile();
    }
  }
  for (const k of ['reset', 'post', 'deal', 'call', 'check', 'street', 'award']) assert.ok(kinds.has(k), k);
});

test('a deal plan flies each card from the deck, hero cards turning face up', () => {
  const d = new Director({ bestFive });
  d.update(null);
  d.update(framesOf(fixtures.hands[0], 0)[0]);
  let item;
  while ((item = d.next()) && item.beat.type !== 'deal');
  const plan = planBeat(item, { reducedMotion: false });
  const cards = plan.moves.filter((m) => m.kind === 'card');
  assert.equal(cards.length, 4);
  assert.ok(cards.every((m) => m.from && m.from.x === LAYOUT.deck.x && m.arc));
  const hero = cards.filter((m) => m.id.startsWith('s0'));
  assert.ok(hero.every((m) => m.faceUp));
  const villain = cards.filter((m) => m.id.startsWith('s1'));
  assert.ok(villain.every((m) => !m.faceUp));
  // staggered, in dealing order
  const delays = cards.map((m) => m.delay);
  assert.deepEqual([...delays].sort((a, b) => a - b), delays);
});

// ── timeline ────────────────────────────────────────────────────────────────

test('the timeline runs tweens in order, finishes a backlog at once, and eases within bounds', () => {
  const tl = new Timeline();
  const log = [];
  tl.add({ delay: 0, duration: 100, update: (k) => log.push(['a', k]), done: () => log.push(['a', 'done']) });
  tl.add({ delay: 50, duration: 0, start: () => log.push(['b', 'start']), done: () => log.push(['b', 'done']) });
  tl.tick(40);
  assert.ok(!log.some(([n]) => n === 'b'));
  tl.tick(20);
  assert.ok(log.some(([n, v]) => n === 'b' && v === 'done'));
  assert.ok(tl.active);
  tl.tick(100);
  assert.ok(!tl.active);
  assert.deepEqual(log.filter(([, v]) => v === 'done').map(([n]) => n), ['b', 'a']);

  const t2 = new Timeline();
  let last = 0;
  let chained = false;
  t2.add({ duration: 1000, update: (k) => (last = k), done: () => t2.add({ duration: 5, done: () => (chained = true) }) });
  t2.finish();
  assert.equal(last, 1);
  assert.ok(chained, 'a tween scheduled from done() is finished too');
  assert.ok(!t2.active);

  for (const group of Object.values(Easing)) {
    for (const [name, f] of Object.entries(group)) {
      assert.ok(Math.abs(f(0)) < 1e-9, name);
      assert.ok(Math.abs(f(1) - 1) < 1e-9, name);
    }
  }
  const p = arc({ x: 0, y: 0, z: 0 }, { x: 1, y: 0, z: 0 }, 0.1, 0.5);
  assert.ok(Math.abs(p.y - 0.1) < 1e-9 && Math.abs(p.x - 0.5) < 1e-9);
});

// ── chips ───────────────────────────────────────────────────────────────────

test('chip breakdowns cover the amount, stay within their caps, and fill out small stacks', () => {
  for (const sb of [1, 5, 50, 1000]) {
    for (const amount of [1, 2, 3, 7, 99, 200, 1234, 20000, 987654]) {
      for (const kind of ['stack', 'bet', 'pot', 'flight']) {
        const parts = breakdown(amount, sb, kind);
        const count = parts.reduce((a, p) => a + p.count, 0);
        assert.ok(count > 0);
        assert.ok(count <= { stack: 60, bet: 24, pot: 48, flight: 24 }[kind]);
        assert.ok(parts.every((p) => p.denom >= minDenomIndex(sb)));
        const shown = shownValue(parts);
        if (count < { stack: 60, bet: 24, pot: 48, flight: 24 }[kind]) {
          assert.ok(shown >= amount && shown - amount < DENOMS[minDenomIndex(sb)].value, `${amount}@${sb} → ${shown}`);
        }
      }
    }
  }
  assert.deepEqual(breakdown(0, 1), []);
  // 200 at 1/2 is a stack, not two black chips
  const stack = breakdown(200, 1, 'stack');
  assert.ok(stack.reduce((a, p) => a + p.count, 0) >= 10);
  const layout = pileLayout(stack, 0.02);
  assert.equal(layout.length, stack.reduce((a, p) => a + p.count, 0));
  assert.ok(layout.every((c) => c.level < COLUMN_MAX && c.jitter >= 0 && c.jitter < 1));
});

// ── card atlas ──────────────────────────────────────────────────────────────

test('the card atlas never evicts a card in use, and its rects stay inside the texture', () => {
  const slots = new AtlasSlots();
  for (const hand of fixtures.hands) {
    const inUse = [...hand.final.seats.flatMap((s) => s.hole), ...hand.final.board];
    slots.retain(inUse);
    for (const c of inUse) slots.slotFor(c);
    const got = inUse.map((c) => slots.peek(c));
    assert.ok(got.every((s) => s != null && s >= 1 && s < ATLAS.slots));
    assert.equal(new Set(got).size, new Set(inUse).size, 'two cards share a slot');
  }
  const a = new AtlasSlots();
  const first = a.slotFor(12);
  assert.ok(first.fresh);
  assert.ok(!a.slotFor(12).fresh);
  for (let s = 0; s < ATLAS.slots; s++) {
    const [u, v, du, dv] = a.uvRect(s);
    assert.ok(u >= 0 && v >= 0 && u + du <= 1 && v + dv <= 1);
  }
  assert.deepEqual(cardParts(12), { rank: 'A', suit: 0, court: null });
  assert.deepEqual(cardParts(51), { rank: 'A', suit: 3, court: null });
  assert.deepEqual(cardParts(13 * 2 + 11), { rank: 'K', suit: 2, court: 'king' });
  assert.deepEqual(cardParts(8), { rank: '10', suit: 0, court: null });
  for (let r = 0; r <= 8; r++) assert.equal(pipLayout(r).length, r + 2, `pips for rank ${r}`);
});

test('every face and the back draw on a recording canvas without throwing', () => {
  const calls = [];
  const ctx = new Proxy(
    {},
    {
      get(target, prop) {
        if (prop in target) return target[prop];
        if (prop === 'measureText') return () => ({ width: 10 });
        return (...args) => calls.push(prop);
      },
      set(target, prop, value) {
        target[prop] = value;
        return true;
      },
    },
  );
  for (let c = 0; c < 52; c++) drawFace(ctx, 0, 0, 400, 560, c, { fourColour: c % 2 === 0 });
  drawBack(ctx, 0, 0, 400, 560, { colour: '#7a1d2e', accent: '#d9b46a' });
  assert.ok(calls.includes('fill') && calls.includes('fillText'));
});

// ── picking ─────────────────────────────────────────────────────────────────

test('felt picking finds the hero cards, the pot, the stack and the far seat', () => {
  const m = emptyModel();
  m.seats[0] = { ...m.seats[0], stack: 100, cards: [1, 2] };
  m.seats[1] = { ...m.seats[1], stack: 100, cards: [null, null] };
  m.pot = 10;
  const near = LAYOUT.near;
  assert.deepEqual(pickOnFelt(near.hole[0], m), { type: 'pick', target: 'heroCards', seat: 0 });
  assert.deepEqual(pickOnFelt(LAYOUT.pot, m), { type: 'pick', target: 'pot', seat: null });
  assert.deepEqual(pickOnFelt(near.stack, m), { type: 'pick', target: 'stack', seat: 0 });
  assert.deepEqual(pickOnFelt(LAYOUT.far.hole[0], m), { type: 'pick', target: 'seat', seat: 1 });
  assert.equal(pickOnFelt({ x: 0.7, z: 0.4 }, m), null);
  m.pot = 0;
  assert.equal(pickOnFelt(LAYOUT.pot, m), null);
  assert.ok(CARD.w > 0.06);
});

test('beatsFor ignores entries it does not draw', () => {
  assert.deepEqual(beatsFor({ ev: 'nonsense' }, emptyModel(), testdata('view_new.json')), []);
});

// ── quality ─────────────────────────────────────────────────────────────────

test('the pixel ratio drops on slow windows, never below 1, and recovers slowly', () => {
  assert.equal(dprCap(3), 2);
  assert.equal(dprCap(3, { coarsePointer: true }), 1.5);
  assert.equal(dprCap(0.5), 1);
  assert.equal(dprCap(3, { maxDpr: 1.25 }), 1.25);
  assert.equal(startTier('auto', {}), 'high');
  assert.equal(startTier('auto', { coarsePointer: true }), 'low');
  assert.equal(startTier('auto', { cores: 4 }), 'low');
  assert.equal(startTier('low', {}), 'low');

  const a = new AdaptiveDpr({ max: 2 });
  const slow = () => {
    let r = null;
    for (let i = 0; i < 60; i++) r = a.sample(30) ?? r;
    return r;
  };
  assert.equal(slow(), 1.75);
  for (let i = 0; i < 10; i++) slow();
  assert.equal(a.current, 1);
  assert.equal(a.sample(500), null, 'an idle gap is not a slow frame');
  const fast = () => {
    for (let i = 0; i < 60; i++) a.sample(8);
  };
  fast();
  fast();
  assert.equal(a.current, 1, 'two good windows are not enough');
  fast();
  assert.equal(a.current, 1.25);
});
