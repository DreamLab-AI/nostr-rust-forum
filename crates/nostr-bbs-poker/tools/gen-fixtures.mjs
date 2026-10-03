// gen-fixtures.mjs — differential fixtures for the Rust port of the Libre
// Poker engine (`nostr-bbs-poker::engine`, `::bots`).
//
// Drives the vendored JavaScript engine (the forum client's byte-for-byte
// copy, `crates/nostr-bbs-forum-client/js/librepoker/`) through random
// heads-up hands and records every intermediate state: the hand after the
// deal, the legal envelope before each action, the action taken, the hand
// after it, and both seat views. The hero's actions come from a separate
// seeded generator; the bot's come from `decide` under the per-step seed the
// table derives (`sha256("<seed>:bot:<step>")`), exactly as the citizen plays.
//
// The Rust tests replay the same inputs and require the same JSON. Regenerate
// after a vendored-engine update:
//
//   node crates/nostr-bbs-poker/tools/gen-fixtures.mjs > crates/nostr-bbs-poker/tests/fixtures/hands.json
//
// The output is deterministic (fixed master seed), so a diff of the fixture
// file is a diff of engine behaviour.

import { createHash } from 'node:crypto';
import { act, evaluate, handName, legal, newHand, rngFromSeed, seatView, bestFive }
  from '../../nostr-bbs-forum-client/js/librepoker/poker.js';
import { chen, decide, equityMC, PROFILES, ROSTER }
  from '../../nostr-bbs-forum-client/js/librepoker/bots.js';

const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
const MASTER = 'nostr-bbs-poker differential fixtures v1';
const master = rngFromSeed(sha256hex(MASTER));
const seedHex = () => {
  let out = '';
  for (let i = 0; i < 8; i++) out += ((master() * 0x100000000) >>> 0).toString(16).padStart(8, '0');
  return out;
};
const pick = (arr) => arr[(master() * arr.length) | 0];
const profiles = Object.keys(PROFILES);

const HANDS = 160;
const hands = [];
for (let n = 0; n < HANDS; n++) {
  const seed = seedHex();
  const limit = n % 4 !== 3;                       // three limit hands to one no-limit
  const bb = pick([2, 10, 20, 100, 200]);
  const sb = bb / 2;
  // short stacks exercise all-in, refunds and side pots
  const stackPick = pick(['even', 'short0', 'short1', 'tiny']);
  const stacks = stackPick === 'even' ? [bb * 100, bb * 100]
    : stackPick === 'short0' ? [bb * 3 + sb, bb * 100]
    : stackPick === 'short1' ? [bb * 100, bb * 2]
    : [bb, bb * 5];
  const button = n % 2;
  const profile = pick(profiles);
  const cfg = { seats: [{ name: 'You', stack: stacks[0] }, { name: 'Bot', stack: stacks[1] }], button, sb, bb, seedHex: seed, limit };
  let h = newHand(cfg);
  const steps = [];
  const dealt = JSON.parse(JSON.stringify(h));
  let guard = 0;
  while (h.phase === 'act' && guard++ < 200) {
    const L = legal(h);
    const before = JSON.parse(JSON.stringify(h));
    let action;
    if (h.toAct === 1) {
      const botSeed = sha256hex(`${seed}:bot:${h.log.length}`);
      action = decide(seatView(h, 1), L, profile, rngFromSeed(botSeed));
    } else {
      // the hero: a random legal action; raises to a random legal total
      const a = pick(L.actions);
      action = { seat: 0, action: a };
      if (a === 'bet' || a === 'raise') {
        const span = L.maxRaiseTo - L.minRaiseTo;
        action.amount = L.minRaiseTo + (span > 0 ? (master() * (span + 1)) | 0 : 0);
      }
    }
    h = act(h, action);
    steps.push({
      legal: L,
      action,
      after: JSON.parse(JSON.stringify(h)),
      view0: seatView(h, 0),
      view1: seatView(h, 1),
      // what the hero saw before acting, for the bot-decision check
      viewBefore: seatView(before, before.toAct),
    });
  }
  hands.push({ cfg, profile, dealt, steps, final: h, view0: seatView(h, 0), view1: seatView(h, 1) });
}

// evaluator spot checks: random 5..7 card sets, plus hand names and best five
const evals = [];
for (let i = 0; i < 400; i++) {
  const n = 5 + ((master() * 3) | 0);
  const deck = Array.from({ length: 52 }, (_, i) => i);
  for (let k = 51; k > 0; k--) { const j = (master() * (k + 1)) | 0; [deck[k], deck[j]] = [deck[j], deck[k]]; }
  const cards = deck.slice(0, n);
  const ev = evaluate(cards);
  evals.push({ cards, eval: ev, name: handName(ev), best: bestFive(cards) });
}

// bot primitives: chen and equityMC under a known rng
const chens = [];
for (let a = 0; a < 52; a++) for (let b = a + 1; b < 52; b++) if ((a * 52 + b) % 37 === 0) chens.push({ hole: [a, b], chen: chen([a, b]) });
const equities = [];
for (let i = 0; i < 40; i++) {
  const deck = Array.from({ length: 52 }, (_, i) => i);
  for (let k = 51; k > 0; k--) { const j = (master() * (k + 1)) | 0; [deck[k], deck[j]] = [deck[j], deck[k]]; }
  const boardLen = pick([0, 3, 4, 5]);
  const hole = deck.slice(0, 2), board = deck.slice(2, 2 + boardLen);
  const rngSeed = seedHex();
  equities.push({ hole, board, opps: 1, rngSeed, rollouts: 60, equity: equityMC(hole, board, 1, rngFromSeed(rngSeed), 60) });
}

// rng: the first 16 draws of a few seeds, and the all-zero seed fallback
const rngs = [];
for (const s of [seedHex(), seedHex(), '0'.repeat(64), 'ffffffff'.repeat(8)]) {
  const r = rngFromSeed(s);
  rngs.push({ seed: s, draws: Array.from({ length: 16 }, () => r()) });
}

process.stdout.write(JSON.stringify({ roster: ROSTER, profiles: PROFILES, hands, evals, chens, equities, rngs }));
