// bots.js — the table's characters. A bot sees only its seatView (the same
// envelope a remote human will get) plus the legal-action envelope, and
// returns a serializable action. Decisions are deterministic given the rng.
import { evaluate, rankOf, suitOf } from './poker.js';

// ---------------------------------------------------------------- profiles

export const PROFILES = {
  rock:    { vpip: 0.13, aggro: 0.45, bluff: 0.03, cap: 0.75 },
  tag:     { vpip: 0.21, aggro: 0.75, bluff: 0.09, cap: 0.95 },
  lag:     { vpip: 0.32, aggro: 0.85, bluff: 0.16, cap: 1.00 },
  station: { vpip: 0.44, aggro: 0.22, bluff: 0.02, cap: 0.60 },
  maniac:  { vpip: 0.55, aggro: 0.95, bluff: 0.24, cap: 1.00 },
};

// ---------------------------------------------------------------- preflop

// Chen formula, halved to 0..1-ish. AA=1.0 scale anchor (20 points).
export function chen(hole) {
  const r = hole.map(rankOf).sort((a, b) => b - a);
  const suited = suitOf(hole[0]) === suitOf(hole[1]);
  const pts = (rank) => (rank === 12 ? 10 : rank === 11 ? 8 : rank === 10 ? 7 : rank === 9 ? 6 : (rank + 2) / 2);
  let score;
  if (r[0] === r[1]) score = Math.max(5, pts(r[0]) * 2);
  else {
    score = pts(r[0]);
    if (suited) score += 2;
    const gap = r[0] - r[1] - 1;
    if (gap === 1) score -= 1; else if (gap === 2) score -= 2;
    else if (gap === 3) score -= 4; else if (gap >= 4) score -= 5;
    if (gap <= 1 && r[0] <= 9) score += 1;   // small connectors can straighten
  }
  return Math.max(0, score / 20);
}

// ---------------------------------------------------------------- equity

// Monte-Carlo equity vs `opps` unknown hands. Deterministic under rng.
export function equityMC(hole, board, opps, rng, rollouts = 60) {
  const seen = new Set([...hole, ...board]);
  const pool = [];
  for (let c = 0; c < 52; c++) if (!seen.has(c)) pool.push(c);
  let win = 0;
  for (let t = 0; t < rollouts; t++) {
    // partial Fisher-Yates over a copy
    const p = [...pool];
    for (let i = 0; i < opps * 2 + (5 - board.length); i++) {
      const j = i + ((rng() * (p.length - i)) | 0);
      [p[i], p[j]] = [p[j], p[i]];
    }
    let k = 0;
    const fullBoard = [...board];
    while (fullBoard.length < 5) fullBoard.push(p[k++]);
    const mine = evaluate([...hole, ...fullBoard]).score;
    let best = true, tie = 1;
    for (let o = 0; o < opps; o++) {
      const theirs = evaluate([p[k], p[k + 1], ...fullBoard]).score;
      k += 2;
      if (theirs > mine) { best = false; break; }
      if (theirs === mine) tie++;
    }
    if (best) win += 1 / tie;
  }
  return win / rollouts;
}

// ---------------------------------------------------------------- decision

// view: seatView(h, seat); L: legal(h). Returns {seat, action, amount?}.
export function decide(view, L, profileName, rng, opts = {}) {
  const raw = decideRaw(view, L, profileName, rng, opts);
  // legality net: whatever the strategy wanted, return something legal,
  // degrading gracefully (raise -> call -> check -> fold).
  if (L.actions.includes(raw.action)) return raw;
  const order = raw.action === 'fold' ? ['check', 'fold']
    : ['call', 'check', 'bet', 'raise', 'fold'];
  for (const a of order) {
    if (!L.actions.includes(a)) continue;
    if (a === 'bet' || a === 'raise') return { seat: view.seat, action: a, amount: L.minRaiseTo };
    return { seat: view.seat, action: a };
  }
  return { seat: view.seat, action: 'fold' };
}

function decideRaw(view, L, profileName, rng, opts = {}) {
  const P = PROFILES[profileName] || PROFILES.tag;
  const me = view.seats[view.seat];
  const hole = view.hole;
  const pot = view.pot;
  const call = L.callAmount;
  const bb = view.bb;
  const stackBB = me.stack / bb;
  const rollouts = opts.rollouts ?? 60;
  const opps = view.seats.filter((s, i) => i !== view.seat && !s.folded && !s.out).length;
  const potOdds = call > 0 ? call / (pot + call) : 0;
  const jitter = (x) => x * (0.92 + rng() * 0.16);

  const raiseTo = (frac) => {
    // bet ~frac of pot, clamped to the legal envelope, chip-rounded
    const target = Math.round((pot * frac + call + me.streetCommit) / bb) * bb;
    return Math.max(L.minRaiseTo, Math.min(L.maxRaiseTo, target));
  };

  // ---- preflop: chart poker + short-stack push/fold
  if (view.street === 'preflop') {
    const s = jitter(chen(hole));
    const openThreshold = 0.30 - P.vpip * 0.35;          // rock .25, station .15
    const facingRaise = view.currentBet > bb;
    if (stackBB <= 10) {                                  // push/fold regime
      const shoveAt = facingRaise ? 0.42 : 0.33 - P.vpip * 0.15;
      if (s >= shoveAt) return { seat: view.seat, action: L.actions.includes('raise') ? 'raise' : 'call', amount: L.maxRaiseTo };
      if (L.actions.includes('check')) return { seat: view.seat, action: 'check' };
      if (call <= bb && s >= 0.2) return { seat: view.seat, action: 'call' };
      return { seat: view.seat, action: 'fold' };
    }
    if (!facingRaise) {
      if (s >= openThreshold + 0.12 || (s >= openThreshold && rng() < P.aggro)) {
        if (L.actions.includes('raise') || L.actions.includes('bet')) {
          return { seat: view.seat, action: L.actions.includes('raise') ? 'raise' : 'bet', amount: raiseTo(1.0) };
        }
      }
      if (L.actions.includes('check')) return { seat: view.seat, action: 'check' };
      if (s >= openThreshold - 0.02 || call <= bb) {
        if (call / (pot + call) < s * 0.9) return { seat: view.seat, action: 'call' };
      }
      if (rng() < P.bluff && L.actions.includes('raise')) return { seat: view.seat, action: 'raise', amount: raiseTo(1.0) };
      return { seat: view.seat, action: 'fold' };
    }
    // facing a raise
    if (s >= 0.62 && (L.actions.includes('raise'))) return { seat: view.seat, action: 'raise', amount: raiseTo(1.2) };
    if (s >= 0.34 && potOdds < s * 0.8) return { seat: view.seat, action: 'call' };
    if (L.actions.includes('check')) return { seat: view.seat, action: 'check' };
    if (rng() < P.bluff * 0.5 && L.actions.includes('raise')) return { seat: view.seat, action: 'raise', amount: raiseTo(1.2) };
    return { seat: view.seat, action: 'fold' };
  }

  // ---- postflop: equity vs pot odds, coloured by personality
  const eq = jitter(equityMC(hole, view.board, opps, rng, rollouts));
  const strong = eq > 0.5 + 0.12 / Math.max(1, opps);
  const monster = eq > 0.78;

  if (call === 0) {
    if ((strong && rng() < P.aggro) || monster) {
      const frac = monster ? 0.85 : 0.6;
      if (L.actions.includes('bet') || L.actions.includes('raise')) {
        return { seat: view.seat, action: L.actions.includes('bet') ? 'bet' : 'raise', amount: raiseTo(frac) };
      }
    }
    if (rng() < P.bluff && (L.actions.includes('bet') || L.actions.includes('raise'))) {
      return { seat: view.seat, action: L.actions.includes('bet') ? 'bet' : 'raise', amount: raiseTo(0.55) };
    }
    return { seat: view.seat, action: 'check' };
  }
  // facing a bet
  const margin = 0.04 * (1 - P.vpip);                     // stations call thinner
  if (monster && L.actions.includes('raise') && rng() < P.aggro * P.cap) {
    return { seat: view.seat, action: 'raise', amount: raiseTo(1.0) };
  }
  if (eq > potOdds + margin) {
    if (strong && L.actions.includes('raise') && rng() < P.aggro * 0.4) {
      return { seat: view.seat, action: 'raise', amount: raiseTo(0.8) };
    }
    return { seat: view.seat, action: 'call' };
  }
  if (rng() < P.bluff * 0.35 && L.actions.includes('raise') && call < pot * 0.6) {
    return { seat: view.seat, action: 'raise', amount: raiseTo(0.9) };
  }
  return { seat: view.seat, action: 'fold' };
}

// The wardroom's six characters — names, styles, table colours.
export const ROSTER = [
  { name: 'Cmdr. Sterling', profile: 'rock',    emoji: '🎖', blurb: 'waits for the navy' },
  { name: 'First Mate Wren', profile: 'tag',    emoji: '🪶', blurb: 'tight, then ruthless' },
  { name: 'Gunner Halloway', profile: 'lag',    emoji: '💣', blurb: 'pressure from any two' },
  { name: 'Cook Barnacle',   profile: 'station',emoji: '🍲', blurb: 'never folds a stew' },
  { name: 'Ensign Puffin',   profile: 'maniac', emoji: '🐧', blurb: 'all sail, no anchor' },
];
