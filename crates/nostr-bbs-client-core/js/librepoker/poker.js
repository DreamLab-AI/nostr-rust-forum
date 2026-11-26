// poker.js — the pure engine of The Wardroom. No DOM, no clock, no network.
// A complete no-limit Texas hold'em hand + tournament state machine, driven
// entirely by serializable action messages ({seat, action, amount}) so that
// bots today and remote humans tomorrow are the same kind of player.
//
// The two places amateur engines go wrong are done by the book here:
//  - min-raise rules, including the under-raise all-in that does NOT reopen
//    the betting for players who already acted;
//  - side pots, built from capped commitments, with the uncalled tail of a
//    bet refunded before any pot is cut.

// ---------------------------------------------------------------- cards

export const RANKS = '23456789TJQKA';
export const SUITS = '♣♦♥♠';
export const rankOf = (c) => c % 13;          // 0=deuce … 12=ace
export const suitOf = (c) => (c / 13) | 0;
export const cardName = (c) => RANKS[rankOf(c)] + SUITS[suitOf(c)];

// The five cards a hand actually plays: argmax of evaluate() over all
// C(n,5) subsets. Ties resolve to the first maximal subset, which is
// deterministic for a given input order. Exists so showdowns can light
// the winning five and transcripts can carry them.
export function bestFive(cards) {
  if (cards.length <= 5) return [...cards];
  let best = null, bestScore = -1;
  const n = cards.length;
  for (let a = 0; a < n - 4; a++)
    for (let b = a + 1; b < n - 3; b++)
      for (let c = b + 1; c < n - 2; c++)
        for (let d = c + 1; d < n - 1; d++)
          for (let e = d + 1; e < n; e++) {
            const five = [cards[a], cards[b], cards[c], cards[d], cards[e]];
            const sc = evaluate(five).score;
            if (sc > bestScore) { bestScore = sc; best = five; }
          }
  return best;
}

// xorshift128 seeded from a 64-hex string — the fleet's shuffle.
export function rngFromSeed(seedHex) {
  if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new Error('seed must be 64 hex chars');
  let a = parseInt(seedHex.slice(0, 8), 16) >>> 0;
  let b = parseInt(seedHex.slice(8, 16), 16) >>> 0;
  let c = parseInt(seedHex.slice(16, 24), 16) >>> 0;
  let d = parseInt(seedHex.slice(24, 32), 16) >>> 0;
  if (!(a | b | c | d)) a = 0x9e3779b9;
  return function () {
    const t = a ^ (a << 11);
    a = b; b = c; c = d;
    d = (d ^ (d >>> 19)) ^ (t ^ (t >>> 8));
    return (d >>> 0) / 4294967296;
  };
}
export function shuffledDeck(seedHex) {
  const rng = rngFromSeed(seedHex);
  const deck = Array.from({ length: 52 }, (_, i) => i);
  for (let i = 51; i > 0; i--) {
    const j = (rng() * (i + 1)) | 0;
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
  return deck;
}

// ---------------------------------------------------------------- evaluator

export const CAT_NAMES = ['high card', 'a pair', 'two pair', 'three of a kind',
  'a straight', 'a flush', 'a full house', 'four of a kind', 'a straight flush'];

// Best 5 of 7. Returns {cat, kick: number[], score} — scores compare as
// integers, higher wins. kick is category-specific tiebreak ranks, high→low.
export function evaluate(cards) {
  const byRank = new Array(13).fill(0);
  const bySuit = [[], [], [], []];
  for (const c of cards) { byRank[rankOf(c)]++; bySuit[suitOf(c)].push(rankOf(c)); }

  const straightHigh = (ranksSet) => {
    // returns high rank of best straight in the set, or -1 (wheel = high 3)
    let run = 0;
    for (let r = 12; r >= 0; r--) {
      run = ranksSet[r] ? run + 1 : 0;
      if (run === 5) return r + 4;
    }
    // wheel: A,2,3,4,5
    if (ranksSet[12] && ranksSet[0] && ranksSet[1] && ranksSet[2] && ranksSet[3]) return 3;
    return -1;
  };

  // straight flush
  for (let s = 0; s < 4; s++) {
    if (bySuit[s].length >= 5) {
      const set = new Array(13).fill(0);
      for (const r of bySuit[s]) set[r] = 1;
      const hi = straightHigh(set);
      if (hi >= 0) return score(8, [hi]);
    }
  }
  const groups = [];                       // [count, rank] sorted desc
  for (let r = 12; r >= 0; r--) if (byRank[r]) groups.push([byRank[r], r]);
  groups.sort((x, y) => y[0] - x[0] || y[1] - x[1]);

  if (groups[0][0] === 4) {
    const kicker = groups.filter((g) => g[1] !== groups[0][1]).map((g) => g[1]).sort((x, y) => y - x)[0];
    return score(7, [groups[0][1], kicker]);
  }
  if (groups[0][0] === 3 && groups[1] && groups[1][0] >= 2) {
    return score(6, [groups[0][1], groups[1][1]]);
  }
  for (let s = 0; s < 4; s++) {
    if (bySuit[s].length >= 5) {
      const top5 = [...bySuit[s]].sort((x, y) => y - x).slice(0, 5);
      return score(5, top5);
    }
  }
  {
    const set = byRank.map((n) => (n ? 1 : 0));
    const hi = straightHigh(set);
    if (hi >= 0) return score(4, [hi]);
  }
  if (groups[0][0] === 3) {
    const kickers = groups.slice(1).map((g) => g[1]).sort((x, y) => y - x).slice(0, 2);
    return score(3, [groups[0][1], ...kickers]);
  }
  if (groups[0][0] === 2 && groups[1] && groups[1][0] === 2) {
    const pairs = groups.filter((g) => g[0] === 2).map((g) => g[1]).sort((x, y) => y - x);
    const kicker = groups.filter((g) => g[0] === 1).map((g) => g[1]).sort((x, y) => y - x)[0];
    return score(2, [pairs[0], pairs[1], kicker]);
  }
  if (groups[0][0] === 2) {
    const kickers = groups.slice(1).map((g) => g[1]).sort((x, y) => y - x).slice(0, 3);
    return score(1, [groups[0][1], ...kickers]);
  }
  return score(0, groups.map((g) => g[1]).slice(0, 5));

  function score(cat, kick) {
    let s = cat;
    const k = [...kick];
    while (k.length < 5) k.push(0);
    for (const r of k) s = s * 16 + r;
    return { cat, kick, score: s };
  }
}

// A speakable name: "two pair, kings and nines", "a flush, ace high" …
const RANK_WORDS = ['deuce', 'three', 'four', 'five', 'six', 'seven', 'eight',
  'nine', 'ten', 'jack', 'queen', 'king', 'ace'];
const plural = (r) => (r === 4 ? 'sixes' : RANK_WORDS[r] + 's');
export function handName(ev) {
  const k = ev.kick;
  switch (ev.cat) {
    case 8: return k[0] === 12 ? 'a royal flush' : `a straight flush, ${RANK_WORDS[k[0]]} high`;
    case 7: return `four ${plural(k[0])}`;
    case 6: return `a full house, ${plural(k[0])} over ${plural(k[1])}`;
    case 5: return `a flush, ${RANK_WORDS[k[0]]} high`;
    case 4: return `a straight, ${RANK_WORDS[k[0]]} high`;
    case 3: return `three ${plural(k[0])}`;
    case 2: return `two pair, ${plural(k[0])} and ${plural(k[1])}`;
    case 1: return `a pair of ${plural(k[0])}`;
    default: return `${RANK_WORDS[k[0]]} high`;
  }
}

// ---------------------------------------------------------------- the hand

export const STREETS = ['preflop', 'flop', 'turn', 'river'];

// seats: [{stack, name}] — stack 0 seats are out and skipped.
// Returns a hand state h. Drive with legal(h) + act(h, {seat, action, amount}).
// limit: true = fixed-limit — bets come in fixed units (bb on preflop/flop,
// 2×bb on turn/river) with a 4-bet cap per street (the big blind counts as
// the first bet preflop, per the standard convention).
export function newHand({ seats, button, sb, bb, ante = 0, seedHex, limit = false }) {
  const deck = shuffledDeck(seedHex);
  const n = seats.length;
  const h = {
    n, button, sb, bb, ante, seedHex,
    deck, deckPos: 0,
    board: [],
    street: 0,
    seats: seats.map((s) => ({
      name: s.name, startStack: s.stack, stack: s.stack,
      hole: null, folded: false, allIn: false, out: s.stack <= 0,
      streetCommit: 0, handCommit: 0, canRaise: true, acted: false,
    })),
    currentBet: 0, minRaiseSize: bb,
    limit: !!limit, limitCap: 4, streetRaises: limit ? 1 : 0,
    toAct: -1, phase: 'act',      // act | done
    log: [], result: null,
  };
  const live = order(h, button + 1).filter((i) => !h.seats[i].out);
  if (live.length < 2) throw new Error('need two players');

  // antes
  for (const i of live) if (ante > 0) commit(h, i, Math.min(ante, h.seats[i].stack), 'ante');
  // blinds — heads-up: the button posts the small blind
  const headsUp = live.length === 2;
  const sbSeat = headsUp ? button : live[0];
  const bbSeat = headsUp ? live.find((i) => i !== button) : live[1];
  commit(h, sbSeat, Math.min(sb, h.seats[sbSeat].stack), 'sb');
  commit(h, bbSeat, Math.min(bb, h.seats[bbSeat].stack), 'bb');
  h.currentBet = Math.max(...h.seats.map((s) => s.streetCommit));
  h.minRaiseSize = bb;

  // deal hole cards, starting left of the button
  for (let round = 0; round < 2; round++) {
    for (const i of order(h, button + 1)) {
      if (h.seats[i].out) continue;
      (h.seats[i].hole = h.seats[i].hole || []).push(h.deck[h.deckPos++]);
    }
  }
  // first to act preflop: left of BB (heads-up: the button)
  h.toAct = headsUp ? sbSeat : nextActor(h, bbSeat + 1);
  h.headsUp = headsUp; h.sbSeat = sbSeat; h.bbSeat = bbSeat;
  h.log.push({ ev: 'deal', sb: sbSeat, bb: bbSeat });
  maybeAutoFinish(h);
  return h;
}

function order(h, from) {
  const out = [];
  for (let k = 0; k < h.n; k++) out.push(((from + k) % h.n + h.n) % h.n);
  return out;
}
function commit(h, i, amount, why) {
  const s = h.seats[i];
  const put = Math.min(amount, s.stack);
  s.stack -= put; s.streetCommit += put; s.handCommit += put;
  if (s.stack === 0) s.allIn = true;
  if (why) h.log.push({ ev: why, seat: i, amount: put });
  return put;
}
const inHand = (h, i) => !h.seats[i].out && !h.seats[i].folded;
const canAct = (h, i) => inHand(h, i) && !h.seats[i].allIn;
function nextActor(h, from) {
  for (const i of order(h, from)) if (canAct(h, i)) return i;
  return -1;
}
function liveSeats(h) { return h.seats.map((_, i) => i).filter((i) => inHand(h, i)); }

// The legal envelope for the seat to act. In fixed-limit the raise amount is
// a single fixed number (minRaiseTo === maxRaiseTo) and the street caps out.
export function legal(h) {
  if (h.phase !== 'act') return null;
  const i = h.toAct, s = h.seats[i];
  const callAmt = Math.min(h.currentBet - s.streetCommit, s.stack);
  const acts = ['fold'];
  if (callAmt === 0) acts.push('check'); else acts.push('call');
  let maxTo = s.streetCommit + s.stack;
  let minTo = h.currentBet + h.minRaiseSize;
  let mayRaise = maxTo > h.currentBet && s.canRaise;
  if (h.limit) {
    const betSize = h.street <= 1 ? h.bb : h.bb * 2;
    if (h.streetRaises >= h.limitCap) mayRaise = false;
    minTo = Math.min(h.currentBet + betSize, s.streetCommit + s.stack);
    maxTo = mayRaise ? minTo : s.streetCommit + s.stack;
  }
  if (mayRaise) {
    acts.push(h.currentBet === 0 ? 'bet' : 'raise');
    if (minTo > maxTo) minTo = maxTo;    // all-in for less than a min-raise
  }
  return { seat: i, actions: acts, callAmount: callAmt, minRaiseTo: minTo, maxRaiseTo: maxTo, currentBet: h.currentBet };
}

export function act(h, { seat, action, amount }) {
  if (h.phase !== 'act') throw new Error('hand is over');
  if (seat !== h.toAct) throw new Error(`not seat ${seat}'s turn`);
  const L = legal(h), s = h.seats[seat];
  if (!L.actions.includes(action)) throw new Error(`illegal ${action} (legal: ${L.actions})`);

  if (action === 'fold') {
    s.folded = true;
    h.log.push({ ev: 'fold', seat });
  } else if (action === 'check') {
    h.log.push({ ev: 'check', seat });
  } else if (action === 'call') {
    commit(h, seat, L.callAmount);
    h.log.push({ ev: 'call', seat, amount: L.callAmount });
  } else { // bet / raise to `amount`
    if (typeof amount !== 'number' || amount < L.minRaiseTo || amount > L.maxRaiseTo) {
      throw new Error(`raise to ${amount} outside [${L.minRaiseTo}, ${L.maxRaiseTo}]`);
    }
    const raiseSize = amount - h.currentBet;
    const fullRaise = raiseSize >= h.minRaiseSize;
    h.streetRaises++;
    commit(h, seat, amount - s.streetCommit);
    h.log.push({ ev: h.currentBet === 0 ? 'bet' : 'raise', seat, to: amount });
    h.currentBet = amount;
    if (fullRaise) {
      h.minRaiseSize = raiseSize;
      for (let k = 0; k < h.n; k++) if (k !== seat) { h.seats[k].canRaise = true; h.seats[k].acted = false; }
    } else {
      // under-raise all-in: players who already acted may call but not re-raise
      for (let k = 0; k < h.n; k++) if (k !== seat && h.seats[k].acted) h.seats[k].canRaise = false;
    }
  }
  s.acted = true;
  advance(h);
  return h;
}

function advance(h) {
  const live = liveSeats(h);
  if (live.length === 1) return finish(h);
  const actors = live.filter((i) => canAct(h, i));
  const settled = actors.every((i) => h.seats[i].acted && h.seats[i].streetCommit === h.currentBet);
  if (!settled) {
    h.toAct = nextActor(h, h.toAct + 1);
    if (h.toAct === -1) return runOut(h);
    return;
  }
  if (actors.length <= 1) return runOut(h);
  if (h.street === 3) return finish(h);
  nextStreet(h);
}

function nextStreet(h) {
  h.street++;
  for (const s of h.seats) { s.streetCommit = 0; s.acted = false; s.canRaise = true; }
  h.currentBet = 0; h.minRaiseSize = h.bb;
  h.streetRaises = 0;
  if (h.street === 1) h.board.push(h.deck[h.deckPos++], h.deck[h.deckPos++], h.deck[h.deckPos++]);
  else h.board.push(h.deck[h.deckPos++]);
  h.log.push({ ev: 'street', street: STREETS[h.street], board: [...h.board] });
  // postflop first actor: left of the button (heads-up: the non-button)
  h.toAct = nextActor(h, h.button + 1);
  if (h.toAct === -1) return runOut(h);
  if (h.headsUp) {                       // HU postflop: BB (non-button) first
    const nb = liveSeats(h).find((i) => i !== h.button);
    if (nb !== undefined && canAct(h, nb)) h.toAct = nb;
  }
}

function maybeAutoFinish(h) {
  // blinds may have put everyone all-in before any action
  const actors = liveSeats(h).filter((i) => canAct(h, i));
  if (actors.length === 0) runOut(h);
  else if (actors.length === 1 && h.seats[actors[0]].streetCommit >= h.currentBet
           && liveSeats(h).length > 1 && liveSeats(h).every((i) => i === actors[0] || h.seats[i].allIn)
           && h.seats[actors[0]].streetCommit === h.currentBet) {
    // everyone else all-in for exactly the blind — still give the actor a turn
  }
}

function runOut(h) {
  while (h.street < 3) {
    h.street++;
    if (h.street === 1) h.board.push(h.deck[h.deckPos++], h.deck[h.deckPos++], h.deck[h.deckPos++]);
    else h.board.push(h.deck[h.deckPos++]);
  }
  h.log.push({ ev: 'runout', board: [...h.board] });
  finish(h);
}

function finish(h) {
  h.phase = 'done'; h.toAct = -1;
  const live = liveSeats(h);

  // refund the uncalled tail of the highest commitment (to a live seat only;
  // a folded seat's chips are dead money and flow into the pots below)
  const commits = h.seats.map((s) => s.handCommit);
  const sorted = [...commits].sort((a, b) => b - a);
  if (sorted[0] > sorted[1]) {
    const top = commits.indexOf(sorted[0]);
    if (inHand(h, top)) {
      const refund = sorted[0] - sorted[1];
      h.seats[top].stack += refund; h.seats[top].handCommit -= refund;
      if (refund > 0) h.log.push({ ev: 'refund', seat: top, amount: refund });
    }
  }

  // fold-out: single live seat scoops without showdown
  if (live.length === 1) {
    const total = h.seats.reduce((a, s) => a + s.handCommit, 0);
    h.seats[live[0]].stack += total;
    h.result = {
      showdown: false,
      pots: [{ amount: total, contenders: live, winners: live }],
      winners: [{ seat: live[0], amount: total }],
    };
    h.log.push({ ev: 'win', seat: live[0], amount: total, showdown: false });
    return;
  }

  // side pots from capped commitments. Levels come from LIVE commitments
  // only; dead money above the top live level (a big folder) cannot be won
  // at a level nobody live reaches, so it joins the final pot.
  const levels = [...new Set(live.map((i) => h.seats[i].handCommit).filter((c) => c > 0))].sort((a, b) => a - b);
  const pots = [];
  let prev = 0, sliced = 0;
  for (const lv of levels) {
    let amount = 0;
    for (const s of h.seats) amount += Math.max(0, Math.min(s.handCommit, lv) - prev);
    const contenders = live.filter((i) => h.seats[i].handCommit >= lv);
    if (contenders.length && amount > 0) { pots.push({ amount, contenders }); sliced += amount; }
    prev = lv;
  }
  const leftover = h.seats.reduce((a, s) => a + s.handCommit, 0) - sliced;
  if (leftover > 0 && pots.length) pots[pots.length - 1].amount += leftover;
  // merge pots with identical contender sets (folded money layers)
  const merged = [];
  for (const p of pots) {
    const last = merged[merged.length - 1];
    if (last && last.contenders.join() === p.contenders.join()) last.amount += p.amount;
    else merged.push({ amount: p.amount, contenders: [...p.contenders] });
  }

  const evals = {};
  for (const i of live) evals[i] = evaluate([...h.seats[i].hole, ...h.board]);
  const winnersTotal = {};
  for (const p of merged) {
    const best = Math.max(...p.contenders.map((i) => evals[i].score));
    const winners = p.contenders.filter((i) => evals[i].score === best);
    p.winners = winners;
    const share = Math.floor(p.amount / winners.length);
    let remainder = p.amount - share * winners.length;
    // odd chips go first to the earliest winner left of the button
    const clockwise = order(h, h.button + 1).filter((i) => winners.includes(i));
    for (const i of clockwise) {
      const got = share + (remainder > 0 ? 1 : 0);
      if (remainder > 0) remainder--;
      h.seats[i].stack += got;
      winnersTotal[i] = (winnersTotal[i] || 0) + got;
    }
  }
  h.result = {
    showdown: true,
    pots: merged,
    evals: Object.fromEntries(live.map((i) => [i, { ...evals[i], name: handName(evals[i]) }])),
    winners: Object.entries(winnersTotal).map(([seat, amount]) => ({ seat: +seat, amount })),
  };
  h.log.push({ ev: 'showdown', winners: h.result.winners });
}

// What a given seat is allowed to see (the multiplayer seam).
export function seatView(h, seat) {
  return {
    seat, street: STREETS[h.street], board: [...h.board],
    phase: h.phase, toAct: h.toAct, currentBet: h.currentBet,
    minRaiseTo: h.phase === 'act' && h.toAct === seat ? legal(h).minRaiseTo : null,
    button: h.button, sb: h.sb, bb: h.bb,
    hole: h.seats[seat] ? h.seats[seat].hole : null,
    pot: h.seats.reduce((a, s) => a + s.handCommit, 0),
    seats: h.seats.map((s, i) => ({
      name: s.name, stack: s.stack, folded: s.folded, allIn: s.allIn, out: s.out,
      streetCommit: s.streetCommit, handCommit: s.handCommit,
      hole: i === seat || (h.phase === 'done' && h.result?.showdown && !s.folded && !s.out) ? s.hole : null,
    })),
    result: h.phase === 'done' ? h.result : null,
  };
}

// ---------------------------------------------------------------- tournament

// A 6-max sit & go. Levels climb every `handsPerLevel` hands.
export const LEVELS = [
  { sb: 10, bb: 20, ante: 0 }, { sb: 15, bb: 30, ante: 0 }, { sb: 25, bb: 50, ante: 0 },
  { sb: 50, bb: 100, ante: 0 }, { sb: 75, bb: 150, ante: 15 }, { sb: 100, bb: 200, ante: 20 },
  { sb: 150, bb: 300, ante: 30 }, { sb: 200, bb: 400, ante: 40 }, { sb: 300, bb: 600, ante: 60 },
  { sb: 400, bb: 800, ante: 80 }, { sb: 500, bb: 1000, ante: 100 }, { sb: 700, bb: 1400, ante: 140 },
  { sb: 1000, bb: 2000, ante: 200 }, { sb: 1500, bb: 3000, ante: 300 }, { sb: 2000, bb: 4000, ante: 400 },
];
export const START_STACK = 1500;   // ~75bb at 10/20 — a 15-20 minute arc, not a marathon

export function newTourney({ names, handsPerLevel = 8 }) {
  return {
    names, handsPerLevel,
    stacks: names.map(() => START_STACK),
    button: 0, handIndex: 0,
    eliminated: [],                 // seat indexes in bust order
    champion: null,
  };
}
export const levelOf = (t) => LEVELS[Math.min(((t.handIndex / t.handsPerLevel) | 0), LEVELS.length - 1)];
export const levelNum = (t) => Math.min(((t.handIndex / t.handsPerLevel) | 0), LEVELS.length - 1) + 1;

export function tourneyHand(t, seedHex) {
  const { sb, bb, ante } = levelOf(t);
  return newHand({
    seats: t.names.map((name, i) => ({ name, stack: t.stacks[i] })),
    button: t.button, sb, bb, ante, seedHex,
  });
}

// Fold the finished hand back into the tournament. Returns {busted:[…]}.
export function absorbHand(t, h) {
  if (h.phase !== 'done') throw new Error('hand not finished');
  const bustedNow = [];
  for (let i = 0; i < t.stacks.length; i++) {
    const was = t.stacks[i];
    t.stacks[i] = h.seats[i].stack;
    if (was > 0 && t.stacks[i] === 0) bustedNow.push(i);
  }
  // simultaneous busts rank by start-of-hand stack: bigger stack finishes higher
  bustedNow.sort((a, b) => h.seats[a].startStack - h.seats[b].startStack);
  t.eliminated.push(...bustedNow);
  t.handIndex++;
  const alive = t.stacks.map((s, i) => i).filter((i) => t.stacks[i] > 0);
  if (alive.length === 1) { t.champion = alive[0]; t.eliminated.push(alive[0]); }
  else {
    // button moves to the next live seat clockwise
    for (const i of orderFrom(t.button + 1, t.stacks.length)) {
      if (t.stacks[i] > 0) { t.button = i; break; }
    }
  }
  return { busted: bustedNow };
}
function orderFrom(from, n) {
  const out = [];
  for (let k = 0; k < n; k++) out.push(((from + k) % n + n) % n);
  return out;
}
// Finishing places, 1st…Nth (champion first), for the payout screen.
export function placings(t) {
  return [...t.eliminated].reverse();
}
