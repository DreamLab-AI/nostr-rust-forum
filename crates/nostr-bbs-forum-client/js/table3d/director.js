// director.js — from (view, log) frames to a queue of beats. Pure: no DOM,
// no three, no clock; node runs it in tools/table3d-test.mjs against the
// engine's recorded hands.
//
// The seat view is the truth. The log only says how the table got there, so
// the director replays the *new* log entries as beats — a deal, a bet, a
// street — each of which is a pure step from one table model to the next,
// and the choreography animates each step. When the queue drains the model
// must equal the one read straight from the view; if it does not (a frame was
// skipped, a log was cut), `reconcile` snaps to the view and counts the drift,
// which the tests require to stay at zero across every recorded hand.
//
// A frame is `{handKey, view, log}`: `view` is a SeatView as the engine
// serialises it (camelCase), `log` the hand's whole log so far, and `handKey`
// anything that changes from one hand to the next (the shuffle commitment).
// Two consecutive hands can have identical views, so the key is what tells
// them apart.

/** A seat with nothing in front of it. */
function emptySeat() {
  return { stack: 0, bet: 0, folded: false, allIn: false, out: false, cards: null, mucked: false };
}

/** The table before any hand: no cards, no chips, no button. */
export function emptyModel() {
  return {
    handKey: null,
    hero: 0,
    button: null,
    sb: 0,
    bb: 0,
    seats: [emptySeat(), emptySeat()],
    board: [],
    pot: 0,
    winners: null,
    showdown: false,
    highlight: [],
    toAct: -1,
    phase: 'idle',
  };
}

/** A deep copy: models are values, and every beat makes a new one. */
export function cloneModel(m) {
  return {
    ...m,
    seats: m.seats.map((s) => ({ ...s, cards: s.cards ? [...s.cards] : null })),
    board: [...m.board],
    winners: m.winners ? m.winners.map((w) => ({ ...w })) : null,
    highlight: [...m.highlight],
  };
}

const sum = (xs) => xs.reduce((a, b) => a + b, 0);

/**
 * The cards to light at a showdown: each winner's best five of hole + board.
 * `bestFive` is the engine's own (`librepoker/poker.js`), injected so this
 * file stays free of imports and testable with the same function.
 */
export function highlightFor(seats, board, winners, bestFive) {
  if (!bestFive || !winners) return [];
  const lit = new Set();
  for (const w of winners) {
    const hole = seats[w.seat] && seats[w.seat].cards;
    if (!hole || hole.some((c) => c == null)) continue;
    const all = [...hole, ...board];
    if (all.length < 5) continue;
    for (const c of bestFive(all)) lit.add(c);
  }
  return [...lit].sort((a, b) => a - b);
}

/**
 * The table a view describes, with no history: what a reconcile snaps to and
 * what a beat sequence must arrive at.
 *
 * While a hand is in play a seat's bet is its street commitment and the pot in
 * the middle is everything committed on earlier streets. Once it is over the
 * view's stacks already include what was won, so the bets and the middle are
 * empty. A folded seat's cards are in the muck: the hero's face known, an
 * opponent's never.
 */
export function modelFromView(view, handKey = null, bestFive = null) {
  if (!view) return emptyModel();
  const hero = view.seat | 0;
  const done = view.phase === 'done';
  const vs = view.seats || [];
  const seats = vs.map((s, i) => {
    let cards = null;
    if (!s.out) {
      if (i === hero) cards = view.hole ? [...view.hole] : [null, null];
      else cards = s.hole ? [...s.hole] : [null, null];
    }
    return {
      stack: s.stack,
      bet: done ? 0 : s.streetCommit,
      folded: !!s.folded,
      allIn: !!s.allIn,
      out: !!s.out,
      cards,
      mucked: !!s.folded && cards != null,
    };
  });
  while (seats.length < 2) seats.push(emptySeat());
  const result = done ? view.result || null : null;
  const winners = result ? result.winners.map((w) => ({ seat: w.seat, amount: w.amount })) : null;
  const showdown = !!(result && result.showdown);
  const board = [...(view.board || [])];
  return {
    handKey,
    hero,
    button: view.button,
    sb: view.sb,
    bb: view.bb,
    seats,
    board,
    pot: done ? 0 : Math.max(0, view.pot - sum(vs.map((s) => s.streetCommit))),
    winners,
    showdown,
    highlight: showdown ? highlightFor(seats, board, winners, bestFive) : [],
    toAct: view.toAct,
    phase: done ? 'done' : 'act',
  };
}

/**
 * Each seat's stack before the hand's first chip moved, read back from a view
 * at any point in the hand: stack + committed − won. The engine's refund
 * moves chips from the commitment back to the stack, so it leaves this sum
 * alone.
 */
export function startStacks(view) {
  const won = new Map();
  if (view.phase === 'done' && view.result) {
    for (const w of view.result.winners) won.set(w.seat, (won.get(w.seat) || 0) + w.amount);
  }
  return view.seats.map((s, i) => s.stack + s.handCommit - (won.get(i) || 0));
}

/**
 * The dealing order for a heads-up deal: one card each, twice, starting with
 * the seat after the button. Heads-up the button is the small blind, so the
 * big blind gets the first card. Returns `[[seat, cardIdx], …]`.
 */
export function dealOrder(button, nSeats = 2) {
  const order = [];
  for (let round = 0; round < 2; round++) {
    for (let k = 1; k <= nSeats; k++) order.push([(button + k) % nSeats, round]);
  }
  return order;
}

/** Sweep every seat's bet into the middle. */
function sweep(m) {
  for (const s of m.seats) {
    m.pot += s.bet;
    s.bet = 0;
  }
}

/** Move `amount` from a seat's stack to its bet, as the engine's commit does. */
function commit(m, seat, amount) {
  const s = m.seats[seat];
  if (!s) return;
  const put = Math.min(amount, s.stack);
  s.stack -= put;
  s.bet += put;
  if (s.stack === 0) s.allIn = true;
}

/**
 * Apply one beat to a model, returning the next model. Every beat type the
 * choreography knows is here; an unknown one is a no-op.
 */
export function applyBeat(model, beat) {
  const m = cloneModel(model);
  switch (beat.type) {
    case 'clear':
      return emptyModel();
    case 'reset': {
      const fresh = emptyModel();
      fresh.handKey = beat.handKey;
      fresh.hero = beat.hero;
      fresh.button = beat.button;
      fresh.sb = beat.sb;
      fresh.bb = beat.bb;
      fresh.seats = beat.stacks.map((stack, i) => ({
        ...emptySeat(),
        stack,
        out: !!(beat.out && beat.out[i]),
      }));
      fresh.phase = 'act';
      return fresh;
    }
    case 'post':
    case 'call':
      commit(m, beat.seat, beat.amount);
      return m;
    case 'bet':
    case 'raise': {
      const s = m.seats[beat.seat];
      if (s) commit(m, beat.seat, Math.max(0, beat.to - s.bet));
      return m;
    }
    case 'deal':
      for (const [seat, idx] of beat.order) {
        const s = m.seats[seat];
        if (!s || s.out) continue;
        if (!s.cards) s.cards = [null, null];
        s.cards[idx] = beat.holes[seat] ? beat.holes[seat][idx] ?? null : null;
      }
      return m;
    case 'fold': {
      const s = m.seats[beat.seat];
      if (s) {
        s.folded = true;
        s.mucked = s.cards != null;
      }
      return m;
    }
    case 'check':
      return m;
    case 'street':
    case 'runout':
      sweep(m);
      m.board = [...beat.board];
      return m;
    case 'refund': {
      const s = m.seats[beat.seat];
      if (!s) return m;
      const fromBet = Math.min(s.bet, beat.amount);
      s.bet -= fromBet;
      m.pot = Math.max(0, m.pot - (beat.amount - fromBet));
      s.stack += beat.amount;
      return m;
    }
    case 'reveal':
      for (const [seat, cards] of Object.entries(beat.cards)) {
        const s = m.seats[seat];
        if (s && cards) s.cards = [...cards];
      }
      return m;
    case 'award': {
      sweep(m);
      for (const w of beat.winners) {
        const s = m.seats[w.seat];
        if (s) s.stack += w.amount;
        m.pot -= w.amount;
      }
      m.pot = Math.max(0, m.pot);
      m.winners = beat.winners.map((w) => ({ ...w }));
      m.showdown = !!beat.showdown;
      m.highlight = [...(beat.highlight || [])];
      m.phase = 'done';
      m.toAct = -1;
      return m;
    }
    default:
      return m;
  }
}

/**
 * The beats one log entry becomes. `model` is the table before the entry and
 * `view` the newest view of the same hand, which supplies what the log does
 * not carry: the hero's hole cards for a deal, the shown hands at showdown.
 */
export function beatsFor(entry, model, view, bestFive = null) {
  const seat = entry.seat;
  switch (entry.ev) {
    case 'ante':
    case 'sb':
    case 'bb':
      return [{ type: 'post', seat, amount: entry.amount || 0, blind: entry.ev }];
    case 'deal': {
      const holes = model.seats.map((s, i) => (i === view.seat && view.hole ? [...view.hole] : null));
      return [{ type: 'deal', order: dealOrder(model.button ?? view.button, model.seats.length), holes }];
    }
    case 'fold':
      return [{ type: 'fold', seat }];
    case 'check':
      return [{ type: 'check', seat }];
    case 'call':
      return [{ type: 'call', seat, amount: entry.amount || 0 }];
    case 'bet':
    case 'raise':
      return [{ type: entry.ev, seat, to: entry.to || 0 }];
    case 'street':
      return [{ type: 'street', street: entry.street, board: [...(entry.board || [])], from: model.board.length }];
    case 'runout': {
      // All-in: show both hands before the remaining cards come, as a dealer
      // would, so the run-out is watched with both hands face up.
      const beats = [];
      const reveal = revealFrom(model, view);
      if (reveal) beats.push(reveal);
      beats.push({ type: 'runout', board: [...(entry.board || [])], from: model.board.length });
      return beats;
    }
    case 'refund':
      return [{ type: 'refund', seat, amount: entry.amount || 0 }];
    case 'showdown': {
      const beats = [];
      const reveal = revealFrom(model, view);
      if (reveal) beats.push(reveal);
      const after = reveal ? applyBeat(model, reveal) : model;
      const winners = (entry.winners || []).map((w) => ({ seat: w.seat, amount: w.amount }));
      beats.push({
        type: 'award',
        winners,
        showdown: true,
        highlight: highlightFor(after.seats, after.board, winners, bestFive),
      });
      return beats;
    }
    case 'win':
      return [
        {
          type: 'award',
          winners: [{ seat, amount: entry.amount || 0 }],
          showdown: false,
          highlight: [],
        },
      ];
    default:
      return [];
  }
}

/**
 * A reveal beat for every live opponent whose cards the view now shows and
 * the model still holds face down; `null` when there is nothing to turn.
 */
function revealFrom(model, view) {
  const cards = {};
  let any = false;
  (view.seats || []).forEach((s, i) => {
    const ms = model.seats[i];
    if (!ms || ms.folded || !ms.cards || !s.hole) return;
    if (ms.cards.some((c) => c == null)) {
      cards[i] = [...s.hole];
      any = true;
    }
  });
  return any ? { type: 'reveal', cards } : null;
}

/**
 * The fields a reconcile compares, as `path: [model, target]` pairs for every
 * difference. Display-only fields (who is to act, the phase) are not drift.
 */
export function diffModels(a, b) {
  const out = [];
  const eq = (x, y) => JSON.stringify(x) === JSON.stringify(y);
  if (a.button !== b.button) out.push(['button', a.button, b.button]);
  if (a.pot !== b.pot) out.push(['pot', a.pot, b.pot]);
  if (!eq(a.board, b.board)) out.push(['board', a.board, b.board]);
  if (!eq(a.winners, b.winners)) out.push(['winners', a.winners, b.winners]);
  if (!eq(a.highlight, b.highlight)) out.push(['highlight', a.highlight, b.highlight]);
  const n = Math.max(a.seats.length, b.seats.length);
  for (let i = 0; i < n; i++) {
    const x = a.seats[i] || emptySeat();
    const y = b.seats[i] || emptySeat();
    for (const k of ['stack', 'bet', 'folded', 'allIn', 'mucked']) {
      if (x[k] !== y[k]) out.push([`seats.${i}.${k}`, x[k], y[k]]);
    }
    if (!eq(x.cards, y.cards)) out.push([`seats.${i}.cards`, x.cards, y.cards]);
  }
  return out;
}

/**
 * The queue. `update(frame)` turns the frame's new log entries into beats;
 * the choreography takes them with `next()` and animates each; `drained()`
 * reports whether the model the beats reach matches the view, and
 * `reconcile()` snaps to the view when it does not.
 */
export class Director {
  /**
   * @param {{bestFive?: Function, maxQueue?: number}} opts
   */
  constructor({ bestFive = null, maxQueue = 12 } = {}) {
    this.bestFive = bestFive;
    this.maxQueue = maxQueue;
    this.handKey = undefined; // undefined: no frame seen yet
    this.cursor = 0;
    /** The model after every queued beat. */
    this.model = emptyModel();
    /** The model the newest view describes. */
    this.target = emptyModel();
    /** `[{beat, before, after}]`, oldest first. */
    this.queue = [];
    /** How many reconciles found a difference (tests require 0). */
    this.drift = 0;
    /** The last reconcile's differences, for diagnosis. */
    this.lastDiff = [];
  }

  /** Beats waiting to be animated. */
  get pending() {
    return this.queue.length;
  }

  /** More beats are waiting than are worth watching: fast-forward them. */
  get backlogged() {
    return this.queue.length > this.maxQueue;
  }

  /**
   * Take a frame (or `null` for an empty table). Returns `'snap'` when the
   * table should jump straight to the view (the first frame, a log that went
   * backwards), `'queued'` when beats were added, `'none'` otherwise.
   */
  update(frame) {
    const first = this.handKey === undefined;
    if (!frame || !frame.view) {
      this.target = emptyModel();
      this.cursor = 0;
      if (first) {
        this.handKey = null;
        this.model = emptyModel();
        return 'snap';
      }
      if (this.handKey === null && this.queue.length === 0) return 'none';
      this.handKey = null;
      this.push({ type: 'clear' });
      return 'queued';
    }
    const { view } = frame;
    const log = Array.isArray(frame.log) ? frame.log : [];
    const key = frame.handKey ?? null;
    this.target = modelFromView(view, key, this.bestFive);

    // Mounted mid-hand, or a log that went backwards within one hand: there
    // is no honest way to animate that, so jump.
    if (first || (key === this.handKey && log.length < this.cursor)) {
      this.handKey = key;
      this.cursor = log.length;
      this.queue = [];
      this.model = this.target;
      return 'snap';
    }

    let queued = false;
    if (key !== this.handKey) {
      this.handKey = key;
      this.cursor = 0;
      this.push({
        type: 'reset',
        handKey: key,
        hero: view.seat | 0,
        button: view.button,
        sb: view.sb,
        bb: view.bb,
        stacks: startStacks(view),
        out: view.seats.map((s) => !!s.out),
      });
      queued = true;
    }
    for (const entry of log.slice(this.cursor)) {
      for (const beat of beatsFor(entry, this.model, view, this.bestFive)) {
        this.push(beat);
        queued = true;
      }
    }
    this.cursor = log.length;
    return queued ? 'queued' : 'none';
  }

  /** Queue one beat on top of the current model. */
  push(beat) {
    const before = this.model;
    const after = applyBeat(before, beat);
    this.queue.push({ beat, before, after });
    this.model = after;
  }

  /** The oldest queued beat, removed from the queue; `null` when empty. */
  next() {
    return this.queue.shift() || null;
  }

  /** Drop every queued beat; the model jumps to where they would end. */
  skipAll() {
    this.queue = [];
  }

  /**
   * Once the queue is empty: compare the model the beats reached with the
   * view's, adopt the view's (which also carries the display-only fields),
   * and report whether anything had to snap.
   */
  reconcile() {
    const diff = diffModels(this.model, this.target);
    this.lastDiff = diff;
    if (diff.length > 0) this.drift += 1;
    this.model = this.target;
    return diff.length > 0;
  }
}
