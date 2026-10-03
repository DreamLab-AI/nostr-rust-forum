// stacks.js — amounts to chips, and chips to columns. Pure: no DOM, no three.
//
// The chips on the table are illustration, never the record: every number a
// member reads (stacks, bets, the pot) is printed in the DOM overlay from the
// seat view. So a pile only has to *look* like its amount: a fuller pile for
// more chips, the casino colours a player expects, and never so many chips
// that a 20,000-chip stack costs 20,000 instances.

/** Denominations, low to high, and their casino colours (linear-ish sRGB hex). */
export const DENOMS = Object.freeze([
  Object.freeze({ value: 1, colour: 0xeeeae0, stripe: 0x2a4f9b }),
  Object.freeze({ value: 5, colour: 0xb3202a, stripe: 0xf3efe6 }),
  Object.freeze({ value: 25, colour: 0x1f7a3d, stripe: 0xf3efe6 }),
  Object.freeze({ value: 100, colour: 0x1b1b1d, stripe: 0xf3efe6 }),
  Object.freeze({ value: 500, colour: 0x5b2a86, stripe: 0xf3efe6 }),
  Object.freeze({ value: 1000, colour: 0xe0a526, stripe: 0x1b1b1d }),
  Object.freeze({ value: 5000, colour: 0x8a4b2a, stripe: 0xf3efe6 }),
  Object.freeze({ value: 25000, colour: 0x2d7fb8, stripe: 0xf3efe6 }),
  Object.freeze({ value: 100000, colour: 0xc9c9cf, stripe: 0x8a1c2b }),
  Object.freeze({ value: 500000, colour: 0xd96aa0, stripe: 0x1b1b1d }),
]);

/** How many chips each kind of pile aims to show, and its hard ceiling. */
export const PILE_TARGET = Object.freeze({
  stack: { target: 36, cap: 60 },
  bet: { target: 10, cap: 24 },
  pot: { target: 24, cap: 48 },
  flight: { target: 10, cap: 24 },
});

/** Chips per column before a pile starts a new one. */
export const COLUMN_MAX = 20;

/**
 * The smallest denomination a table shows: the largest one not above its
 * small blind, so chips under the smallest bet never clutter the felt.
 */
export function minDenomIndex(smallBlind) {
  const sb = Math.max(1, Math.floor(smallBlind || 1));
  let idx = 0;
  for (let i = 0; i < DENOMS.length; i++) if (DENOMS[i].value <= sb) idx = i;
  return idx;
}

/**
 * Break `amount` into chips: `[{denom, count}]`, highest denomination first.
 *
 * Greedy first (fewest chips), then the largest chips are changed into the
 * next denomination down while the pile stays within `target`, so a stack
 * looks like a stack rather than three black chips. Anything below the
 * table's smallest denomination is shown as one more of that denomination:
 * the overlay carries the exact figure. A pile never exceeds `cap` chips;
 * past it the lowest denominations are left off.
 */
export function breakdown(amount, smallBlind, kind = 'stack') {
  const { target, cap } = PILE_TARGET[kind] || PILE_TARGET.stack;
  const n = Math.max(0, Math.floor(Number(amount) || 0));
  if (n === 0) return [];
  const lo = minDenomIndex(smallBlind);
  const counts = new Array(DENOMS.length).fill(0);
  let rest = n;
  for (let i = DENOMS.length - 1; i >= lo; i--) {
    const d = DENOMS[i].value;
    counts[i] = Math.floor(rest / d);
    rest -= counts[i] * d;
  }
  if (rest > 0) counts[lo] += 1;

  const total = () => counts.reduce((a, b) => a + b, 0);
  // change big chips into smaller ones while the pile has room
  for (let guard = 0; guard < 64; guard++) {
    let changed = false;
    for (let i = DENOMS.length - 1; i > lo; i--) {
      if (counts[i] === 0) continue;
      const ratio = DENOMS[i].value / DENOMS[i - 1].value;
      if (!Number.isInteger(ratio)) continue;
      // keep at least one of the top denomination once the pile is fullish
      if (total() - 1 + ratio > target) continue;
      counts[i] -= 1;
      counts[i - 1] += ratio;
      changed = true;
      break;
    }
    if (!changed) break;
  }

  // enforce the ceiling from the bottom up
  let over = total() - cap;
  for (let i = lo; i < DENOMS.length && over > 0; i++) {
    const cut = Math.min(counts[i], over);
    counts[i] -= cut;
    over -= cut;
  }

  const out = [];
  for (let i = DENOMS.length - 1; i >= 0; i--) {
    if (counts[i] > 0) out.push({ denom: i, count: counts[i] });
  }
  return out;
}

/** The chip value a breakdown shows (≥ the amount it was made from, unless capped). */
export function shownValue(parts) {
  return parts.reduce((a, p) => a + DENOMS[p.denom].value * p.count, 0);
}

/**
 * Lay a breakdown out as columns around a pile's anchor: one or more columns
 * per denomination (≤ `COLUMN_MAX` each), arranged in a compact grid that
 * grows from the anchor. Returns chips as `{denom, dx, dz, level, jitter}`;
 * `jitter` is a stable per-chip value in [0, 1) used for the small random
 * yaw and offset that make a stack look hand-built.
 */
export function pileLayout(parts, radius, spacing = 2.15) {
  const columns = [];
  for (const p of parts) {
    let left = p.count;
    while (left > 0) {
      const n = Math.min(COLUMN_MAX, left);
      columns.push({ denom: p.denom, n });
      left -= n;
    }
  }
  if (columns.length === 0) return [];
  // grid: up to 3 per row, rows stepping back; centred on the anchor
  const perRow = columns.length <= 2 ? columns.length : columns.length <= 4 ? 2 : 3;
  const rows = Math.ceil(columns.length / perRow);
  const step = radius * spacing;
  const chips = [];
  columns.forEach((col, ci) => {
    const row = Math.floor(ci / perRow);
    const inRow = Math.min(perRow, columns.length - row * perRow);
    const colIdx = ci - row * perRow;
    // stagger alternate rows by half a chip, like a real stack
    const dx = (colIdx - (inRow - 1) / 2) * step + (row % 2 ? step * 0.25 : 0);
    const dz = (row - (rows - 1) / 2) * step * 0.92;
    for (let level = 0; level < col.n; level++) {
      chips.push({ denom: col.denom, dx, dz, level, jitter: hash01(ci * 131 + level * 17 + col.denom) });
    }
  });
  return chips;
}

/** A deterministic hash of an integer to [0, 1). */
export function hash01(n) {
  let x = (n | 0) ^ 0x9e3779b9;
  x = Math.imul(x ^ (x >>> 16), 0x85ebca6b);
  x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35);
  x ^= x >>> 16;
  return (x >>> 0) / 4294967296;
}
