// quality.js — render quality: the starting tier and the adaptive pixel
// ratio. Pure: no DOM, no three.
//
// The table renders only while something moves, so frame times are sampled
// only from consecutive animated frames; an idle gap is not a slow frame.

/**
 * The tier to start at: `high` (real-time soft shadows, bumped felt) or
 * `low` (blob shadows, flat felt). `auto` keeps phones and small machines on
 * `low`; the adaptive pixel ratio then handles the rest.
 */
export function startTier(quality, { coarsePointer = false, deviceMemory = 8, cores = 8 } = {}) {
  if (quality === 'high' || quality === 'low') return quality;
  if (coarsePointer || deviceMemory < 4 || cores <= 4) return 'low';
  return 'high';
}

/** The pixel-ratio ceiling: 2 on desktops, 1.5 on touch devices. */
export function dprCap(devicePixelRatio, { coarsePointer = false, maxDpr = null } = {}) {
  const ceiling = maxDpr ?? (coarsePointer ? 1.5 : 2);
  return Math.max(1, Math.min(devicePixelRatio || 1, ceiling));
}

/**
 * Lowers the pixel ratio in 0.25 steps (never below 1) when the 90th
 * percentile frame time of a 60-frame window is over budget, and raises it
 * back, more slowly, after three comfortable windows in a row.
 */
export class AdaptiveDpr {
  constructor({ max, min = 1, step = 0.25, budgetMs = 22, comfortMs = 14, window = 60 } = {}) {
    this.max = max;
    this.min = Math.min(min, max);
    this.step = step;
    this.budgetMs = budgetMs;
    this.comfortMs = comfortMs;
    this.window = window;
    this.current = max;
    this.samples = [];
    this.goodWindows = 0;
  }

  /**
   * Record one animated frame's duration. Returns the new pixel ratio when it
   * changes, else `null`. Gaps over 100 ms (the loop was idle) are ignored.
   */
  sample(ms) {
    if (!(ms > 0) || ms > 100) return null;
    this.samples.push(ms);
    if (this.samples.length < this.window) return null;
    const sorted = [...this.samples].sort((a, b) => a - b);
    const p90 = sorted[Math.floor(sorted.length * 0.9)];
    this.samples = [];
    if (p90 > this.budgetMs && this.current > this.min) {
      this.goodWindows = 0;
      this.current = Math.max(this.min, this.current - this.step);
      return this.current;
    }
    if (p90 < this.comfortMs && this.current < this.max) {
      this.goodWindows += 1;
      if (this.goodWindows >= 3) {
        this.goodWindows = 0;
        this.current = Math.min(this.max, this.current + this.step);
        return this.current;
      }
    } else {
      this.goodWindows = 0;
    }
    return null;
  }

  /** Change the ceiling (the window moved to another screen). */
  setMax(max) {
    this.max = max;
    this.current = Math.min(this.current, max);
  }
}
