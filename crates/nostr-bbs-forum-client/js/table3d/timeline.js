// timeline.js — the table's tweening clock. Pure: no DOM, no three.
//
// Every animation on the table is a tween advanced by the render loop's own
// frame delta, so there is no second requestAnimationFrame and a paused loop
// (hidden tab, table scrolled away) pauses the animations with it. The
// director decides what moves; this file only decides how a value gets from
// 0 to 1 over time.
//
// The easing curves are ported from tween.js (https://github.com/tweenjs/tween.js,
// MIT, Copyright (c) 2010-2012 Tween.js authors; easing equations Copyright
// (c) 2001 Robert Penner). Only the curves are taken: the scheduling below is
// our own, because the table needs `finish()` (fast-forward a backlog in one
// call) and a single owner of time, which tween.js's global group does not give.

/** Easing curves, `k` in [0, 1] → eased [0, 1] (Back overshoots). */
export const Easing = Object.freeze({
  Linear: { None: (k) => k },
  Quadratic: {
    In: (k) => k * k,
    Out: (k) => k * (2 - k),
    InOut: (k) => ((k *= 2) < 1 ? 0.5 * k * k : -0.5 * (--k * (k - 2) - 1)),
  },
  Cubic: {
    In: (k) => k * k * k,
    Out: (k) => --k * k * k + 1,
    InOut: (k) => ((k *= 2) < 1 ? 0.5 * k * k * k : 0.5 * ((k -= 2) * k * k + 2)),
  },
  Quartic: {
    Out: (k) => 1 - --k * k * k * k,
  },
  Exponential: {
    Out: (k) => (k === 1 ? 1 : 1 - Math.pow(2, -10 * k)),
    InOut: (k) => {
      if (k === 0) return 0;
      if (k === 1) return 1;
      if ((k *= 2) < 1) return 0.5 * Math.pow(1024, k - 1);
      return 0.5 * (-Math.pow(2, -10 * (k - 1)) + 2);
    },
  },
  Sinusoidal: {
    InOut: (k) => 0.5 * (1 - Math.cos(Math.PI * k)),
  },
  Back: {
    Out: (k) => {
      const s = 1.70158;
      return --k * k * ((s + 1) * k + s) + 1;
    },
  },
});

/**
 * A set of tweens on one clock.
 *
 * `add({delay, duration, ease, start, update, done})` schedules a tween:
 * `start()` runs when its delay has elapsed, `update(e)` runs every tick
 * with the eased progress, and `done()` runs once after `update(1)`.
 * `tick(ms)` advances the clock; `finish()` runs every pending tween to its
 * end at once, in schedule order, which is how a backlog is fast-forwarded.
 */
export class Timeline {
  constructor() {
    /** @type {Array<object>} */
    this.items = [];
    this.now = 0;
  }

  /** Whether any tween is still waiting or running. */
  get active() {
    return this.items.length > 0;
  }

  /**
   * Schedule a tween. A zero duration still calls `update(1)` and `done()`,
   * on the tick its delay ends, so instant moves keep the same code path.
   * Returns the time (ms from now) at which the tween ends.
   */
  add({ delay = 0, duration = 0, ease = Easing.Cubic.InOut, start, update, done }) {
    const item = {
      at: this.now + Math.max(0, delay),
      duration: Math.max(0, duration),
      ease,
      start,
      update,
      done,
      started: false,
    };
    this.items.push(item);
    return Math.max(0, delay) + item.duration;
  }

  /** Advance the clock by `ms`; returns whether anything is still active. */
  tick(ms) {
    this.now += Math.max(0, ms);
    // Tweens may schedule further tweens from their callbacks; those join
    // the list and are seen on the next tick.
    const current = this.items;
    this.items = [];
    const keep = [];
    for (const it of current) {
      if (this.now < it.at) {
        keep.push(it);
        continue;
      }
      if (!it.started) {
        it.started = true;
        if (it.start) it.start();
      }
      const k = it.duration === 0 ? 1 : Math.min(1, (this.now - it.at) / it.duration);
      if (it.update) it.update(it.ease(k));
      if (k >= 1) {
        if (it.done) it.done();
      } else {
        keep.push(it);
      }
    }
    this.items = keep.concat(this.items);
    return this.active;
  }

  /**
   * Run every pending tween to its end now, in the order they would have
   * ended, including tweens their callbacks schedule. Bounded so a callback
   * that keeps scheduling cannot hang the page.
   */
  finish() {
    for (let guard = 0; guard < 64 && this.items.length > 0; guard++) {
      const pending = this.items.slice().sort((a, b) => a.at + a.duration - (b.at + b.duration));
      this.items = [];
      for (const it of pending) {
        if (!it.started) {
          it.started = true;
          if (it.start) it.start();
        }
        if (it.update) it.update(1);
        if (it.done) it.done();
      }
    }
    this.items = [];
  }

  /** Drop every tween without running it (used on dispose). */
  clear() {
    this.items = [];
  }
}

/** Linear interpolation. */
export const lerp = (a, b, t) => a + (b - a) * t;

/**
 * A point on the quadratic Bézier arc from `a` to `b` that rises `lift`
 * metres above the higher end at its middle: the path a dealt card or a
 * pushed stack of chips follows. `a`/`b` are `{x, y, z}`.
 */
export function arc(a, b, lift, t) {
  const cx = (a.x + b.x) / 2;
  const cz = (a.z + b.z) / 2;
  const cy = Math.max(a.y, b.y) + lift * 2;
  const u = 1 - t;
  return {
    x: u * u * a.x + 2 * u * t * cx + t * t * b.x,
    y: u * u * a.y + 2 * u * t * cy + t * t * b.y,
    z: u * u * a.z + 2 * u * t * cz + t * t * b.z,
  };
}
