// inspect.js — lifting a group of cards up to the camera for a closer look.
// Pure: no DOM, no three.
//
// Hovering the hero's hole cards, the board, or (once shown) the other
// seat's cards lifts that group off the felt to a face-on pose in front of
// the camera; leaving drops it back to exactly where it lay. This file owns
// the state machine and the numbers: how far up each group is (`s`, 0 on the
// felt, 1 face-on), which flourish plays on the way up, and how the face-on
// row is laid out for a canvas. index.js turns those numbers into instance
// matrices, composed over the card's resting pose at render time, so an
// inspection never writes to the card states the director's beats animate.
//
// Every tween starts from where the group *is*, so re-entering mid-drop (or
// leaving mid-rise) reverses smoothly with no snap and nothing queued.

import { CARD } from './layout.js';
import { Easing } from './timeline.js';

/** Timings in ms: the travel up, the drop, and the reduced-motion crossfade. */
export const PEEK = Object.freeze({
  rise: 700,
  drop: 500,
  fade: 140,
  minRise: 140,
  minDrop: 110,
  /** Share of the canvas's shorter side the group fills, when it can. */
  fill: 0.8,
  /** Gap between cards in the face-on row (metres). */
  gap: 0.012,
});

/**
 * The flourishes, one chosen at random per inspection. Each plays within
 * the travel time, so it never delays reading the cards:
 *
 * - `flip`  — a quick tumble end over end, with a glint sweeping the face;
 * - `fan`   — the cards spread like a hand on the way up, then square up;
 * - `spin`  — a slow full turn about the vertical that settles face-on;
 * - `float` — a gentle bob and rock while a glossy sheen comes up;
 * - `wave`  — a ripple runs along the row, each card tipping in turn.
 */
export const FLOURISHES = Object.freeze(['flip', 'fan', 'spin', 'float', 'wave']);

const clamp01 = (x) => (x < 0 ? 0 : x > 1 ? 1 : x);

/**
 * A flourish's offsets for card `i` of `n` at flourish progress `f` (0..1),
 * in the face-on frame: `dx`, `dy`, `dz` (metres along camera right, up and
 * towards the camera), `tumble`, `spin`, `roll` (radians about the card's
 * horizontal axis, the vertical, and the view axis) and `sheen` (0..1, the
 * card's gloss; a glint sweeps the face as it rises). Every motion offset is
 * zero at `f = 0` and `f = 1`, so a flourish starts and ends on the plain
 * pose and scaling it down (a drop) can never leave a card turned.
 */
export function flourishPose(name, f, i = 0, n = 1) {
  const o = { dx: 0, dy: 0, dz: 0, tumble: 0, spin: 0, roll: 0, sheen: 0 };
  const c = i - (n - 1) / 2;
  f = clamp01(f);
  switch (name) {
    case 'flip': {
      const k = clamp01((f - 0.08) / 0.72);
      o.tumble = Math.PI * 2 * Easing.Cubic.InOut(k);
      o.dz = 0.02 * Math.sin(Math.PI * k);
      o.sheen = clamp01((f - 0.6) / 0.4);
      break;
    }
    case 'fan': {
      const e = Math.sin(Math.PI * clamp01(f / 0.85));
      o.dx = c * CARD.w * 0.35 * e;
      o.dy = -Math.abs(c) * 0.012 * e;
      o.roll = -c * 0.22 * e;
      break;
    }
    case 'spin':
      o.spin = Math.PI * 2 * Easing.Cubic.InOut(f);
      break;
    case 'float':
      o.dy = 0.016 * Math.sin(Math.PI * 2 * f);
      o.tumble = 0.14 * Math.sin(Math.PI * 2 * f);
      o.sheen = Easing.Sinusoidal.InOut(f);
      break;
    case 'wave': {
      const k = clamp01(f * 1.5 - (n > 1 ? i / (n - 1) : 0) * 0.5);
      o.tumble = 0.55 * Math.sin(Math.PI * k);
      o.dz = 0.02 * Math.sin(Math.PI * k);
      break;
    }
    default:
      break;
  }
  return o;
}

/**
 * Where a face-on row of `n` cards sits for a camera with vertical field of
 * view `fovY` (radians) over a `w` × `h` canvas (CSS pixels): its distance
 * from the camera `d`, each card's offset along camera right `xs`, and the
 * row's offset along camera up `y` (metres). The row fills `PEEK.fill` of the
 * shorter side where the row's shape allows, never more than 92% of the
 * width, and stays inside the free band `band = {top, bottom}` (pixels; the
 * seat labels sit above and below it). `near` is the camera's near plane.
 */
export function faceOnLayout(n, { fovY, w, h, band = null, near = 0.05 }) {
  const gap = PEEK.gap;
  const gw = n * CARD.w + (n - 1) * gap;
  const gh = CARD.h;
  const tan = Math.tan(fovY / 2);
  const top = band ? Math.max(0, band.top) : 0;
  const bottom = band ? Math.min(h, band.bottom) : h;
  const free = Math.max(h * 0.3, bottom - top - 16);
  const targetH = Math.min(PEEK.fill * Math.min(w, h), free);
  const targetW = w * 0.92;
  // pixels per metre at distance d is h / (2 d tan), on both axes
  const d = Math.max(gh * h / (2 * tan * targetH), gw * h / (2 * tan * targetW), near + 0.05);
  const centre = band && bottom - top > h * 0.3 ? (top + bottom) / 2 : h / 2;
  const y = ((h / 2 - centre) / h) * 2 * d * tan;
  const xs = [];
  for (let i = 0; i < n; i++) xs.push((i - (n - 1) / 2) * (CARD.w + gap));
  return { d, xs, y };
}

/**
 * The inspection state machine.
 *
 * At most one group is *active* (wanted up); others may still be dropping.
 * `enter(group, members)` lifts a group (dropping any other), `leave()`
 * drops the active one, `dropAll()` drops whatever is up (a new frame
 * arrived), `reset()` puts everything down at once (fast-forward), and
 * `tick(ms)` advances. While `blocked` (the director is animating) nothing
 * new is lifted. `onPeek({group, inspecting, cards})` hears every change of
 * the active group, for the page's live region.
 */
export class Inspector {
  constructor({ reducedMotion = false, random = Math.random } = {}) {
    this.reducedMotion = reducedMotion;
    this.random = random;
    /** group → {group, ids, cards, s, f, w, dir, mode, flourish, …} */
    this.groups = new Map();
    this.active = null;
    this.blocked = false;
    this.disposed = false;
    this.onPeek = null;
    this.lastFlourish = null;
  }

  /** Lift `group` (`members` from picking's `groupCards`); false if refused. */
  enter(group, members) {
    if (this.disposed || this.blocked || !members || !members.ids.length) return false;
    if (this.active === group) return false;
    if (this.active) this.leave();
    let g = this.groups.get(group);
    if (!g) {
      const flourish = FLOURISHES[Math.min(FLOURISHES.length - 1, Math.floor(this.random() * FLOURISHES.length))];
      g = { group, ids: [...members.ids], cards: [...members.cards], s: 0, f: 0, w: 1, dir: 0, mode: 'motion', flourish };
      this.groups.set(group, g);
      this.lastFlourish = flourish;
    } else {
      // re-entered mid-drop: same cards, same flourish, carry on from here
      g.ids = [...members.ids];
      g.cards = [...members.cards];
    }
    this.start(g, 1);
    this.active = group;
    this.emit({ group, inspecting: true, cards: [...g.cards] });
    return true;
  }

  /** Drop the active group (only if it is `group`, when one is named). */
  leave(group = null) {
    if (!this.active || (group && group !== this.active)) return false;
    const g = this.groups.get(this.active);
    const was = this.active;
    this.active = null;
    if (g) this.start(g, -1);
    this.emit({ group: was, inspecting: false, cards: g ? [...g.cards] : [] });
    return true;
  }

  /** Drop everything that is up: a new frame is coming. */
  dropAll() {
    this.leave();
    for (const g of this.groups.values()) if (g.dir >= 0) this.start(g, -1);
  }

  /** Everything back on the felt at once, no animation. */
  reset() {
    if (this.active) {
      const g = this.groups.get(this.active);
      const was = this.active;
      this.active = null;
      this.emit({ group: was, inspecting: false, cards: g ? [...g.cards] : [] });
    }
    this.groups.clear();
  }

  setReducedMotion(v) {
    this.reducedMotion = !!v;
  }

  setBlocked(v) {
    this.blocked = !!v;
  }

  /** Begin a tween of `g` up (`dir` 1) or down (−1) from where it is. */
  start(g, dir) {
    g.mode = this.reducedMotion ? 'fade' : 'motion';
    g.dir = dir;
    g.u = 0;
    g.s0 = g.s;
    g.f0 = g.f;
    g.w0 = g.w;
    if (g.mode === 'fade') {
      g.dur = Math.max(1, PEEK.fade * (dir > 0 ? 1 - g.s : g.s));
    } else if (dir > 0) {
      g.dur = Math.max(PEEK.minRise, PEEK.rise * (1 - g.s));
    } else {
      g.dur = Math.max(PEEK.minDrop, PEEK.drop * g.s);
    }
  }

  /** Advance by `dt` ms; true while anything still moves. */
  tick(dt) {
    let moving = false;
    for (const [key, g] of this.groups) {
      if (g.dir === 0) continue;
      g.u = Math.min(1, g.u + dt / g.dur);
      const u = g.u;
      if (g.dir > 0) {
        const e = g.mode === 'fade' ? u : Easing.Cubic.Out(u);
        g.s = g.s0 + (1 - g.s0) * e;
        g.f = g.f0 + (1 - g.f0) * u;
        g.w = g.w0 + (1 - g.w0) * u;
        if (u >= 1) {
          g.s = 1;
          g.f = 1;
          g.w = 1;
          g.dir = 0;
        } else moving = true;
      } else {
        const e = g.mode === 'fade' ? u : Easing.Cubic.In(u);
        g.s = g.s0 * (1 - e);
        // the flourish fades with the height: the drop has none of its own
        g.w = g.s0 > 0 ? g.w0 * (g.s / g.s0) : 0;
        if (u >= 1) this.groups.delete(key);
        else moving = true;
      }
    }
    return moving;
  }

  /** Whether any group is mid-tween. */
  get moving() {
    for (const g of this.groups.values()) if (g.dir !== 0) return true;
    return false;
  }

  /** Whether every card is on the felt. */
  get idle() {
    return this.groups.size === 0;
  }

  /** The group card `id` is in, with its index, or null. */
  lookup(id) {
    for (const g of this.groups.values()) {
      const i = g.ids.indexOf(id);
      if (i >= 0) return { g, i, n: g.ids.length };
    }
    return null;
  }

  /** How far up card `id` is (0 on the felt). */
  levelOf(id) {
    const hit = this.lookup(id);
    return hit ? hit.g.s : 0;
  }

  emit(ev) {
    if (this.onPeek) this.onPeek(ev);
  }

  dispose() {
    this.groups.clear();
    this.active = null;
    this.onPeek = null;
    this.disposed = true;
  }
}
