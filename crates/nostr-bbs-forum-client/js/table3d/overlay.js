// overlay.js — pins the DOM labels to the table.
//
// Names, stacks, bets and the pot are DOM, not canvas text: they stay sharp,
// selectable and readable by assistive technology, and the Leptos page owns
// them. The page renders them inside the table's container, marked with
// `data-t3d-anchor` (where on the table) and `data-t3d-field` (which number
// this module may write). This module only moves anchors to their projected
// spot and writes the numbers the animation has reached, so a bet label
// changes when the chips land, not before.

import * as THREE from './three.js';
import { CHIP, LAYOUT, sideOf } from './layout.js';

/** World points the labels hang from, by anchor name. */
function anchorPoint(name) {
  switch (name) {
    case 'near-seat': return { ...LAYOUT.near.seat, y: 0.0 };
    case 'far-seat': return { ...LAYOUT.far.seat, y: 0.0 };
    case 'near-bet': return { x: LAYOUT.near.bet.x + 0.085, y: 0.0, z: LAYOUT.near.bet.z };
    case 'far-bet': return { x: LAYOUT.far.bet.x - 0.085, y: 0.0, z: LAYOUT.far.bet.z };
    case 'pot': return { x: LAYOUT.pot.x, y: 0.0, z: LAYOUT.pot.z + CHIP.r * 2.6 };
    default: return null;
  }
}

/** Thousands separated, as the DOM table prints them. */
const fmt = (n) => Math.round(n).toLocaleString('en-GB');

export class Overlay {
  /** @param {HTMLElement|null} root the element holding the labels */
  constructor(root) {
    this.root = root;
    this.anchors = [];
    this.fields = new Map();
    this.last = new Map();
    this._v = new THREE.Vector3();
    this.scan();
  }

  /** Find the labels (again, after the page re-rendered them). */
  scan() {
    if (!this.root) return;
    this.anchors = [...this.root.querySelectorAll('[data-t3d-anchor]')].map((el) => ({
      el,
      name: el.getAttribute('data-t3d-anchor'),
      at: anchorPoint(el.getAttribute('data-t3d-anchor')),
    }));
    this.fields = new Map([...this.root.querySelectorAll('[data-t3d-field]')].map((el) => [el.getAttribute('data-t3d-field'), el]));
    this.last.clear();
  }

  /** Move every label to where its anchor projects, in CSS pixels. */
  place(camera, width, height) {
    if (this.anchors.some((a) => !a.el.isConnected)) this.scan();
    for (const a of this.anchors) {
      if (!a.at) continue;
      this._v.set(a.at.x, a.at.y, a.at.z).project(camera);
      // clamp inside the canvas so the near seat's label never drops off it
      const x = Math.max(56, Math.min(width - 56, ((this._v.x + 1) / 2) * width));
      const y = Math.max(16, Math.min(height - 16, ((1 - this._v.y) / 2) * height));
      const t = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) translate(-50%, -50%)`;
      if (this.last.get(a.el) !== t) {
        a.el.style.transform = t;
        this.last.set(a.el, t);
      }
    }
  }

  /**
   * Write the amounts the chips show now, and mark the seat to act and the
   * winners. `amounts` are pile amounts by pile id; `model` the director's.
   */
  write(amounts, model, winners = []) {
    const hero = model.hero | 0;
    const other = hero === 0 ? 1 : 0;
    const set = (key, text, hidden) => {
      const el = this.fields.get(key);
      if (!el) return;
      if (el.textContent !== text) el.textContent = text;
      // a stack hides only its number; a bet or the pot hides its whole tag
      const holder = key.endsWith('-stack') ? el.parentElement || el : el.closest('[data-t3d-anchor]') || el;
      if (hidden !== undefined) holder.style.visibility = hidden ? 'hidden' : 'visible';
    };
    const seatOf = { near: hero, far: other };
    for (const side of ['near', 'far']) {
      const s = seatOf[side];
      // before the first hand there is no stack to show
      set(`${side}-stack`, fmt(amounts[`stack${s}`] || 0), model.phase === 'idle');
      const bet = amounts[`bet${s}`] || 0;
      set(`${side}-bet`, fmt(bet), bet <= 0);
      const anchor = this.anchors.find((a) => a.name === `${side}-seat`);
      if (anchor) {
        const toAct = model.phase === 'act' && model.toAct === s;
        anchor.el.toggleAttribute('data-t3d-active', toAct);
        anchor.el.toggleAttribute('data-t3d-winner', winners.includes(s));
        const seat = model.seats[s];
        anchor.el.toggleAttribute('data-t3d-allin', !!(seat && seat.allIn && model.phase === 'act'));
        anchor.el.toggleAttribute('data-t3d-folded', !!(seat && seat.folded));
        anchor.el.toggleAttribute('data-t3d-button', model.button === s);
      }
    }
    set('pot', fmt(amounts.pot || 0), (amounts.pot || 0) <= 0);
  }

  /** Flash a seat's label (a check: the knuckle tap). */
  pulse(seat, model, ms) {
    const side = sideOf(seat, model.hero | 0);
    const anchor = this.anchors.find((a) => a.name === `${side}-seat`);
    if (!anchor) return;
    anchor.el.setAttribute('data-t3d-check', '');
    setTimeout(() => anchor.el.removeAttribute('data-t3d-check'), ms);
  }
}
