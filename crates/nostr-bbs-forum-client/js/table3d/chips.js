// chips.js — every chip on the table as one instanced mesh.
//
// A pile (a stack, a bet line, the pot) is just an amount at an anchor; its
// chips are laid out afresh from that amount whenever it changes
// (stacks.js). Chips in motion are flights: a small stack of an amount
// travelling from one pile to another along a lerp or an arc. Rebuilding
// a few hundred instance matrices on a frame that moves is cheaper than
// keeping chip identities, and nothing on screen can tell the difference.

import * as THREE from './three.js';
import { CHIP, LAYOUT, sideOf } from './layout.js';
import { DENOMS, breakdown, hash01, pileLayout } from './stacks.js';
import { chipMaterial } from './materials.js';

/** The most chips the mesh can show at once. */
export const CHIP_CAPACITY = 420;

/**
 * A chip's geometry: a short cylinder whose rim and faces are told apart
 * by a `part` attribute (0 rim, 1 faces) for the single chip material.
 */
export function chipGeometry() {
  const g = new THREE.CylinderGeometry(CHIP.r, CHIP.r, CHIP.h, 28, 1, false);
  const part = new Float32Array(g.getAttribute('position').count);
  const index = g.getIndex();
  for (const grp of g.groups) {
    if (grp.materialIndex === 0) continue;
    for (let k = grp.start; k < grp.start + grp.count; k++) part[index.getX(k)] = 1;
  }
  g.setAttribute('part', new THREE.BufferAttribute(part, 1));
  g.clearGroups();
  g.translate(0, CHIP.h / 2, 0);
  return g;
}

/** The world anchor of a pile id (`stack0`, `bet1`, `pot`) for a hero seat. */
export function pileAnchor(id, hero) {
  if (id === 'pot') return LAYOUT.pot;
  const seat = Number(id.slice(-1));
  const side = LAYOUT[sideOf(seat, hero)];
  return id.startsWith('stack') ? side.stack : side.bet;
}

/** The instanced chips: piles at rest and flights in the air. */
export class ChipSet {
  constructor({ edgeMask, capMask, castShadow }) {
    this.colourAttr = new THREE.InstancedBufferAttribute(new Float32Array(CHIP_CAPACITY * 3), 3);
    this.stripeAttr = new THREE.InstancedBufferAttribute(new Float32Array(CHIP_CAPACITY * 3), 3);
    this.colourAttr.setUsage(THREE.DynamicDrawUsage);
    this.stripeAttr.setUsage(THREE.DynamicDrawUsage);
    this.geometry = chipGeometry();
    this.material = chipMaterial({ colourAttr: this.colourAttr, stripeAttr: this.stripeAttr, edgeMask, capMask });
    this.mesh = new THREE.InstancedMesh(this.geometry, this.material, CHIP_CAPACITY);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.castShadow = castShadow;
    this.mesh.receiveShadow = true;
    this.mesh.frustumCulled = false;
    this.mesh.count = 0;
    this.mesh.name = 'chips';
    /** pile id → amount shown */
    this.amounts = { stack0: 0, stack1: 0, bet0: 0, bet1: 0, pot: 0 };
    /** in-flight stacks: {amount, from, to, k, arc} */
    this.flights = new Set();
    this.hero = 0;
    this.smallBlind = 1;
    this.dirty = true;
    this.colours = DENOMS.map((d) => [new THREE.Color(d.colour), new THREE.Color(d.stripe)]);
    this._m = new THREE.Matrix4();
    this._q = new THREE.Quaternion();
    this._p = new THREE.Vector3();
    this._s = new THREE.Vector3(1, 1, 1);
    this._y = new THREE.Vector3(0, 1, 0);
  }

  /** Seat orientation and the table's smallest denomination. */
  configure(hero, smallBlind) {
    if (hero !== this.hero || smallBlind !== this.smallBlind) {
      this.hero = hero;
      this.smallBlind = smallBlind || 1;
      this.dirty = true;
    }
  }

  /** Show every pile at exactly `amounts`, with nothing in flight. */
  set(amounts) {
    this.amounts = { ...this.amounts, ...amounts };
    this.flights.clear();
    this.dirty = true;
  }

  /** Change one pile's amount by `delta`. */
  add(id, delta) {
    this.amounts[id] = Math.max(0, (this.amounts[id] || 0) + delta);
    this.dirty = true;
  }

  /**
   * Start a flight of `amount` from pile `from` to pile `to`: the source
   * shrinks now, the destination grows when `land()` is called.
   */
  launch(from, to, amount, arc) {
    this.add(from, -amount);
    const f = { amount, from, to, k: 0, arc };
    this.flights.add(f);
    this.dirty = true;
    return f;
  }

  /** End a flight: its chips join the destination pile. */
  land(f) {
    if (!this.flights.delete(f)) return;
    this.add(f.to, f.amount);
  }

  /** The current centre of a flight, for the blob shadow. */
  flightPosition(f) {
    const a = pileAnchor(f.from, this.hero);
    const b = pileAnchor(f.to, this.hero);
    const k = f.k;
    const y = f.arc ? Math.sin(Math.PI * k) * 0.05 : Math.sin(Math.PI * k) * 0.008;
    return { x: a.x + (b.x - a.x) * k, y, z: a.z + (b.z - a.z) * k };
  }

  /** Lay out one pile's chips, appending instances from `n`; returns the next index. */
  writePile(n, amount, kind, ox, oy, oz, seed) {
    if (amount <= 0) return n;
    const chips = pileLayout(breakdown(amount, this.smallBlind, kind), CHIP.r);
    for (const c of chips) {
      if (n >= CHIP_CAPACITY) break;
      const j = hash01(seed * 977 + c.level * 31 + Math.round(c.dx * 1e4));
      // a hand-built stack: each chip a hair off centre and turned a little
      this._p.set(ox + c.dx + (j - 0.5) * 0.0012, oy + c.level * CHIP.h, oz + c.dz + (c.jitter - 0.5) * 0.0012);
      this._q.setFromAxisAngle(this._y, j * Math.PI * 2);
      this._m.compose(this._p, this._q, this._s);
      this.mesh.setMatrixAt(n, this._m);
      const [body, stripe] = this.colours[c.denom];
      this.colourAttr.setXYZ(n, body.r, body.g, body.b);
      this.stripeAttr.setXYZ(n, stripe.r, stripe.g, stripe.b);
      n += 1;
    }
    return n;
  }

  /** Rebuild every instance; returns whether anything was written. */
  commit() {
    if (!this.dirty) return false;
    let n = 0;
    ['stack0', 'stack1', 'bet0', 'bet1', 'pot'].forEach((id, k) => {
      const a = pileAnchor(id, this.hero);
      const kind = id === 'pot' ? 'pot' : id.startsWith('stack') ? 'stack' : 'bet';
      n = this.writePile(n, this.amounts[id], kind, a.x, 0, a.z, k + 1);
    });
    let f = 0;
    for (const fl of this.flights) {
      const p = this.flightPosition(fl);
      n = this.writePile(n, fl.amount, 'flight', p.x, p.y, p.z, 40 + f++);
    }
    this.mesh.count = n;
    this.mesh.instanceMatrix.needsUpdate = true;
    this.colourAttr.needsUpdate = true;
    this.stripeAttr.needsUpdate = true;
    this.dirty = false;
    return true;
  }

  /** The footprint of each pile for blob shadows: `[{x, z, r}]`. */
  footprints() {
    const out = [];
    for (const id of ['stack0', 'stack1', 'bet0', 'bet1', 'pot']) {
      if (this.amounts[id] > 0) {
        const a = pileAnchor(id, this.hero);
        const cols = pileLayout(breakdown(this.amounts[id], this.smallBlind, id === 'pot' ? 'pot' : id.startsWith('stack') ? 'stack' : 'bet'), CHIP.r);
        const spread = cols.reduce((m, c) => Math.max(m, Math.hypot(c.dx, c.dz)), 0);
        out.push({ x: a.x, z: a.z, r: spread + CHIP.r * 1.4 });
      }
    }
    for (const fl of this.flights) {
      const p = this.flightPosition(fl);
      out.push({ x: p.x, z: p.z, r: CHIP.r * 1.6, lifted: p.y });
    }
    return out;
  }

  dispose() {
    this.geometry.dispose();
    this.material.dispose();
    this.mesh.dispose();
  }
}
