// camera.js — the hero's seat at the table.
//
// The camera sits behind the hero's cards looking across the felt, framed so
// the whole rail fits whatever the canvas shape: on a wide screen it sits
// lower and the table fills the width; in a portrait phone it rises and
// looks down more, so the far seat stays in view. A member may lean a little
// (a limited orbit), but the camera always springs back towards the seat it
// belongs in. A mouse leans by dragging; on touch the page keeps its scroll
// unless "free look" is on.

import * as THREE from './three.js';
import { TABLE } from './layout.js';

const DEG = Math.PI / 180;

/** The rail's outer edge, top and bottom, sampled round the stadium. */
const RIM = (() => {
  const r = TABLE.halfDepth + TABLE.trim + TABLE.railWidth;
  const s = TABLE.halfLength - TABLE.halfDepth;
  const pts = [];
  for (let i = 0; i < 48; i++) {
    const a = (i / 48) * Math.PI * 2;
    const x = Math.cos(a) * r + Math.sign(Math.cos(a)) * s;
    const z = Math.sin(a) * r;
    pts.push([x, 0, z], [x, TABLE.railHeight, z]);
  }
  return pts;
})();

/** Where the camera looks: just behind the board. */
const LOOK_AT = new THREE.Vector3(0, 0, 0.035);

/**
 * The seated view for an aspect ratio: polar angle (from straight down),
 * field of view, both in radians.
 */
export function seatedView(aspect) {
  // blend from portrait (look down more, wider lens) to landscape
  const t = Math.min(1, Math.max(0, (aspect - 0.6) / (1.6 - 0.6)));
  return { polar: (24 + t * 18) * DEG, fov: (44 - t * 10) * DEG };
}

/** The camera rig: framing, a damped limited orbit, parallax, and input. */
export class CameraRig {
  constructor(dom, { reducedMotion = false, freeLook = false } = {}) {
    this.dom = dom;
    this.camera = new THREE.PerspectiveCamera(40, 1, 0.05, 20);
    this.reducedMotion = reducedMotion;
    this.freeLook = freeLook;
    this.aspect = 1;
    this.base = { polar: 50 * DEG, radius: 2 };
    // the lean the member asked for (target) and where the camera is (now)
    this.want = { az: 0, polar: 0, zoom: 1 };
    this.now = { az: 0, polar: 0, zoom: 1 };
    this.parallax = { want: { x: 0, y: 0 }, now: { x: 0, y: 0 } };
    this.moved = true;
    this.drag = null;
    this.onTap = null; // (ndcX, ndcY, pointerType) => void
    this.onChange = null; // () => void: something to render
    this._v = new THREE.Vector3();
    this.bind();
    this.applyTouchAction();
  }

  /** Frame the table for a canvas of `w` × `h` CSS pixels. */
  fit(w, h) {
    this.aspect = Math.max(0.3, w / Math.max(1, h));
    const { polar, fov } = seatedView(this.aspect);
    this.camera.fov = fov / DEG;
    this.camera.aspect = this.aspect;
    this.base.polar = polar;
    // the nearest radius at which every corner of the table is in frame
    let lo = 0.4, hi = 8;
    for (let i = 0; i < 26; i++) {
      const mid = (lo + hi) / 2;
      if (this.fits(mid, polar)) hi = mid;
      else lo = mid;
    }
    this.base.radius = hi * 1.02;
    this.moved = true;
    this.apply();
  }

  /**
   * Whether the rail's outer edge (its rounded outline, not a bounding box,
   * whose corners lie well outside a stadium) fits the view from `radius`
   * at `polar`, with a margin for the seat labels above and below.
   */
  fits(radius, polar) {
    this.place(radius, polar, 0);
    this.camera.updateProjectionMatrix();
    this.camera.updateMatrixWorld(true);
    for (const p of RIM) {
      this._v.set(p[0], p[1], p[2]).project(this.camera);
      if (Math.abs(this._v.x) > 0.97 || Math.abs(this._v.y) > 0.84 || this._v.z > 1) return false;
    }
    return true;
  }

  /** Put the camera on its sphere round the look-at point. */
  place(radius, polar, az) {
    const sp = Math.sin(polar);
    this.camera.position.set(
      LOOK_AT.x + radius * sp * Math.sin(az),
      LOOK_AT.y + radius * Math.cos(polar),
      LOOK_AT.z + radius * sp * Math.cos(az),
    );
    this.camera.lookAt(LOOK_AT);
  }

  /** Apply the current lean, zoom and parallax. */
  apply() {
    const az = this.now.az + this.parallax.now.x;
    const polar = Math.min(68 * DEG, Math.max(24 * DEG, this.base.polar + this.now.polar + this.parallax.now.y));
    this.place(this.base.radius * this.now.zoom, polar, az);
    this.camera.updateProjectionMatrix();
    this.camera.updateMatrixWorld(true);
  }

  /** Spring towards the wanted lean; returns whether the camera still moves. */
  tick(dtMs) {
    const k = this.reducedMotion ? 1 : 1 - Math.exp(-dtMs / 110);
    let moving = false;
    const step = (obj, key, want) => {
      const d = want - obj[key];
      if (Math.abs(d) > 1e-5) {
        obj[key] += d * k;
        moving = true;
      } else obj[key] = want;
    };
    step(this.now, 'az', this.want.az);
    step(this.now, 'polar', this.want.polar);
    step(this.now, 'zoom', this.want.zoom);
    step(this.parallax.now, 'x', this.parallax.want.x);
    step(this.parallax.now, 'y', this.parallax.want.y);
    if (moving || this.moved) {
      this.apply();
      this.moved = false;
      return true;
    }
    return false;
  }

  /** Back to the seat. */
  reset() {
    this.want = { az: 0, polar: 0, zoom: 1 };
    this.changed();
  }

  setOptions({ reducedMotion, freeLook }) {
    if (reducedMotion !== undefined) {
      this.reducedMotion = reducedMotion;
      if (reducedMotion) this.parallax.want = { x: 0, y: 0 };
    }
    if (freeLook !== undefined) {
      this.freeLook = freeLook;
      this.applyTouchAction();
    }
    this.changed();
  }

  applyTouchAction() {
    // touch keeps scrolling the page unless free look is on
    this.dom.style.touchAction = this.freeLook ? 'none' : 'pan-y';
  }

  changed() {
    this.moved = true;
    if (this.onChange) this.onChange();
  }

  /** Pointer to normalised device coordinates. */
  ndc(e) {
    const r = this.dom.getBoundingClientRect();
    return [((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1];
  }

  bind() {
    const d = this.dom;
    this.handlers = {
      pointerdown: (e) => {
        if (e.button !== 0 && e.pointerType === 'mouse') return;
        this.drag = { id: e.pointerId, x: e.clientX, y: e.clientY, moved: 0, orbit: e.pointerType === 'mouse' || this.freeLook };
        if (this.drag.orbit) d.setPointerCapture?.(e.pointerId);
      },
      pointermove: (e) => {
        if (this.drag && this.drag.id === e.pointerId) {
          const dx = e.clientX - this.drag.x;
          const dy = e.clientY - this.drag.y;
          this.drag.moved += Math.abs(dx) + Math.abs(dy);
          this.drag.x = e.clientX;
          this.drag.y = e.clientY;
          if (this.drag.orbit && this.drag.moved > 4) {
            this.want.az = Math.max(-25 * DEG, Math.min(25 * DEG, this.want.az - dx * 0.006));
            this.want.polar = Math.max(-15 * DEG, Math.min(13 * DEG, this.want.polar - dy * 0.004));
            this.changed();
          }
          return;
        }
        if (e.pointerType === 'mouse' && !this.reducedMotion) {
          // a gentle lean towards the pointer: life without a control
          const [x, y] = this.ndc(e);
          this.parallax.want = { x: -x * 2 * DEG, y: y * 1.5 * DEG };
          this.changed();
        }
      },
      pointerup: (e) => {
        if (!this.drag || this.drag.id !== e.pointerId) return;
        const tap = this.drag.moved < 6;
        this.drag = null;
        if (tap && this.onTap) this.onTap(...this.ndc(e), e.pointerType);
      },
      pointercancel: () => {
        this.drag = null;
      },
      pointerleave: () => {
        this.parallax.want = { x: 0, y: 0 };
        this.changed();
      },
      dblclick: () => this.reset(),
      wheel: (e) => {
        if (!this.freeLook) return;
        e.preventDefault();
        this.want.zoom = Math.max(0.78, Math.min(1.15, this.want.zoom * (1 + Math.sign(e.deltaY) * 0.06)));
        this.changed();
      },
    };
    for (const [ev, fn] of Object.entries(this.handlers)) d.addEventListener(ev, fn, ev === 'wheel' ? { passive: false } : undefined);
  }

  dispose() {
    for (const [ev, fn] of Object.entries(this.handlers)) this.dom.removeEventListener(ev, fn);
  }
}
