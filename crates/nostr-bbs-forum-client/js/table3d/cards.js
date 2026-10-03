// cards.js — every card on the table as one instanced mesh.
//
// Nine cards can be in play heads-up (`CARD_IDS` in choreography.js), plus a
// short deck stub the dealer works from. Each has a visual state — position,
// yaw, how far it is turned face up, lift, opacity, glow, dim, and the face
// it shows — that the timeline tweens; `commit()` writes the instance
// matrices and attributes once per rendered frame. The fourth fx channel is
// the inspection sheen (inspect.js): gloss, and a glint while it is positive.

import * as THREE from './three.js';
import { CARD, LAYOUT } from './layout.js';
import { CARD_IDS } from './choreography.js';
import { cardMaterial } from './materials.js';

/** Cards in the deck stub (drawn, not dealt from: purely scenery). */
const DECK_STUB = 7;

/**
 * One card's geometry: a rounded rectangle extruded to the card's
 * thickness, lying in the xz plane with its face up (+y) and its top edge
 * towards −z. A `side` attribute tells the shader face (1), back (0) and edge
 * (0.5) apart; UVs span the card on both faces.
 */
export function cardGeometry() {
  const { w, h, t, r } = CARD;
  const s = new THREE.Shape();
  const x0 = -w / 2, y0 = -h / 2;
  s.moveTo(x0 + r, y0);
  s.lineTo(x0 + w - r, y0);
  s.quadraticCurveTo(x0 + w, y0, x0 + w, y0 + r);
  s.lineTo(x0 + w, y0 + h - r);
  s.quadraticCurveTo(x0 + w, y0 + h, x0 + w - r, y0 + h);
  s.lineTo(x0 + r, y0 + h);
  s.quadraticCurveTo(x0, y0 + h, x0, y0 + h - r);
  s.lineTo(x0, y0 + r);
  s.quadraticCurveTo(x0, y0, x0 + r, y0);
  const g = new THREE.ExtrudeGeometry(s, { depth: t, bevelEnabled: false, curveSegments: 5 });
  // shape y → −z (top of the card away from the hero), extrusion → +y
  g.rotateX(-Math.PI / 2);
  g.translate(0, -t / 2, 0);
  g.computeVertexNormals();
  const pos = g.getAttribute('position');
  const nrm = g.getAttribute('normal');
  const uv = new Float32Array(pos.count * 2);
  const side = new Float32Array(pos.count);
  for (let i = 0; i < pos.count; i++) {
    const ny = nrm.getY(i);
    side[i] = ny > 0.9 ? 1 : ny < -0.9 ? 0 : 0.5;
    uv[i * 2] = (pos.getX(i) + w / 2) / w;
    uv[i * 2 + 1] = (-pos.getZ(i) + h / 2) / h;
  }
  g.setAttribute('uv', new THREE.BufferAttribute(uv, 2));
  g.setAttribute('side', new THREE.BufferAttribute(side, 1));
  return g;
}

/** A card's visual state: what the timeline animates. */
function blankState() {
  return { visible: false, card: null, x: 0, y: 0, z: 0, yaw: 0, flip: 0, lift: 0, alpha: 1, glow: 0, dim: 0 };
}

/** The instanced cards plus the deck stub, sharing one material and atlas. */
export class CardSet {
  /**
   * @param {import('./card-faces.js').CardAtlas} atlas
   * @param {THREE.Texture} atlasTexture
   */
  constructor(atlas, atlasTexture, { castShadow }) {
    this.atlas = atlas;
    this.count = CARD_IDS.length + DECK_STUB;
    this.faceAttr = new THREE.InstancedBufferAttribute(new Float32Array(this.count * 4), 4);
    this.fxAttr = new THREE.InstancedBufferAttribute(new Float32Array(this.count * 4), 4);
    this.faceAttr.setUsage(THREE.DynamicDrawUsage);
    this.fxAttr.setUsage(THREE.DynamicDrawUsage);
    this.geometry = cardGeometry();
    this.backRect = atlas.rectFor(null);
    this.material = cardMaterial({ atlasTexture, faceAttr: this.faceAttr, fxAttr: this.fxAttr, backRect: this.backRect });
    this.mesh = new THREE.InstancedMesh(this.geometry, this.material, this.count);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.castShadow = castShadow;
    this.mesh.receiveShadow = true;
    this.mesh.frustumCulled = false;
    this.mesh.name = 'cards';
    /**
     * Optional `(id, state, restingMatrix) => {matrix, alpha, sheen} | null`:
     * the inspection pose composed over a card's resting pose (index.js).
     * It never writes to the state, which stays the director's.
     */
    this.poser = null;
    /** id → visual state */
    this.state = new Map(CARD_IDS.map((id) => [id, blankState()]));
    this.dirty = true;
    this._m = new THREE.Matrix4();
    this._q = new THREE.Quaternion();
    this._qf = new THREE.Quaternion();
    this._p = new THREE.Vector3();
    this._s = new THREE.Vector3(1, 1, 1);
    this._yAxis = new THREE.Vector3(0, 1, 0);
    this._zAxis = new THREE.Vector3(0, 0, 1);
    this.layDeck();
  }

  /** The deck stub: a squared-up pile of backs at the dealer's place. */
  layDeck() {
    for (let k = 0; k < DECK_STUB; k++) {
      const i = CARD_IDS.length + k;
      this._p.set(LAYOUT.deck.x + (k % 2) * 0.0004, CARD.t * (k + 0.5), LAYOUT.deck.z);
      this._q.setFromAxisAngle(this._yAxis, Math.PI / 2 + (k % 3) * 0.004);
      this._qf.setFromAxisAngle(this._zAxis, Math.PI);
      this._q.multiply(this._qf);
      this._m.compose(this._p, this._q, this._s);
      this.mesh.setMatrixAt(i, this._m);
      this.faceAttr.setXYZW(i, ...this.backRect);
      this.fxAttr.setXYZW(i, 0, 0, 1, 0);
    }
  }

  /** The state of card `id` (mutable; call `touch()` after changing it). */
  get(id) {
    return this.state.get(id);
  }

  /** Mark the instances for re-upload on the next commit. */
  touch() {
    this.dirty = true;
  }

  /**
   * Put card `id` at rest in `pose` (from choreography's `posesOf`):
   * position, face, glow and dim at once, no animation.
   */
  place(id, pose) {
    const s = this.state.get(id);
    if (!pose || !pose.visible) {
      s.visible = false;
    } else {
      Object.assign(s, {
        visible: true,
        card: pose.card,
        x: pose.x,
        y: pose.y,
        z: pose.z,
        yaw: pose.yaw,
        flip: pose.faceUp ? 1 : 0,
        lift: 0,
        alpha: 1,
        glow: pose.glow || 0,
        dim: pose.dim || 0,
      });
    }
    this.dirty = true;
  }

  /** Write every changed instance to the GPU buffers. */
  commit() {
    if (!this.dirty) return false;
    CARD_IDS.forEach((id, i) => {
      const s = this.state.get(id);
      if (!s.visible || s.alpha <= 0.001) {
        this._m.makeScale(0, 0, 0);
        this.mesh.setMatrixAt(i, this._m);
        this.fxAttr.setXYZW(i, 0, 0, 0, 0);
        return;
      }
      // face down is half a turn about the card's long axis; while turning,
      // the card rises by half its width so its edge clears the felt
      const turn = Math.PI * (1 - s.flip);
      const rise = Math.sin(Math.PI * s.flip) * (CARD.w / 2 + 0.004);
      this._p.set(s.x, s.y + s.lift + rise, s.z);
      this._q.setFromAxisAngle(this._yAxis, s.yaw);
      this._qf.setFromAxisAngle(this._zAxis, turn);
      this._q.multiply(this._qf);
      this._m.compose(this._p, this._q, this._s);
      // a card lifted for inspection is posed over its resting place
      const over = this.poser ? this.poser(id, s, this._m) : null;
      this.mesh.setMatrixAt(i, over ? over.matrix : this._m);
      const rect = s.card == null ? this.backRect : this.atlas.rectFor(s.card);
      this.faceAttr.setXYZW(i, ...rect);
      this.fxAttr.setXYZW(i, s.glow, s.dim, over ? s.alpha * over.alpha : s.alpha, over ? over.sheen : 0);
    });
    this.mesh.instanceMatrix.needsUpdate = true;
    this.faceAttr.needsUpdate = true;
    this.fxAttr.needsUpdate = true;
    this.dirty = false;
    return true;
  }

  dispose() {
    this.geometry.dispose();
    this.material.dispose();
    this.mesh.dispose();
  }
}
