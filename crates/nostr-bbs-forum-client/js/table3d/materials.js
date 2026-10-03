// materials.js — the table's node materials (TSL), for both backends.
//
// Physically based throughout: the felt is cloth (sheen) with procedural
// fibre and mottling so it never visibly tiles; the rail is padded leather
// and the racetrack lacquered wood, both from small CC0 maps; cards are
// coated stock (a little clearcoat) reading their faces from the shared
// atlas; chips are clay with edge spots. Everything per-instance (which face
// a card shows, its glow and fade, a chip's colours) arrives as instanced
// attributes, so all cards are one draw and all chips another.

import * as THREE from './three.js';
import { TABLE } from './layout.js';

const {
  abs, attribute, clamp, float, instancedDynamicBufferAttribute, length, max, min, mix,
  mx_fractal_noise_float, mx_noise_float, oneMinus, positionWorld, select, sin, smoothstep,
  texture, uniform, uv, vec2, vec3, bumpMap,
} = THREE.TSL;

/**
 * Signed distance (metres) from a point on the felt plane to a stadium of
 * the table's proportions inset by `inset`: negative inside.
 */
function stadiumSdf(p, inset) {
  const r = TABLE.halfDepth - inset;
  const straight = TABLE.halfLength - TABLE.halfDepth;
  const q = vec2(max(abs(p.x).sub(straight), 0.0), p.y);
  return length(q).sub(r);
}

/**
 * The baize. `tier` `high` adds a fibre bump; both tiers get the mottling,
 * the printed betting line and the darkening under the rail's lip, which
 * stands in for ambient occlusion where shadows are off.
 */
export function feltMaterial({ colour, tier }) {
  const base = new THREE.Color(colour);
  const m = new THREE.MeshPhysicalNodeMaterial({ roughness: 0.92, metalness: 0 });
  const p = positionWorld.xz;
  const mottle = mx_fractal_noise_float(vec3(p.mul(5.0), 0.0), 3, 2.0, 0.5);
  const fibre = mx_noise_float(vec3(p.mul(260.0), 0.0));
  const tint = vec3(base.r, base.g, base.b);
  let c = tint.mul(float(0.94).add(mottle.mul(0.07)).add(fibre.mul(0.035)));
  // the printed racetrack line, a slightly lighter, worn ink
  const d = stadiumSdf(p, 0.115);
  const line = oneMinus(smoothstep(0.0011, 0.0024, abs(d)));
  c = mix(c, tint.mul(1.55).add(0.03), line.mul(0.5));
  // shade under the rail
  const edge = stadiumSdf(p, 0.0);
  const shade = smoothstep(-0.09, 0.0, edge).mul(0.45);
  c = c.mul(oneMinus(shade));
  m.colorNode = c;
  m.sheen = 1.0;
  m.sheenRoughness = 0.75;
  m.sheenColor = base.clone().offsetHSL(0, -0.05, 0.12);
  if (tier === 'high') {
    m.normalNode = bumpMap(fibre.mul(0.5).add(mottle.mul(0.2)), float(0.0006));
  }
  return m;
}

/** Repeat-wrapped, mip-mapped, anisotropic: how every tiling map is set up. */
export function tiling(tex, repeatX, repeatY, aniso, colour = false) {
  if (!tex) return null;
  tex.wrapS = THREE.RepeatWrapping;
  tex.wrapT = THREE.RepeatWrapping;
  tex.repeat.set(repeatX, repeatY);
  tex.anisotropy = aniso;
  tex.colorSpace = colour ? THREE.SRGBColorSpace : THREE.NoColorSpace;
  tex.needsUpdate = true;
  return tex;
}

/** The padded rail: leather maps tinted by the theme's rail colour. */
export function railMaterial({ colour, maps }) {
  const m = new THREE.MeshPhysicalNodeMaterial({
    color: new THREE.Color(colour),
    roughness: 0.62,
    metalness: 0,
    clearcoat: 0.25,
    clearcoatRoughness: 0.45,
  });
  if (maps.albedo) m.map = maps.albedo;
  if (maps.normal) {
    m.normalMap = maps.normal;
    m.normalScale = new THREE.Vector2(0.9, 0.9);
  }
  if (maps.rough) m.roughnessMap = maps.rough;
  return m;
}

/** The racetrack: dark wood under a hard lacquer. */
export function woodMaterial({ maps }) {
  const m = new THREE.MeshPhysicalNodeMaterial({
    color: new THREE.Color(0xc8b29a),
    roughness: 0.38,
    metalness: 0,
    clearcoat: 1.0,
    clearcoatRoughness: 0.07,
  });
  if (maps.albedo) m.map = maps.albedo;
  else m.color = new THREE.Color(0x3b2416);
  return m;
}

/** The apron under the rail and the floor: plain, dark, rough. */
export function plainMaterial(colour, roughness = 0.8) {
  return new THREE.MeshStandardNodeMaterial({ color: new THREE.Color(colour), roughness, metalness: 0 });
}

/**
 * The cards. `faceAttr` (vec4 per instance) is the face's atlas rectangle;
 * `fxAttr` (vec4) carries glow, dim and opacity. The geometry's `side`
 * attribute says which surface a vertex is on: 1 face, 0 back, 0.5 edge.
 */
export function cardMaterial({ atlasTexture, faceAttr, fxAttr, backRect }) {
  const m = new THREE.MeshPhysicalNodeMaterial({
    roughness: 0.42,
    metalness: 0,
    clearcoat: 0.35,
    clearcoatRoughness: 0.3,
    transparent: true,
  });
  const face = instancedDynamicBufferAttribute(faceAttr);
  const fx = instancedDynamicBufferAttribute(fxAttr);
  const side = attribute('side', 'float');
  const back = uniform(new THREE.Vector4(...backRect));
  const rect = select(side.greaterThan(0.75), face, back);
  const auv = rect.xy.add(uv().mul(rect.zw));
  const ink = texture(atlasTexture, auv).rgb;
  const isEdge = side.greaterThan(0.25).and(side.lessThan(0.75));
  const paper = select(isEdge, vec3(0.9, 0.89, 0.85), ink);
  m.colorNode = paper.mul(oneMinus(fx.y.mul(0.62)));
  // the winning five: a warm rim on the face, strongest at the edge
  const u = uv();
  const toEdge = min(min(u.x, oneMinus(u.x)), min(u.y, oneMinus(u.y)));
  const rim = oneMinus(smoothstep(0.0, 0.07, toEdge));
  // inspection sheen (fx.w): its size raises the coat's gloss; while it is
  // positive (a card on its way up) a glint also sweeps the face corner to
  // corner as it grows, and is gone by the time it reaches 1
  const sheen = abs(fx.w);
  m.clearcoatNode = float(0.35).add(sheen.mul(0.65));
  m.clearcoatRoughnessNode = float(0.3).sub(sheen.mul(0.24));
  const diag = u.x.add(oneMinus(u.y)).mul(0.5);
  const sweep = oneMinus(smoothstep(0.0, 0.09, abs(diag.sub(sheen.mul(1.6).sub(0.3)))));
  const glint = select(fx.w.greaterThan(0.0).and(side.greaterThan(0.75)), sweep.mul(sin(sheen.mul(Math.PI))).mul(0.55), float(0.0));
  m.emissiveNode = vec3(1.0, 0.7, 0.24).mul(fx.x).mul(rim.mul(2.4).add(0.08)).add(vec3(1.0, 0.97, 0.9).mul(glint));
  m.opacityNode = clamp(fx.z, 0.0, 1.0);
  m.metadata = { back };
  return m;
}

/**
 * The chips: clay coloured per instance (`colourAttr`, `stripeAttr`, vec3),
 * with the edge spots and the top inlay read from two small mask textures.
 * The geometry's `part` attribute is 0 on the rim, 1 on the faces.
 */
export function chipMaterial({ colourAttr, stripeAttr, edgeMask, capMask }) {
  const m = new THREE.MeshPhysicalNodeMaterial({
    roughness: 0.48,
    metalness: 0,
    clearcoat: 0.15,
    clearcoatRoughness: 0.5,
  });
  const body = instancedDynamicBufferAttribute(colourAttr);
  const stripe = instancedDynamicBufferAttribute(stripeAttr);
  const part = attribute('part', 'float');
  const edge = texture(edgeMask, uv()).r;
  const cap = texture(capMask, uv());
  const rimColour = mix(body, stripe, edge);
  // the top: body, an inlay ring in the stripe colour, a lighter centre disc
  const capColour = mix(mix(body, stripe, cap.r), vec3(0.93, 0.91, 0.86), cap.g.mul(0.85));
  m.colorNode = select(part.greaterThan(0.5), capColour, rimColour);
  return m;
}

/**
 * The soft dark ellipse that grounds a card or a pile where real-time
 * shadows are off. Opacity per instance in `alphaAttr` (float).
 */
export function blobMaterial({ alphaAttr }) {
  const m = new THREE.MeshBasicNodeMaterial({ transparent: true, depthWrite: false });
  const a = instancedDynamicBufferAttribute(alphaAttr);
  const d = length(uv().sub(0.5)).mul(2.0);
  m.colorNode = vec3(0.0, 0.0, 0.0);
  m.opacityNode = oneMinus(smoothstep(0.35, 1.0, d)).mul(a).mul(0.55);
  return m;
}

/** The dealer button: white acrylic with the word on its face. */
export function buttonMaterials(faceTexture) {
  const rim = new THREE.MeshPhysicalNodeMaterial({ color: 0xf4f1ea, roughness: 0.3, clearcoat: 1.0, clearcoatRoughness: 0.08 });
  const top = new THREE.MeshPhysicalNodeMaterial({ map: faceTexture, roughness: 0.3, clearcoat: 1.0, clearcoatRoughness: 0.08 });
  return [rim, top, top];
}

/** Draw the two chip masks: edge spots (rim) and the inlay (top). */
export function chipMasks() {
  const edge = document.createElement('canvas');
  edge.width = 256;
  edge.height = 16;
  const e = edge.getContext('2d');
  e.fillStyle = '#000';
  e.fillRect(0, 0, 256, 16);
  e.fillStyle = '#f00';
  // six edge spots, each a short block, as on a casino chip
  for (let i = 0; i < 6; i++) e.fillRect(i * (256 / 6) + 10, 0, 256 / 6 - 22, 16);
  const top = document.createElement('canvas');
  top.width = 128;
  top.height = 128;
  const t = top.getContext('2d');
  t.fillStyle = '#000';
  t.fillRect(0, 0, 128, 128);
  // R: the inlay ring and its spokes; G: the centre disc
  t.strokeStyle = '#f00';
  t.lineWidth = 6;
  t.beginPath();
  t.arc(64, 64, 46, 0, Math.PI * 2);
  t.stroke();
  t.lineWidth = 9;
  for (let i = 0; i < 6; i++) {
    const a = (i / 6) * Math.PI * 2;
    t.beginPath();
    t.moveTo(64 + Math.cos(a) * 52, 64 + Math.sin(a) * 52);
    t.lineTo(64 + Math.cos(a) * 62, 64 + Math.sin(a) * 62);
    t.stroke();
  }
  t.fillStyle = '#0f0';
  t.beginPath();
  t.arc(64, 64, 30, 0, Math.PI * 2);
  t.fill();
  const edgeTex = new THREE.CanvasTexture(edge);
  edgeTex.wrapS = THREE.RepeatWrapping;
  const capTex = new THREE.CanvasTexture(top);
  for (const tx of [edgeTex, capTex]) tx.colorSpace = THREE.NoColorSpace;
  return { edgeTex, capTex };
}

/** The dealer button's face: "DEALER" round a centred D. */
export function buttonFace() {
  const c = document.createElement('canvas');
  c.width = 256;
  c.height = 256;
  const g = c.getContext('2d');
  g.fillStyle = '#f4f1ea';
  g.fillRect(0, 0, 256, 256);
  g.strokeStyle = '#1b1b1d';
  g.lineWidth = 6;
  g.beginPath();
  g.arc(128, 128, 104, 0, Math.PI * 2);
  g.stroke();
  g.fillStyle = '#1b1b1d';
  g.textAlign = 'center';
  g.textBaseline = 'middle';
  g.font = '800 120px "Inter", "Helvetica Neue", Arial, sans-serif';
  g.fillText('D', 128, 134);
  g.font = '700 26px "Inter", "Helvetica Neue", Arial, sans-serif';
  const word = 'DEALER';
  for (let i = 0; i < word.length; i++) {
    const a = -Math.PI / 2 + (i - (word.length - 1) / 2) * 0.32;
    g.save();
    g.translate(128 + Math.cos(a) * 80, 128 + Math.sin(a) * 80);
    g.rotate(a + Math.PI / 2);
    g.fillText(word[i], 0, 0);
    g.restore();
  }
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

