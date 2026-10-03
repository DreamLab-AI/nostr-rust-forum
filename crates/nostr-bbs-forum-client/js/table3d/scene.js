// scene.js — the room and the table: felt, racetrack, padded rail, apron,
// floor, the lamp over the table and the studio reflections.
//
// The table outline is a stadium (see layout.js). The felt and the
// racetrack are flat shapes; the rail is swept from a padded profile along
// the outline, generated here rather than modelled, so the whole table is a
// few kilobytes of code and no mesh download.

import * as THREE from './three.js';
import { TABLE } from './layout.js';
import { feltMaterial, plainMaterial, railMaterial, woodMaterial } from './materials.js';

/** A stadium outline (x along the length, y along the depth) inset by `inset`. */
function stadiumShape(inset = 0) {
  const r = TABLE.halfDepth + inset;
  const s = TABLE.halfLength - TABLE.halfDepth;
  const shape = new THREE.Shape();
  shape.moveTo(-s, -r);
  shape.lineTo(s, -r);
  shape.absarc(s, 0, r, -Math.PI / 2, Math.PI / 2, false);
  shape.lineTo(-s, r);
  shape.absarc(-s, 0, r, Math.PI / 2, (3 * Math.PI) / 2, false);
  shape.autoClose = true;
  return shape;
}

/**
 * Points round the stadium at offset `inset` (metres outward), evenly spaced,
 * with their outward normals: the path the rail is swept along.
 */
export function stadiumPath(inset, n) {
  const r = TABLE.halfDepth + inset;
  const s = TABLE.halfLength - TABLE.halfDepth;
  const straight = 2 * s;
  const arcLen = Math.PI * r;
  const total = 2 * straight + 2 * arcLen;
  const pts = [];
  for (let i = 0; i < n; i++) {
    let d = (i / n) * total;
    let x, z, nx, nz;
    if (d < straight) {
      // near straight, running +x
      x = -s + d;
      z = r;
      nx = 0;
      nz = 1;
    } else if ((d -= straight) < arcLen) {
      const a = Math.PI / 2 - d / r; // right end, from +z round to −z
      x = s + Math.cos(a) * r;
      z = Math.sin(a) * r;
      nx = Math.cos(a);
      nz = Math.sin(a);
    } else if ((d -= arcLen) < straight) {
      x = s - d;
      z = -r;
      nx = 0;
      nz = -1;
    } else {
      d -= straight;
      const a = -Math.PI / 2 - d / r; // left end, from −z round to +z
      x = -s + Math.cos(a) * r;
      z = Math.sin(a) * r;
      nx = Math.cos(a);
      nz = Math.sin(a);
    }
    pts.push({ x, z, nx, nz, u: (i / n) * total });
  }
  return { pts, total };
}

/**
 * The padded rail: a rounded, slightly bulging profile swept round the
 * table. UVs run along the rail (u, in metres) and round the profile (v).
 */
function railGeometry() {
  const inner = TABLE.trim;
  const w = TABLE.railWidth;
  const h = TABLE.railHeight;
  const along = 192;
  const around = 20;
  const { pts } = stadiumPath(inner, along);
  // profile: a squashed half-pipe from the inner lip, over the top, to the
  // outer drop, as (out, up) offsets
  const profile = [];
  for (let j = 0; j <= around; j++) {
    const t = j / around;
    const a = Math.PI * (1 - t); // inner side → top → outer side
    const out = w / 2 + Math.cos(a) * (w / 2);
    const up = Math.sin(a) * h * (0.82 + 0.18 * Math.sin(a)) + 0.004;
    profile.push([out, up, t]);
  }
  const pos = [];
  const uvs = [];
  const idx = [];
  for (let i = 0; i <= along; i++) {
    const p = pts[i % along];
    const u = i === along ? pts.length : i;
    for (const [out, up, t] of profile) {
      pos.push(p.x + p.nx * out, up, p.z + p.nz * out);
      uvs.push((u / along) * 36, t);
    }
  }
  const row = profile.length;
  for (let i = 0; i < along; i++) {
    for (let j = 0; j < row - 1; j++) {
      const a = i * row + j;
      const b = (i + 1) * row + j;
      idx.push(a, a + 1, b, b, a + 1, b + 1);
    }
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
  g.setAttribute('uv', new THREE.Float32BufferAttribute(uvs, 2));
  g.setIndex(idx);
  g.computeVertexNormals();
  return g;
}

/** A flat stadium ring (the racetrack) between two insets, UVs in metres. */
function ringGeometry(innerInset, outerInset) {
  const shape = stadiumShape(outerInset);
  const hole = stadiumShape(innerInset);
  shape.holes.push(hole);
  const g = new THREE.ShapeGeometry(shape, 48);
  g.rotateX(-Math.PI / 2);
  const p = g.getAttribute('position');
  const uv = g.getAttribute('uv');
  for (let i = 0; i < p.count; i++) uv.setXY(i, p.getX(i) * 4, p.getZ(i) * 4);
  return g;
}

/** The apron: the table's side, from under the rail down to the base. */
function apronGeometry() {
  const { pts } = stadiumPath(TABLE.trim + TABLE.railWidth * 0.92, 160);
  const pos = [];
  const idx = [];
  for (let i = 0; i <= pts.length; i++) {
    const p = pts[i % pts.length];
    pos.push(p.x, 0.004, p.z, p.x * 0.96, -TABLE.bodyDepth, p.z * 0.96);
  }
  for (let i = 0; i < pts.length; i++) {
    const a = i * 2;
    idx.push(a, a + 1, a + 2, a + 1, a + 3, a + 2); // outward-facing
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
  g.setIndex(idx);
  g.computeVertexNormals();
  return g;
}

/**
 * Build the room and table into `scene`. `maps` holds the loaded CC0
 * textures (any may be null: the material falls back to a plain colour).
 * Returns the objects that later code needs and a `dispose()`.
 */
export function buildTable(scene, { theme, tier, maps }) {
  const owned = [];
  const own = (x) => (owned.push(x), x);

  scene.background = new THREE.Color(theme.background);
  scene.fog = new THREE.Fog(new THREE.Color(theme.background), 2.6, 6.5);

  // felt
  const feltGeo = own(new THREE.ShapeGeometry(stadiumShape(0), 48));
  feltGeo.rotateX(-Math.PI / 2);
  const felt = new THREE.Mesh(feltGeo, own(feltMaterial({ colour: theme.felt, tier })));
  felt.receiveShadow = true;
  felt.name = 'felt';
  scene.add(felt);

  // racetrack
  const wood = new THREE.Mesh(own(ringGeometry(0, TABLE.trim)), own(woodMaterial({ maps: { albedo: maps.woodAlbedo } })));
  wood.position.y = 0.0015;
  wood.receiveShadow = true;
  scene.add(wood);

  // rail
  const rail = new THREE.Mesh(
    own(railGeometry()),
    own(railMaterial({ colour: theme.rail, maps: { albedo: maps.leatherAlbedo, normal: maps.leatherNormal, rough: maps.leatherRough } })),
  );
  rail.castShadow = tier === 'high';
  rail.receiveShadow = true;
  scene.add(rail);

  // apron and floor
  const apron = new THREE.Mesh(own(apronGeometry()), own(plainMaterial(0x15100c, 0.7)));
  scene.add(apron);
  const floor = new THREE.Mesh(own(new THREE.CircleGeometry(6, 48)), own(plainMaterial(theme.floor, 0.96)));
  floor.rotation.x = -Math.PI / 2;
  floor.position.y = -TABLE.bodyDepth - 0.55;
  floor.receiveShadow = tier === 'high';
  scene.add(floor);

  // the lamp: one warm spot straight over the table, soft-edged, plus a
  // cool sky fill so the shadows are not black
  const lamp = new THREE.SpotLight(0xfff1dc, 9, 0, 0.78, 0.7, 2);
  lamp.position.set(0.12, 1.75, 0.35);
  lamp.target.position.set(0, 0, 0);
  scene.add(lamp, lamp.target);
  if (tier === 'high') {
    lamp.castShadow = true;
    lamp.shadow.mapSize.set(2048, 2048);
    lamp.shadow.camera.near = 0.6;
    lamp.shadow.camera.far = 3.2;
    lamp.shadow.bias = -0.00015;
    lamp.shadow.normalBias = 0.004;
    lamp.shadow.radius = 4;
  }
  const fill = new THREE.HemisphereLight(0xcfd8ff, 0x1a1208, 0.35);
  scene.add(fill);

  return {
    felt,
    lamp,
    dispose() {
      for (const x of owned) x.dispose();
      scene.remove(felt, wood, rail, apron, floor, lamp, lamp.target, fill);
    },
  };
}

/**
 * The studio reflections: three's procedural RoomEnvironment, prefiltered
 * once into the scene's environment. Gives the lacquer and the card coating
 * something to reflect without downloading an HDRI. Returns a disposer.
 */
export async function buildEnvironment(renderer, scene, intensity = 0.4) {
  const pmrem = new THREE.PMREMGenerator(renderer);
  const room = new THREE.RoomEnvironment();
  const target = pmrem.fromSceneAsync ? await pmrem.fromSceneAsync(room, 0.04) : pmrem.fromScene(room, 0.04);
  scene.environment = target.texture;
  scene.environmentIntensity = intensity;
  room.traverse((o) => {
    if (o.geometry) o.geometry.dispose();
    if (o.material) o.material.dispose();
  });
  return () => {
    scene.environment = null;
    target.dispose();
    pmrem.dispose();
  };
}
