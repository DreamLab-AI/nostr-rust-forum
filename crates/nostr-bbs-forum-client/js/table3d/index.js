// index.js — the 3D table: one object per canvas, driven by frames.
//
// Loaded on demand by the wasm-bindgen snippet js/table3d.js (never on page
// load). `create(canvas, opts, deps)` resolves to a handle with `update`,
// `setOptions`, `onEvent` and `dispose`; the snippet turns that into the
// JSON-string seam the Rust component calls.
//
// The loop renders on demand: only while a beat animates, the camera
// settles, or something was just repainted. An idle table costs nothing. A
// hidden tab or a table scrolled out of view stops the loop, and anything
// queued meanwhile is fast-forwarded rather than replayed.
//
// Inspection (inspect.js): hovering a face-up group of cards lifts it to the
// camera. Its pose is composed over the cards' resting poses at commit time
// (CardSet.poser), never written to the card states, so the director's
// model and beats are untouched; a new frame drops the group first and the
// next beat waits until it has landed.

import * as THREE from './three.js';
import { anisotropy, createRenderer } from './renderer.js';
import { buildEnvironment, buildTable } from './scene.js';
import { CardAtlas } from './card-faces.js';
import { CardSet } from './cards.js';
import { ChipSet } from './chips.js';
import { CameraRig } from './camera.js';
import { Overlay } from './overlay.js';
import { Director, emptyModel } from './director.js';
import { Timeline, arc, lerp } from './timeline.js';
import { CARD_IDS, pileAmounts, planBeat, posesOf } from './choreography.js';
import { groupCards, groupOnFelt, groupsOf, pickOnFelt } from './picking.js';
import { Inspector, faceOnLayout, flourishPose } from './inspect.js';
import { PeekKeys } from './peek-keys.js';
import { AdaptiveDpr, dprCap, startTier } from './quality.js';
import { blobMaterial, buttonFace, buttonMaterials, chipMasks, tiling } from './materials.js';
import { CARD, LAYOUT, sideOf } from './layout.js';

/** The look when the operator sets none. */
export const DEFAULT_THEME = Object.freeze({
  felt: '#17603f',
  rail: '#5a4236', // multiplies the leather's own brown: a dark oxblood
  back: '#7a1d2e',
  accent: '#d9b46a',
  background: '#0b0f14',
  floor: '#12151b',
});

/** Options and their defaults. */
const DEFAULTS = Object.freeze({
  backend: 'webgpu',
  quality: 'auto',
  maxDpr: null,
  reducedMotion: false,
  fourColour: false,
  freeLook: false,
});

const asset = (path) => new URL(path, import.meta.url).href;

/** The shortest way round from angle `a` to `b`, at `t`. */
function lerpAngle(a, b, t) {
  let d = (b - a) % (Math.PI * 2);
  if (d > Math.PI) d -= Math.PI * 2;
  if (d < -Math.PI) d += Math.PI * 2;
  return a + d * t;
}

/** Every known card in a model, for the atlas to keep. */
function cardsOf(m) {
  const out = [...m.board];
  for (const s of m.seats) if (s && s.cards) for (const c of s.cards) if (c != null) out.push(c);
  return out;
}

/**
 * A table with one of everything on it — face-up, face-down and lit cards,
 * every pile, the button — drawn once at start-up to build every pipeline.
 */
function warmModel() {
  const m = emptyModel();
  m.button = 0;
  m.sb = 1;
  m.seats[0] = { ...m.seats[0], stack: 180, bet: 10, cards: [12, 51] };
  m.seats[1] = { ...m.seats[1], stack: 180, bet: 10, cards: [null, null] };
  m.board = [0, 13, 26, 39, 9];
  m.pot = 40;
  m.highlight = [12];
  return m;
}

class Table3D {
  constructor(canvas, opts, deps) {
    this.canvas = canvas;
    this.container = canvas.parentElement;
    this.opts = { ...DEFAULTS, ...opts };
    this.theme = { ...DEFAULT_THEME, ...(opts.theme || {}) };
    this.deps = deps || {};
    this.listeners = new Set();
    this.timeline = new Timeline();
    this.director = new Director({ bestFive: this.deps.bestFive || null });
    this.current = null;
    this.busy = false;
    this.winners = [];
    this.raf = 0;
    this.last = 0;
    this.hidden = typeof document !== 'undefined' && document.visibilityState === 'hidden';
    this.offscreen = false;
    this.disposed = false;
    this.lost = false;
    this.needsRender = true;
    this.frame = this.frame.bind(this);
  }

  // ── lifecycle ─────────────────────────────────────────────────────────────

  async start() {
    const coarse = matchMedia('(pointer: coarse)').matches;
    this.coarse = coarse;
    this.tier = startTier(this.opts.quality, {
      coarsePointer: coarse,
      deviceMemory: navigator.deviceMemory ?? 8,
      cores: navigator.hardwareConcurrency ?? 8,
    });
    const cap = dprCap(window.devicePixelRatio, { coarsePointer: coarse, maxDpr: this.opts.maxDpr });
    this.dpr = new AdaptiveDpr({ max: cap });
    // at a high pixel ratio the extra pixels already smooth the edges
    const { renderer, backend } = await createRenderer(this.canvas, {
      backend: this.opts.backend,
      antialias: cap <= 1.5,
      tier: this.tier,
    });
    if (this.disposed) {
      renderer.dispose();
      throw new Error('disposed during start');
    }
    this.renderer = renderer;
    this.backend = backend;
    renderer.setPixelRatio(this.dpr.current);
    renderer.onDeviceLost = (info) => this.deviceLost(info);

    this.scene = new THREE.Scene();
    const aniso = anisotropy(renderer);
    const maps = await this.loadMaps(aniso);
    this.table = buildTable(this.scene, { theme: this.theme, tier: this.tier, maps });
    this.maps = maps;
    this.disposeEnv = await buildEnvironment(renderer, this.scene, 0.45);

    await this.fontsReady();
    this.atlas = new CardAtlas({
      fourColour: this.opts.fourColour,
      back: { colour: this.theme.back, accent: this.theme.accent },
      assetUrl: asset,
      onChange: () => {
        if (this.atlasTexture) this.atlasTexture.needsUpdate = true;
        this.needsRender = true;
        this.request();
      },
    });
    this.atlasTexture = new THREE.CanvasTexture(this.atlas.canvas);
    this.atlasTexture.colorSpace = THREE.SRGBColorSpace;
    this.atlasTexture.anisotropy = aniso;
    this.cards = new CardSet(this.atlas, this.atlasTexture, { castShadow: this.tier === 'high' });
    this.scene.add(this.cards.mesh);

    const { edgeTex, capTex } = chipMasks();
    this.chipTextures = [edgeTex, capTex];
    this.chips = new ChipSet({ edgeMask: edgeTex, capMask: capTex, castShadow: this.tier === 'high' });
    this.scene.add(this.chips.mesh);

    this.buttonTexture = buttonFace();
    this.buttonGeometry = new THREE.CylinderGeometry(0.022, 0.022, 0.0065, 40);
    this.buttonGeometry.translate(0, 0.0065 / 2, 0);
    this.buttonMaterials = buttonMaterials(this.buttonTexture);
    this.button = new THREE.Mesh(this.buttonGeometry, this.buttonMaterials);
    this.button.castShadow = this.tier === 'high';
    this.button.visible = false;
    this.scene.add(this.button);

    if (this.tier !== 'high') this.buildBlobs();

    this.rig = new CameraRig(this.canvas, { reducedMotion: this.opts.reducedMotion, freeLook: this.opts.freeLook });
    this.rig.onChange = () => this.request();
    this.rig.onTap = (x, y, pointerType) => this.tap(x, y, pointerType);
    this.raycaster = new THREE.Raycaster();
    this.plane = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0);
    this.hit = new THREE.Vector3();
    this.hoverHandler = (e) => this.hover(e);
    this.leaveHandler = (e) => this.hoverOut(e);
    this.canvas.addEventListener('pointermove', this.hoverHandler);
    this.canvas.addEventListener('pointerleave', this.leaveHandler);

    this.overlay = new Overlay(this.container && this.container.querySelector('[data-t3d-overlay]'));
    this.buildInspection();
    this.resize();
    this.observe();

    // Build every pipeline before the first deal, behind the loading veil.
    // compileAsync alone misses what is not drawn yet (no chips, hidden
    // cards) and the shadow pass, and on a real GPU the physical materials
    // take a second or two to link: a first deal would freeze on them.
    this.snapTo(warmModel());
    this.cards.commit();
    this.chips.commit();
    this.commitBlobs();
    await renderer.compileAsync(this.scene, this.rig.camera);
    if (this.disposed) throw new Error('disposed during start');
    renderer.render(this.scene, this.rig.camera);
    this.snapTo(this.director.model);
    this.cards.commit();
    this.chips.commit();
    this.commitBlobs();
    this.needsRender = true;
    this.request();
    this.emit({ type: 'ready', backend: this.backend, tier: this.tier });
  }

  /** The CC0 maps; any that fail to load are left out, not fatal. */
  async loadMaps(aniso) {
    const loader = new THREE.TextureLoader();
    const load = async (path, rx, ry, colour) => {
      try {
        return tiling(await loader.loadAsync(asset(path)), rx, ry, aniso, colour);
      } catch (_e) {
        return null;
      }
    };
    const [leatherAlbedo, leatherNormal, leatherRough, woodAlbedo] = await Promise.all([
      load('assets/textures/leather-albedo.webp', 1, 1, true),
      load('assets/textures/leather-normal.webp', 1, 1, false),
      load('assets/textures/leather-rough.webp', 1, 1, false),
      load('assets/textures/wood-albedo.webp', 1, 1, true),
    ]);
    return { leatherAlbedo, leatherNormal, leatherRough, woodAlbedo };
  }

  /** Wait (briefly) for Inter, so the first faces are painted in it. */
  async fontsReady() {
    if (!document.fonts || !document.fonts.load) return;
    const wait = Promise.all([document.fonts.load('700 64px Inter'), document.fonts.load('800 64px Inter')]);
    await Promise.race([wait.catch(() => null), new Promise((r) => setTimeout(r, 1200))]);
  }

  observe() {
    this.onVisibility = () => {
      this.hidden = document.visibilityState === 'hidden';
      if (this.hidden) this.pause();
      else this.resume();
    };
    document.addEventListener('visibilitychange', this.onVisibility);
    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(this.container || this.canvas);
    this.intersection = new IntersectionObserver((entries) => {
      const visible = entries.some((e) => e.isIntersecting);
      this.offscreen = !visible;
      if (this.offscreen) this.pause();
      else this.resume();
    });
    this.intersection.observe(this.canvas);
    this.onMediaChange = () => {
      const cap = dprCap(window.devicePixelRatio, { coarsePointer: this.coarse, maxDpr: this.opts.maxDpr });
      this.dpr.setMax(cap);
      this.renderer.setPixelRatio(this.dpr.current);
      this.resize();
    };
    window.addEventListener('resize', this.onMediaChange);
  }

  resize() {
    if (!this.renderer) return;
    const w = Math.max(1, this.canvas.clientWidth);
    const h = Math.max(1, this.canvas.clientHeight);
    this.renderer.setSize(w, h, false);
    this.rig.fit(w, h);
    this.size = { w, h };
    this.needsRender = true;
    this.request();
  }

  /** Stop the loop; anything mid-animation jumps to where it was going. */
  pause() {
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
    this.last = 0;
    if (this.busy) this.fastForward();
  }

  resume() {
    if (this.hidden || this.offscreen) return;
    this.needsRender = true;
    this.request();
  }

  deviceLost(info) {
    if (this.lost || this.disposed) return;
    this.lost = true;
    this.pause();
    this.emit({ type: 'lost', reason: String((info && (info.message || info.reason)) || 'device lost') });
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
    this.timeline.clear();
    this.listeners.clear();
    if (this.onVisibility) document.removeEventListener('visibilitychange', this.onVisibility);
    if (this.onMediaChange) window.removeEventListener('resize', this.onMediaChange);
    if (this.resizeObserver) this.resizeObserver.disconnect();
    if (this.intersection) this.intersection.disconnect();
    if (this.hoverHandler) this.canvas.removeEventListener('pointermove', this.hoverHandler);
    if (this.leaveHandler) this.canvas.removeEventListener('pointerleave', this.leaveHandler);
    if (this.inspector) this.inspector.dispose();
    if (this.peekKeys) this.peekKeys.dispose();
    if (this.overlay && this.overlay.root) this.overlay.root.removeAttribute('data-t3d-inspecting');
    if (this.cards) this.cards.poser = null;
    if (this.rig) this.rig.dispose();
    if (this.cards) this.cards.dispose();
    if (this.chips) this.chips.dispose();
    if (this.blobs) {
      this.blobs.geometry.dispose();
      this.blobs.material.dispose();
      this.blobs.dispose();
    }
    if (this.buttonGeometry) this.buttonGeometry.dispose();
    if (this.buttonMaterials) new Set(this.buttonMaterials).forEach((m) => m.dispose());
    for (const t of [this.atlasTexture, this.buttonTexture, ...(this.chipTextures || [])]) if (t) t.dispose();
    if (this.maps) for (const t of Object.values(this.maps)) if (t) t.dispose();
    if (this.atlas) this.atlas.dispose();
    if (this.table) this.table.dispose();
    if (this.disposeEnv) this.disposeEnv();
    if (this.renderer) this.renderer.dispose();
  }

  // ── events ────────────────────────────────────────────────────────────────

  onEvent(cb) {
    this.listeners.add(cb);
    // a listener added after start still learns the backend and busy state
    if (this.renderer) {
      cb({ type: 'ready', backend: this.backend, tier: this.tier });
      cb({ type: 'busy', value: this.busy });
    }
    return () => this.listeners.delete(cb);
  }

  emit(ev) {
    for (const cb of this.listeners) {
      try {
        cb(ev);
      } catch (e) {
        console.warn('[table3d] event listener threw', e);
      }
    }
  }

  setBusy(v) {
    if (this.busy === v) return;
    this.busy = v;
    if (this.inspector) {
      this.inspector.setBlocked(v);
      // the pointer may have rested on a group while the beats played
      if (!v && this.lastHover) this.hoverAt(...this.lastHover);
    }
    this.emit({ type: 'busy', value: v });
  }

  // ── frames and options ────────────────────────────────────────────────────

  update(frame) {
    if (this.disposed || this.lost) return;
    const r = this.director.update(frame);
    if ((r === 'snap' || r === 'queued') && this.inspector) this.inspector.dropAll();
    if (r === 'snap') {
      this.timeline.finish();
      this.current = null;
      this.director.reconcile();
      this.snapTo(this.director.model);
      this.setBusy(false);
      this.needsRender = true;
      this.request();
      return;
    }
    if (r === 'queued') {
      if (this.hidden || this.offscreen || this.director.backlogged) {
        this.fastForward();
        return;
      }
      this.setBusy(true);
      this.request();
      return;
    }
    if (!this.busy) {
      // a new view with no new log entry: only who is to act can differ
      this.director.reconcile();
      this.needsRender = true;
      this.request();
    }
  }

  setOptions(o) {
    if (o.reducedMotion !== undefined) {
      this.opts.reducedMotion = !!o.reducedMotion;
      if (this.inspector) this.inspector.setReducedMotion(this.opts.reducedMotion);
    }
    if (o.freeLook !== undefined) this.opts.freeLook = !!o.freeLook;
    if (this.rig) this.rig.setOptions({ reducedMotion: this.opts.reducedMotion, freeLook: this.opts.freeLook });
    if (o.fourColour !== undefined) {
      this.opts.fourColour = !!o.fourColour;
      if (this.atlas) {
        this.atlas.setFourColour(this.opts.fourColour);
        this.cards.touch();
      }
    }
    if (o.maxDpr !== undefined && this.dpr) {
      this.opts.maxDpr = o.maxDpr;
      this.onMediaChange();
    }
    // `quality` and `backend` choose pipelines (shadows, the GPU API) and
    // apply at the next init; the Rust side re-creates the table for them.
    this.needsRender = true;
    this.request();
  }

  // ── the loop ──────────────────────────────────────────────────────────────

  request() {
    if (this.raf || this.disposed || this.lost || this.hidden || this.offscreen) return;
    this.raf = requestAnimationFrame(this.frame);
  }

  frame(now) {
    this.raf = 0;
    if (this.disposed || this.lost) return;
    // the atlas can ask for a frame while start() is still building the rig
    if (!this.rig || !this.size) return;
    // The clock restarts after every idle spell (last = 0), so the clamp
    // only guards against a stalled tab; it is generous so that a slow
    // device's animations, and the buttons they hold, keep wall-clock time.
    const dt = this.last ? Math.min(250, now - this.last) : 16;
    const continuous = this.last !== 0;
    this.last = now;

    this.timeline.tick(dt);
    // a group that lands this tick leaves the inspector, so note it was up:
    // its last commit must put it back exactly on its resting pose
    const wasPeeking = !this.inspector.idle;
    const peekMoving = this.inspector.tick(dt);
    this.advance();
    const camMoving = this.rig.tick(dt);
    // a lifted group faces the camera, so it follows every camera move
    if (wasPeeking && (peekMoving || camMoving || this.needsRender || this.inspector.idle)) this.cards.touch();
    // the face-on layout for this frame, after the camera has moved
    this.peekFrame = null;
    const cardsChanged = this.cards.commit();
    const chipsChanged = this.chips.commit();
    if (cardsChanged || chipsChanged || this.button.userData.moving) this.commitBlobs();
    if (camMoving || cardsChanged || chipsChanged || this.needsRender) {
      this.renderer.render(this.scene, this.rig.camera);
      this.overlay.place(this.rig.camera, this.size.w, this.size.h);
      this.overlay.write(this.chips.amounts, this.director.model, this.winners);
      this.syncPeekKeys();
      this.needsRender = false;
    }
    if (continuous) {
      const next = this.dpr.sample(dt);
      if (next != null) {
        this.renderer.setPixelRatio(next);
        this.resize();
        this.emit({ type: 'quality', dpr: next });
      }
    }
    if (this.timeline.active || camMoving || peekMoving || this.director.pending > 0 || this.current) {
      this.request();
    } else {
      this.last = 0;
    }
  }

  /** Between beats: finish the one that ended, start the next, or settle. */
  advance() {
    if (this.timeline.active) return;
    if (this.current) {
      this.finishBeat(this.current);
      this.current = null;
    }
    // an inspected group lands before the next beat plays
    if (!this.inspector.idle && this.director.pending > 0) return;
    const item = this.director.next();
    if (item) {
      this.startBeat(item);
      return;
    }
    if (this.busy) {
      this.director.reconcile();
      this.snapTo(this.director.model);
      this.setBusy(false);
      this.needsRender = true;
    }
  }

  /** Jump past everything queued, straight to the newest view. */
  fastForward() {
    if (this.inspector) this.inspector.reset();
    this.timeline.finish();
    this.current = null;
    this.director.skipAll();
    this.director.reconcile();
    this.snapTo(this.director.model);
    this.setBusy(false);
    this.needsRender = true;
    this.request();
  }

  /** Put every card, chip and the button where a model says, at once. */
  snapTo(model) {
    this.atlas.retain(cardsOf(model));
    const poses = posesOf(model);
    for (const id of CARD_IDS) this.cards.place(id, poses[id]);
    this.chips.configure(model.hero | 0, model.sb || 1);
    this.chips.set(pileAmounts(model));
    this.placeButton(model);
    this.winners = model.phase === 'done' && model.winners ? model.winners.map((w) => w.seat) : [];
  }

  placeButton(model) {
    if (model.button == null) {
      this.button.visible = false;
      return;
    }
    const a = LAYOUT[sideOf(model.button, model.hero | 0)].button;
    this.button.position.set(a.x, 0, a.z);
    this.button.visible = true;
  }

  startBeat(item) {
    this.current = item;
    this.setBusy(true);
    this.atlas.retain([...cardsOf(item.before), ...cardsOf(item.after)]);
    this.chips.configure(item.after.hero | 0, item.after.sb || 1);
    if (item.beat.type === 'reset' || item.beat.type === 'clear') this.winners = [];
    const plan = planBeat(item, { reducedMotion: this.opts.reducedMotion });
    for (const mv of plan.moves) this.schedule(mv, item, plan);
    // a beat with nothing to show still takes one tick, so beats stay in order
    this.timeline.add({ delay: plan.duration, duration: 0 });
    this.needsRender = true;
  }

  finishBeat(item) {
    const poses = posesOf(item.after);
    for (const id of CARD_IDS) this.cards.place(id, poses[id]);
    this.chips.set(pileAmounts(item.after));
    this.placeButton(item.after);
    if (item.beat.type === 'award') this.winners = item.beat.winners.map((w) => w.seat);
  }

  schedule(mv, item, plan) {
    const tl = this.timeline;
    const base = { delay: mv.delay, duration: mv.duration, ease: mv.ease };
    switch (mv.kind) {
      case 'card': {
        const st = this.cards.get(mv.id);
        const to = mv.to;
        let from = null;
        tl.add({
          ...base,
          start: () => {
            if (mv.from && mv.from !== 'current') {
              Object.assign(st, {
                visible: true,
                card: mv.from.card,
                x: mv.from.x,
                y: mv.from.y,
                z: mv.from.z,
                yaw: mv.from.yaw,
                flip: mv.from.faceUp ? 1 : 0,
                lift: 0,
                alpha: 1,
                glow: 0,
                dim: 0,
              });
            }
            from = { ...st };
            if (to.visible && to.card != null) st.card = to.card;
            st.visible = st.visible || !!to.visible;
            this.cards.touch();
          },
          update: (k) => {
            const toFlip = to.visible === false ? from.flip : to.faceUp ? 1 : 0;
            if (mv.fade) {
              // reduced motion: fade out where it was, fade in where it goes
              if (k < 0.5) {
                st.alpha = from.alpha * (1 - k * 2);
              } else {
                Object.assign(st, { x: to.x ?? st.x, y: to.y ?? st.y, z: to.z ?? st.z, yaw: to.yaw ?? st.yaw, flip: toFlip, lift: 0 });
                st.glow = to.glow || 0;
                st.dim = to.dim || 0;
                st.alpha = to.visible === false ? 0 : (k - 0.5) * 2;
              }
            } else {
              const p = mv.arc ? arc(from, to, mv.lift, k) : { x: lerp(from.x, to.x, k), y: lerp(from.y, to.y, k), z: lerp(from.z, to.z, k) };
              st.x = p.x;
              st.y = p.y;
              st.z = p.z;
              st.yaw = lerpAngle(from.yaw, to.yaw ?? from.yaw, k);
              // a dealt card turns over in the last part of its flight
              const fk = mv.flip ? k : Math.max(0, (k - 0.35) / 0.65);
              st.flip = lerp(from.flip, toFlip, fk);
              st.lift = mv.flip && mv.lift ? Math.sin(Math.PI * k) * mv.lift : 0;
              st.glow = lerp(from.glow, to.glow || 0, k);
              st.dim = lerp(from.dim, to.dim || 0, k);
              st.alpha = to.visible === false ? (k < 0.7 ? 1 : 1 - (k - 0.7) / 0.3) : 1;
            }
            this.cards.touch();
          },
          done: () => {
            if (to.visible === false) st.visible = false;
            this.cards.touch();
          },
        });
        break;
      }
      case 'chips': {
        let flight = null;
        tl.add({
          ...base,
          start: () => {
            if (mv.fade) {
              // reduced motion: the amounts change in place
              this.chips.add(mv.from, -mv.amount);
              this.chips.add(mv.to, mv.amount);
              return;
            }
            flight = this.chips.launch(mv.from, mv.to, mv.amount, mv.arc);
          },
          update: (k) => {
            if (!flight) return;
            flight.k = k;
            this.chips.dirty = true;
          },
          done: () => {
            if (flight) this.chips.land(flight);
          },
        });
        break;
      }
      case 'pulse':
        tl.add({ ...base, start: () => this.overlay.pulse(mv.seat, item.after, mv.duration + 240) });
        break;
      case 'button': {
        const a = LAYOUT[sideOf(mv.seat, item.after.hero | 0)].button;
        let from = null;
        tl.add({
          ...base,
          start: () => {
            from = this.button.visible ? this.button.position.clone() : new THREE.Vector3(a.x, 0, a.z);
            this.button.visible = true;
            this.button.userData.moving = true;
          },
          update: (k) => {
            const p = arc({ x: from.x, y: 0, z: from.z }, { x: a.x, y: 0, z: a.z }, mv.fade ? 0 : 0.015, k);
            this.button.position.set(p.x, p.y, p.z);
            this.needsRender = true;
          },
          done: () => {
            this.button.userData.moving = false;
          },
        });
        break;
      }
      case 'piles':
        tl.add({ ...base, start: () => this.chips.set(plan.piles) });
        break;
      case 'highlight': {
        const poses = posesOf(item.after);
        const from = new Map();
        tl.add({
          ...base,
          start: () => {
            for (const id of CARD_IDS) {
              const s = this.cards.get(id);
              from.set(id, { glow: s.glow, dim: s.dim });
            }
          },
          update: (k) => {
            for (const id of CARD_IDS) {
              const s = this.cards.get(id);
              const f = from.get(id);
              s.glow = lerp(f.glow, poses[id].glow || 0, k);
              s.dim = lerp(f.dim, poses[id].dim || 0, k);
            }
            this.cards.touch();
          },
        });
        break;
      }
      case 'winner':
        tl.add({ ...base, start: () => (this.winners = mv.seats.slice()) });
        break;
      default:
        break;
    }
  }

  // ── blob shadows (low tier) ───────────────────────────────────────────────

  buildBlobs() {
    const n = CARD_IDS.length + 5 + 6 + 2;
    this.blobAlpha = new THREE.InstancedBufferAttribute(new Float32Array(n), 1);
    this.blobAlpha.setUsage(THREE.DynamicDrawUsage);
    const geo = new THREE.PlaneGeometry(1, 1);
    geo.rotateX(-Math.PI / 2);
    this.blobs = new THREE.InstancedMesh(geo, blobMaterial({ alphaAttr: this.blobAlpha }), n);
    this.blobs.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.blobs.frustumCulled = false;
    this.blobs.renderOrder = -1;
    this.scene.add(this.blobs);
    this._bm = new THREE.Matrix4();
    this._bq = new THREE.Quaternion();
    this._bp = new THREE.Vector3();
    this._bs = new THREE.Vector3();
    this._by = new THREE.Vector3(0, 1, 0);
  }

  commitBlobs() {
    if (!this.blobs) return;
    let n = 0;
    const put = (x, z, sx, sz, yaw, alpha) => {
      if (n >= this.blobs.count) return;
      this._bp.set(x, 0.0008, z);
      this._bq.setFromAxisAngle(this._by, yaw);
      this._bs.set(sx, 1, sz);
      this._bm.compose(this._bp, this._bq, this._bs);
      this.blobs.setMatrixAt(n, this._bm);
      this.blobAlpha.setX(n, alpha);
      n += 1;
    };
    for (const id of CARD_IDS) {
      const s = this.cards.get(id);
      if (!s.visible) continue;
      const height = s.y + s.lift;
      const fade = Math.max(0, 1 - height * 12) * s.alpha * (1 - this.inspector.levelOf(id));
      put(s.x, s.z, CARD.w * 1.5, CARD.h * 1.35, s.yaw, fade);
    }
    put(LAYOUT.deck.x, LAYOUT.deck.z, CARD.h * 1.4, CARD.w * 1.5, 0, 0.9);
    for (const f of this.chips.footprints()) {
      const fade = f.lifted ? Math.max(0.2, 1 - f.lifted * 10) : 1;
      put(f.x, f.z, f.r * 2.5, f.r * 2.5, 0, fade);
    }
    if (this.button.visible) put(this.button.position.x, this.button.position.z, 0.07, 0.07, 0, 0.8);
    for (let i = n; i < this.blobs.count; i++) this.blobAlpha.setX(i, 0);
    this.blobs.instanceMatrix.needsUpdate = true;
    this.blobAlpha.needsUpdate = true;
  }

  // ── picking ───────────────────────────────────────────────────────────────

  feltPoint(x, y) {
    this.raycaster.setFromCamera({ x, y }, this.rig.camera);
    return this.raycaster.ray.intersectPlane(this.plane, this.hit) ? { x: this.hit.x, z: this.hit.z } : null;
  }

  tap(x, y, pointerType = 'mouse') {
    const pick = pickOnFelt(this.feltPoint(x, y), this.director.model);
    if (pick) this.emit(pick);
    // touch (and pen): a tap on a group inspects it, a tap anywhere else drops
    if (pointerType === 'mouse') return;
    const g = this.groupUnder(x, y);
    if (g && g === this.inspector.active) return;
    if (g) this.peek(g, 'tap');
    else this.inspector.leave();
  }

  hover(e) {
    if (e.pointerType !== 'mouse' || this.rig.drag) return;
    const [x, y] = this.rig.ndc(e);
    this.lastHover = [x, y];
    this.hoverAt(x, y);
  }

  hoverAt(x, y) {
    const g = this.groupUnder(x, y);
    const pick = pickOnFelt(this.feltPoint(x, y), this.director.model);
    this.canvas.style.cursor = pick || g ? 'pointer' : '';
    if (g) {
      if (g !== this.inspector.active) this.peek(g, 'hover');
    } else if (this.peekSource === 'hover') {
      this.inspector.leave();
    }
  }

  hoverOut(e) {
    if (e.pointerType !== 'mouse') return;
    this.lastHover = null;
    if (this.peekSource === 'hover') this.inspector.leave();
  }

  // ── inspection ────────────────────────────────────────────────────────────

  buildInspection() {
    this.inspector = new Inspector({ reducedMotion: this.opts.reducedMotion });
    this.inspector.setBlocked(this.busy);
    this.peekSource = null;
    this.lastHover = null;
    this.peekFrame = null;
    this.inspector.onPeek = (ev) => {
      if (!ev.inspecting) this.peekSource = null;
      if (this.overlay.root) this.overlay.root.toggleAttribute('data-t3d-inspecting', ev.inspecting);
      this.emit({ type: 'peek', group: ev.group, inspecting: ev.inspecting, cards: ev.cards });
      this.needsRender = true;
      this.request();
    };
    this._pm = new THREE.Matrix4();
    this._pp = new THREE.Vector3();
    this._pq = new THREE.Quaternion();
    this._ps = new THREE.Vector3();
    this._pt = new THREE.Vector3();
    this._qf = new THREE.Quaternion();
    this._qx = new THREE.Quaternion();
    this._basis = new THREE.Matrix4();
    this._right = new THREE.Vector3();
    this._up = new THREE.Vector3();
    this._back = new THREE.Vector3();
    this._down = new THREE.Vector3();
    this._camPos = new THREE.Vector3();
    this._one = new THREE.Vector3(1, 1, 1);
    this._ax = new THREE.Vector3(1, 0, 0);
    this._ay = new THREE.Vector3(0, 1, 0);
    this._az = new THREE.Vector3(0, 0, 1);
    this._inv = new THREE.Matrix4();
    this._ray = new THREE.Ray();
    this._corner = new THREE.Vector3();
    this.cards.poser = (id, _st, resting) => this.peekPose(id, resting);
    this.peekKeys = new PeekKeys(this.container, {
      onToggle: (g) => {
        if (this.inspector.active === g) this.inspector.leave();
        else this.peek(g, 'key');
      },
      onDrop: (g) => (this.peekSource === 'key' ? this.inspector.leave(g) : false),
    });
  }

  /** Lift group `g`, remembering what asked (hover, tap or key). */
  peek(g, source) {
    if (this.inspector.enter(g, groupCards(this.director.model, g))) {
      this.peekSource = source;
      this.request();
    }
  }

  /** The group whose cards are under NDC (x, y), lifted ones first. */
  groupUnder(x, y) {
    this.raycaster.setFromCamera({ x, y }, this.rig.camera);
    for (const g of this.inspector.groups.values()) {
      for (const id of g.ids) if (this.rayHitsCard(id)) return g.group;
    }
    return groupOnFelt(this.feltPoint(x, y), this.director.model);
  }

  /** Whether the raycaster's ray crosses card `id` where it is drawn now. */
  rayHitsCard(id) {
    const i = CARD_IDS.indexOf(id);
    if (i < 0) return false;
    this.cards.mesh.getMatrixAt(i, this._inv);
    if (Math.abs(this._inv.determinant()) < 1e-12) return false;
    this._inv.invert();
    this._ray.copy(this.raycaster.ray).applyMatrix4(this._inv);
    const t = -this._ray.origin.y / (this._ray.direction.y || 1e-9);
    if (!(t > 0)) return false;
    const px = this._ray.origin.x + this._ray.direction.x * t;
    const pz = this._ray.origin.z + this._ray.direction.z * t;
    return Math.abs(px) <= CARD.w / 2 + 0.004 && Math.abs(pz) <= CARD.h / 2 + 0.004;
  }

  /** The free band between the seat labels, in canvas pixels. */
  labelBand() {
    const root = this.overlay.root;
    if (!root) return null;
    const far = root.querySelector('[data-t3d-anchor="far-seat"]');
    const near = root.querySelector('[data-t3d-anchor="near-seat"]');
    const c = this.canvas.getBoundingClientRect();
    const h = this.size.h;
    let top = 0;
    let bottom = h;
    if (far) {
      const r = far.getBoundingClientRect();
      if (r.height > 0 && r.bottom - c.top < h / 2) top = r.bottom - c.top;
    }
    if (near) {
      const r = near.getBoundingClientRect();
      if (r.height > 0 && r.top - c.top > h / 2) bottom = r.top - c.top;
    }
    return { top, bottom };
  }

  /** The camera's basis and the face-on layouts, once per frame. */
  peekFrameState() {
    if (this.peekFrame) return this.peekFrame;
    const cam = this.rig.camera;
    cam.updateMatrixWorld(true);
    this._right.setFromMatrixColumn(cam.matrixWorld, 0).normalize();
    this._up.setFromMatrixColumn(cam.matrixWorld, 1).normalize();
    this._back.setFromMatrixColumn(cam.matrixWorld, 2).normalize();
    this._down.copy(this._up).negate();
    this._camPos.setFromMatrixPosition(cam.matrixWorld);
    // a face-on card: its x along camera right, its face (+y) towards the
    // camera, its top (−z) up
    this._basis.makeBasis(this._right, this._back, this._down);
    this._qf.setFromRotationMatrix(this._basis);
    this.peekFrame = { band: this.labelBand(), layouts: new Map() };
    return this.peekFrame;
  }

  layoutFor(n) {
    const pf = this.peekFrameState();
    let lay = pf.layouts.get(n);
    if (!lay) {
      const cam = this.rig.camera;
      lay = faceOnLayout(n, { fovY: (cam.fov * Math.PI) / 180, w: this.size.w, h: this.size.h, band: pf.band, near: cam.near });
      pf.layouts.set(n, lay);
    }
    return lay;
  }

  /**
   * The inspection pose of card `id` over its `resting` matrix, or null when
   * it is not lifted: `{matrix, alpha, sheen}`.
   */
  peekPose(id, resting) {
    const hit = this.inspector.lookup(id);
    if (!hit || !this.size) return null;
    const { g, i, n } = hit;
    this.peekFrameState();
    const lay = this.layoutFor(n);
    const motion = g.mode === 'motion';
    const fl = motion ? flourishPose(g.flourish, g.f, i, n) : null;
    const w = motion ? g.w : 0;
    const s = g.s;
    // the face-on target, with the flourish's offsets (scaled by its weight)
    const t = this._pt
      .copy(this._camPos)
      .addScaledVector(this._back, -(lay.d - (fl ? fl.dz * w : 0)))
      .addScaledVector(this._right, lay.xs[i] + (fl ? fl.dx * w : 0))
      .addScaledVector(this._up, lay.y + (fl ? fl.dy * w : 0));
    resting.decompose(this._pp, this._pq, this._ps);
    if (!motion) {
      // reduced motion: fade out on the felt, fade in face-on
      if (s < 0.5) return { matrix: resting, alpha: 1 - s * 2, sheen: 0 };
      this._pm.compose(t, this._qf, this._one);
      return { matrix: this._pm, alpha: (s - 0.5) * 2, sheen: 0 };
    }
    // travel: straight towards the camera, lifted off the felt early on
    this._pp.lerp(t, s);
    this._pp.y += 0.05 * Math.sin(Math.PI * s);
    this._pq.slerp(this._qf, s);
    // the flourish turns the card in its own frame, after the travel's turn
    if (fl.tumble) this._pq.multiply(this._qx.setFromAxisAngle(this._ax, fl.tumble * w));
    if (fl.spin) this._pq.multiply(this._qx.setFromAxisAngle(this._az, fl.spin * w));
    if (fl.roll) this._pq.multiply(this._qx.setFromAxisAngle(this._ay, fl.roll * w));
    this._pm.compose(this._pp, this._pq, this._one);
    // gloss rises with the flourish; a falling card's is negative: no glint
    const sheen = fl.sheen * w * (g.dir < 0 ? -1 : 1);
    return { matrix: this._pm, alpha: 1, sheen };
  }

  /** Lay the keyboard buttons over their groups and mark the lifted one. */
  syncPeekKeys() {
    if (!this.peekKeys || !this.size) return;
    const model = this.director.model;
    const available = new Set(this.busy ? [] : groupsOf(model));
    for (const g of this.inspector.groups.keys()) available.add(g);
    const rects = new Map();
    const c = this.rig.camera;
    for (const g of available) {
      const members = this.inspector.groups.get(g) || groupCards(model, g);
      if (!members) continue;
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const id of members.ids) {
        const idx = CARD_IDS.indexOf(id);
        if (idx < 0) continue;
        this.cards.mesh.getMatrixAt(idx, this._inv);
        for (const [cx, cz] of [[-1, -1], [1, -1], [1, 1], [-1, 1]]) {
          this._corner.set((cx * CARD.w) / 2, 0, (cz * CARD.h) / 2).applyMatrix4(this._inv).project(c);
          const px = ((this._corner.x + 1) / 2) * this.size.w;
          const py = ((1 - this._corner.y) / 2) * this.size.h;
          x0 = Math.min(x0, px);
          y0 = Math.min(y0, py);
          x1 = Math.max(x1, px);
          y1 = Math.max(y1, py);
        }
      }
      if (x1 > x0) rects.set(g, { x: x0 - 4, y: y0 - 4, w: x1 - x0 + 8, h: y1 - y0 + 8 });
    }
    this.peekKeys.sync(available, this.inspector.active, rects);
  }
}

/**
 * Start a table on `canvas`. Resolves once the first frame's pipelines are
 * compiled and the `ready` event has been sent; rejects (and cleans up) if
 * neither GPU backend starts.
 */
export async function create(canvas, opts = {}, deps = {}) {
  const t = new Table3D(canvas, opts, deps);
  const api = {
    update: (frame) => t.update(frame),
    setOptions: (o) => t.setOptions(o || {}),
    onEvent: (cb) => t.onEvent(cb),
    dispose: () => t.dispose(),
    // for tests and diagnosis in the browser console
    get backend() {
      return t.backend;
    },
    get drift() {
      return t.director.drift;
    },
    // the inspection now: which group is up and the last flourish chosen
    get inspect() {
      const i = t.inspector;
      return i ? { active: i.active, lastFlourish: i.lastFlourish, groups: [...i.groups.keys()] } : null;
    },
  };
  try {
    await t.start();
  } catch (e) {
    t.dispose();
    throw e;
  }
  return api;
}

