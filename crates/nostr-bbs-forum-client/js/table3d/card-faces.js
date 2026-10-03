// card-faces.js — the card atlas: which card sits in which slot of one
// canvas texture, and how each face and the back are painted.
//
// Heads-up shows at most nine distinct faces in a hand (two hole cards each,
// five on the board), so one 2048² canvas with fifteen card slots holds every
// face the table needs plus the back, repainted as cards are dealt, and GPU
// memory stays fixed whatever the deck. Pips, indices and the back are drawn
// in code; the twelve court figures are Dmitry Fomin's English-pattern deck
// (CC0, Wikimedia Commons; see assets/cards/LICENSE.md), loaded only when a
// court card is first dealt, with a drawn court standing in until it arrives.
//
// The pure parts (slot bookkeeping, layouts, the painter given any 2D
// context) run under node in tools/table3d-test.mjs; `CardAtlas` is the
// browser half and is the only thing here that touches the DOM.

/** The atlas grid: 5 × 3 cells of 408 × 568 px, each a 400 × 560 card. */
export const ATLAS = Object.freeze({
  width: 2048,
  height: 2048,
  cols: 5,
  rows: 3,
  slots: 15,
  cellW: 408,
  cellH: 568,
  cardW: 400,
  cardH: 560,
  gutter: 4,
  back: 0, // slot 0 is always the back
});

/** Ranks by `card % 13` (0 = deuce … 12 = ace). */
export const RANKS = Object.freeze(['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']);
/** Suits by `card / 13`, in the engine's order. */
export const SUIT_NAMES = Object.freeze(['clubs', 'diamonds', 'hearts', 'spades']);
const COURTS = Object.freeze({ 9: 'jack', 10: 'queen', 11: 'king' });

/** Ink colours: the usual red and black, or the four-colour deck. */
export const SUIT_INK = Object.freeze({
  two: Object.freeze(['#16161b', '#c1121f', '#c1121f', '#16161b']),
  four: Object.freeze(['#0f7a3a', '#1d5fbf', '#c1121f', '#16161b']),
});

/** A card index split into what is drawn: rank label, suit, court figure. */
export function cardParts(card) {
  const r = ((card % 13) + 13) % 13;
  return { rank: RANKS[r], suit: Math.floor(card / 13), court: COURTS[r] || null };
}

/**
 * Pip centres for a number card, rank index 0 (deuce) … 8 (ten), in a unit
 * field: x across, y down. Pips below the middle are drawn upside down.
 */
export function pipLayout(r) {
  const L = 0.0, C = 0.5, R = 1.0;
  const four = [[L, 0], [R, 0], [L, 1], [R, 1]];
  switch (r) {
    case 0: return [[C, 0], [C, 1]];
    case 1: return [[C, 0], [C, 0.5], [C, 1]];
    case 2: return four;
    case 3: return [...four, [C, 0.5]];
    case 4: return [...four, [L, 0.5], [R, 0.5]];
    case 5: return [...four, [L, 0.5], [R, 0.5], [C, 0.25]];
    case 6: return [...four, [L, 0.5], [R, 0.5], [C, 0.25], [C, 0.75]];
    case 7: return [[L, 0], [R, 0], [L, 1 / 3], [R, 1 / 3], [L, 2 / 3], [R, 2 / 3], [L, 1], [R, 1], [C, 0.5]];
    case 8: return [[L, 0], [R, 0], [L, 1 / 3], [R, 1 / 3], [L, 2 / 3], [R, 2 / 3], [L, 1], [R, 1], [C, 1 / 6], [C, 5 / 6]];
    default: return [];
  }
}

/**
 * Trace one suit symbol as a path in a box of side `s` centred on (cx, cy),
 * pointing up (spade and heart lobes up, as on a card's upper half).
 */
export function suitPath(ctx, suit, cx, cy, s) {
  const P = (x, y) => [cx + x * s, cy + y * s];
  const m = (x, y) => ctx.moveTo(...P(x, y));
  const l = (x, y) => ctx.lineTo(...P(x, y));
  const c = (a, b, d, e, f, g) => ctx.bezierCurveTo(...P(a, b), ...P(d, e), ...P(f, g));
  const q = (a, b, d, e) => ctx.quadraticCurveTo(...P(a, b), ...P(d, e));
  ctx.beginPath();
  switch (suit) {
    case 0: // clubs: three lobes and a flared stem
      ctx.moveTo(...P(0.22, -0.24));
      ctx.arc(...P(0, -0.24), 0.22 * s, 0, Math.PI * 2);
      ctx.moveTo(...P(-0.02, 0.07));
      ctx.arc(...P(-0.24, 0.07), 0.22 * s, 0, Math.PI * 2);
      ctx.moveTo(...P(0.46, 0.07));
      ctx.arc(...P(0.24, 0.07), 0.22 * s, 0, Math.PI * 2);
      ctx.moveTo(...P(0.12, 0.0));
      ctx.arc(...P(0, 0.0), 0.12 * s, 0, Math.PI * 2);
      m(0.035, 0.02);
      q(0.05, 0.36, 0.2, 0.5);
      l(-0.2, 0.5);
      q(-0.05, 0.36, -0.035, 0.02);
      break;
    case 1: // diamonds: a rhombus with gently hollow sides
      m(0, -0.5);
      q(0.12, -0.22, 0.38, 0);
      q(0.12, 0.22, 0, 0.5);
      q(-0.12, 0.22, -0.38, 0);
      q(-0.12, -0.22, 0, -0.5);
      break;
    case 2: // hearts
      m(0, 0.44);
      c(-0.06, 0.33, -0.48, 0.08, -0.48, -0.17);
      c(-0.48, -0.37, -0.33, -0.48, -0.2, -0.48);
      c(-0.09, -0.48, -0.02, -0.4, 0, -0.3);
      c(0.02, -0.4, 0.09, -0.48, 0.2, -0.48);
      c(0.33, -0.48, 0.48, -0.37, 0.48, -0.17);
      c(0.48, 0.08, 0.06, 0.33, 0, 0.44);
      break;
    default: // spades: an inverted heart on a flared stem
      m(0, -0.5);
      c(0.06, -0.38, 0.48, -0.15, 0.48, 0.09);
      c(0.48, 0.28, 0.34, 0.38, 0.21, 0.38);
      c(0.12, 0.38, 0.05, 0.33, 0.025, 0.25);
      q(0.05, 0.4, 0.19, 0.5);
      l(-0.19, 0.5);
      q(-0.05, 0.4, -0.025, 0.25);
      c(-0.05, 0.33, -0.12, 0.38, -0.21, 0.38);
      c(-0.34, 0.38, -0.48, 0.28, -0.48, 0.09);
      c(-0.48, -0.15, -0.06, -0.38, 0, -0.5);
      break;
  }
  ctx.closePath();
}

/** Fill a suit symbol, optionally upside down. */
function pip(ctx, suit, cx, cy, s, ink, flip = false) {
  ctx.save();
  if (flip) {
    ctx.translate(cx, cy);
    ctx.rotate(Math.PI);
    ctx.translate(-cx, -cy);
  }
  ctx.fillStyle = ink;
  suitPath(ctx, suit, cx, cy, s);
  ctx.fill('nonzero');
  ctx.restore();
}

/** A rounded rectangle path. */
function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

/** The font stack: Inter is already on the page; the rest are fallbacks. */
const FACE_FONT = '"Inter", "Helvetica Neue", Arial, sans-serif';
const COURT_FONT = 'Georgia, "Times New Roman", serif';

/** One corner index (rank over a small suit), upright at (cx, top). */
function cornerIndex(ctx, rank, suit, cx, top, h, ink) {
  const size = h * 0.118;
  ctx.save();
  ctx.fillStyle = ink;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'alphabetic';
  ctx.font = `700 ${size}px ${FACE_FONT}`;
  if (rank === '10') {
    // condensed, so "10" sits in the same column as a single letter
    ctx.translate(cx, top + size * 0.86);
    ctx.scale(0.74, 1);
    ctx.fillText('10', 0, 0);
  } else {
    ctx.fillText(rank, cx, top + size * 0.86);
  }
  ctx.restore();
  pip(ctx, suit, cx, top + size * 1.42, h * 0.062, ink);
}

/** Both corner indices: top-left, and bottom-right turned half a revolution. */
function indices(ctx, x, y, w, h, rank, suit, ink) {
  cornerIndex(ctx, rank, suit, x + w * 0.105, y + h * 0.035, h, ink);
  ctx.save();
  ctx.translate(x + w / 2, y + h / 2);
  ctx.rotate(Math.PI);
  ctx.translate(-(x + w / 2), -(y + h / 2));
  cornerIndex(ctx, rank, suit, x + w * 0.105, y + h * 0.035, h, ink);
  ctx.restore();
}

/** Where Fomin's own corner indices sit on the art, as fractions of it. */
const FOMIN_INDEX = Object.freeze({ w: 0.153, h: 0.273 });

/**
 * Paint one card face into the rectangle (x, y, w, h) of `ctx`.
 * `opts.fourColour` picks the four-colour deck; `opts.court` is the loaded
 * court art (any `drawImage` source) for J/Q/K, or null for the drawn court.
 */
export function drawFace(ctx, x, y, w, h, card, opts = {}) {
  const { rank, suit, court } = cardParts(card);
  const ink = (opts.fourColour ? SUIT_INK.four : SUIT_INK.two)[suit];
  const r = w * 0.055;

  // the paper: warm white with a faint edge falloff, as coated stock reads
  ctx.save();
  roundRect(ctx, x, y, w, h, r);
  ctx.fillStyle = '#fbf9f3';
  ctx.fill();
  ctx.restore();

  if (court) {
    if (opts.court) {
      // Fomin's art fitted by height and centred; his corner indices are
      // painted over with ours so every card shares one typeface and the
      // four-colour deck reaches the courts too.
      const img = opts.court;
      const iw = img.width || 468;
      const ih = img.height || 708;
      const dh = h * 0.985;
      const dw = (dh * iw) / ih;
      const dx = x + (w - dw) / 2;
      const dy = y + (h - dh) / 2;
      ctx.drawImage(img, dx, dy, dw, dh);
      ctx.fillStyle = '#fbf9f3';
      ctx.fillRect(dx - 1, dy - 1, dw * FOMIN_INDEX.w + 1, dh * FOMIN_INDEX.h + 1);
      ctx.fillRect(dx + dw * (1 - FOMIN_INDEX.w), dy + dh * (1 - FOMIN_INDEX.h), dw * FOMIN_INDEX.w + 1, dh * FOMIN_INDEX.h + 1);
    } else {
      drawnCourt(ctx, x, y, w, h, rank, suit, ink);
    }
    indices(ctx, x, y, w, h, rank, suit, ink);
    return;
  }

  indices(ctx, x, y, w, h, rank, suit, ink);
  const ri = RANKS.indexOf(rank);
  if (rank === 'A') {
    // the ace: one large pip, the spade larger still, as by custom
    pip(ctx, suit, x + w / 2, y + h / 2, h * (suit === 3 ? 0.36 : 0.26), ink);
    return;
  }
  const fx = x + w * 0.29;
  const fw = w * 0.42;
  const fy = y + h * 0.2;
  const fh = h * 0.6;
  const size = h * 0.115;
  for (const [px, py] of pipLayout(ri)) {
    pip(ctx, suit, fx + px * fw, fy + py * fh, size, ink, py > 0.5);
  }
}

/**
 * The court card drawn in code, shown until Fomin's art has loaded (or if it
 * cannot): a framed panel with the letter and the suit, mirrored top to
 * bottom like a double-headed court.
 */
function drawnCourt(ctx, x, y, w, h, rank, suit, ink) {
  const fx = x + w * 0.2;
  const fy = y + h * 0.12;
  const fw = w * 0.6;
  const fh = h * 0.76;
  ctx.save();
  ctx.strokeStyle = ink;
  ctx.lineWidth = Math.max(1, w * 0.008);
  ctx.strokeRect(fx, fy, fw, fh);
  ctx.globalAlpha = 0.08;
  ctx.fillStyle = ink;
  ctx.fillRect(fx, fy, fw, fh);
  ctx.globalAlpha = 1;
  // a diagonal sash, as the English pattern divides its courts
  ctx.beginPath();
  ctx.moveTo(fx, fy + fh * 0.62);
  ctx.lineTo(fx + fw, fy + fh * 0.38);
  ctx.stroke();
  for (const flip of [false, true]) {
    ctx.save();
    if (flip) {
      ctx.translate(x + w / 2, y + h / 2);
      ctx.rotate(Math.PI);
      ctx.translate(-(x + w / 2), -(y + h / 2));
    }
    ctx.fillStyle = ink;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = `700 ${h * 0.2}px ${COURT_FONT}`;
    ctx.fillText(rank, fx + fw * 0.5, fy + fh * 0.24);
    pip(ctx, suit, fx + fw * 0.8, fy + fh * 0.1, h * 0.06, ink);
    ctx.restore();
  }
  ctx.restore();
}

/**
 * The back: a white border round a field of the theme colour, laid with a
 * guilloché of fine sine rosettes and a four-suit medallion. Symmetric under
 * a half turn, so a card never shows which way up it was dealt.
 */
export function drawBack(ctx, x, y, w, h, { colour = '#7a1d2e', accent = '#d9b46a' } = {}) {
  const r = w * 0.055;
  ctx.save();
  roundRect(ctx, x, y, w, h, r);
  ctx.fillStyle = '#fbf9f3';
  ctx.fill();
  const m = w * 0.06;
  const ix = x + m, iy = y + m, iw = w - 2 * m, ih = h - 2 * m;
  roundRect(ctx, ix, iy, iw, ih, r * 0.6);
  ctx.fillStyle = colour;
  ctx.fill();
  ctx.clip();

  // guilloché: two families of phase-shifted sine bands across the field
  ctx.strokeStyle = accent;
  ctx.lineWidth = Math.max(0.6, w * 0.0032);
  ctx.globalAlpha = 0.34;
  const bands = 22;
  for (let k = 0; k < bands; k++) {
    for (const dir of [1, -1]) {
      ctx.beginPath();
      const steps = 64;
      for (let i = 0; i <= steps; i++) {
        const t = i / steps;
        const px = ix + t * iw;
        const py = iy + ((k + 0.5) / bands) * ih + Math.sin(t * Math.PI * 6 + k * 0.7) * ih * 0.022 * dir;
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.stroke();
    }
  }
  ctx.globalAlpha = 1;

  // the medallion: a rosette ring with the four suits at its compass points
  const cx = x + w / 2;
  const cy = y + h / 2;
  const R = Math.min(iw, ih) * 0.26;
  ctx.beginPath();
  ctx.arc(cx, cy, R * 1.08, 0, Math.PI * 2);
  ctx.fillStyle = colour;
  ctx.fill();
  ctx.lineWidth = Math.max(1, w * 0.008);
  ctx.strokeStyle = accent;
  ctx.stroke();
  ctx.beginPath();
  for (let i = 0; i <= 180; i++) {
    const a = (i / 180) * Math.PI * 2;
    const rr = R * (0.78 + 0.12 * Math.cos(a * 12));
    const px = cx + Math.cos(a) * rr;
    const py = cy + Math.sin(a) * rr;
    if (i === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  }
  ctx.lineWidth = Math.max(0.8, w * 0.004);
  ctx.stroke();
  [0, 1, 2, 3].forEach((s, i) => {
    const a = -Math.PI / 2 + (i * Math.PI) / 2;
    pip(ctx, s, cx + Math.cos(a) * R * 0.42, cy + Math.sin(a) * R * 0.42, R * 0.34, accent, false);
  });
  ctx.restore();
}

/**
 * Which card is in which atlas slot. Slot 0 is the back; faces take slots
 * 1…14 and the least recently used face not in the current hand is the one
 * given up when a new card needs room.
 */
export class AtlasSlots {
  constructor(slots = ATLAS.slots) {
    this.capacity = slots - 1;
    /** card → slot */
    this.bySlot = new Map();
    this.order = []; // cards, least recently used first
    this.keep = new Set();
  }

  /** Mark the cards of the hand on the table: they are never evicted. */
  retain(cards) {
    this.keep = new Set(cards.filter((c) => c != null));
  }

  /** The slot a card is in, or null. */
  peek(card) {
    return this.bySlot.has(card) ? this.bySlot.get(card) : null;
  }

  /**
   * The slot for `card`, allocating (and evicting) as needed. `fresh` says
   * the slot has to be painted.
   */
  slotFor(card) {
    if (this.bySlot.has(card)) {
      this.order = this.order.filter((c) => c !== card);
      this.order.push(card);
      return { slot: this.bySlot.get(card), fresh: false };
    }
    let slot;
    if (this.bySlot.size < this.capacity) {
      const used = new Set(this.bySlot.values());
      for (let s = 1; s <= this.capacity; s++) {
        if (!used.has(s)) {
          slot = s;
          break;
        }
      }
    } else {
      const victim = this.order.find((c) => !this.keep.has(c)) ?? this.order[0];
      slot = this.bySlot.get(victim);
      this.bySlot.delete(victim);
      this.order = this.order.filter((c) => c !== victim);
    }
    this.bySlot.set(card, slot);
    this.order.push(card);
    return { slot, fresh: true };
  }

  /** Forget every face (the atlas is being repainted from scratch). */
  reset() {
    this.bySlot.clear();
    this.order = [];
  }

  /** The canvas rectangle of a slot's card, in pixels. */
  pixelRect(slot) {
    const col = slot % ATLAS.cols;
    const row = Math.floor(slot / ATLAS.cols);
    return [col * ATLAS.cellW + ATLAS.gutter, row * ATLAS.cellH + ATLAS.gutter, ATLAS.cardW, ATLAS.cardH];
  }

  /**
   * The texture rectangle of a slot as `[u, v, du, dv]`, with v measured
   * from the bottom as three.js samples a canvas texture (flipY).
   */
  uvRect(slot) {
    const [x, y, w, h] = this.pixelRect(slot);
    return [x / ATLAS.width, 1 - (y + h) / ATLAS.height, w / ATLAS.width, h / ATLAS.height];
  }
}

/**
 * The browser half: one canvas holding the back and every face in play,
 * painted on demand. `onChange()` is called whenever pixels changed, so the
 * texture can be re-uploaded and a frame rendered.
 */
export class CardAtlas {
  /**
   * @param {{fourColour?: boolean, back?: {colour: string, accent: string},
   *          assetUrl: (path: string) => string, onChange: () => void}} opts
   */
  constructor(opts) {
    this.opts = { fourColour: false, back: { colour: '#7a1d2e', accent: '#d9b46a' }, ...opts };
    this.canvas = document.createElement('canvas');
    this.canvas.width = ATLAS.width;
    this.canvas.height = ATLAS.height;
    this.ctx = this.canvas.getContext('2d');
    this.slots = new AtlasSlots();
    /** court key → image (loaded) | 'loading' | 'failed' */
    this.courts = new Map();
    this.disposed = false;
    this.paintBack();
  }

  /** Repaint the back (theme change). */
  paintBack() {
    const [x, y, w, h] = this.slots.pixelRect(ATLAS.back);
    this.clearCell(ATLAS.back);
    drawBack(this.ctx, x, y, w, h, this.opts.back);
    this.opts.onChange();
  }

  clearCell(slot) {
    const col = slot % ATLAS.cols;
    const row = Math.floor(slot / ATLAS.cols);
    // fill the whole cell, gutter included, so mipmaps never bleed a
    // neighbour's ink into this card's edge
    this.ctx.fillStyle = '#fbf9f3';
    this.ctx.fillRect(col * ATLAS.cellW, row * ATLAS.cellH, ATLAS.cellW, ATLAS.cellH);
  }

  /** Keep the cards of the hand in play; the rest may be evicted. */
  retain(cards) {
    this.slots.retain(cards);
  }

  /** The texture rectangle for `card` (null: the back), painting it if new. */
  rectFor(card) {
    if (card == null) return this.slots.uvRect(ATLAS.back);
    const { slot, fresh } = this.slots.slotFor(card);
    if (fresh) this.paint(card, slot);
    return this.slots.uvRect(slot);
  }

  paint(card, slot) {
    const { court, suit } = cardParts(card);
    let art = null;
    if (court) {
      const key = `${court}-${SUIT_NAMES[suit]}`;
      const got = this.courts.get(key);
      if (got && got !== 'loading' && got !== 'failed') art = got;
      else if (!got) this.loadCourt(key);
    }
    const [x, y, w, h] = this.slots.pixelRect(slot);
    this.clearCell(slot);
    drawFace(this.ctx, x, y, w, h, card, { fourColour: this.opts.fourColour, court: art });
    this.opts.onChange();
  }

  loadCourt(key) {
    this.courts.set(key, 'loading');
    const img = new Image();
    img.decoding = 'async';
    img.onload = () => {
      if (this.disposed) return;
      this.courts.set(key, img);
      // repaint whichever cards of that figure are in the atlas now
      for (const [card, slot] of this.slots.bySlot) {
        const p = cardParts(card);
        if (p.court && `${p.court}-${SUIT_NAMES[p.suit]}` === key) this.paint(card, slot);
      }
    };
    img.onerror = () => this.courts.set(key, 'failed');
    img.src = this.opts.assetUrl(`assets/cards/${key}.png`);
  }

  /** Switch between the two- and four-colour decks: every face repaints. */
  setFourColour(on) {
    if (this.opts.fourColour === !!on) return;
    this.opts.fourColour = !!on;
    for (const [card, slot] of this.slots.bySlot) this.paint(card, slot);
  }

  dispose() {
    this.disposed = true;
    this.courts.clear();
    this.canvas.width = 1;
    this.canvas.height = 1;
  }
}
