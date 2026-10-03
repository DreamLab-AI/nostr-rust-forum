// layout.js — where everything sits on the heads-up table, in metres.
// Pure: no DOM, no three.
//
// The scene is modelled at real scale (a poker card is 63.5 × 88.9 mm, a
// chip 39 × 3.3 mm) so shadows, the environment map and the camera's near
// and far planes behave physically. +y is up, the felt is the y = 0 plane,
// the hero sits at +z (nearest the camera) and the opponent at −z. Seats are
// named by side, `near` and `far`, never by seat number: the hero may be seat
// 0 or seat 1, and `sideOf` is the one place that mapping happens.

/**
 * Cards are drawn half again over real size: at true scale a face is a few
 * dozen pixels tall in a phone-sized canvas, and the board must read there.
 */
export const CARD_SCALE = 1.55;

/** One playing card. `t` is the thickness, `r` the corner radius. */
export const CARD = Object.freeze({
  w: 0.0635 * CARD_SCALE,
  h: 0.0889 * CARD_SCALE,
  t: 0.0004,
  r: 0.0032 * CARD_SCALE,
});

/** One casino chip. */
export const CHIP = Object.freeze({ r: 0.0195, h: 0.0033 });

/**
 * The table: a stadium (a rectangle with semicircular ends) of felt, ringed by
 * a lacquered wood racetrack and a padded rail. `halfLength` runs along x,
 * `halfDepth` along z and is also the end radius.
 */
export const TABLE = Object.freeze({
  halfLength: 0.92,
  halfDepth: 0.54,
  trim: 0.034, // width of the wood racetrack outside the felt
  railWidth: 0.085,
  railHeight: 0.055,
  bodyDepth: 0.16, // apron below the rail, for silhouette
});

const v = (x, z, y = 0) => Object.freeze({ x, y, z });

/** Gap between board cards. */
const BOARD_GAP = 0.012;

/**
 * The anchors of one side of the table. The far side is the near side turned
 * half a revolution about the centre, so a seat's stack is always on its own
 * right hand, as a player would keep it.
 */
function side(sign) {
  const s = sign; // +1 near, −1 far
  return Object.freeze({
    // hole cards: a slight fan, each turned a few degrees outwards
    hole: Object.freeze([v(-0.054 * s, 0.37 * s), v(0.054 * s, 0.37 * s)]),
    holeYaw: Object.freeze([0.07, -0.07]),
    stack: v(0.29 * s, 0.36 * s),
    bet: v(0.0, 0.225 * s),
    button: v(-0.175 * s, 0.31 * s),
    // the seat's label sits just beyond the rail, clear of the cards
    seat: v(0.0, (TABLE.halfDepth + TABLE.trim + TABLE.railWidth + 0.02) * s),
  });
}

/** Every anchor on the table. */
export const LAYOUT = Object.freeze({
  near: side(1),
  far: side(-1),
  board: Object.freeze(
    [-2, -1, 0, 1, 2].map((i) => v(i * (CARD.w + BOARD_GAP), -0.03)),
  ),
  pot: v(0.0, 0.118),
  deck: v(0.52, -0.03),
  muck: v(-0.5, -0.04),
  // where the cards of a finished hand are swept to before the next deal
  sweep: v(0.52, -0.03),
});

/** `near` for the hero's seat, `far` for the other. */
export function sideOf(seat, hero) {
  return seat === hero ? 'near' : 'far';
}

/**
 * The anchors for `seat` given the hero's seat. Heads-up only: any seat that
 * is not the hero's is the far seat.
 */
export function seatAnchors(seat, hero) {
  return LAYOUT[sideOf(seat, hero)];
}

/**
 * The resting yaw of a card on the table, by where it lies: hole cards fan,
 * board cards sit square, mucked cards lie askew. Cards always read for the
 * hero (a shown far hand is turned to face the camera), because the hero is
 * the only person looking at this table.
 */
export function holeYaw(side, idx) {
  return LAYOUT[side].holeYaw[idx] ?? 0;
}

/**
 * A muck pile position for the `n`th mucked card: a loose heap, the same
 * each time for a given `n`, so a reconcile never shuffles the heap.
 */
export function muckSpot(n) {
  const a = (n * 2.399963) % (Math.PI * 2); // golden angle: no two cards align
  const r = 0.006 + 0.004 * (n % 3);
  return {
    x: LAYOUT.muck.x + Math.cos(a) * r,
    y: CARD.t * (n + 1),
    z: LAYOUT.muck.z + Math.sin(a) * r,
    yaw: 0.6 + ((n * 0.73) % 1.0) - 0.5,
  };
}
