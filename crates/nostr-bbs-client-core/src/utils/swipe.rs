//! Horizontal row swipe, shared by the forum and the BBS topic lists.
//!
//! [`SwipeTracker`] is the DOM-free state machine (unit-tested here);
//! [`attach_row_swipe`] is the thin pointer-event binding a view attaches to
//! a row element.
//!
//! Rules:
//! - Touch and pen pointers only; a mouse never drags a row.
//! - A gesture starting within [`EDGE_EXCLUSION_PX`] of either screen edge is
//!   ignored: that is the browser's back/forward swipe.
//! - The row claims the gesture only once horizontal travel exceeds
//!   [`LOCK_PX`] **and** is more than [`LOCK_RATIO`] times the vertical. Until
//!   then nothing is prevented, and once vertical travel passes [`LOCK_PX`]
//!   first the gesture is the page's for good, so vertical scrolling is never
//!   touched. Rows carry `touch-action: pan-y` ([`ROW_TOUCH_ACTION`]).
//! - While dragging, the row follows the finger and the view reveals a strip
//!   behind it. On release past [`COMMIT_FRACTION`] of the row's width the
//!   swipe commits (either direction toggles the subscription), otherwise the
//!   row springs back; `pointercancel` always springs back.
//! - With `prefers-reduced-motion`, the spring back is instant
//!   ([`RowSwipeState::reduced_motion`]).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gloo::events::{EventListener, EventListenerOptions};
use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// Horizontal travel, in CSS pixels, before a row may claim a gesture.
pub const LOCK_PX: f64 = 10.0;
/// Horizontal travel must exceed this many times the vertical to claim.
pub const LOCK_RATIO: f64 = 2.0;
/// Fraction of the row's width past which a release commits.
pub const COMMIT_FRACTION: f64 = 1.0 / 3.0;
/// Gestures starting this close to either screen edge are ignored (CSS px).
pub const EDGE_EXCLUSION_PX: f64 = 24.0;
/// The `touch-action` a swipeable row must carry.
pub const ROW_TOUCH_ACTION: &str = "pan-y";

/// The kind of pointer that started a gesture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerKind {
    /// A mouse: never drags a row.
    Mouse,
    /// A finger.
    Touch,
    /// A stylus.
    Pen,
    /// Anything else (treated like a mouse).
    Other,
}

impl PointerKind {
    /// From a `PointerEvent.pointerType` string.
    pub fn from_type(t: &str) -> Self {
        match t {
            "mouse" => PointerKind::Mouse,
            "touch" => PointerKind::Touch,
            "pen" => PointerKind::Pen,
            _ => PointerKind::Other,
        }
    }

    fn swipes(self) -> bool {
        matches!(self, PointerKind::Touch | PointerKind::Pen)
    }
}

/// Which way a committed swipe went. Either direction toggles the
/// subscription; the direction is reported for the view's strip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwipeDir {
    /// Finger moved left (row slid left).
    Left,
    /// Finger moved right (row slid right).
    Right,
}

/// What a pointer move meant.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SwipeMove {
    /// Not ours (no gesture, another pointer, or the page's scroll).
    None,
    /// Too little travel to decide yet: do nothing, prevent nothing.
    Undecided,
    /// The row has just claimed the gesture: capture the pointer, prevent the
    /// default, move the row by `dx`.
    Claim {
        /// Horizontal offset from the start, CSS px.
        dx: f64,
    },
    /// The row keeps following the finger: prevent the default, move by `dx`.
    Drag {
        /// Horizontal offset from the start, CSS px.
        dx: f64,
    },
}

/// How a gesture ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwipeEnd {
    /// Not ours, or never claimed: nothing to do.
    None,
    /// Released past the threshold: toggle, then return the row.
    Commit(SwipeDir),
    /// Released short of it, or cancelled: return the row.
    SpringBack,
}

/// Axis decision for travel `(dx, dy)` from the start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lock {
    /// Not enough travel to decide.
    Undecided,
    /// The row's: horizontal travel past [`LOCK_PX`] and more than
    /// [`LOCK_RATIO`] times the vertical.
    Horizontal,
    /// The page's: vertical travel passed [`LOCK_PX`] first.
    Vertical,
}

/// Decide the axis for travel `(dx, dy)`.
pub fn lock_decision(dx: f64, dy: f64) -> Lock {
    let (ax, ay) = (dx.abs(), dy.abs());
    if ax > LOCK_PX && ax > LOCK_RATIO * ay {
        Lock::Horizontal
    } else if ay > LOCK_PX {
        Lock::Vertical
    } else {
        Lock::Undecided
    }
}

/// Whether a release at offset `dx` on a row `row_width` wide commits.
pub fn commits(dx: f64, row_width: f64) -> bool {
    row_width > 0.0 && dx.abs() >= row_width * COMMIT_FRACTION
}

/// Whether a gesture starting at `x` on a `viewport_width`-wide screen is in
/// the browser's edge-swipe zone.
pub fn in_edge_zone(x: f64, viewport_width: f64) -> bool {
    x < EDGE_EXCLUSION_PX || x > viewport_width - EDGE_EXCLUSION_PX
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum State {
    #[default]
    Idle,
    Pending {
        id: i32,
        x0: f64,
        y0: f64,
    },
    Dragging {
        id: i32,
        x0: f64,
        dx: f64,
    },
    /// Given to the page (vertical, or excluded) until this pointer ends.
    Ignored {
        id: i32,
    },
}

/// The swipe state machine for one row. DOM-free.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SwipeTracker {
    state: State,
}

impl SwipeTracker {
    /// A pointer went down. Returns whether the row tracks it.
    pub fn down(
        &mut self,
        kind: PointerKind,
        id: i32,
        x: f64,
        y: f64,
        viewport_width: f64,
    ) -> bool {
        if !matches!(self.state, State::Idle) {
            // A second pointer while one is tracked: leave both alone.
            return false;
        }
        if !kind.swipes() || in_edge_zone(x, viewport_width) {
            self.state = State::Ignored { id };
            return false;
        }
        self.state = State::Pending { id, x0: x, y0: y };
        true
    }

    /// The pointer moved.
    pub fn move_to(&mut self, id: i32, x: f64, y: f64) -> SwipeMove {
        match self.state {
            State::Pending { id: pid, x0, y0 } if pid == id => {
                match lock_decision(x - x0, y - y0) {
                    Lock::Horizontal => {
                        let dx = x - x0;
                        self.state = State::Dragging { id, x0, dx };
                        SwipeMove::Claim { dx }
                    }
                    Lock::Vertical => {
                        self.state = State::Ignored { id };
                        SwipeMove::None
                    }
                    Lock::Undecided => SwipeMove::Undecided,
                }
            }
            State::Dragging { id: pid, x0, .. } if pid == id => {
                let dx = x - x0;
                self.state = State::Dragging { id, x0, dx };
                SwipeMove::Drag { dx }
            }
            _ => SwipeMove::None,
        }
    }

    /// The pointer went up over a row `row_width` wide.
    pub fn up(&mut self, id: i32, row_width: f64) -> SwipeEnd {
        let end = match self.state {
            State::Dragging { id: pid, dx, .. } if pid == id => {
                if commits(dx, row_width) {
                    SwipeEnd::Commit(if dx < 0.0 {
                        SwipeDir::Left
                    } else {
                        SwipeDir::Right
                    })
                } else {
                    SwipeEnd::SpringBack
                }
            }
            State::Pending { id: pid, .. } | State::Ignored { id: pid } if pid == id => {
                SwipeEnd::None
            }
            _ => return SwipeEnd::None,
        };
        self.state = State::Idle;
        end
    }

    /// The pointer was cancelled (the browser took the gesture).
    pub fn cancel(&mut self, id: i32) -> SwipeEnd {
        let end = match self.state {
            State::Dragging { id: pid, .. } if pid == id => SwipeEnd::SpringBack,
            State::Pending { id: pid, .. } | State::Ignored { id: pid } if pid == id => {
                SwipeEnd::None
            }
            _ => return SwipeEnd::None,
        };
        self.state = State::Idle;
        end
    }

    /// Whether the row currently follows a finger.
    pub fn dragging(&self) -> bool {
        matches!(self.state, State::Dragging { .. })
    }
}

/// Whether the member asked for reduced motion.
pub fn prefers_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-reduced-motion: reduce)")
                .ok()
                .flatten()
        })
        .is_some_and(|m| m.matches())
}

/// Reactive state a view renders a swipeable row from.
#[derive(Clone, Copy)]
pub struct RowSwipeState {
    /// Horizontal offset of the row's content, CSS px (0 at rest).
    pub offset: RwSignal<f64>,
    /// The row is returning to rest: animate `transform` unless
    /// [`Self::reduced_motion`].
    pub settling: RwSignal<bool>,
    /// The member prefers reduced motion: never animate.
    pub reduced_motion: bool,
}

impl RowSwipeState {
    /// Fresh state for one row, following the system's reduced-motion
    /// preference.
    pub fn new() -> Self {
        Self::with_reduced_motion(prefers_reduced_motion())
    }

    /// Fresh state with an explicit reduced-motion choice (a client with its
    /// own motion setting).
    pub fn with_reduced_motion(reduced_motion: bool) -> Self {
        Self {
            offset: RwSignal::new(0.0),
            settling: RwSignal::new(false),
            reduced_motion,
        }
    }

    /// The direction the strip should show for the current offset, if any.
    pub fn revealing(&self) -> Option<SwipeDir> {
        let dx = self.offset.get();
        if dx < 0.0 {
            Some(SwipeDir::Left)
        } else if dx > 0.0 {
            Some(SwipeDir::Right)
        } else {
            None
        }
    }

    /// Inline style for the moving content: the offset, and a short spring
    /// transition while settling (none under reduced motion).
    pub fn content_style(&self) -> String {
        let dx = self.offset.get();
        let transition = if self.settling.get() && !self.reduced_motion {
            "transform 180ms ease-out"
        } else {
            "none"
        };
        format!("transform: translateX({dx}px); transition: {transition};")
    }
}

impl Default for RowSwipeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Listeners attached by [`attach_row_swipe`]; dropping it detaches them.
/// Keep it alive as long as the row (for example in
/// `StoredValue::new_local`, which drops it with the row's owner).
pub struct RowSwipeGuard {
    _listeners: Vec<EventListener>,
}

/// Bind swipe handling to `row`, driving `state` and calling `on_commit` on a
/// committed swipe. Also sets `touch-action: pan-y` on the row and swallows
/// the click that ends a claimed swipe (so a row that is a link does not
/// navigate).
pub fn attach_row_swipe(
    row: &web_sys::HtmlElement,
    state: RowSwipeState,
    on_commit: impl Fn(SwipeDir) + 'static,
) -> RowSwipeGuard {
    let _ = row.style().set_property("touch-action", ROW_TOUCH_ACTION);
    let tracker = Rc::new(RefCell::new(SwipeTracker::default()));
    let swallow_click = Rc::new(Cell::new(false));
    let on_commit = Rc::new(on_commit);
    let settle = move || {
        state.settling.set(true);
        state.offset.set(0.0);
    };

    let down = {
        let tracker = tracker.clone();
        EventListener::new(row, "pointerdown", move |e| {
            let Some(e) = e.dyn_ref::<web_sys::PointerEvent>() else {
                return;
            };
            let width = web_sys::window()
                .and_then(|w| w.inner_width().ok())
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if tracker.borrow_mut().down(
                PointerKind::from_type(&e.pointer_type()),
                e.pointer_id(),
                e.client_x() as f64,
                e.client_y() as f64,
                width,
            ) {
                state.settling.set(false);
            }
        })
    };
    let moved = {
        let tracker = tracker.clone();
        let row = row.clone();
        EventListener::new_with_options(
            &row.clone(),
            "pointermove",
            EventListenerOptions::enable_prevent_default(),
            move |e| {
                let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                    return;
                };
                let outcome = tracker.borrow_mut().move_to(
                    pe.pointer_id(),
                    pe.client_x() as f64,
                    pe.client_y() as f64,
                );
                match outcome {
                    SwipeMove::Claim { dx } => {
                        let _ = row.set_pointer_capture(pe.pointer_id());
                        e.prevent_default();
                        state.offset.set(dx);
                    }
                    SwipeMove::Drag { dx } => {
                        e.prevent_default();
                        state.offset.set(dx);
                    }
                    SwipeMove::None | SwipeMove::Undecided => {}
                }
            },
        )
    };
    let up = {
        let tracker = tracker.clone();
        let row = row.clone();
        let swallow = swallow_click.clone();
        let on_commit = on_commit.clone();
        EventListener::new(&row.clone(), "pointerup", move |e| {
            let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                return;
            };
            let width = row.get_bounding_client_rect().width();
            match tracker.borrow_mut().up(pe.pointer_id(), width) {
                SwipeEnd::Commit(dir) => {
                    swallow.set(true);
                    settle();
                    on_commit(dir);
                }
                SwipeEnd::SpringBack => {
                    swallow.set(true);
                    settle();
                }
                SwipeEnd::None => {}
            }
        })
    };
    let cancel = {
        let tracker = tracker.clone();
        EventListener::new(row, "pointercancel", move |e| {
            let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                return;
            };
            if tracker.borrow_mut().cancel(pe.pointer_id()) == SwipeEnd::SpringBack {
                settle();
            }
        })
    };
    let click = {
        let swallow = swallow_click.clone();
        EventListener::new_with_options(
            row,
            "click",
            EventListenerOptions {
                phase: gloo::events::EventListenerPhase::Capture,
                passive: false,
            },
            move |e| {
                if swallow.replace(false) {
                    e.prevent_default();
                    e.stop_propagation();
                }
            },
        )
    };
    let settled = {
        EventListener::new(row, "transitionend", move |_| {
            state.settling.set(false);
        })
    };
    RowSwipeGuard {
        _listeners: vec![down, moved, up, cancel, click, settled],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: f64 = 400.0;

    fn tracking() -> SwipeTracker {
        let mut t = SwipeTracker::default();
        assert!(t.down(PointerKind::Touch, 1, 200.0, 300.0, W));
        t
    }

    #[test]
    fn the_axis_locks_only_past_ten_pixels_and_twice_the_vertical() {
        assert_eq!(
            lock_decision(10.0, 0.0),
            Lock::Undecided,
            "exactly 10 px is not past"
        );
        assert_eq!(lock_decision(10.5, 0.0), Lock::Horizontal);
        assert_eq!(lock_decision(-12.0, 5.0), Lock::Horizontal);
        assert_eq!(
            lock_decision(12.0, 6.0),
            Lock::Undecided,
            "not more than 2x"
        );
        assert_eq!(lock_decision(12.0, 11.0), Lock::Vertical);
        assert_eq!(lock_decision(3.0, -15.0), Lock::Vertical);
    }

    #[test]
    fn a_vertical_gesture_is_the_pages_and_never_claimed_later() {
        let mut t = tracking();
        assert_eq!(t.move_to(1, 202.0, 304.0), SwipeMove::Undecided);
        assert_eq!(
            t.move_to(1, 203.0, 320.0),
            SwipeMove::None,
            "vertical first"
        );
        assert_eq!(
            t.move_to(1, 300.0, 320.0),
            SwipeMove::None,
            "stays the page's"
        );
        assert_eq!(t.up(1, W), SwipeEnd::None);
    }

    #[test]
    fn a_horizontal_gesture_claims_follows_and_commits_past_a_third() {
        let mut t = tracking();
        assert_eq!(t.move_to(1, 188.0, 302.0), SwipeMove::Claim { dx: -12.0 });
        assert!(t.dragging());
        assert_eq!(t.move_to(1, 60.0, 340.0), SwipeMove::Drag { dx: -140.0 });
        assert_eq!(t.up(1, W), SwipeEnd::Commit(SwipeDir::Left));
        assert!(!t.dragging());

        let mut t = tracking();
        t.move_to(1, 215.0, 300.0);
        t.move_to(1, 200.0 + W / 3.0, 300.0);
        assert_eq!(
            t.up(1, W),
            SwipeEnd::Commit(SwipeDir::Right),
            "either direction"
        );
    }

    #[test]
    fn a_short_release_or_a_cancel_springs_back() {
        let mut t = tracking();
        t.move_to(1, 230.0, 300.0);
        assert_eq!(t.up(1, W), SwipeEnd::SpringBack);
        let mut t = tracking();
        t.move_to(1, 100.0, 300.0);
        assert_eq!(t.cancel(1), SwipeEnd::SpringBack, "even past the threshold");
        let mut t = tracking();
        assert_eq!(
            t.cancel(1),
            SwipeEnd::None,
            "never claimed: nothing to undo"
        );
    }

    #[test]
    fn mice_and_screen_edges_never_swipe() {
        let mut t = SwipeTracker::default();
        assert!(!t.down(PointerKind::Mouse, 1, 200.0, 300.0, W));
        assert_eq!(t.move_to(1, 50.0, 300.0), SwipeMove::None);
        assert_eq!(t.up(1, W), SwipeEnd::None);
        assert!(t.down(PointerKind::Pen, 2, 200.0, 300.0, W), "a pen may");
        t.cancel(2);
        assert!(!t.down(PointerKind::Touch, 3, 23.0, 300.0, W), "left edge");
        t.up(3, W);
        assert!(
            !t.down(PointerKind::Touch, 4, W - 23.0, 300.0, W),
            "right edge"
        );
        t.up(4, W);
        assert!(t.down(PointerKind::Touch, 5, 24.0, 300.0, W), "just inside");
    }

    #[test]
    fn a_second_pointer_is_left_alone() {
        let mut t = tracking();
        assert!(!t.down(PointerKind::Touch, 9, 100.0, 100.0, W));
        assert_eq!(t.move_to(9, 10.0, 100.0), SwipeMove::None);
        assert_eq!(t.move_to(1, 180.0, 300.0), SwipeMove::Claim { dx: -20.0 });
    }

    #[test]
    fn commit_threshold_is_a_third_of_the_row() {
        assert!(!commits(133.0, 400.0));
        assert!(commits(-134.0, 400.0));
        assert!(!commits(500.0, 0.0), "unknown width never commits");
    }
}
