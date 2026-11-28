//! Thread (topic) subscriptions in the BBS: the subscribe toggle on a board's
//! topic rows, and the panel of subscribed topics (a collapsible column on
//! desktop, an off-canvas drawer behind a small edge tab on phones).
//!
//! The data and the shared view pieces live in client core
//! ([`thread_subs`](nostr_bbs_client_core::stores::thread_subs),
//! [`subs_panel`](nostr_bbs_client_core::stores::subs_panel),
//! [`swipe`](nostr_bbs_client_core::utils::swipe)); this module renders them
//! in the TUI idiom. The decisions that are logic rather than markup (the
//! panel row's route, keys, the drawer drag, focus wrapping) are the plain
//! functions at the top, unit-tested on the native target.
//!
//! Keys: `s` on a focused topic row toggles its subscription (Enter or Space
//! opens it), and `]` shows or hides the panel. Both are listed on the Help
//! screen.

use leptos::prelude::*;
use nostr_bbs_client_core::stores::subs_panel::{
    swipe_label, toggle_label, unread_badge, use_subs_panel, SubsPanel, SubscribeToggle,
    TITLE_PLACEHOLDER,
};
use nostr_bbs_client_core::stores::thread_subs::{use_thread_subs, SubscribedTopic};
use nostr_bbs_client_core::toast::{use_toasts, ToastStore, ToastVariant};
use nostr_bbs_client_core::utils::swipe::{
    commits, lock_decision, Lock, PointerKind, RowSwipeGuard, RowSwipeState, SwipeDir,
};

use crate::prefs::use_bbs_prefs;
use crate::router::{use_router, Route};

// -- Logic (native-testable) --------------------------------------------------

/// The row toggle's text when the topic is followed.
pub const TOGGLE_ON: &str = "[*]";
/// The row toggle's text when it is not. Same width as [`TOGGLE_ON`] in a
/// monospace face, so pressing it moves nothing.
pub const TOGGLE_OFF: &str = "[ ]";

/// The global key that shows or hides the subscriptions panel.
pub const PANEL_KEY: &str = "]";

/// Id of the panel element (desktop column or mobile drawer), for
/// `aria-controls`.
pub const PANEL_ID: &str = "bbs-subs-panel";

/// The row toggle's text for `pressed`.
pub fn toggle_glyph(pressed: bool) -> &'static str {
    if pressed {
        TOGGLE_ON
    } else {
        TOGGLE_OFF
    }
}

/// What a polite live region says after a toggle by key or swipe (a button
/// press is announced through its `aria-pressed`).
pub fn toggle_announcement(followed: bool) -> &'static str {
    if followed {
        "Subscribed to this topic"
    } else {
        "Unsubscribed from this topic"
    }
}

/// The BBS route a panel row opens: the topic's thread in its zone (by slug
/// when known, else by id), or, while the zone is unknown, the post resolver
/// with the channel hint (a thread route with an empty zone would not parse).
pub fn panel_route(t: &SubscribedTopic) -> Route {
    let zone = t
        .zone_slug
        .clone()
        .filter(|z| !z.is_empty())
        .or_else(|| (!t.zone.is_empty()).then(|| t.zone.clone()));
    match zone {
        Some(zone) => Route::Thread {
            zone,
            channel_id: t.channel.clone(),
            root_id: t.root.clone(),
            focus: None,
        },
        None => Route::Go {
            event_id: t.root.clone(),
            channel: (!t.channel.is_empty()).then(|| t.channel.clone()),
        },
    }
}

/// The text a panel row shows: the title, or the neutral placeholder while it
/// is unknown.
pub fn panel_title(t: &SubscribedTopic) -> String {
    t.title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(TITLE_PLACEHOLDER)
        .to_string()
}

/// A panel row's accessible name: the title, then the new-post count when
/// there is one ("Weekly call, 3 new posts").
pub fn row_accessible_name(title: &str, count: usize, capped: bool) -> String {
    match unread_badge(count, capped) {
        None => title.to_string(),
        Some(n) => {
            let noun = if n == "1" { "new post" } else { "new posts" };
            format!("{title}, {n} {noun}")
        }
    }
}

/// The mobile tab's accessible name for a total of unread posts.
pub fn tab_accessible_name(count: usize, capped: bool) -> String {
    row_accessible_name("Subscribed topics", count, capped)
}

/// The `created_at` of the newest post a thread view shows: the newest of the
/// root and the replies, or `None` while the root is not shown.
pub fn newest_shown(root: Option<u64>, replies: impl IntoIterator<Item = u64>) -> Option<u64> {
    let root = root?;
    Some(replies.into_iter().fold(root, u64::max))
}

/// What a key pressed on a focused topic row does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKey {
    /// Open the topic (Enter, Space).
    Open,
    /// Toggle the subscription (`s`).
    ToggleSubscription,
}

/// The action for `key` on a focused topic row. Nothing while a modifier is
/// held (`modified`: Ctrl, Meta or Alt), and nothing for an auto-repeat of
/// `s` (holding the key must not flip it back and forth).
pub fn row_key(key: &str, modified: bool, repeat: bool) -> Option<RowKey> {
    if modified {
        return None;
    }
    match key {
        "Enter" | " " | "Spacebar" => Some(RowKey::Open),
        "s" | "S" if !repeat => Some(RowKey::ToggleSubscription),
        _ => None,
    }
}

/// Focus wrapping inside a modal drawer of `len` focusable elements, focus
/// being on element `current` (`None` when it is outside them): the index to
/// focus instead of the browser's own Tab move, or `None` to let it happen.
pub fn trap_focus_target(current: Option<usize>, len: usize, backwards: bool) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let last = len - 1;
    match current {
        None => Some(if backwards { last } else { 0 }),
        Some(i) if backwards && i == 0 => Some(last),
        Some(i) if !backwards && i >= last => Some(0),
        Some(_) => None,
    }
}

/// Which drawer drag a gesture is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DragKind {
    /// Pulling the closed drawer out by its edge tab (finger moves left).
    Open,
    /// Pushing the open drawer away (finger moves right).
    Close,
}

/// The drawer's `translateX`, CSS px (0 = fully open, `width` = fully
/// closed), for a drag of kind `kind` that has travelled `dx` horizontally.
pub fn drawer_offset(kind: DragKind, dx: f64, width: f64) -> f64 {
    let width = width.max(0.0);
    match kind {
        DragKind::Open => (width + dx).clamp(0.0, width),
        DragKind::Close => dx.clamp(0.0, width),
    }
}

/// How a drawer drag ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DragEnd {
    /// Never claimed (a tap, or the page's scroll): nothing to do.
    None,
    /// Released or cancelled after a claim: the drawer settles open or
    /// closed.
    Settle {
        /// Whether the drawer ends open.
        open: bool,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum DragState {
    #[default]
    Idle,
    Pending {
        id: i32,
        kind: DragKind,
        x0: f64,
        y0: f64,
    },
    Dragging {
        id: i32,
        kind: DragKind,
        x0: f64,
        dx: f64,
    },
    Ignored {
        id: i32,
    },
}

/// The drawer drag state machine (the edge tab's pull, the open drawer's
/// push). DOM-free. It claims a gesture with the same axis rule as a row
/// swipe ([`lock_decision`]) and settles past the same third of the width
/// ([`commits`]); a gesture that goes vertical first is the page's.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DrawerDrag {
    state: DragState,
}

impl DrawerDrag {
    /// A pointer went down. Returns whether the drag tracks it.
    pub fn down(&mut self, kind: DragKind, id: i32, x: f64, y: f64) -> bool {
        if !matches!(self.state, DragState::Idle) {
            return false;
        }
        self.state = DragState::Pending {
            id,
            kind,
            x0: x,
            y0: y,
        };
        true
    }

    /// The pointer moved: the drawer's offset ([`drawer_offset`]) once the
    /// drag is claimed, else `None`. The first `Some` is the claim (capture
    /// the pointer then).
    pub fn move_to(&mut self, id: i32, x: f64, y: f64, width: f64) -> Option<f64> {
        match self.state {
            DragState::Pending {
                id: pid,
                kind,
                x0,
                y0,
            } if pid == id => match lock_decision(x - x0, y - y0) {
                Lock::Horizontal => {
                    let dx = x - x0;
                    self.state = DragState::Dragging { id, kind, x0, dx };
                    Some(drawer_offset(kind, dx, width))
                }
                Lock::Vertical => {
                    self.state = DragState::Ignored { id };
                    None
                }
                Lock::Undecided => None,
            },
            DragState::Dragging {
                id: pid, kind, x0, ..
            } if pid == id => {
                let dx = x - x0;
                self.state = DragState::Dragging { id, kind, x0, dx };
                Some(drawer_offset(kind, dx, width))
            }
            _ => None,
        }
    }

    /// The pointer went up over a drawer `width` wide.
    pub fn up(&mut self, id: i32, width: f64) -> DragEnd {
        let end = match self.state {
            DragState::Dragging {
                id: pid, kind, dx, ..
            } if pid == id => {
                let open = match kind {
                    DragKind::Open => dx < 0.0 && commits(dx, width),
                    DragKind::Close => !(dx > 0.0 && commits(dx, width)),
                };
                DragEnd::Settle { open }
            }
            DragState::Pending { id: pid, .. } | DragState::Ignored { id: pid } if pid == id => {
                DragEnd::None
            }
            _ => return DragEnd::None,
        };
        self.state = DragState::Idle;
        end
    }

    /// The pointer was cancelled: a claimed drag returns to where it began.
    pub fn cancel(&mut self, id: i32) -> DragEnd {
        let end = match self.state {
            DragState::Dragging { id: pid, kind, .. } if pid == id => DragEnd::Settle {
                open: kind == DragKind::Close,
            },
            DragState::Pending { id: pid, .. } | DragState::Ignored { id: pid } if pid == id => {
                DragEnd::None
            }
            _ => return DragEnd::None,
        };
        self.state = DragState::Idle;
        end
    }

    /// Whether a claimed drag is under way.
    pub fn dragging(&self) -> bool {
        matches!(self.state, DragState::Dragging { .. })
    }
}

// -- Row toggle ---------------------------------------------------------------

/// The subscribe control a board hands its topic rows: the shared toggle, the
/// toast for a refusal and a polite live region for toggles made by key or
/// swipe. Create once per board during setup ([`RowSubs::new`]) and render
/// [`SubsAnnouncer`] once.
#[derive(Clone, Copy)]
pub struct RowSubs {
    toggle: SubscribeToggle,
    toasts: ToastStore,
    announce: RwSignal<String>,
}

impl RowSubs {
    /// For the current board (reads the stores from context).
    pub fn new() -> Self {
        Self {
            toggle: SubscribeToggle::new(),
            toasts: use_toasts(),
            announce: RwSignal::new(String::new()),
        }
    }

    /// Whether the controls show at all (a member is signed in). Reactive.
    pub fn available(&self) -> bool {
        self.toggle.available()
    }

    /// Whether `root` is followed. Reactive.
    pub fn pressed(&self, root: &str) -> bool {
        self.toggle.pressed(root)
    }

    /// Toggle `root` in `channel`. `announce` says the outcome in the live
    /// region (for a key or a swipe; a button's `aria-pressed` speaks for
    /// itself). A refusal is shown as a toast and cleared.
    pub fn toggle(&self, root: &str, channel: &str, announce: bool) {
        if !self.toggle.available() {
            return;
        }
        match self.toggle.toggle(root, channel) {
            Ok(on) => {
                if announce {
                    self.announce.set(toggle_announcement(on).to_string());
                }
            }
            Err(e) => {
                self.toasts.show(e.to_string(), ToastVariant::Warning);
                self.toggle.clear_error();
            }
        }
    }
}

impl Default for RowSubs {
    fn default() -> Self {
        Self::new()
    }
}

/// The visually hidden live region of a board's [`RowSubs`].
#[component]
pub fn SubsAnnouncer(subs: RowSubs) -> impl IntoView {
    view! {
        <div class="bbs-sr-only" role="status" aria-live="polite">
            {move || subs.announce.try_get().unwrap_or_default()}
        </div>
    }
}

/// The swipeable frame of one topic row: a strip behind it that says what the
/// swipe will do, the row itself (`children`, the card) on a layer that
/// follows the finger, and the `[ ]`/`[*]` toggle in a gutter the card
/// reserves. The toggle is a sibling of the card, not inside it (the card is
/// `role="button"`, whose children are presentational), and has a fixed size,
/// so pressing it changes neither the row's height nor the board's order.
#[component]
pub fn SubsRowFrame(
    subs: RowSubs,
    /// Topic root id.
    root: String,
    /// The board's channel id.
    channel: String,
    children: Children,
) -> impl IntoView {
    let swipe = RowSwipeState::new();
    let frame = NodeRef::<leptos::html::Div>::new();
    let guard = StoredValue::new_local(None::<RowSwipeGuard>);
    let ids = StoredValue::new((root.clone(), channel.clone()));

    // The swipe is bound only while the controls are available; signing out
    // drops it with the toggle.
    Effect::new(move |_| {
        let Some(el) = frame.get() else {
            return;
        };
        let on = subs.available();
        let bound = guard.try_with_value(Option::is_some).unwrap_or(true);
        if on && !bound {
            let el: &web_sys::HtmlElement = &el;
            let g = nostr_bbs_client_core::utils::swipe::attach_row_swipe(el, swipe, move |_dir| {
                if let Some((root, channel)) = ids.try_get_value() {
                    subs.toggle(&root, &channel, true);
                }
            });
            guard.try_set_value(Some(g));
        } else if !on && bound {
            guard.try_set_value(None);
            swipe.offset.set(0.0);
        }
    });

    let pressed = {
        let root = root.clone();
        Memo::new(move |_| subs.pressed(&root))
    };
    let available = Memo::new(move |_| subs.available());
    let revealing = Memo::new(move |_| swipe.revealing());

    view! {
        <div
            class="bbs-topic-item"
            class:bbs-subs-on=move || available.try_get().unwrap_or(false)
            class:bbs-swiping=move || revealing.try_get().flatten().is_some()
            node_ref=frame
        >
            {move || revealing.try_get().flatten().map(|dir| {
                let side = match dir {
                    // The row slid left: the strip shows on the right.
                    SwipeDir::Left => "bbs-swipe-strip bbs-swipe-strip-end",
                    SwipeDir::Right => "bbs-swipe-strip bbs-swipe-strip-start",
                };
                view! {
                    <div class=side aria-hidden="true">
                        {swipe_label(pressed.try_get().unwrap_or(false))}
                    </div>
                }
            })}
            <div class="bbs-topic-slide" style=move || swipe.content_style()>
                {children()}
                <Show when=move || available.try_get().unwrap_or(false) fallback=|| ()>
                    <button
                        type="button"
                        class="bbs-sub-toggle"
                        class:on=move || pressed.try_get().unwrap_or(false)
                        aria-pressed=move || if pressed.try_get().unwrap_or(false) { "true" } else { "false" }
                        aria-label=move || toggle_label(pressed.try_get().unwrap_or(false))
                        title=move || format!("{} (s)", toggle_label(pressed.try_get().unwrap_or(false)))
                        on:click=move |ev| {
                            ev.stop_propagation();
                            if let Some((root, channel)) = ids.try_get_value() {
                                subs.toggle(&root, &channel, false);
                            }
                        }
                    >
                        {move || toggle_glyph(pressed.try_get().unwrap_or(false))}
                    </button>
                </Show>
            </div>
        </div>
    }
}

// -- Panel --------------------------------------------------------------------

/// The subscribed-topic rows, alphabetical as the store delivers them. Keyed
/// by root; each row reads its own fields, so a count or a late title updates
/// the row in place (and keeps focus) instead of rebuilding the list.
#[component]
fn SubsList(
    /// Called after a row is followed (the mobile drawer closes).
    on_open: Callback<()>,
    mobile: bool,
) -> impl IntoView {
    let subs = use_thread_subs();
    let router = use_router();
    let topics = subs.topics();
    let order =
        Memo::new(move |_| topics.with(|ts| ts.iter().map(|t| t.root.clone()).collect::<Vec<_>>()));
    let empty = Memo::new(move |_| topics.with(Vec::is_empty));
    let empty_text = if mobile {
        "No subscriptions yet. Swipe a topic row, or tap its [ ] box, to follow it."
    } else {
        "No subscriptions yet. Press s on a focused topic row, or click its [ ] box, to follow it."
    };

    view! {
        <Show when=move || empty.try_get().unwrap_or(true) fallback=|| ()>
            <p class="tui-subs-empty">{empty_text}</p>
        </Show>
        <ul class="tui-subs-list">
            <For
                each=move || order.try_get().unwrap_or_default()
                key=|root| root.clone()
                children=move |root: String| {
                    let topic = Memo::new(move |prev: Option<&Option<SubscribedTopic>>| {
                        topics
                            .try_with(|ts| ts.iter().find(|t| t.root == root).cloned())
                            .flatten()
                            .or_else(|| prev.cloned().flatten())
                    });
                    let title = Memo::new(move |_| {
                        topic.try_with(|t| t.as_ref().map(panel_title)).flatten().unwrap_or_default()
                    });
                    let counts = Memo::new(move |_| {
                        topic
                            .try_with(|t| t.as_ref().map(|t| (t.unread, t.capped)))
                            .flatten()
                            .unwrap_or((0, false))
                    });
                    let route = Memo::new(move |_| topic.try_with(|t| t.as_ref().map(panel_route)).flatten());
                    let badge = move || {
                        let (n, capped) = counts.try_get().unwrap_or((0, false));
                        unread_badge(n, capped)
                    };
                    view! {
                        <li>
                            <a
                                class="tui-subs-item"
                                class:unread=move || badge().is_some()
                                href=move || route.try_get().flatten().map(|r| r.to_hash()).unwrap_or_default()
                                title=move || title.try_get().unwrap_or_default()
                                aria-label=move || {
                                    let (n, capped) = counts.try_get().unwrap_or((0, false));
                                    row_accessible_name(&title.try_get().unwrap_or_default(), n, capped)
                                }
                                on:click=move |ev| {
                                    ev.prevent_default();
                                    if let Some(r) = route.try_get_untracked().flatten() {
                                        router.go(r);
                                    }
                                    on_open.run(());
                                }
                            >
                                // Always laid out (empty at zero), so a count
                                // appearing never moves the name.
                                <span class="tui-subs-num" aria-hidden="true">{badge}</span>
                                <span class="tui-subs-name">{move || title.try_get().unwrap_or_default()}</span>
                            </a>
                        </li>
                    }
                }
            />
        </ul>
    }
}

/// The desktop column: a collapsible side pane to the right of the main pane.
/// Its grid column exists only while it is open (`.tui-body.subs-open`), and
/// whether it is open is known at first paint (the session and the remembered
/// choice are read synchronously), so loading never shifts the main pane.
#[component]
fn SubsPane(panel: SubsPanel) -> impl IntoView {
    let subs = use_thread_subs();
    let count = Memo::new(move |_| subs.topics().with(Vec::len));
    view! {
        <aside class="tui-subs-pane" id=PANEL_ID aria-labelledby="bbs-subs-heading">
            <div class="tui-side-heading tui-subs-head">
                <span id="bbs-subs-heading">"SUBSCRIBED"</span>
                <span class="tui-muted">{move || count.try_get().unwrap_or(0)}</span>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm tui-subs-close"
                    aria-label="Hide subscribed topics"
                    title="Hide subscribed topics (])"
                    on:click=move |_| panel.set_open(false)
                >"»"</button>
            </div>
            <SubsList on_open=Callback::new(|_| ()) mobile=false />
        </aside>
    }
}

fn active_html_element() -> Option<web_sys::HtmlElement> {
    use wasm_bindgen::JsCast;
    web_sys::window()?
        .document()?
        .active_element()?
        .dyn_into::<web_sys::HtmlElement>()
        .ok()
}

/// Selector for what Tab can reach inside the drawer.
const FOCUSABLE: &str = "a[href], button:not([disabled]), [tabindex]:not([tabindex='-1'])";

fn focusables(root: &web_sys::Element) -> Vec<web_sys::HtmlElement> {
    use wasm_bindgen::JsCast;
    let Ok(list) = root.query_selector_all(FOCUSABLE) else {
        return Vec::new();
    };
    (0..list.length())
        .filter_map(|i| list.item(i))
        .filter_map(|n| n.dyn_into::<web_sys::HtmlElement>().ok())
        .collect()
}

/// Width of an element, CSS px.
fn width_of(el: &web_sys::Element) -> f64 {
    el.get_bounding_client_rect().width()
}

/// Bind a drawer drag (`kind`) to `el`, previewing the drawer through `drag`
/// (its offset while a drag is claimed) and settling `panel` on release.
/// `drawer` gives the drawer element for its width. A claimed drag swallows
/// the click that ends it. Touch and pen only for a push (a mouse selects
/// text in the drawer); any pointer for the tab's pull.
fn attach_drawer_drag(
    el: &web_sys::HtmlElement,
    kind: DragKind,
    panel: SubsPanel,
    drag: RwSignal<Option<f64>>,
    drawer: NodeRef<leptos::html::Div>,
) -> Vec<gloo::events::EventListener> {
    use gloo::events::{EventListener, EventListenerOptions, EventListenerPhase};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use wasm_bindgen::JsCast;

    let tracker = Rc::new(RefCell::new(DrawerDrag::default()));
    let swallow = Rc::new(Cell::new(false));
    let drawer_width = move || drawer.get_untracked().map_or(0.0, |d| width_of(&d));

    let down = {
        let tracker = tracker.clone();
        EventListener::new(el, "pointerdown", move |e| {
            let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                return;
            };
            let pointer = PointerKind::from_type(&pe.pointer_type());
            if kind == DragKind::Close && !matches!(pointer, PointerKind::Touch | PointerKind::Pen)
            {
                return;
            }
            tracker.borrow_mut().down(
                kind,
                pe.pointer_id(),
                pe.client_x() as f64,
                pe.client_y() as f64,
            );
        })
    };
    let moved = {
        let tracker = tracker.clone();
        let target = el.clone();
        EventListener::new_with_options(
            el,
            "pointermove",
            EventListenerOptions::enable_prevent_default(),
            move |e| {
                let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                    return;
                };
                let was = tracker.borrow().dragging();
                let offset = tracker.borrow_mut().move_to(
                    pe.pointer_id(),
                    pe.client_x() as f64,
                    pe.client_y() as f64,
                    drawer_width(),
                );
                if let Some(px) = offset {
                    if !was {
                        let _ = target.set_pointer_capture(pe.pointer_id());
                    }
                    e.prevent_default();
                    drag.set(Some(px));
                }
            },
        )
    };
    let settle = move |end: DragEnd, swallow: &Cell<bool>| {
        if let DragEnd::Settle { open } = end {
            swallow.set(true);
            drag.set(None);
            panel.set_open(open);
        }
    };
    let up = {
        let tracker = tracker.clone();
        let swallow = swallow.clone();
        EventListener::new(el, "pointerup", move |e| {
            let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                return;
            };
            let end = tracker.borrow_mut().up(pe.pointer_id(), drawer_width());
            settle(end, &swallow);
        })
    };
    let cancel = {
        let tracker = tracker.clone();
        let swallow = swallow.clone();
        EventListener::new(el, "pointercancel", move |e| {
            let Some(pe) = e.dyn_ref::<web_sys::PointerEvent>() else {
                return;
            };
            let end = tracker.borrow_mut().cancel(pe.pointer_id());
            settle(end, &swallow);
        })
    };
    let click = {
        let swallow = swallow.clone();
        EventListener::new_with_options(
            el,
            "click",
            EventListenerOptions {
                phase: EventListenerPhase::Capture,
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
    vec![down, moved, up, cancel, click]
}

/// The phone drawer (≤ 640 px): off-canvas on the right (the navigation
/// drawer is on the left), opened by tapping or pulling its edge tab, closed
/// by a push to the right, a tap on the scrim, Escape (handled with the
/// shell's keys) or opening a topic. Never opened by an edge swipe or a swipe
/// on the content: those belong to the browser's back gesture and the row
/// swipe. While open it is modal: Tab and Shift+Tab stay inside it, and focus
/// returns to where it was (the tab) when it closes.
#[component]
fn SubsDrawer(panel: SubsPanel) -> impl IntoView {
    let subs = use_thread_subs();
    let prefs = use_bbs_prefs();
    let total = subs.total_unread();
    let drawer = NodeRef::<leptos::html::Div>::new();
    let tab = NodeRef::<leptos::html::Button>::new();
    let close_btn = NodeRef::<leptos::html::Button>::new();
    // The drawer's offset while a drag is claimed (None at rest).
    let drag = RwSignal::new(None::<f64>);
    let open = Memo::new(move |_| panel.is_open());
    let reduced = Memo::new(move |_| prefs.reduced_motion.get());

    // Opening this drawer closes the navigation drawer, and the reverse.
    Effect::new(move |_| {
        if open.get() {
            prefs.mobile_drawer_open.set(false);
        }
    });
    Effect::new(move |_| {
        if prefs.mobile_drawer_open.get() && open.get_untracked() {
            panel.set_open(false);
        }
    });

    // Focus: into the drawer on open, back where it came from on close.
    let return_to = StoredValue::new_local(None::<web_sys::HtmlElement>);
    Effect::new(move |prev: Option<bool>| {
        let now = open.get();
        match (prev, now) {
            (Some(false) | None, true) => {
                return_to.try_set_value(active_html_element());
                nostr_bbs_client_core::utils::set_timeout_once(
                    move || {
                        if let Some(b) = close_btn.get_untracked() {
                            let _ = b.focus();
                        }
                    },
                    0,
                );
            }
            (Some(true), false) => {
                let back = return_to
                    .try_update_value(Option::take)
                    .flatten()
                    .filter(|el| el.is_connected())
                    .or_else(|| tab.get_untracked().map(|t| t.into()));
                if let Some(el) = back {
                    let _ = el.focus();
                }
            }
            _ => {}
        }
        now
    });

    // Tab and Shift+Tab wrap inside the open drawer.
    let trap = window_event_listener(leptos::ev::keydown, move |ev| {
        if ev.key() != "Tab" || !open.get_untracked() {
            return;
        }
        let Some(root) = drawer.get_untracked() else {
            return;
        };
        let items = focusables(&root);
        let active = active_html_element();
        let current = active
            .as_ref()
            .and_then(|a| items.iter().position(|i| i == a));
        if let Some(i) = trap_focus_target(current, items.len(), ev.shift_key()) {
            ev.prevent_default();
            let _ = items[i].focus();
        }
    });
    on_cleanup(move || trap.remove());

    // Drags: the tab pulls the drawer out, a push on the drawer closes it.
    let listeners = StoredValue::new_local(Vec::<gloo::events::EventListener>::new());
    Effect::new(move |_| {
        let (Some(t), Some(d)) = (tab.get(), drawer.get()) else {
            return;
        };
        let mut all = attach_drawer_drag(&t, DragKind::Open, panel, drag, drawer);
        all.extend(attach_drawer_drag(&d, DragKind::Close, panel, drag, drawer));
        listeners.try_set_value(all);
    });

    let drawer_style = move || match drag.try_get().flatten() {
        Some(px) => {
            format!("transform: translateX({px}px); transition: none; visibility: visible;")
        }
        None => String::new(),
    };
    let badge = move || {
        total
            .try_get()
            .and_then(|t| unread_badge(t.count, t.capped))
    };

    view! {
        <button
            type="button"
            class="tui-subs-tab"
            class:has-unread=move || badge().is_some()
            node_ref=tab
            aria-controls=PANEL_ID
            aria-expanded=move || if open.try_get().unwrap_or(false) { "true" } else { "false" }
            aria-label=move || {
                let t = total.try_get().unwrap_or_default();
                tab_accessible_name(t.count, t.capped)
            }
            title="Subscribed topics"
            on:click=move |_| panel.set_open(true)
        >
            <span class="tui-subs-tab-label" aria-hidden="true">"SUBS"</span>
            {move || badge().map(|n| view! { <span class="tui-subs-tab-num" aria-hidden="true">{n}</span> })}
        </button>
        <div
            class="tui-subs-scrim"
            class:open=move || open.try_get().unwrap_or(false) || drag.try_get().flatten().is_some()
            aria-hidden="true"
            on:click=move |_| panel.set_open(false)
        ></div>
        <div
            class="tui-subs-drawer"
            class:open=move || open.try_get().unwrap_or(false)
            class:no-motion=move || reduced.try_get().unwrap_or(false)
            id=PANEL_ID
            node_ref=drawer
            role="dialog"
            aria-modal="true"
            aria-labelledby="bbs-subs-drawer-heading"
            inert=move || !open.try_get().unwrap_or(false) && drag.try_get().flatten().is_none()
            style=drawer_style
        >
            <div class="tui-side-heading tui-subs-head">
                <span id="bbs-subs-drawer-heading">"SUBSCRIBED"</span>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-ghost bbs-btn-sm tui-subs-close"
                    node_ref=close_btn
                    aria-label="Close subscribed topics"
                    on:click=move |_| panel.set_open(false)
                >"×"</button>
            </div>
            <SubsList on_open=Callback::new(move |_| panel.set_open(false)) mobile=true />
        </div>
    }
}

/// The subscriptions panel for the current viewport: the desktop column while
/// open, the phone tab and drawer, or nothing for a visitor who is not signed
/// in. Rendered by the shell beside (never inside) the scrolling `#bbs-main`.
#[component]
pub fn SubsPanelHost() -> impl IntoView {
    let subs = use_thread_subs();
    let panel = use_subs_panel();
    let available = Memo::new(move |_| subs.available());
    let mobile = Memo::new(move |_| panel.is_mobile());

    // Signing out with the drawer open leaves nothing modal behind.
    Effect::new(move |_| {
        if !available.get() && mobile.get_untracked() && panel.is_open() {
            panel.set_open(false);
        }
    });

    move || {
        if !available.get() {
            return ().into_any();
        }
        if mobile.get() {
            view! { <SubsDrawer panel=panel /> }.into_any()
        } else if panel.is_open() {
            view! { <SubsPane panel=panel /> }.into_any()
        } else {
            ().into_any()
        }
    }
}

/// Whether the desktop column takes its grid column (the shell's
/// `.tui-body.subs-open`): a member is signed in, the viewport is not
/// phone-width, and the column is open. Reactive; read the stores during
/// setup and call this from a render closure.
pub fn desktop_column_open(available: bool, panel: SubsPanel) -> bool {
    available && !panel.is_mobile() && panel.is_open()
}

/// The top bar's desktop button that shows or hides the column, with the
/// total of new posts. Hidden on phones (the edge tab does that job) and for
/// visitors.
#[component]
pub fn SubsTopBarButton() -> impl IntoView {
    let subs = use_thread_subs();
    let panel = use_subs_panel();
    let total = subs.total_unread();
    let shown = Memo::new(move |_| subs.available() && !panel.is_mobile());
    view! {
        <Show when=move || shown.try_get().unwrap_or(false) fallback=|| ()>
            <button
                type="button"
                class="bbs-icon-btn tui-subs-topbtn"
                aria-controls=PANEL_ID
                aria-expanded=move || if panel.is_open() { "true" } else { "false" }
                aria-label=move || {
                    let t = total.try_get().unwrap_or_default();
                    tab_accessible_name(t.count, t.capped)
                }
                title="Subscribed topics (])"
                on:click=move |_| panel.toggle()
            >
                {TOGGLE_ON}
                {move || {
                    let t = total.try_get().unwrap_or_default();
                    unread_badge(t.count, t.capped).map(|n| view! { <span class="tui-bnav-badge">{n}</span> })
                }}
            </button>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic(zone: &str, slug: Option<&str>, title: Option<&str>) -> SubscribedTopic {
        SubscribedTopic {
            root: "ab".repeat(32),
            channel: "cd".repeat(32),
            zone: zone.to_string(),
            zone_slug: slug.map(str::to_string),
            title: title.map(str::to_string),
            unread: 0,
            capped: false,
        }
    }

    #[test]
    fn a_panel_row_opens_the_thread_by_slug_then_id_else_the_post_resolver() {
        let t = topic("zone-id", Some("lobby"), None);
        assert_eq!(
            panel_route(&t),
            Route::Thread {
                zone: "lobby".into(),
                channel_id: "cd".repeat(32),
                root_id: "ab".repeat(32),
                focus: None,
            }
        );
        let t = topic("zone-id", None, None);
        assert!(matches!(panel_route(&t), Route::Thread { zone, .. } if zone == "zone-id"));
        let t = topic("", Some(""), None);
        assert_eq!(
            panel_route(&t),
            Route::Go {
                event_id: "ab".repeat(32),
                channel: Some("cd".repeat(32)),
            },
            "an empty zone would give #/z//b/…, which does not parse"
        );
        // The route round-trips through the hash the row links to.
        let t = topic("zone-id", Some("lobby"), None);
        let r = panel_route(&t);
        assert_eq!(Route::from_hash(&r.to_hash()), r);
    }

    #[test]
    fn an_unknown_title_shows_the_neutral_placeholder() {
        assert_eq!(panel_title(&topic("z", None, None)), TITLE_PLACEHOLDER);
        assert_eq!(
            panel_title(&topic("z", None, Some("  "))),
            TITLE_PLACEHOLDER
        );
        assert_eq!(panel_title(&topic("z", None, Some("Hello"))), "Hello");
    }

    #[test]
    fn accessible_names_carry_the_count_in_plain_english() {
        assert_eq!(row_accessible_name("Weekly call", 0, false), "Weekly call");
        assert_eq!(
            row_accessible_name("Weekly call", 1, false),
            "Weekly call, 1 new post"
        );
        assert_eq!(
            row_accessible_name("Weekly call", 3, true),
            "Weekly call, 3+ new posts"
        );
        assert_eq!(
            row_accessible_name("Weekly call", 500, false),
            "Weekly call, 99+ new posts"
        );
        assert_eq!(tab_accessible_name(0, false), "Subscribed topics");
    }

    #[test]
    fn the_newest_shown_post_is_the_latest_of_root_and_replies() {
        assert_eq!(newest_shown(None, [5, 9]), None, "no root shown yet");
        assert_eq!(newest_shown(Some(10), []), Some(10));
        assert_eq!(newest_shown(Some(10), [12, 11, 4]), Some(12));
        assert_eq!(newest_shown(Some(20), [12]), Some(20), "an edited root");
    }

    #[test]
    fn row_keys_open_and_toggle_without_modifiers_or_repeats() {
        assert_eq!(row_key("Enter", false, false), Some(RowKey::Open));
        assert_eq!(row_key(" ", false, true), Some(RowKey::Open));
        assert_eq!(row_key("s", false, false), Some(RowKey::ToggleSubscription));
        assert_eq!(row_key("S", false, false), Some(RowKey::ToggleSubscription));
        assert_eq!(row_key("s", false, true), None, "held key does not flip");
        assert_eq!(row_key("s", true, false), None, "Ctrl+S is the browser's");
        assert_eq!(row_key("t", false, false), None, "the shell's theme key");
    }

    #[test]
    fn the_toggle_text_keeps_its_width() {
        assert_eq!(toggle_glyph(true), "[*]");
        assert_eq!(toggle_glyph(false), "[ ]");
        assert_eq!(TOGGLE_ON.chars().count(), TOGGLE_OFF.chars().count());
        assert_eq!(toggle_announcement(true), "Subscribed to this topic");
        assert_eq!(toggle_announcement(false), "Unsubscribed from this topic");
    }

    #[test]
    fn focus_wraps_only_at_the_ends() {
        assert_eq!(
            trap_focus_target(Some(0), 0, false),
            None,
            "nothing to focus"
        );
        assert_eq!(trap_focus_target(None, 3, false), Some(0), "pulled in");
        assert_eq!(trap_focus_target(None, 3, true), Some(2));
        assert_eq!(
            trap_focus_target(Some(2), 3, false),
            Some(0),
            "wraps forward"
        );
        assert_eq!(trap_focus_target(Some(0), 3, true), Some(2), "wraps back");
        assert_eq!(trap_focus_target(Some(1), 3, false), None, "browser moves");
        assert_eq!(trap_focus_target(Some(1), 3, true), None);
        assert_eq!(trap_focus_target(Some(0), 1, false), Some(0));
    }

    #[test]
    fn the_drawer_offset_follows_the_finger_within_its_width() {
        assert_eq!(drawer_offset(DragKind::Open, 0.0, 300.0), 300.0, "closed");
        assert_eq!(drawer_offset(DragKind::Open, -120.0, 300.0), 180.0);
        assert_eq!(
            drawer_offset(DragKind::Open, -400.0, 300.0),
            0.0,
            "open, no further"
        );
        assert_eq!(
            drawer_offset(DragKind::Open, 50.0, 300.0),
            300.0,
            "no further closed"
        );
        assert_eq!(drawer_offset(DragKind::Close, 120.0, 300.0), 120.0);
        assert_eq!(drawer_offset(DragKind::Close, -40.0, 300.0), 0.0);
    }

    #[test]
    fn pulling_the_tab_past_a_third_opens_and_short_of_it_stays_closed() {
        let mut d = DrawerDrag::default();
        assert!(d.down(DragKind::Open, 1, 390.0, 400.0));
        assert_eq!(d.move_to(1, 385.0, 400.0, 300.0), None, "undecided");
        assert_eq!(d.move_to(1, 370.0, 402.0, 300.0), Some(280.0), "claimed");
        assert!(d.dragging());
        assert_eq!(d.move_to(1, 280.0, 405.0, 300.0), Some(190.0));
        assert_eq!(d.up(1, 300.0), DragEnd::Settle { open: true });

        let mut d = DrawerDrag::default();
        d.down(DragKind::Open, 1, 390.0, 400.0);
        d.move_to(1, 340.0, 400.0, 300.0);
        assert_eq!(d.up(1, 300.0), DragEnd::Settle { open: false });

        let mut d = DrawerDrag::default();
        d.down(DragKind::Open, 1, 390.0, 400.0);
        assert_eq!(d.up(1, 300.0), DragEnd::None, "a tap is the click's");
    }

    #[test]
    fn pushing_the_drawer_right_past_a_third_closes_and_vertical_is_the_lists() {
        let mut d = DrawerDrag::default();
        d.down(DragKind::Close, 1, 100.0, 400.0);
        assert_eq!(d.move_to(1, 115.0, 401.0, 300.0), Some(15.0));
        d.move_to(1, 210.0, 401.0, 300.0);
        assert_eq!(d.up(1, 300.0), DragEnd::Settle { open: false });

        let mut d = DrawerDrag::default();
        d.down(DragKind::Close, 1, 100.0, 400.0);
        d.move_to(1, 150.0, 401.0, 300.0);
        assert_eq!(d.up(1, 300.0), DragEnd::Settle { open: true }, "short");

        let mut d = DrawerDrag::default();
        d.down(DragKind::Close, 1, 100.0, 400.0);
        d.move_to(1, 20.0, 401.0, 300.0);
        assert_eq!(
            d.up(1, 300.0),
            DragEnd::Settle { open: true },
            "leftwards stays open"
        );

        let mut d = DrawerDrag::default();
        d.down(DragKind::Close, 1, 100.0, 400.0);
        assert_eq!(
            d.move_to(1, 102.0, 440.0, 300.0),
            None,
            "scrolling the list"
        );
        assert_eq!(d.move_to(1, 250.0, 440.0, 300.0), None, "stays the list's");
        assert_eq!(d.up(1, 300.0), DragEnd::None);
    }

    #[test]
    fn a_cancelled_drag_returns_to_where_it_began() {
        let mut d = DrawerDrag::default();
        d.down(DragKind::Open, 1, 390.0, 400.0);
        d.move_to(1, 200.0, 400.0, 300.0);
        assert_eq!(d.cancel(1), DragEnd::Settle { open: false });
        let mut d = DrawerDrag::default();
        d.down(DragKind::Close, 1, 100.0, 400.0);
        d.move_to(1, 250.0, 400.0, 300.0);
        assert_eq!(d.cancel(1), DragEnd::Settle { open: true });
        let mut d = DrawerDrag::default();
        d.down(DragKind::Close, 1, 100.0, 400.0);
        assert_eq!(d.cancel(1), DragEnd::None);
        assert!(d.down(DragKind::Close, 2, 0.0, 0.0), "idle again");
        assert!(
            !d.down(DragKind::Close, 3, 0.0, 0.0),
            "second pointer ignored"
        );
    }
}
