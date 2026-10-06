//! Hover to inspect on the flat (DOM) poker table: the 2D counterpart of the
//! 3D table's card inspection (`js/table3d/inspect.js`).
//!
//! Hovering the hero's face-up hole cards, or the board, enlarges that group
//! towards the viewer: a fixed-position clone of the group is laid exactly
//! over it, then translated and scaled with a CSS transition until it fills
//! most of the viewport, centred, above the page and below any modal. The
//! group's own slot keeps its place (transparent while the clone is up, and
//! still hoverable), so the table never reflows; leaving shrinks the clone back onto the
//! slot and removes it. The animation is CSS transforms alone, so it runs on
//! every render tier, including the CSS-only one, and costs nothing at rest.
//!
//! The state is a small pure machine ([`PeekModel::next`]) held in a signal
//! by [`FlatPeek`]; one effect turns its changes into DOM work. It never
//! touches the game: a new frame drops the group at once, before the new
//! view is shown, and so does the 3D table taking over, a scroll or a resize.
//!
//! Input: mouse hover; touch taps a group to inspect and anywhere else to
//! drop; the keyboard reaches each group as a tab stop, Enter or Space
//! toggles, Escape or Tab away drops. A polite live region names the cards.

use leptos::ev;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::components::table3d::{peek_text, Peek, PeekGroup};

/// Rise time, ms (ease-out); the stylesheet's `.peek2d-clone` transition.
pub const RISE_MS: i32 = 450;
/// Drop time, ms (ease-in); `.peek2d-clone.peek2d-down`.
pub const DROP_MS: i32 = 350;
/// The reduced-motion crossfade, ms; `.peek2d-fade`.
pub const FADE_MS: i32 = 140;
/// Share of the viewport's shorter side the enlarged group fills.
pub const FILL: f64 = 0.8;
/// The enlarged group never grows wider than this share of the viewport.
pub const MAX_WIDTH: f64 = 0.92;

/// What lifted the active group: it decides what drops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeekSource {
    /// The mouse is over the group; leaving drops it.
    Hover,
    /// A tap; a tap anywhere else drops it.
    Tap,
    /// Enter or Space on the group's tab stop; Escape or Tab away drops it.
    Key,
}

/// The inspection state: the group up (and what lifted it), the flourish's
/// tilt, and whether the last drop should skip its animation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeekModel {
    /// The group enlarged now, if any.
    pub active: Option<(PeekGroup, PeekSource)>,
    /// The settle-in tilt of the current inspection, in degrees (signed).
    pub tilt_deg: f64,
    /// The last drop was instant (a new frame, a scroll): no shrink back.
    pub instant: bool,
}

impl Default for PeekModel {
    fn default() -> Self {
        Self {
            active: None,
            tilt_deg: 0.0,
            instant: false,
        }
    }
}

/// Everything that can change the inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeekInput {
    /// The mouse entered a group.
    Enter(PeekGroup),
    /// The mouse left a group.
    Leave(PeekGroup),
    /// A tap or a key (Enter, Space) on a group.
    Toggle(PeekGroup, PeekSource),
    /// Escape.
    Escape,
    /// A group's tab stop lost focus.
    Blur(PeekGroup),
    /// A tap outside every group.
    TapAway,
    /// A new frame (the view or the log changed): drop at once.
    Frame,
    /// The flat table stopped being the one shown (the 3D table took
    /// over), the page scrolled or the window resized: drop at once.
    Reset,
}

/// The settle-in tilt for a random draw `r` in [0, 1): either sign, between
/// 1.5° and 4°.
pub fn tilt_for(r: f64) -> f64 {
    let r = r.clamp(0.0, 0.999_999);
    let sign = if r < 0.5 { -1.0 } else { 1.0 };
    sign * (1.5 + 2.5 * (r * 2.0).fract())
}

impl PeekModel {
    /// The group enlarged now.
    pub fn group(&self) -> Option<PeekGroup> {
        self.active.map(|(g, _)| g)
    }

    /// The state after `input`; `r` (in [0, 1)) draws a new inspection's tilt.
    pub fn next(self, input: PeekInput, r: f64) -> Self {
        let lift = |g, src| Self {
            active: Some((g, src)),
            tilt_deg: tilt_for(r),
            instant: false,
        };
        let fall = |instant| Self {
            active: None,
            tilt_deg: self.tilt_deg,
            instant,
        };
        match (input, self.active) {
            (PeekInput::Enter(g), Some((a, _))) if a == g => self,
            (PeekInput::Enter(g), _) => lift(g, PeekSource::Hover),
            (PeekInput::Leave(g), Some((a, PeekSource::Hover))) if a == g => fall(false),
            (PeekInput::Toggle(g, _), Some((a, _))) if a == g => fall(false),
            (PeekInput::Toggle(g, src), _) => lift(g, src),
            (PeekInput::Escape | PeekInput::TapAway, Some(_)) => fall(false),
            (PeekInput::Blur(g), Some((a, PeekSource::Key))) if a == g => fall(false),
            (PeekInput::Frame | PeekInput::Reset, Some(_)) => fall(true),
            _ => self,
        }
    }
}

/// Whether the group up now was lifted by a tap (not a mouse or a key): only
/// then does the clone layer take the next tap (`capture_taps`).
pub fn lifted_by_tap(model: &PeekModel) -> bool {
    matches!(model.active, Some((_, PeekSource::Tap)))
}

/// Where the enlarged group goes: the translation (px) that centres a group
/// at `rect` (left, top, width, height) in a `vw` × `vh` viewport, and the
/// scale that makes it fill [`FILL`] of the shorter side (no wider than
/// [`MAX_WIDTH`] of the viewport, never smaller than it is).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fit {
    /// Horizontal translation, px.
    pub dx: f64,
    /// Vertical translation, px.
    pub dy: f64,
    /// Scale about the group's own centre.
    pub scale: f64,
}

/// The [`Fit`] for a group at `rect` in a `vw` × `vh` viewport.
pub fn fit(rect: (f64, f64, f64, f64), vw: f64, vh: f64) -> Fit {
    let (l, t, w, h) = rect;
    let w = w.max(1.0);
    let h = h.max(1.0);
    let scale = (FILL * vw.min(vh) / h).min(MAX_WIDTH * vw / w).max(1.0);
    Fit {
        dx: vw / 2.0 - (l + w / 2.0),
        dy: vh / 2.0 - (t + h / 2.0),
        scale,
    }
}

impl Fit {
    /// The CSS `transform` value.
    pub fn css(&self) -> String {
        format!(
            "translate({:.1}px, {:.1}px) scale({:.4})",
            self.dx, self.dy, self.scale
        )
    }
}

/// The live-region text for `model`, naming `cards` with `name`.
pub fn live_text(model: &PeekModel, cards: &[u8], name: impl Fn(u8) -> String) -> String {
    match model.group() {
        Some(group) => peek_text(
            &Peek {
                group,
                inspecting: true,
                cards: cards.to_vec(),
            },
            name,
        ),
        None => String::new(),
    }
}

/// The `aria-label` of a group's tab stop. The stop is a button, which
/// hides the cards inside it from assistive technology, so it names them.
pub fn slot_label(group: PeekGroup, names: &[String]) -> String {
    if names.is_empty() {
        format!("Inspect {}", group.label())
    } else {
        format!("Inspect {}: {}", group.label(), names.join(" "))
    }
}

// -- The controller --------------------------------------------------------------

/// One registered group on the page.
struct Slot {
    group: PeekGroup,
    el: web_sys::HtmlElement,
    cards: Vec<u8>,
}

/// One enlarged clone.
struct Lifted {
    group: PeekGroup,
    el: web_sys::HtmlElement,
    slot: web_sys::HtmlElement,
    /// Bumped on every rise and drop, so a stale timer does nothing.
    gen: u64,
    down: bool,
}

/// The flat table's inspection: its state signal, the registered groups, the
/// clones that are up, and the window listeners that exist only while one is.
#[derive(Clone, Copy)]
pub struct FlatPeek {
    /// The inspection state.
    pub state: RwSignal<PeekModel>,
    /// Whether the flat table is the one shown (false under the 3D table).
    pub enabled: Signal<bool>,
    reduced: Signal<bool>,
    slots: StoredValue<Vec<Slot>, LocalStorage>,
    lifted: StoredValue<Vec<Lifted>, LocalStorage>,
    listeners: StoredValue<Vec<WindowListenerHandle>, LocalStorage>,
    gen: StoredValue<u64>,
}

/// A random draw in [0, 1) (the browser's; a fixed draw off the web).
fn random() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Math::random()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0.5
    }
}

impl FlatPeek {
    /// A controller with no DOM work installed (see [`provide_flat_peek`]).
    pub fn new(enabled: Signal<bool>, reduced: Signal<bool>) -> Self {
        Self {
            state: RwSignal::new(PeekModel::default()),
            enabled,
            reduced,
            slots: StoredValue::new_local(Vec::new()),
            lifted: StoredValue::new_local(Vec::new()),
            listeners: StoredValue::new_local(Vec::new()),
            gen: StoredValue::new(0),
        }
    }

    /// Apply `input` with tilt draw `r`; true if the state changed.
    pub fn dispatch_with(&self, input: PeekInput, r: f64) -> bool {
        let now = self.state.get_untracked();
        let next = now.next(input, r);
        if next == now {
            return false;
        }
        self.state.set(next);
        true
    }

    /// Apply `input`; true if the state changed.
    pub fn dispatch(&self, input: PeekInput) -> bool {
        self.dispatch_with(input, random())
    }

    /// The cards of the newest registered `group`.
    pub fn cards_of(&self, group: PeekGroup) -> Vec<u8> {
        self.slots.with_value(|s| {
            s.iter()
                .rev()
                .find(|s| s.group == group)
                .map(|s| s.cards.clone())
                .unwrap_or_default()
        })
    }

    fn register(&self, group: PeekGroup, el: web_sys::HtmlElement, cards: Vec<u8>) {
        self.slots.update_value(|s| {
            s.retain(|x| x.el.is_connected() && !x.el.is_same_node(Some(&el)));
            s.push(Slot { group, el, cards });
        });
    }

    fn unregister(&self, el: &web_sys::HtmlElement) {
        self.slots
            .try_update_value(|s| s.retain(|x| !x.el.is_same_node(Some(el))));
    }

    fn slot_el(&self, group: PeekGroup) -> Option<web_sys::HtmlElement> {
        self.slots.with_value(|s| {
            s.iter()
                .rev()
                .find(|s| s.group == group && s.el.is_connected())
                .map(|s| s.el.clone())
        })
    }

    /// Whether `target` lies inside a registered group.
    fn in_any_slot(&self, target: &web_sys::Node) -> bool {
        self.slots
            .with_value(|s| s.iter().any(|x| x.el.contains(Some(target))))
    }

    fn next_gen(&self) -> u64 {
        self.gen.update_value(|g| *g += 1);
        self.gen.get_value()
    }

    /// Enlarge `group`: a new clone over its slot, or the one still
    /// shrinking turned round from where it is.
    fn raise(&self, group: PeekGroup, tilt: f64) {
        let gen = self.next_gen();
        let reduced = self.reduced.get_untracked();
        let turned = self.lifted.try_update_value(|l| {
            let c = l.iter_mut().find(|c| c.group == group)?;
            c.down = false;
            c.gen = gen;
            let _ = c.el.class_list().remove_1("peek2d-down");
            let style = c.el.style();
            let _ = style.set_property("will-change", "transform");
            if !reduced {
                if let Some(f) = fit_of(&c.slot) {
                    let _ = style.set_property("transform", &f.css());
                }
            }
            let _ = c.el.class_list().add_1("peek2d-up");
            Some(c.el.clone())
        });
        if let Some(Some(el)) = turned {
            self.settle_later(el, gen);
            return;
        }
        let Some(slot) = self.slot_el(group) else {
            return;
        };
        let Some(el) = clone_of(&slot, tilt) else {
            return;
        };
        let Some(layer) = layer() else {
            return;
        };
        let Some(target) = fit_of(&slot) else {
            return;
        };
        let style = el.style();
        if reduced {
            // a crossfade in place of the travel: appear where it ends up
            let _ = el.class_list().add_1("peek2d-fade");
            let _ = style.set_property("transform", &target.css());
        } else {
            let _ = style.set_property("transform", "translate(0px, 0px) scale(1)");
        }
        let _ = layer.append_child(&el);
        // commit the start state, so the change below transitions
        let _ = el.offset_width();
        if !reduced {
            let _ = style.set_property("transform", &target.css());
            // opacity, not visibility: a hidden slot cannot be hovered, so the
            // pointer would leave it the moment the clone rose
            let _ = slot.style().set_property("opacity", "0");
        }
        let _ = el.class_list().add_1("peek2d-up");
        self.lifted.update_value(|l| {
            l.push(Lifted {
                group,
                el: el.clone(),
                slot,
                gen,
                down: false,
            })
        });
        self.settle_later(el, gen);
    }

    /// Once risen, drop `will-change`, so the browser repaints the enlarged
    /// cards at full resolution rather than scaling a bitmap.
    fn settle_later(&self, el: web_sys::HtmlElement, gen: u64) {
        let this = *self;
        crate::utils::set_timeout_once(
            move || {
                let current = this
                    .lifted
                    .try_with_value(|l| l.iter().any(|c| c.gen == gen && !c.down))
                    .unwrap_or(false);
                if current {
                    let _ = el.style().remove_property("will-change");
                }
            },
            RISE_MS + 40,
        );
    }

    /// Shrink `group` back onto its slot (or remove it at once).
    fn drop_group(&self, group: PeekGroup, instant: bool) {
        if instant {
            self.remove_where(|c| c.group == group);
            return;
        }
        let gen = self.next_gen();
        let reduced = self.reduced.get_untracked();
        let found = self.lifted.try_update_value(|l| {
            let c = l.iter_mut().find(|c| c.group == group)?;
            c.down = true;
            c.gen = gen;
            let style = c.el.style();
            let _ = style.set_property("will-change", "transform");
            let _ = c.el.class_list().remove_1("peek2d-up");
            let _ = c.el.class_list().add_1("peek2d-down");
            if !c.el.class_list().contains("peek2d-fade") {
                let _ = style.set_property("transform", "translate(0px, 0px) scale(1)");
            }
            Some(())
        });
        if !matches!(found, Some(Some(()))) {
            return;
        }
        let this = *self;
        let wait = if reduced { FADE_MS } else { DROP_MS } + 40;
        crate::utils::set_timeout_once(move || this.remove_where(|c| c.gen == gen && c.down), wait);
    }

    /// Remove the clones matching `pred` and show their slots again; once
    /// none is left, taps go through to the page again.
    fn remove_where(&self, pred: impl Fn(&Lifted) -> bool) {
        let emptied = self.lifted.try_update_value(|l| {
            l.retain(|c| {
                if pred(c) {
                    c.el.remove();
                    let _ = c.slot.style().remove_property("opacity");
                    false
                } else {
                    true
                }
            });
            l.is_empty()
        });
        if emptied == Some(true) {
            capture_taps(false);
        }
    }

    /// While a group is up: a tap elsewhere drops it, and a scroll or a
    /// resize (which move the slot under the clone) drop it at once. The
    /// listeners exist only while something is up.
    fn sync_listeners(&self, active: bool) {
        let have = self.listeners.with_value(|l| !l.is_empty());
        if active == have {
            return;
        }
        if !active {
            self.listeners
                .update_value(|l| l.drain(..).for_each(WindowListenerHandle::remove));
            return;
        }
        let this = *self;
        let tap = window_event_listener(ev::pointerdown, move |e: web_sys::PointerEvent| {
            if e.pointer_type() == "mouse"
                && this.state.get_untracked().active.map(|a| a.1) == Some(PeekSource::Hover)
            {
                return;
            }
            let inside = e
                .target()
                .and_then(|t| t.dyn_into::<web_sys::Node>().ok())
                .is_some_and(|n| this.in_any_slot(&n));
            if !inside {
                this.dispatch(PeekInput::TapAway);
            }
        });
        let scroll = window_event_listener(ev::scroll, move |_| {
            this.dispatch(PeekInput::Reset);
        });
        let resize = window_event_listener(ev::resize, move |_| {
            this.dispatch(PeekInput::Reset);
        });
        self.listeners
            .update_value(|l| l.extend([tap, scroll, resize]));
    }

    /// Put everything down at once and release every listener.
    pub fn teardown(&self) {
        self.remove_where(|_| true);
        let _ = self
            .listeners
            .try_update_value(|l| l.drain(..).for_each(WindowListenerHandle::remove));
        if let Some(layer) = existing_layer() {
            if layer.child_element_count() == 0 {
                layer.remove();
            }
        }
    }
}

/// The fixed layer the clones live in, a direct child of `<body>` (an
/// ancestor with a backdrop filter would otherwise capture `position: fixed`).
fn existing_layer() -> Option<web_sys::Element> {
    web_sys::window()?
        .document()?
        .query_selector(".peek2d-layer")
        .ok()
        .flatten()
}

/// Whether the clone layer takes taps itself. A group lifted by a tap covers
/// most of a phone's screen, the action buttons included; the tap that puts
/// it down must land on the layer, not on whatever lies under the cards. It
/// stays on until the last clone has shrunk away, so the click that follows
/// the tap never reaches the page either.
fn capture_taps(on: bool) {
    let Some(layer) = existing_layer() else {
        return;
    };
    let _ = if on {
        layer.set_attribute("data-peek-capture", "")
    } else {
        layer.remove_attribute("data-peek-capture")
    };
}

fn layer() -> Option<web_sys::Element> {
    if let Some(l) = existing_layer() {
        return Some(l);
    }
    let doc = web_sys::window()?.document()?;
    let l = doc.create_element("div").ok()?;
    l.set_class_name("peek2d-layer");
    let _ = l.set_attribute("aria-hidden", "true");
    doc.body()?.append_child(&l).ok()?;
    Some(l)
}

/// The slot's [`Fit`] in the current viewport.
fn fit_of(slot: &web_sys::HtmlElement) -> Option<Fit> {
    let w = web_sys::window()?;
    let vw = w.inner_width().ok()?.as_f64()?;
    let vh = w.inner_height().ok()?.as_f64()?;
    let r = slot.get_bounding_client_rect();
    Some(fit((r.left(), r.top(), r.width(), r.height()), vw, vh))
}

/// A static copy of `slot`, laid exactly over it, inert to input and to
/// assistive technology (the slot stays the accessible one).
fn clone_of(slot: &web_sys::HtmlElement, tilt: f64) -> Option<web_sys::HtmlElement> {
    let el: web_sys::HtmlElement = slot.clone_node_with_deep(true).ok()?.dyn_into().ok()?;
    for attr in ["tabindex", "role", "aria-pressed", "aria-label", "id"] {
        let _ = el.remove_attribute(attr);
    }
    let _ = el.set_attribute("aria-hidden", "true");
    el.set_class_name(&format!("{} peek2d-clone", slot.class_name()));
    let _ = el.class_list().remove_1("peek2d-slot");
    let r = slot.get_bounding_client_rect();
    let style = el.style();
    let _ = style.set_property("left", &format!("{:.1}px", r.left()));
    let _ = style.set_property("top", &format!("{:.1}px", r.top()));
    let _ = style.set_property("width", &format!("{:.1}px", r.width()));
    let _ = style.set_property("height", &format!("{:.1}px", r.height()));
    let _ = style.set_property("--peek-tilt", &format!("{tilt:.2}deg"));
    let _ = style.set_property("will-change", "transform");
    let _ = style.remove_property("opacity");
    Some(el)
}

/// Whether the OS asks for reduced motion.
fn os_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-reduced-motion: reduce)")
                .ok()
                .flatten()
        })
        .is_some_and(|mq| mq.matches())
}

/// Provide the flat table's inspection to the groups below, drive the DOM
/// from its state, and drop everything when `frame` changes or the flat
/// table stops being the one shown. Returns the live-region text.
pub fn provide_flat_peek(enabled: Signal<bool>, frame: Signal<Option<String>>) -> Signal<String> {
    let prefs = crate::stores::preferences::use_preferences();
    let reduced = Signal::derive(move || prefs.with(|p| p.reduced_motion) || os_reduced_motion());
    let peek = FlatPeek::new(enabled, reduced);
    provide_context(peek);

    // the state's changes, as DOM work
    Effect::new(move |prev: Option<Option<PeekGroup>>| {
        let m = peek.state.get();
        let now = m.group();
        let before = prev.flatten();
        if before != now {
            if let Some(b) = before {
                peek.drop_group(b, m.instant);
            }
            if let Some(n) = now {
                peek.raise(n, m.tilt_deg);
            }
            if lifted_by_tap(&m) {
                capture_taps(true);
            }
            peek.sync_listeners(now.is_some());
        }
        now
    });

    // a new frame drops the group before the new view is read
    // (read and compared, not merely tracked: the frame is a memo, and only
    // a read brings it up to date)
    Effect::new(move |prev: Option<Option<String>>| {
        let now = frame.get();
        if prev.is_some_and(|p| p != now) {
            peek.dispatch(PeekInput::Frame);
        }
        now
    });

    // the 3D table took over
    Effect::new(move |_| {
        if !enabled.get() {
            peek.dispatch(PeekInput::Reset);
        }
    });

    on_cleanup(move || peek.teardown());

    Signal::derive(move || {
        let m = peek.state.get();
        match m.group() {
            Some(g) => live_text(&m, &peek.cards_of(g), crate::poker::card_name),
            None => String::new(),
        }
    })
}

/// A group of cards the member can inspect on the flat table: the hero's
/// hole cards or the board. Outside a [`provide_flat_peek`] scope, or with
/// no cards, it is a plain wrapper.
#[component]
pub fn PeekSlot(
    /// Which group.
    group: PeekGroup,
    /// The group's cards, for the announcement.
    cards: Vec<u8>,
    /// The wrapper's classes (its layout in the table).
    #[prop(into)]
    class: String,
    /// The cards.
    children: Children,
) -> impl IntoView {
    let Some(peek) = use_context::<FlatPeek>().filter(|_| !cards.is_empty()) else {
        return view! { <div class=class>{children()}</div> }.into_any();
    };
    let label = slot_label(
        group,
        &cards
            .iter()
            .map(|&c| crate::poker::card_name(c))
            .collect::<Vec<_>>(),
    );
    let node = NodeRef::<leptos::html::Div>::new();
    let registered: StoredValue<Option<web_sys::HtmlElement>, LocalStorage> =
        StoredValue::new_local(None);
    Effect::new(move |_| {
        if let Some(el) = node.get() {
            let el: web_sys::HtmlElement = el.into();
            peek.register(group, el.clone(), cards.clone());
            registered.set_value(Some(el));
        }
    });
    on_cleanup(move || {
        if let Some(el) = registered.try_get_value().flatten() {
            peek.unregister(&el);
        }
    });
    let on = move || peek.enabled.get();
    let pressed = move || (peek.state.get().group() == Some(group)).to_string();
    view! {
        <div
            node_ref=node
            class=format!("{class} peek2d-slot")
            tabindex=move || on().then_some("0")
            role=move || on().then_some("button")
            aria-label=move || on().then(|| label.clone())
            aria-pressed=move || on().then(pressed)
            on:pointerenter=move |e: web_sys::PointerEvent| {
                if on() && e.pointer_type() == "mouse" {
                    peek.dispatch(PeekInput::Enter(group));
                }
            }
            on:pointerleave=move |e: web_sys::PointerEvent| {
                if e.pointer_type() == "mouse" {
                    peek.dispatch(PeekInput::Leave(group));
                }
            }
            on:pointerup=move |e: web_sys::PointerEvent| {
                if on() && e.pointer_type() != "mouse" {
                    peek.dispatch(PeekInput::Toggle(group, PeekSource::Tap));
                }
            }
            on:keydown=move |e: web_sys::KeyboardEvent| {
                if !on() {
                    return;
                }
                match e.key().as_str() {
                    "Enter" | " " | "Spacebar" => {
                        // the page's own Enter (deal the next hand) never sees it
                        e.prevent_default();
                        e.stop_propagation();
                        peek.dispatch(PeekInput::Toggle(group, PeekSource::Key));
                    }
                    "Escape" if peek.state.get_untracked().active.is_some() => {
                        e.prevent_default();
                        e.stop_propagation();
                        peek.dispatch(PeekInput::Escape);
                    }
                    _ => {}
                }
            }
            on:blur=move |_| {
                peek.dispatch(PeekInput::Blur(group));
            }
        >
            {children()}
        </div>
    }
    .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLE: PeekGroup = PeekGroup::Hole;
    const BOARD: PeekGroup = PeekGroup::Board;

    #[test]
    fn only_a_tap_lift_captures_the_next_tap() {
        let m = PeekModel::default();
        assert!(!lifted_by_tap(&m));
        let tapped = m.next(PeekInput::Toggle(HOLE, PeekSource::Tap), 0.3);
        assert!(lifted_by_tap(&tapped));
        assert!(!lifted_by_tap(&m.next(PeekInput::Enter(BOARD), 0.3)));
        assert!(!lifted_by_tap(
            &m.next(PeekInput::Toggle(BOARD, PeekSource::Key), 0.3)
        ));
        // the tap that lands on the layer puts the group down
        assert!(!lifted_by_tap(&tapped.next(PeekInput::TapAway, 0.3)));
    }

    #[test]
    fn hover_lifts_and_leaving_drops() {
        let m = PeekModel::default();
        let up = m.next(PeekInput::Enter(HOLE), 0.7);
        assert_eq!(up.active, Some((HOLE, PeekSource::Hover)));
        assert!(!up.instant);
        assert_eq!(
            up.next(PeekInput::Enter(HOLE), 0.1),
            up,
            "re-entering is a no-op"
        );
        assert_eq!(
            up.next(PeekInput::Leave(BOARD), 0.1),
            up,
            "leaving another group"
        );
        let down = up.next(PeekInput::Leave(HOLE), 0.1);
        assert_eq!(down.active, None);
        assert!(!down.instant, "a hover drop shrinks back");
        // hovering another group switches straight to it
        let board = up.next(PeekInput::Enter(BOARD), 0.2);
        assert_eq!(board.group(), Some(BOARD));
    }

    #[test]
    fn taps_and_keys_toggle_and_only_their_own_ends_drop_them() {
        let m = PeekModel::default();
        let tap = m.next(PeekInput::Toggle(BOARD, PeekSource::Tap), 0.3);
        assert_eq!(tap.active, Some((BOARD, PeekSource::Tap)));
        assert_eq!(
            tap.next(PeekInput::Leave(BOARD), 0.3),
            tap,
            "no hover to leave"
        );
        assert_eq!(tap.next(PeekInput::TapAway, 0.3).active, None);
        assert_eq!(
            tap.next(PeekInput::Toggle(BOARD, PeekSource::Tap), 0.3)
                .active,
            None
        );
        let key = m.next(PeekInput::Toggle(HOLE, PeekSource::Key), 0.3);
        assert_eq!(key.active, Some((HOLE, PeekSource::Key)));
        assert_eq!(key.next(PeekInput::Blur(BOARD), 0.3), key);
        assert_eq!(
            key.next(PeekInput::Blur(HOLE), 0.3).active,
            None,
            "Tab away drops"
        );
        assert_eq!(key.next(PeekInput::Escape, 0.3).active, None);
        assert_eq!(
            key.next(PeekInput::Toggle(HOLE, PeekSource::Key), 0.3)
                .active,
            None
        );
        // nothing up: Escape, a tap away and a blur change nothing
        for i in [
            PeekInput::Escape,
            PeekInput::TapAway,
            PeekInput::Blur(HOLE),
            PeekInput::Leave(HOLE),
        ] {
            assert_eq!(m.next(i, 0.3), m);
        }
    }

    #[test]
    fn a_new_frame_or_a_reset_drops_at_once() {
        let up = PeekModel::default().next(PeekInput::Enter(HOLE), 0.6);
        for i in [PeekInput::Frame, PeekInput::Reset] {
            let d = up.next(i, 0.6);
            assert_eq!(d.active, None);
            assert!(d.instant, "{i:?} skips the shrink");
        }
        // and a later lift animates again
        let again = up
            .next(PeekInput::Frame, 0.6)
            .next(PeekInput::Enter(BOARD), 0.6);
        assert!(!again.instant);
        assert_eq!(
            PeekModel::default().next(PeekInput::Frame, 0.6),
            PeekModel::default()
        );
    }

    #[test]
    fn the_tilt_is_either_way_and_gentle() {
        let tilts: Vec<f64> = (0..100).map(|i| tilt_for(f64::from(i) / 100.0)).collect();
        assert!(tilts.iter().all(|t| (1.5..=4.0).contains(&t.abs())));
        assert!(tilts.iter().any(|t| *t < 0.0) && tilts.iter().any(|t| *t > 0.0));
        let lifted = PeekModel::default().next(PeekInput::Enter(HOLE), 0.9);
        assert_eq!(lifted.tilt_deg, tilt_for(0.9));
        assert!(tilt_for(1.0).abs() <= 4.0);
    }

    #[test]
    fn the_fit_centres_and_fills_the_shorter_side() {
        // two hole cards near the bottom of a landscape window
        let f = fit((600.0, 700.0, 104.0, 64.0), 1280.0, 900.0);
        assert!((f.scale * 64.0 - 0.8 * 900.0).abs() < 1e-9);
        assert!(f.scale * 104.0 <= 0.92 * 1280.0);
        // the centre lands on the viewport's centre
        assert!((600.0 + 52.0 + f.dx - 640.0).abs() < 1e-9);
        assert!((700.0 + 32.0 + f.dy - 450.0).abs() < 1e-9);
        // the board: bound by the width
        let b = fit((400.0, 300.0, 280.0, 64.0), 1280.0, 900.0);
        assert!((b.scale * 280.0 - 0.92 * 1280.0).abs() < 1e-9);
        // a phone: the shorter side is the width
        let p = fit((100.0, 500.0, 90.0, 56.0), 390.0, 844.0);
        assert!(p.scale * 56.0 <= 0.8 * 390.0 + 1e-9);
        assert!(p.scale * 90.0 <= 0.92 * 390.0 + 1e-9);
        // never shrinks
        assert_eq!(fit((0.0, 0.0, 2000.0, 2000.0), 800.0, 600.0).scale, 1.0);
        assert_eq!(
            f.css(),
            format!(
                "translate({:.1}px, {:.1}px) scale({:.4})",
                f.dx, f.dy, f.scale
            )
        );
    }

    #[test]
    fn the_announcement_names_the_group_and_its_cards() {
        let name = |c: u8| ["A♠", "K♥", "7♣", "2♦", "T♠"][usize::from(c) % 5].to_string();
        let m = PeekModel::default().next(PeekInput::Enter(HOLE), 0.5);
        assert_eq!(
            live_text(&m, &[0, 1], name),
            "Inspecting your hole cards: A♠ K♥"
        );
        let b = m.next(PeekInput::Enter(BOARD), 0.5);
        assert_eq!(
            live_text(&b, &[2, 3, 4], name),
            "Inspecting the board: 7♣ 2♦ T♠"
        );
        assert_eq!(live_text(&PeekModel::default(), &[0], name), "");
        assert_eq!(slot_label(HOLE, &[]), "Inspect your hole cards");
        assert_eq!(
            slot_label(BOARD, &["7♣".into(), "2♦".into(), "T♠".into()]),
            "Inspect the board: 7♣ 2♦ T♠"
        );
    }

    #[test]
    fn the_state_signal_follows_the_inputs() {
        let owner = Owner::new();
        owner.with(|| {
            let p = FlatPeek::new(Signal::derive(|| true), Signal::derive(|| false));
            assert!(p.dispatch_with(PeekInput::Enter(HOLE), 0.25));
            assert_eq!(p.state.get_untracked().group(), Some(HOLE));
            assert!(
                !p.dispatch_with(PeekInput::Enter(HOLE), 0.9),
                "unchanged: no notification"
            );
            assert_eq!(
                p.state.get_untracked().tilt_deg,
                tilt_for(0.25),
                "the tilt is kept"
            );
            // a new frame lands while inspecting
            assert!(p.dispatch_with(PeekInput::Frame, 0.1));
            let s = p.state.get_untracked();
            assert_eq!(s.active, None);
            assert!(s.instant);
            assert!(!p.dispatch_with(PeekInput::Frame, 0.1));
            assert!(p.dispatch_with(PeekInput::Toggle(BOARD, PeekSource::Key), 0.6));
            assert!(p.dispatch_with(PeekInput::Escape, 0.6));
            assert_eq!(p.state.get_untracked().active, None);
            assert!(
                p.cards_of(HOLE).is_empty(),
                "nothing registered off the page"
            );
        });
    }
}
