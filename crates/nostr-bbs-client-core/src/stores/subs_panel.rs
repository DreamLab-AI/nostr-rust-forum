//! View-side pieces of thread subscriptions shared by the forum and the BBS:
//! the panel's open/closed state on this device ([`SubsPanel`]) and the
//! subscribe toggle a topic row uses ([`SubscribeToggle`]).
//!
//! The panel's rows come from
//! [`ThreadSubsStore::topics`](crate::stores::thread_subs::ThreadSubsStore::topics),
//! already sorted; a thread view keeps counts clear with
//! [`ThreadSubsStore::mark_read_while_viewing`](crate::stores::thread_subs::ThreadSubsStore::mark_read_while_viewing).

use gloo::storage::{LocalStorage, Storage};
use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::stores::thread_subs::{use_thread_subs, SubscribeError, ThreadSubsStore};

/// localStorage key of the desktop panel's open/closed choice. Per device,
/// never synced, and not account data (it holds only `true` or `false`).
pub const PANEL_KEY: &str = "nostrbbs:subs_panel:v1";

/// Widths at or below this (CSS px) are "mobile": the panel is an off-canvas
/// drawer that starts closed.
pub const MOBILE_MAX_WIDTH_PX: u32 = 640;

/// Whether the panel starts open: never on mobile (the drawer always starts
/// closed); on desktop the remembered choice, open when none. See
/// [`initial_open_at`] for the width-aware rule the provider uses.
pub fn initial_open(mobile: bool, stored: Option<bool>) -> bool {
    !mobile && stored.unwrap_or(true)
}

/// Widths at or above this (CSS px) leave room for the desktop column beside
/// the content, so it starts open when the member has not chosen.
pub const DESKTOP_OPEN_MIN_WIDTH_PX: u32 = 1280;

/// Whether the panel starts open at viewport `width`: never on mobile
/// (≤ [`MOBILE_MAX_WIDTH_PX`]); otherwise the remembered choice, or, with
/// none, open only from [`DESKTOP_OPEN_MIN_WIDTH_PX`] (below that the column
/// would cover the content).
pub fn initial_open_at(width: f64, stored: Option<bool>) -> bool {
    if width <= MOBILE_MAX_WIDTH_PX as f64 {
        return false;
    }
    stored.unwrap_or(width >= DESKTOP_OPEN_MIN_WIDTH_PX as f64)
}

fn viewport_width() -> f64 {
    web_sys::window()
        .and_then(|w| w.inner_width().ok())
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

/// The subscriptions panel's open/closed state on this device. Provide once
/// at the app root with [`provide_subs_panel`]; read with [`use_subs_panel`].
#[derive(Clone, Copy)]
pub struct SubsPanel {
    open: RwSignal<bool>,
    mobile: RwSignal<bool>,
}

impl SubsPanel {
    /// Whether the panel (desktop column or mobile drawer) is open. Reactive.
    pub fn is_open(&self) -> bool {
        self.open.get()
    }

    /// Whether the viewport is mobile-width ([`MOBILE_MAX_WIDTH_PX`]).
    /// Reactive: follows resizes.
    pub fn is_mobile(&self) -> bool {
        self.mobile.get()
    }

    /// Open or close it. The desktop choice is remembered on this device;
    /// the mobile drawer's is not (it always starts closed).
    pub fn set_open(&self, open: bool) {
        self.open.set(open);
        if !self.mobile.get_untracked() {
            let _ = LocalStorage::set(PANEL_KEY, open);
        }
    }

    /// Flip it.
    pub fn toggle(&self) {
        self.set_open(!self.open.get_untracked());
    }
}

fn mobile_query() -> Option<web_sys::MediaQueryList> {
    web_sys::window()?
        .match_media(&format!("(max-width: {MOBILE_MAX_WIDTH_PX}px)"))
        .ok()
        .flatten()
}

/// Provide the panel state. Call once at the app root.
pub fn provide_subs_panel() -> SubsPanel {
    let query = mobile_query();
    let mobile = query.as_ref().is_some_and(|q| q.matches());
    let stored = LocalStorage::get::<bool>(PANEL_KEY).ok();
    let open = if mobile {
        false
    } else {
        initial_open_at(viewport_width(), stored)
    };
    let panel = SubsPanel {
        open: RwSignal::new(open),
        mobile: RwSignal::new(mobile),
    };
    if let Some(q) = query {
        let target: web_sys::EventTarget = q.clone().unchecked_into();
        let listener = gloo::events::EventListener::new(&target, "change", move |_| {
            let now_mobile = q.matches();
            if now_mobile != panel.mobile.get_untracked() {
                panel.mobile.set(now_mobile);
                // Crossing into mobile closes the drawer; back to desktop
                // restores the remembered column.
                let stored = LocalStorage::get::<bool>(PANEL_KEY).ok();
                panel
                    .open
                    .set(!now_mobile && initial_open_at(viewport_width(), stored));
            }
        });
        listener.forget();
    }
    provide_context(panel);
    panel
}

/// The panel state from context. Panics if [`provide_subs_panel`] has not
/// run.
pub fn use_subs_panel() -> SubsPanel {
    expect_context::<SubsPanel>()
}

/// The subscribe toggle a topic row (button or swipe) uses.
///
/// The store applies a change synchronously to the local list, so the
/// pressed state flips at once (optimistic) and the relay copy follows later;
/// a refused change ([`SubscribeError`]) leaves the state as it was (the
/// revert) and is kept in [`Self::error`] for the view to show.
#[derive(Clone, Copy)]
pub struct SubscribeToggle {
    store: ThreadSubsStore,
    error: RwSignal<Option<SubscribeError>>,
}

impl SubscribeToggle {
    /// For a row in the current view (reads the store from context).
    pub fn new() -> Self {
        Self {
            store: use_thread_subs(),
            error: RwSignal::new(None),
        }
    }

    /// Whether the controls should show at all: a member is signed in.
    /// Reactive. (Rows a member cannot read are not listed in the first
    /// place.)
    pub fn available(&self) -> bool {
        self.store.available()
    }

    /// Whether topic `root` is followed (the button's `aria-pressed`).
    /// Reactive.
    pub fn pressed(&self, root: &str) -> bool {
        self.store.is_subscribed(root)
    }

    /// Follow or stop following topic `root` of channel `channel`. Returns
    /// whether it is followed afterwards; on refusal the state is unchanged
    /// and the error kept.
    pub fn toggle(&self, root: &str, channel: &str) -> Result<bool, SubscribeError> {
        let result = self.store.toggle(root, channel);
        self.error.set(result.as_ref().err().cloned());
        result
    }

    /// The last refusal, if the last toggle was refused. Reactive.
    pub fn error(&self) -> Option<SubscribeError> {
        self.error.get()
    }

    /// Clear the kept refusal (after the view has shown it).
    pub fn clear_error(&self) {
        self.error.set(None);
    }
}

impl Default for SubscribeToggle {
    fn default() -> Self {
        Self::new()
    }
}

/// The button's accessible label and tooltip for `pressed`.
pub fn toggle_label(pressed: bool) -> &'static str {
    if pressed {
        "Unsubscribe from this topic"
    } else {
        "Subscribe to this topic"
    }
}

/// The swipe strip's text for a row whose topic is (`pressed`) or is not
/// followed: what the swipe will do.
pub fn swipe_label(pressed: bool) -> &'static str {
    if pressed {
        "Unsubscribe"
    } else {
        "Subscribe"
    }
}

/// The unread numeral a panel row or the mobile tab shows: `None` for zero
/// (nothing is shown), `"99+"` past the display cap, `"N+"` when the count
/// may be incomplete.
pub fn unread_badge(count: usize, capped: bool) -> Option<String> {
    use crate::stores::thread_subs::UNREAD_DISPLAY_CAP;
    if count == 0 {
        None
    } else if count > UNREAD_DISPLAY_CAP {
        Some(format!("{UNREAD_DISPLAY_CAP}+"))
    } else if capped {
        Some(format!("{count}+"))
    } else {
        Some(count.to_string())
    }
}

/// The text a panel row shows for a topic whose title is not known (root not
/// fetched yet, or an encrypted zone this member cannot read): neutral, never
/// a stale title.
pub const TITLE_PLACEHOLDER: &str = "Topic unavailable";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_always_starts_closed_desktop_remembers_and_defaults_open() {
        assert!(!initial_open(true, None));
        assert!(!initial_open(true, Some(true)));
        assert!(initial_open(false, None));
        assert!(!initial_open(false, Some(false)));
        assert!(initial_open(false, Some(true)));
    }

    #[test]
    fn the_desktop_column_starts_open_only_where_it_has_room() {
        assert!(!initial_open_at(390.0, None), "mobile");
        assert!(
            !initial_open_at(640.0, Some(true)),
            "mobile ignores the choice"
        );
        assert!(!initial_open_at(641.0, None), "it would cover the content");
        assert!(!initial_open_at(1279.0, None));
        assert!(initial_open_at(1280.0, None));
        assert!(initial_open_at(1920.0, None));
        assert!(initial_open_at(900.0, Some(true)), "a choice is kept");
        assert!(!initial_open_at(1920.0, Some(false)));
    }

    #[test]
    fn the_numeral_is_hidden_at_zero_and_capped_for_display() {
        assert_eq!(unread_badge(0, false), None);
        assert_eq!(unread_badge(0, true), None);
        assert_eq!(unread_badge(7, false).as_deref(), Some("7"));
        assert_eq!(unread_badge(42, true).as_deref(), Some("42+"));
        assert_eq!(unread_badge(100, false).as_deref(), Some("99+"));
        assert_eq!(unread_badge(250, true).as_deref(), Some("99+"));
    }

    #[test]
    fn labels_say_what_the_action_will_do() {
        assert_eq!(toggle_label(false), "Subscribe to this topic");
        assert_eq!(toggle_label(true), "Unsubscribe from this topic");
        assert_eq!(swipe_label(false), "Subscribe");
        assert_eq!(swipe_label(true), "Unsubscribe");
    }
}
