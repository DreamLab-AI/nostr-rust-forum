//! Screen reader announcer component for dynamic content updates.
//!
//! Provides a live region that components can write to for accessible
//! announcements (e.g. "New message from X", "Search results: N found").

use leptos::prelude::*;

/// Provide the screen reader announcement signal. Call once near the app root.
pub fn provide_announcer() {
    let signal = RwSignal::new(String::new());
    provide_context(AnnouncerSignal(signal));
}

/// Wrapper around the announcement signal for type-safe context.
#[derive(Clone, Copy)]
pub struct AnnouncerSignal(pub RwSignal<String>);

/// Retrieve the announcer signal from context.
pub fn use_announcer() -> AnnouncerSignal {
    use_context::<AnnouncerSignal>().unwrap_or_else(|| {
        let signal = RwSignal::new(String::new());
        let ann = AnnouncerSignal(signal);
        provide_context(ann);
        ann
    })
}

/// Push an announcement to the screen reader live region.
///
/// Must be called from within a reactive scope (component body).
/// The signal is cleared and re-set so repeated identical messages still trigger.
#[allow(dead_code)]
pub fn announce(ann: AnnouncerSignal, message: &str) {
    ann.0.set(String::new());
    let msg = message.to_string();
    crate::utils::set_timeout_once(move || {
        ann.0.set(msg);
    }, 50);
}

/// Invisible live region that relays announcements to screen readers.
///
/// Mount once in the layout. Components announce via `use_announcer()` and
/// the `announce()` helper function.
#[component]
pub(crate) fn ScreenReaderAnnouncer() -> impl IntoView {
    let ann = use_announcer();

    view! {
        <div
            role="status"
            aria-live="polite"
            aria-atomic="true"
            class="sr-only"
        >
            {move || ann.0.get()}
        </div>
    }
}
