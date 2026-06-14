//! `InfoTerm` — an inline "what does this mean?" explainer for hard terms.
//!
//! The onboarding surfaces lead with plain-English benefits (private, secure,
//! on your device, you're in control) and keep protocol jargon out of the
//! primary reading path. But some technical labels still appear in the
//! *advanced* / *good-to-know* corners (e.g. "relay", "WebID", "encrypted").
//! Rather than delete those terms, `InfoTerm` wraps them so a curious user can
//! get a one-line, jargon-free explanation on hover, focus, or long-press —
//! without us shipping a heavyweight popover system.
//!
//! Mechanics (self-contained, no JS, no popover coordinator):
//!
//! * the visible term is rendered as a dotted-underline `<span>`;
//! * a Tailwind `group`/`group-hover` + `focus-within` bubble is the single
//!   visible tooltip for pointer and keyboard users — we deliberately do *not*
//!   also set a native `title=` on that element, since the browser would paint
//!   its own tooltip on top of the styled bubble, producing two overlapping
//!   tooltips on hover;
//! * accessibility is carried instead by `aria-label` (the term + explainer)
//!   plus `aria-describedby` pointing at the bubble, so screen readers still
//!   announce the explanation without a competing native tooltip;
//! * `tabindex="0"` + `role="note"` make it keyboard- and AT-focusable.
//!
//! It is brand-neutral by construction: it only renders the `term` and
//! `explainer` strings the caller passes, so deploy-time branding is untouched.

use leptos::prelude::*;

/// Inline explainer for a single hard term.
///
/// # Arguments
/// * `term` — the word as shown in the UI (e.g. `"relay"`).
/// * `explainer` — a one-line, plain-English description shown on
///   hover/focus/long-press (e.g. `"The server that stores and relays the
///   forum's messages."`).
#[component]
pub(crate) fn InfoTerm(
    /// The visible term (rendered with a dotted underline).
    #[prop(into)]
    term: String,
    /// One-line plain-English explanation surfaced on hover / focus / long-press.
    #[prop(into)]
    explainer: String,
) -> impl IntoView {
    let aria = format!("{term}: {explainer}");
    // Stable per-instance id so `aria-describedby` can point screen readers at
    // the styled bubble (which carries the explainer) without us also setting a
    // native `title=` — that would paint a second, overlapping tooltip on hover.
    let bubble_id = format!("info-term-{}", next_info_term_id());
    view! {
        <span
            class="relative inline-block group"
            tabindex="0"
            role="note"
            aria-label=aria
            aria-describedby=bubble_id.clone()
        >
            <span class="underline decoration-dotted decoration-from-font underline-offset-2 cursor-help">
                {term}
            </span>
            <span
                id=bubble_id.clone()
                class="pointer-events-none absolute left-1/2 -translate-x-1/2 bottom-full mb-2 z-20 \
                       w-56 max-w-[14rem] rounded-lg bg-gray-900 text-gray-100 text-xs font-normal \
                       leading-snug px-3 py-2 shadow-lg ring-1 ring-gray-700 \
                       opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 \
                       transition-opacity duration-150 normal-case tracking-normal text-left \
                       rs-no-print"
                role="tooltip"
            >
                {explainer}
            </span>
        </span>
    }
}

/// Monotonic counter giving each `InfoTerm` instance a unique element id so
/// `aria-describedby` can reference its tooltip bubble.
fn next_info_term_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
