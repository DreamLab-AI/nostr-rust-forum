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
//! * the bubble carries a "Learn more →" link to the full glossary entry for
//!   the term (issue #19), so a curious user can read a longer plain-English
//!   explanation. The bubble itself stays `pointer-events-none` (so it never
//!   eats clicks meant for the page behind it) and only the link re-enables
//!   `pointer-events`, so it is clickable while hovered/focused;
//! * accessibility is carried instead by `aria-label` (the term + explainer)
//!   plus `aria-describedby` pointing at the bubble, so screen readers still
//!   announce the explanation without a competing native tooltip;
//! * `tabindex="0"` + `role="note"` make it keyboard- and AT-focusable.
//!
//! It is brand-neutral by construction: it only renders the `term` and
//! `explainer` strings the caller passes, so deploy-time branding is untouched.
//! The glossary link respects `FORUM_BASE` via [`crate::app::base_href`].

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;

/// Inline explainer for a single hard term.
///
/// # Arguments
/// * `term` — the word as shown in the UI (e.g. `"relay"`).
/// * `explainer` — a one-line, plain-English description shown on
///   hover/focus/long-press (e.g. `"The server that stores and relays the
///   forum's messages."`).
/// * `slug` — optional glossary anchor for the "Learn more →" link. When set
///   (e.g. `"relay"`) the link targets `/glossary#relay`; when omitted it links
///   to the top of the glossary. Slugs are defined in
///   [`crate::pages::glossary`].
#[component]
pub(crate) fn InfoTerm(
    /// The visible term (rendered with a dotted underline).
    #[prop(into)]
    term: String,
    /// One-line plain-English explanation surfaced on hover / focus / long-press.
    #[prop(into)]
    explainer: String,
    /// Optional glossary anchor slug (e.g. `"nip44"`). Defaults to the glossary
    /// top when not provided.
    #[prop(into, optional)]
    slug: Option<String>,
    /// When `true`, the tooltip bubble opens DOWNWARD instead of the default
    /// upward. Use where the term sits directly ABOVE interactive content (e.g.
    /// in helper text below a text input): an upward bubble would cover the
    /// control, and its clickable "Learn more →" link would steal the click
    /// (the DM recipient-box → glossary misclick).
    #[prop(optional)]
    below: bool,
) -> impl IntoView {
    let aria = format!("{term}: {explainer}");
    // Stable per-instance id so `aria-describedby` can point screen readers at
    // the styled bubble (which carries the explainer) without us also setting a
    // native `title=` — that would paint a second, overlapping tooltip on hover.
    let bubble_id = format!("info-term-{}", next_info_term_id());
    // Deep-link to the matching glossary entry when a slug is given; otherwise
    // link to the glossary top. `base_href` keeps the FORUM_BASE prefix correct
    // in sub-directory deployments (e.g. `/community/glossary#relay`).
    let learn_more_href = match slug.as_deref() {
        Some(s) if !s.is_empty() => base_href(&format!("/glossary#{s}")),
        _ => base_href("/glossary"),
    };
    // Flip the bubble downward when requested. Done with an inline style (higher
    // specificity than the default `bottom-full mb-2` classes) so we do not have
    // to rely on a `top-full` Tailwind utility being present in the build.
    let bubble_flip_style = if below {
        "top:100%;bottom:auto;margin-top:0.5rem;margin-bottom:0;"
    } else {
        ""
    };
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
                style=bubble_flip_style
                role="tooltip"
            >
                {explainer}
                // The bubble is `pointer-events-none` so it never intercepts
                // clicks meant for the page behind it; the link re-enables
                // pointer events on itself so it stays clickable on hover/focus.
                <A
                    href=learn_more_href
                    attr:class="pointer-events-auto mt-1.5 block text-amber-400 hover:text-amber-300 underline font-medium"
                >
                    "Learn more →"
                </A>
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
