//! Compact inline user display component.
//!
//! Shows a small identicon avatar and display name (or shortened pubkey) in a
//! single-line layout. Used in message headers, user lists, and other compact
//! contexts. Resolves display names from a layered cache:
//!
//!   1. `ProfileCache` (kind-0 metadata, batch-fetched from relay-worker).
//!   2. Legacy `NameCache` string overrides (still populated by some flows).
//!   3. Shortened hex pubkey fallback (`shorten_pubkey`).
//!
//! Display name precedence (per Sprint v10 plan):
//!   `display_name` > `name` > NIP-05 handle > shortened pubkey.

use leptos::prelude::*;

use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::copy_key::KeyGlyph;
use crate::components::profile_popover::ProfilePopover;

#[allow(unused_imports)]
pub use nostr_bbs_client_core::name_cache::{
    canonical_pubkey, provide_name_cache, try_display_name, try_display_name_tracked,
    use_display_name, use_display_name_memo, use_display_name_tracked, use_profile_cache,
    NameCache,
};

// -- Clickable inline user display -------------------------------------------

/// Inline avatar + display name that opens a [`ProfilePopover`] on click.
///
/// A self-contained, reusable unit: it renders the same compact identicon +
/// name layout used across message headers and user lists, but wraps it in a
/// `position: relative` container and a trigger button so a click toggles an
/// anchored profile preview beneath it. Open/close state is local to each
/// instance (a plain `RwSignal<bool>`), so multiple displays are independent
/// and the popover is strictly additive — nothing renders until first clicked.
///
/// This is the lightweight, popover-based counterpart to the modal flow wired
/// through [`ProfileModalTarget`](crate::components::message_bubble::ProfileModalTarget):
/// prefer it where an inline, glanceable preview is enough.
///
/// Not yet mounted at a call site — the swap of `MessageBubble`'s modal trigger
/// for this popover is a pending product decision (it would trade the modal's
/// DM/Mute actions for a lighter read-only preview), so `allow(dead_code)` keeps
/// the ready-to-mount component from warning until that call is made.
#[allow(dead_code)]
#[component]
pub fn UserDisplay(
    /// Hex pubkey to render and preview.
    pubkey: String,
    /// Avatar size. Defaults to `Md` (36 px) to match inline message headers.
    #[prop(optional)]
    size: AvatarSize,
    /// Optional extra classes for the name `<span>` (e.g. colour overrides).
    #[prop(optional, into)]
    name_class: Option<String>,
) -> impl IntoView {
    let open = RwSignal::new(false);
    let display_name = use_display_name_memo(pubkey.clone());

    let pk_avatar = pubkey.clone();
    let pk_popover = pubkey.clone();

    let name_cls = format!(
        "font-semibold text-sm truncate transition-colors {}",
        name_class
            .as_deref()
            .unwrap_or("text-amber-400 hover:text-amber-300"),
    );

    view! {
        <div class="relative inline-flex items-center">
            <button
                class="flex items-center gap-2 min-w-0 cursor-pointer text-left"
                aria-haspopup="dialog"
                aria-expanded=move || if open.get() { "true" } else { "false" }
                on:click=move |_| open.update(|o| *o = !*o)
            >
                <Avatar pubkey=pk_avatar size=size />
                <span class=name_cls>{move || display_name.get()}</span>
            </button>
            // The trigger opens the popover; while the name is still the
            // abridged key, a copy glyph sits beside it.
            <KeyGlyph pubkey=pubkey.clone() />

            <Show when=move || open.get()>
                <ProfilePopover pubkey=pk_popover.clone() is_open=open />
            </Show>
        </div>
    }
}
