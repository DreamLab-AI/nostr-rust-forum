//! Lightweight, anchored profile popover.
//!
//! A compact, click-outside-dismissable card that surfaces a user's profile at
//! a glance — larger avatar, display name, NIP-05 handle, a truncated bio, and a
//! copyable shortened pubkey. Unlike [`ProfileModal`](crate::components::profile_modal::ProfileModal),
//! which is a centred full overlay with DM/mute actions and a live relay fetch,
//! this popover is purely a read-only preview driven off the shared
//! [`ProfileCache`]. It is meant to be rendered inside a `position: relative`
//! wrapper (e.g. [`UserDisplay`](crate::components::user_display::UserDisplay))
//! so it anchors just beneath the clicked avatar/name.
//!
//! All data is resolved *reactively* from the cache, so the card fills in as
//! kind-0 metadata arrives — a cache miss schedules the debounced batch fetch
//! and the fields populate without any imperative refresh.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;

use crate::components::avatar::{Avatar, AvatarSize};
use crate::components::user_display::use_display_name_tracked;
use crate::stores::profile_cache::{format_nip05_handle, try_use_profile_cache};
use crate::utils::{set_timeout_once, shorten_pubkey};

/// Copy `text` to the clipboard via `navigator.clipboard.writeText`, reached
/// through `Reflect` so we don't need the (unstable) web-sys `Clipboard`
/// feature. Best-effort: any missing capability is a silent no-op. Mirrors the
/// approach in [`ProfileModal`](crate::components::profile_modal).
fn copy_to_clipboard(text: &str) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let nav = window.navigator();
    let Ok(clipboard) = js_sys::Reflect::get(&nav, &"clipboard".into()) else {
        return;
    };
    if clipboard.is_undefined() {
        return;
    }
    if let Ok(write_fn) = js_sys::Reflect::get(&clipboard, &"writeText".into()) {
        if let Ok(func) = write_fn.dyn_into::<js_sys::Function>() {
            let _ = func.call1(&clipboard, &text.into());
        }
    }
}

/// Anchored, read-only profile preview card.
///
/// Renders nothing but the card + a transparent full-screen backdrop; the
/// caller owns the `relative` wrapper and the trigger. Set `is_open` to `false`
/// to dismiss (the backdrop and close button both do this).
#[component]
pub(crate) fn ProfilePopover(
    /// Hex pubkey of the user to preview.
    pubkey: String,
    /// Open/close state. The backdrop and the ✕ button set this to `false`.
    is_open: RwSignal<bool>,
) -> impl IntoView {
    let cache = try_use_profile_cache();

    // Reactive field derivations — each re-runs when the cache fills. Cheap
    // HashMap reads, so separate closures are fine and keep the view readable.
    // Two independent closures — one for the visible name, one for the `title`
    // tooltip — since a closure isn't `Copy` and each attribute/child consumes
    // its own.
    let pk_name = pubkey.clone();
    let display_name = move || use_display_name_tracked(&pk_name);
    let pk_name_title = pubkey.clone();
    let display_name_title = move || use_display_name_tracked(&pk_name_title);

    let pk_nip05 = pubkey.clone();
    let nip05 = move || {
        cache
            .as_ref()
            .and_then(|c| c.lookup_reactive(&pk_nip05))
            .and_then(|e| e.nip05)
            .map(|n| format_nip05_handle(&n))
            .filter(|n| !n.is_empty())
    };

    let pk_about = pubkey.clone();
    let about = move || cache.as_ref().and_then(|c| c.about_reactive(&pk_about));

    let short_pk = shorten_pubkey(&pubkey);

    // Copy-pubkey affordance with a transient "Copied!" acknowledgement.
    let copied = RwSignal::new(false);
    let pk_copy = pubkey.clone();
    let on_copy = move |ev: leptos::ev::MouseEvent| {
        // Keep the click from bubbling to the trigger/backdrop.
        ev.stop_propagation();
        copy_to_clipboard(&pk_copy);
        copied.set(true);
        set_timeout_once(move || copied.set(false), 2_000);
    };

    // "Send DM" navigates to the DM chat route for this user — same target as
    // the ProfileModal's DM action (`/dm/{pubkey}` via the router).
    let navigate = StoredValue::new(use_navigate());
    let pk_dm = pubkey.clone();
    let on_dm = move |ev: leptos::ev::MouseEvent| {
        ev.stop_propagation();
        is_open.set(false);
        let href = format!("/dm/{}", pk_dm);
        navigate.with_value(|nav| nav(&href, NavigateOptions::default()));
    };

    let pk_avatar = pubkey.clone();

    view! {
        // Transparent click-catcher: dismiss on any outside click. Sits below
        // the card (z-40 < z-50) so clicks on the card itself never reach it.
        <div
            class="fixed inset-0 z-40"
            on:click=move |_| is_open.set(false)
        ></div>

        // The anchored card. `stop_propagation` so interacting inside never
        // bubbles up to the trigger button that toggles `is_open`.
        <div
            class="absolute left-0 top-full mt-2 z-50 w-72 rounded-xl border border-gray-700 \
                   bg-gray-800 p-4 shadow-2xl text-left cursor-default"
            on:click=move |ev| ev.stop_propagation()
            role="dialog"
            aria-label="User profile"
        >
            // Close button
            <button
                class="absolute top-2 right-2 p-1 rounded text-gray-500 hover:text-gray-200 \
                       hover:bg-gray-700/60 transition-colors"
                aria-label="Close profile"
                on:click=move |ev| { ev.stop_propagation(); is_open.set(false); }
            >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 6L6 18M6 6l12 12" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </button>

            // Header: larger avatar + name + NIP-05
            <div class="flex items-start gap-3 pr-5">
                <div class="flex-shrink-0">
                    <Avatar pubkey=pk_avatar size=AvatarSize::Xl />
                </div>
                <div class="min-w-0 flex-1">
                    <div class="font-bold text-white text-sm truncate" title=display_name_title>
                        {display_name}
                    </div>
                    {move || nip05().map(|handle| view! {
                        <div class="text-xs text-green-400 truncate mt-0.5">
                            {handle}
                        </div>
                    })}
                </div>
            </div>

            // About / bio — truncated to ~3 lines.
            {move || about().map(|text| view! {
                <p class="mt-3 text-xs text-gray-300 leading-relaxed line-clamp-3">
                    {text}
                </p>
            })}

            // Shortened pubkey + copy affordance.
            <button
                class="mt-3 w-full flex items-center justify-between gap-2 rounded-lg \
                       bg-gray-900/60 border border-gray-700/50 px-2.5 py-1.5 \
                       hover:border-gray-600 transition-colors group/copy"
                title="Copy public key"
                on:click=on_copy
            >
                <span class="font-mono text-[11px] text-amber-400/80 truncate">
                    {short_pk}
                </span>
                <span class="flex-shrink-0 text-[10px] uppercase tracking-wide text-gray-500 group-hover/copy:text-gray-300">
                    {move || if copied.get() { "Copied" } else { "Copy" }}
                </span>
            </button>

            // Primary action: open a DM with this user.
            <button
                class="mt-3 w-full flex items-center justify-center gap-2 rounded-lg \
                       bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold \
                       py-2 px-3 text-sm transition-colors"
                on:click=on_dm
            >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"
                        stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                "Send DM"
            </button>
        </div>
    }
}
