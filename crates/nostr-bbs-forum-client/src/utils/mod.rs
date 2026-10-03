//! Shared utility functions used across forum-client components.

pub mod bake;
pub mod bootstrap;
pub mod clipboard;
pub mod devices;
pub mod freshness;
pub mod governance_view;
pub mod image_compress;
pub mod paths;
pub mod pod_client;
pub mod pwa_install;
pub mod reconcile;
pub mod relay_url;
pub mod sanitize;
pub mod search_client;
pub mod slug_hash;
// zone_theme.rs is owned elsewhere (do-not-touch) and contains one genuinely
// unused fn (`zone_accent_style`, superseded by `zone_accent_style_cfg`).
// Scoped here rather than touching that file.
#[allow(dead_code)]
pub mod zone_theme;

use gloo::events::EventListener;
use leptos::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// Slot type for a one-shot WASM timer closure (used by `set_timeout_once`).
type TimerSlot = Rc<Cell<Option<Closure<dyn FnMut()>>>>;

/// Run `reload` whenever ANOTHER same-origin tab writes `key` in localStorage
/// (or clears all storage, e.g. logout). The DOM `storage` event fires only in
/// the OTHER tabs, never the writer.
///
/// This is the cross-tab-consistency primitive behind the "mark all read keeps
/// resetting" class of bug (first fixed in `stores::notifications`): a reactive
/// store that persists a whole-snapshot to a single shared localStorage key
/// lets a STALE sibling tab (every tab auto-authenticates the same account
/// under remember-me / passkey) clobber a fresh tab's write on its next
/// persist. Reloading the store's signal from the authoritative localStorage
/// snapshot on each sibling write means no stale copy survives to clobber with.
///
/// `reload` must be LOAD-ONLY (read localStorage, set the signal) — persisting
/// inside it would bounce another `storage` event to the siblings and could
/// echo. The listener is leaked (`.forget()`) because the stores it serves are
/// provided once at the app root and live for the whole session.
pub fn on_cross_tab_storage_write<F>(key: &'static str, reload: F)
where
    F: Fn() + 'static,
{
    let listener = EventListener::new(&gloo::utils::window(), "storage", move |event| {
        let changed = event
            .dyn_ref::<web_sys::StorageEvent>()
            .and_then(|e| e.key());
        // `None` = a whole-storage clear() in another tab; `Some(k)` = a targeted
        // write we act on only when it hit our key.
        if changed.is_none() || changed.as_deref() == Some(key) {
            reload();
        }
    });
    listener.forget();
}

/// Format a UNIX timestamp as a human-readable relative time string.
///
/// Returns strings like "just now", "5m ago", "2h ago", "3d ago", or a
/// formatted date with time ("Jan 15 09:30") for older timestamps.
pub fn format_relative_time(timestamp: u64) -> String {
    if timestamp == 0 {
        return "never".to_string();
    }

    let now = (js_sys::Date::now() / 1000.0) as u64;
    if now < timestamp {
        return "just now".to_string();
    }
    let diff = now - timestamp;

    if diff < 60 {
        return "just now".to_string();
    }
    if diff < 3600 {
        let mins = diff / 60;
        return format!("{}m ago", mins);
    }
    if diff < 86400 {
        let hours = diff / 3600;
        return format!("{}h ago", hours);
    }
    if diff < 604800 {
        let days = diff / 86400;
        return format!("{}d ago", days);
    }

    let date = js_sys::Date::new_0();
    date.set_time((timestamp as f64) * 1000.0);
    let month = date.get_month();
    let day = date.get_date();
    let hours = date.get_hours();
    let minutes = date.get_minutes();
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_name = months.get(month as usize).unwrap_or(&"???");
    format!("{} {} {:02}:{:02}", month_name, day, hours, minutes)
}

/// Generate a deterministic HSL color from a pubkey for avatar backgrounds.
///
/// Uses the first 6 hex characters as a hue seed, producing consistent colors
/// for the same pubkey across the application.
pub fn pubkey_color(pubkey: &str) -> String {
    let hue = pubkey
        .chars()
        .take(6)
        .enumerate()
        .fold(0u32, |acc, (i, c)| {
            acc.wrapping_add((c as u32).wrapping_mul((i as u32) + 1))
        })
        % 360;

    format!("hsl({}, 55%, 45%)", hue)
}

/// The abbreviation styles the forum uses for a public key (hex or npub) or
/// any other long identifier. Every style slices by CHARACTER via
/// [`Abbrev::apply`], so none of them can panic on non-ASCII input.
///
/// The visible formats are the ones each surface already used — they are kept
/// distinct on purpose, because the width of a key in a table column or a
/// header chip is part of that surface's layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abbrev {
    /// `abcdef...wxyz` — 6 head, 4 tail, ASCII dots ([`shorten_pubkey`]).
    Pubkey,
    /// `abcdefgh...wxyz` — 8 head, 4 tail, ASCII dots (admin tables, mentions,
    /// admin action banners).
    Long,
    /// `abcdefgh…wxyz` — 8 head, 4 tail, a single ellipsis (governance ids,
    /// admin alert labels).
    Id,
    /// `abcdef…wxyz` — 6 head, 4 tail, a single ellipsis (board assignees).
    Chip,
    /// `abcdefghijkl…uvwxyz` — 12 head, 6 tail, a single ellipsis (wallet).
    Wallet,
    /// `abcdefgh…` — first 8 then an ellipsis (registration action messages).
    Prefix,
    /// `abcdefgh` — the bare first 8 characters: the fallback *name* for a
    /// member with no profile (mention autocomplete, composer handles).
    Name,
}

impl Abbrev {
    /// `(head, tail, separator)` for this style.
    const fn parts(self) -> (usize, usize, &'static str) {
        match self {
            Abbrev::Pubkey => (6, 4, "..."),
            Abbrev::Long => (8, 4, "..."),
            Abbrev::Id => (8, 4, "\u{2026}"),
            Abbrev::Chip => (6, 4, "\u{2026}"),
            Abbrev::Wallet => (12, 6, "\u{2026}"),
            Abbrev::Prefix => (8, 0, "\u{2026}"),
            Abbrev::Name => (8, 0, ""),
        }
    }

    /// Abbreviate `s` in this style. See [`abbreviate`].
    pub fn apply(self, s: &str) -> String {
        let (head, tail, sep) = self.parts();
        abbreviate(s, head, tail, sep)
    }
}

/// Keep the first `head` and last `tail` characters of `s`, joined by `sep`.
///
/// Slices by CHARACTER, not by byte: a byte slice such as `&pk[..8]` panics
/// whenever the offset falls inside a multi-byte character (or past the end of
/// a short string), and a panic in WASM aborts the whole reactive render,
/// blanking the client. A Nostr event field is only ever guaranteed to be a
/// string, so no caller may assume 64-char ASCII hex.
///
/// `s` is returned unchanged when abbreviating would hide fewer than two
/// characters — eliding a single character only makes the text harder to read.
pub fn abbreviate(s: &str, head: usize, tail: usize, sep: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= head + tail + 1 {
        return s.to_string();
    }
    let mut out: String = chars[..head].iter().collect();
    out.push_str(sep);
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// Shorten a hex pubkey to "abcd12...ef56" format for display
/// ([`Abbrev::Pubkey`]). Character-safe; see [`abbreviate`].
pub fn shorten_pubkey(pubkey: &str) -> String {
    Abbrev::Pubkey.apply(pubkey)
}

/// Simple left arrow SVG icon for back navigation buttons.
pub fn arrow_left_svg() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/>
        </svg>
    }
}

/// Capitalize the first letter of a string.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Schedule a one-shot callback via `setTimeout` that properly drops the
/// `Closure` after execution instead of leaking it with `.forget()`.
///
/// The standard pattern of `Closure::once` + `cb.forget()` intentionally leaks
/// the closure into WASM linear memory so the JS runtime can invoke it. On a
/// spotty mobile connection triggering reconnect loops, this accumulates leaked
/// closures until the tab crashes.
///
/// This helper stores the `Closure` in an `Rc<Cell<Option<...>>>` and drops it
/// from inside the callback itself, so the memory is reclaimed after execution.
pub fn set_timeout_once<F: FnOnce() + 'static>(f: F, delay_ms: i32) {
    // Shared slot: the closure is stored here so it can drop itself.
    let slot: TimerSlot = Rc::new(Cell::new(None));
    let slot_clone = slot.clone();

    // Wrap f in Option so we can .take() it from inside an FnMut closure.
    let f_cell: Rc<Cell<Option<F>>> = Rc::new(Cell::new(Some(f)));

    let closure = Closure::wrap(Box::new(move || {
        if let Some(func) = f_cell.take() {
            func();
        }
        // Drop the closure, reclaiming the WASM memory.
        slot_clone.set(None);
    }) as Box<dyn FnMut()>);

    if let Some(window) = web_sys::window() {
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            delay_ms,
        );
    }

    // Park the closure in the slot so it lives until the callback fires.
    slot.set(Some(closure));
}

/// Check browser storage quota via `navigator.storage.estimate()`.
/// Returns `(usage_bytes, quota_bytes)` or `None` if the API is unavailable.
pub async fn check_storage_quota() -> Option<(f64, f64)> {
    let window = web_sys::window()?;
    let navigator = window.navigator();
    let storage = navigator.storage();
    let promise = storage.estimate().ok()?;
    let result = wasm_bindgen_futures::JsFuture::from(promise).await.ok()?;
    // StorageEstimate is a plain JS object with `usage` and `quota` properties.
    let usage = js_sys::Reflect::get(&result, &"usage".into())
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let quota = js_sys::Reflect::get(&result, &"quota".into())
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    Some((usage, quota))
}

#[cfg(test)]
mod shorten_pubkey_tests {
    use super::shorten_pubkey;

    #[test]
    fn shortens_a_hex_pubkey() {
        let pk = "a".repeat(64);
        assert_eq!(shorten_pubkey(&pk), "aaaaaa...aaaa");
    }

    #[test]
    fn leaves_a_short_string_alone() {
        assert_eq!(shorten_pubkey("abc"), "abc");
        assert_eq!(shorten_pubkey(""), "");
    }

    #[test]
    fn never_panics_on_multi_byte_input() {
        // Byte offsets 6 and len-4 both fall mid-character here.
        for s in ["日本語テキストの長い文字列", "😀😀😀😀😀😀😀😀😀😀😀😀"]
        {
            let out = shorten_pubkey(s);
            assert!(out.contains("..."));
        }
    }
}

#[cfg(test)]
mod abbrev_tests {
    use super::{abbreviate, Abbrev};

    const HEX: &str = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";
    const NPUB: &str = "npub1z8kkggja6h3vtcv0vxk58t2kjfedppee6w3qm5tzscvhkpecvc7qgjdy6l";

    const ALL: [Abbrev; 7] = [
        Abbrev::Pubkey,
        Abbrev::Long,
        Abbrev::Id,
        Abbrev::Chip,
        Abbrev::Wallet,
        Abbrev::Prefix,
        Abbrev::Name,
    ];

    #[test]
    fn hex_pubkey_in_every_style() {
        assert_eq!(Abbrev::Pubkey.apply(HEX), "11ed64...663c");
        assert_eq!(Abbrev::Long.apply(HEX), "11ed6422...663c");
        assert_eq!(Abbrev::Id.apply(HEX), "11ed6422\u{2026}663c");
        assert_eq!(Abbrev::Chip.apply(HEX), "11ed64\u{2026}663c");
        assert_eq!(Abbrev::Wallet.apply(HEX), "11ed64225dd5\u{2026}38663c");
        assert_eq!(Abbrev::Prefix.apply(HEX), "11ed6422\u{2026}");
        assert_eq!(Abbrev::Name.apply(HEX), "11ed6422");
    }

    #[test]
    fn npub_keeps_its_prefix_and_checksum_tail() {
        assert_eq!(Abbrev::Long.apply(NPUB), "npub1z8k...dy6l");
        assert_eq!(Abbrev::Pubkey.apply(NPUB), "npub1z...dy6l");
        assert_eq!(Abbrev::Wallet.apply(NPUB), "npub1z8kkggj\u{2026}gjdy6l");
    }

    #[test]
    fn short_input_is_returned_unchanged() {
        for style in ALL {
            assert_eq!(style.apply(""), "");
            assert_eq!(style.apply("abc"), "abc");
            assert_eq!(style.apply("alice"), "alice");
        }
        // Exactly head + tail + 1 characters: eliding one char is pointless.
        assert_eq!(abbreviate("abcdefghijk", 6, 4, "..."), "abcdefghijk");
        // One more and it abbreviates.
        assert_eq!(abbreviate("abcdefghijkl", 6, 4, "..."), "abcdef...ijkl");
    }

    #[test]
    fn never_panics_or_splits_a_character() {
        let inputs = [
            "日本語テキストの長い文字列です",
            "😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀😀",
            "aé",
            "ééééééééééééééééééééééé",
            "\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}",
        ];
        for s in inputs {
            for style in ALL {
                let out = style.apply(s);
                // Every output char came from the input or the separator.
                assert!(out
                    .chars()
                    .all(|c| s.contains(c) || c == '.' || c == '\u{2026}'));
            }
        }
        assert_eq!(
            Abbrev::Id.apply("😀😀😀😀😀😀😀😀😀😀😀😀😀😀"),
            "😀😀😀😀😀😀😀😀\u{2026}😀😀😀😀"
        );
    }
}
