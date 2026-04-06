//! Shared utility functions used across forum-client components.

pub mod image_compress;
pub mod pod_client;
pub mod relay_url;
pub mod sanitize;
pub mod search_client;

use leptos::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// Slot type for a one-shot WASM timer closure (used by `set_timeout_once`).
type TimerSlot = Rc<Cell<Option<Closure<dyn FnMut()>>>>;

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

/// Shorten a hex pubkey to "abcd12...ef56" format for display.
pub fn shorten_pubkey(pubkey: &str) -> String {
    if pubkey.len() < 12 {
        return pubkey.to_string();
    }
    format!("{}...{}", &pubkey[..6], &pubkey[pubkey.len() - 4..])
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
