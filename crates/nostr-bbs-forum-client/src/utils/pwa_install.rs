//! Zone-bound BBS PWA install orchestration (ADR-109, Decisions #1/#3/#4).
//!
//! This module owns three concerns for the FORUM (write) side:
//! 1. The **gating predicate** — reused verbatim from ADR-107
//!    ([`crate::stores::zone_access::home_zone_for`]) so admins and multi/zero-zone
//!    members never see the install affordance.
//! 2. **Install orchestration** — after the bake (see [`crate::utils::bake`]) the
//!    member is LINKED to the BBS (`/bbs/?pwa=1`) where installation actually
//!    happens: `beforeinstallprompt` belongs to the BBS scope (`/community/bbs/`,
//!    which carries the manifest + service worker), not the forum page.
//! 3. **iOS instruction text** — Add-to-Home-Screen is manual on iOS, and the
//!    isolated-storage rebind note is stated up front.
//!
//! The `beforeinstallprompt` capture here ([`init_capture`]) is **defensive only**:
//! the event does not fire on the forum origin, so the listener is a harmless
//! no-op that simply records the event on the rare build/scope where it does.

use leptos::prelude::*;
use send_wrapper::SendWrapper;
use std::cell::{Cell, RefCell};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::app::base_href;
use crate::stores::zone_access::home_zone_for;
use crate::stores::zones::Zone;

/// `window.__ENV__` key toggling the whole feature. Missing ⇒ DISABLED (the
/// forum-side default is OFF, per the ADR-109 rollout gate). The deploy sets
/// `BBS_PWA_ENABLED:"true"` when the operator opts in.
const FEATURE_FLAG_KEY: &str = "BBS_PWA_ENABLED";

// ---------------------------------------------------------------------------
// (a) Gating predicate
// ---------------------------------------------------------------------------

/// The exact ADR-107 predicate: the install option is visible only to a
/// non-admin member whose cohorts resolve to exactly ONE locked zone.
///
/// Pure and unit-tested (truth table below). The runtime `BBS_PWA_ENABLED`
/// gate is a SEPARATE concern ([`feature_enabled`]); the caller ANDs them so
/// this predicate stays a faithful mirror of `home_zone_for`.
pub fn install_option_visible(zones: &[Zone], cohorts: &[String], is_admin: bool) -> bool {
    !is_admin && home_zone_for(zones, cohorts, is_admin).is_some()
}

/// Whether the operator has enabled the BBS-PWA feature for this deployment.
///
/// Reads `window.__ENV__.BBS_PWA_ENABLED`; treats a missing/undefined value as
/// DISABLED (default off) and any value other than `"false"` as enabled.
pub fn feature_enabled() -> bool {
    window_env(FEATURE_FLAG_KEY)
        .map(|v| !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// (b) Platform detection
// ---------------------------------------------------------------------------

/// Whether the current device is iOS (iPhone/iPad/iPod), including iPadOS 13+
/// which reports as `MacIntel` but exposes a touch screen. Drives which panel
/// (manual Add-to-Home-Screen vs. redirect/prompt) the Settings section renders.
pub fn platform_is_ios() -> bool {
    let Some(nav) = web_sys::window().map(|w| w.navigator()) else {
        return false;
    };
    let ua = nav.user_agent().unwrap_or_default();
    let platform = nav.platform().unwrap_or_default();
    is_ios_ua(&ua, &platform, nav.max_touch_points())
}

/// Pure iOS heuristic, extracted for unit testing.
fn is_ios_ua(ua: &str, platform: &str, max_touch_points: i32) -> bool {
    let ua = ua.to_ascii_lowercase();
    let platform = platform.to_ascii_lowercase();
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
        return true;
    }
    // iPadOS 13+ desktop-class Safari: reports MacIntel + a touch screen.
    (platform.contains("mac") || ua.contains("macintosh")) && max_touch_points > 1
}

// ---------------------------------------------------------------------------
// (c) Install flow — link to the BBS where the prompt actually fires
// ---------------------------------------------------------------------------

/// Full-document navigate to the BBS one-shot boot URL (`<base>/bbs/?pwa=1`),
/// mirroring [`crate::components::bbs_sash`]: a plain `<a>` would be hijacked by
/// the Leptos router, so we force `location.set_href`. The BBS page carries the
/// manifest + service worker and fires its own `beforeinstallprompt`; the forum
/// page cannot prompt for the `/community/bbs/` scope. `zone_id` is the bound
/// zone (already written into the BootProfile) — logged for traceability.
pub fn open_installed_app(zone_id: &str) {
    let href = base_href("/bbs/?pwa=1");
    web_sys::console::log_1(
        &format!("[pwa_install] opening installed app for zone '{zone_id}' → {href}").into(),
    );
    if let Some(w) = web_sys::window() {
        let _ = w.location().set_href(&href);
    }
}

// ---------------------------------------------------------------------------
// (d) Defensive beforeinstallprompt capture
// ---------------------------------------------------------------------------

thread_local! {
    /// The stashed (prevented-default) `beforeinstallprompt` event, if one ever
    /// fires on this origin. `SendWrapper` keeps the JS handle on the WASM thread.
    static DEFERRED_PROMPT: RefCell<Option<SendWrapper<web_sys::Event>>> =
        const { RefCell::new(None) };
    /// Reactive "an install prompt is available" flag. Created lazily under a
    /// reactive owner by [`installable`].
    static INSTALLABLE: RefCell<Option<RwSignal<bool>>> = const { RefCell::new(None) };
    /// Guards against double-registering the window listener.
    static CAPTURE_REGISTERED: Cell<bool> = const { Cell::new(false) };
}

/// The reactive `installable` flag, created on first use under the current
/// reactive owner (App / a component). Defensive: on the forum origin it never
/// flips true.
pub fn installable() -> RwSignal<bool> {
    INSTALLABLE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(sig) = *slot {
            sig
        } else {
            let sig = RwSignal::new(false);
            *slot = Some(sig);
            sig
        }
    })
}

/// Register a `beforeinstallprompt` listener once, as early as possible (called
/// from `App()`), per MDN: the event can originate from an earlier load. It
/// `preventDefault`s and stashes the event + flips [`installable`]. No-op-safe:
/// harmless if the event never fires (the forum origin), idempotent across calls.
pub fn init_capture() {
    let already = CAPTURE_REGISTERED.with(|c| c.replace(true));
    if already {
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    // Materialise the signal now, under App()'s owner, so later `.set(true)`
    // from the (owner-less) event callback is safe.
    let installable = installable();

    let cb = Closure::<dyn Fn(web_sys::Event)>::new(move |event: web_sys::Event| {
        // Suppress the browser's default mini-infobar; we drive install from
        // the gated Settings button instead.
        event.prevent_default();
        DEFERRED_PROMPT.with(|slot| *slot.borrow_mut() = Some(SendWrapper::new(event)));
        installable.set(true);
    });
    let _ =
        window.add_event_listener_with_callback("beforeinstallprompt", cb.as_ref().unchecked_ref());
    // Leak for the page lifetime (a single listener, registered once).
    cb.forget();
}

/// Whether a deferred `beforeinstallprompt` event is currently stashed.
pub fn deferred_prompt_available() -> bool {
    DEFERRED_PROMPT.with(|slot| slot.borrow().is_some())
}

/// Fire the stashed install prompt if one exists (single-use: the event is
/// consumed). Returns `true` when a prompt was shown, `false` when none was
/// available — the caller then falls back to the redirect path. On the forum
/// origin this returns `false` because the event never fires here.
pub async fn trigger_prompt() -> bool {
    let event = DEFERRED_PROMPT.with(|slot| slot.borrow_mut().take());
    let Some(event) = event else {
        return false;
    };
    installable().set(false);
    // `BeforeInstallPromptEvent` is not in web-sys; call `.prompt()` via Reflect.
    let event: JsValue = event.take().into();
    let Ok(prompt_fn) = js_sys::Reflect::get(&event, &"prompt".into()) else {
        return false;
    };
    let Ok(func) = prompt_fn.dyn_into::<js_sys::Function>() else {
        return false;
    };
    match func.call0(&event) {
        Ok(ret) => {
            // `prompt()` returns a Promise; await it so a caller can sequence
            // navigation after the choice resolves. Ignore the userChoice value.
            if let Ok(promise) = ret.dyn_into::<js_sys::Promise>() {
                let _ = JsFuture::from(promise).await;
            }
            true
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// (e) iOS instruction copy (owned here so the strings are testable + single-source)
// ---------------------------------------------------------------------------

/// The manual Add-to-Home-Screen steps shown on iOS (no `beforeinstallprompt`
/// there). UK English.
pub fn ios_instructions() -> [&'static str; 3] {
    [
        "Tap the Share button in Safari's toolbar.",
        "Choose \"Add to Home Screen\".",
        "Tap \"Add\", then open the new icon from your home screen.",
    ]
}

/// The one-time-rebind note for iOS: because iOS isolates the installed app's
/// storage from Safari, the baked key cannot cross over, so first launch
/// re-establishes your identity once. UK English.
pub fn ios_rebind_note() -> &'static str {
    "On iPhone and iPad the app keeps its own separate storage, so the first \
     time you open it you'll confirm once — a passkey tap, or pasting your \
     recovery key. After that it opens straight into your zone."
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a `window.__ENV__` key (mirrors the private reader in `utils::relay_url`).
fn window_env(key: &str) -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let val = js_sys::Reflect::get(&env, &key.into()).ok()?;
    let s = val.as_string()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::zones::ZoneVisibility;

    fn locked_zone(id: &str, cohort: &str) -> Zone {
        Zone {
            id: id.to_string(),
            slug: None,
            display_name: String::new(),
            required_cohorts: vec![cohort.to_string()],
            write_cohorts: None,
            banner_image_url: None,
            visibility: ZoneVisibility::Locked,
            encrypted: false,
            accent_hex: None,
        }
    }

    fn public_zone(id: &str) -> Zone {
        Zone {
            id: id.to_string(),
            slug: None,
            display_name: String::new(),
            required_cohorts: vec![],
            write_cohorts: None,
            banner_image_url: None,
            visibility: ZoneVisibility::Public,
            encrypted: false,
            accent_hex: None,
        }
    }

    // ── install_option_visible: the exact ADR-107 truth table ───────────────

    #[test]
    fn admin_never_sees_install() {
        let zones = vec![locked_zone("business", "business")];
        let cohorts = vec!["business".to_string()];
        assert!(!install_option_visible(&zones, &cohorts, true));
    }

    #[test]
    fn single_locked_zone_member_sees_install() {
        let zones = vec![public_zone("public"), locked_zone("business", "business")];
        let cohorts = vec!["business".to_string()];
        assert!(install_option_visible(&zones, &cohorts, false));
    }

    #[test]
    fn two_locked_zones_hide_install() {
        let zones = vec![
            locked_zone("business", "business"),
            locked_zone("family", "family"),
        ];
        let cohorts = vec!["business".to_string(), "family".to_string()];
        assert!(!install_option_visible(&zones, &cohorts, false));
    }

    #[test]
    fn zero_accessible_zones_hide_install() {
        // A member with no cohorts can only read the public zone → no home zone.
        let zones = vec![public_zone("public"), locked_zone("business", "business")];
        let cohorts: Vec<String> = vec![];
        assert!(!install_option_visible(&zones, &cohorts, false));
    }

    // ── is_ios_ua heuristic ─────────────────────────────────────────────────

    #[test]
    fn detects_iphone_and_ipad_by_ua() {
        assert!(is_ios_ua(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
            "iPhone",
            5
        ));
        assert!(is_ios_ua("Mozilla/5.0 (iPad; CPU OS 17_4)", "iPad", 5));
        assert!(is_ios_ua("something ipod touch", "iPod", 5));
    }

    #[test]
    fn detects_ipados13_reporting_as_mac_with_touch() {
        assert!(is_ios_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari",
            "MacIntel",
            5
        ));
    }

    #[test]
    fn desktop_mac_without_touch_is_not_ios() {
        assert!(!is_ios_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari",
            "MacIntel",
            0
        ));
    }

    #[test]
    fn android_and_desktop_are_not_ios() {
        assert!(!is_ios_ua(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8)",
            "Linux armv8l",
            5
        ));
        assert!(!is_ios_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Win32",
            0
        ));
    }

    // ── iOS copy is present and honest ──────────────────────────────────────

    #[test]
    fn ios_copy_mentions_home_screen_and_rebind() {
        assert!(ios_instructions()
            .iter()
            .any(|s| s.contains("Add to Home Screen")));
        let note = ios_rebind_note();
        assert!(note.contains("passkey") && note.contains("recovery key"));
    }
}
