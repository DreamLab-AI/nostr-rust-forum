//! Session timeout warning banner.
//!
//! Periodically checks auth session age and shows a slide-down amber warning
//! banner when the session is close to expiring (> 23 hours old). Provides
//! "Refresh Session" and "Dismiss" actions with auto-dismiss after 30 seconds.

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::auth::use_auth;

/// Maximum session lifetime in seconds (24 hours).
const SESSION_MAX_SECS: f64 = 86400.0;
/// Warn when this many seconds remain (1 hour).
const WARN_REMAINING_SECS: f64 = 3600.0;
/// How often to check session age, in milliseconds.
const CHECK_INTERVAL_MS: i32 = 30_000;
/// Auto-dismiss the banner after this many milliseconds.
const AUTO_DISMISS_MS: i32 = 30_000;

/// Session timeout warning banner component.
///
/// Mounts a `setInterval` timer that reads the auth store's session creation
/// time. When the remaining session time drops below `WARN_REMAINING_SECS`,
/// a slide-down warning banner appears. The banner auto-dismisses after 30s
/// or can be manually dismissed.
#[component]
pub(crate) fn SessionTimeout() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();

    let show_warning = RwSignal::new(false);
    let dismissed = RwSignal::new(false);

    // Session start timestamp (UNIX seconds), set when auth becomes active.
    let session_start = RwSignal::new(0.0_f64);

    // Track when auth state changes to capture session start time.
    Effect::new(move |_| {
        if is_authed.get() {
            let current = session_start.get_untracked();
            if current == 0.0 {
                let now = js_sys::Date::now() / 1000.0;
                session_start.set(now);
            }
        } else {
            session_start.set(0.0);
            show_warning.set(false);
            dismissed.set(false);
        }
    });

    // Periodic check via setInterval.
    Effect::new(move |prev: Option<Option<i32>>| {
        // Clear previous interval if any.
        if let Some(Some(id)) = prev {
            if let Some(window) = web_sys::window() {
                window.clear_interval_with_handle(id);
            }
        }

        if !is_authed.get() {
            return None;
        }

        let cb = Closure::<dyn FnMut()>::new(move || {
            if dismissed.get_untracked() {
                return;
            }
            let start = session_start.get_untracked();
            if start == 0.0 {
                return;
            }
            let now = js_sys::Date::now() / 1000.0;
            let age = now - start;
            let remaining = SESSION_MAX_SECS - age;

            if remaining <= WARN_REMAINING_SECS && remaining > 0.0 {
                show_warning.set(true);
            } else if remaining <= 0.0 {
                // Session expired — force logout handled elsewhere.
                show_warning.set(false);
            }
        });

        let interval_id = web_sys::window().and_then(|w| {
            w.set_interval_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                CHECK_INTERVAL_MS,
            )
            .ok()
        });

        // Leak the closure — it lives for the lifetime of the interval.
        cb.forget();

        interval_id
    });

    // Auto-dismiss timer: starts when warning becomes visible.
    Effect::new(move |prev: Option<Option<i32>>| {
        if let Some(Some(id)) = prev {
            if let Some(window) = web_sys::window() {
                window.clear_timeout_with_handle(id);
            }
        }

        if !show_warning.get() {
            return None;
        }

        let cb = Closure::<dyn FnMut()>::new(move || {
            dismissed.set(true);
            show_warning.set(false);
        });

        let timeout_id = web_sys::window().and_then(|w| {
            w.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                AUTO_DISMISS_MS,
            )
            .ok()
        });

        cb.forget();

        timeout_id
    });

    let on_refresh = move |_| {
        // Re-triggering passkey auth is the canonical "refresh" — but that
        // requires async. For now, reset the session clock as a placeholder.
        let now = js_sys::Date::now() / 1000.0;
        session_start.set(now);
        show_warning.set(false);
        dismissed.set(false);
    };

    let on_dismiss = move |_| {
        dismissed.set(true);
        show_warning.set(false);
    };

    view! {
        <Show when=move || show_warning.get()>
            <div class="fixed top-0 left-0 right-0 z-[100] animate-slide-in-down">
                <div class="max-w-3xl mx-auto px-4 py-3">
                    <div class="flex items-center gap-3 bg-gray-900/95 backdrop-blur-md border border-amber-500/40 rounded-xl px-4 py-3 shadow-lg">
                        // Warning icon
                        <svg class="w-5 h-5 text-amber-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
                                stroke-linecap="round" stroke-linejoin="round"/>
                            <line x1="12" y1="9" x2="12" y2="13"
                                stroke-linecap="round" stroke-linejoin="round"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"
                                stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>

                        <p class="flex-1 text-sm text-gray-200">
                            "Your session will expire soon. Save your work."
                        </p>

                        <button
                            class="text-xs font-medium bg-amber-500 hover:bg-amber-400 text-gray-900 px-3 py-1.5 rounded-lg transition-colors flex-shrink-0"
                            on:click=on_refresh
                        >
                            "Refresh Session"
                        </button>

                        <button
                            class="text-gray-500 hover:text-gray-300 transition-colors p-1 flex-shrink-0"
                            on:click=on_dismiss
                            aria-label="Dismiss"
                        >
                            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                                <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
