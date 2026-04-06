//! Offline/online connectivity banner.
//!
//! Displays an amber banner when `navigator.onLine` is false and a brief
//! green "Back online" banner when connectivity returns, auto-hiding after 3s.

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// Reactive banner that watches `online`/`offline` window events.
#[component]
pub fn OfflineBanner() -> impl IntoView {
    let (is_online, set_online) = signal(navigator_online());
    let (show_restored, set_show_restored) = signal(false);

    // Track whether we were offline to show "back online" message
    let was_offline = StoredValue::new(false);

    // Register window event listeners
    Effect::new(move |_| {
        let Some(window) = web_sys::window() else {
            return;
        };

        let set_online_clone = set_online;
        let on_online = Closure::wrap(Box::new(move |_: web_sys::Event| {
            set_online_clone.set(true);
            if was_offline.get_value() {
                set_show_restored.set(true);
                was_offline.set_value(false);
                // Auto-hide after 3 seconds
                crate::utils::set_timeout_once(
                    move || {
                        set_show_restored.set(false);
                    },
                    3000,
                );
            }
        }) as Box<dyn FnMut(web_sys::Event)>);

        let set_online_clone2 = set_online;
        let on_offline = Closure::wrap(Box::new(move |_: web_sys::Event| {
            set_online_clone2.set(false);
            was_offline.set_value(true);
        }) as Box<dyn FnMut(web_sys::Event)>);

        let _ = window.add_event_listener_with_callback(
            "online",
            on_online.as_ref().unchecked_ref(),
        );
        let _ = window.add_event_listener_with_callback(
            "offline",
            on_offline.as_ref().unchecked_ref(),
        );

        // Leak intentionally -- these listeners live for the app lifetime
        on_online.forget();
        on_offline.forget();
    });

    view! {
        <Show when=move || !is_online.get()>
            <div class="fixed top-0 left-0 right-0 z-50 bg-amber-600 text-white text-center py-2 px-4 text-sm font-medium shadow-lg">
                "You're offline \u{2014} messages will be sent when you reconnect"
            </div>
        </Show>
        <Show when=move || show_restored.get()>
            <div class="fixed top-0 left-0 right-0 z-50 bg-emerald-600 text-white text-center py-2 px-4 text-sm font-medium shadow-lg transition-opacity duration-300">
                "Back online"
            </div>
        </Show>
    }
}

/// Read the current `navigator.onLine` value.
fn navigator_online() -> bool {
    web_sys::window()
        .map(|w| w.navigator().on_line())
        .unwrap_or(true)
}
