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

        let _ =
            window.add_event_listener_with_callback("online", on_online.as_ref().unchecked_ref());
        let _ =
            window.add_event_listener_with_callback("offline", on_offline.as_ref().unchecked_ref());

        // These `window` listeners write to `set_online`/`set_show_restored`,
        // which belong to this component's reactive scope. They previously
        // leaked via `.forget()` with no `on_cleanup`, so if `OfflineBanner`
        // ever unmounts (it is not app-root-pinned — nothing prevents a
        // future call site from mounting/unmounting it conditionally), a
        // later online/offline event would still fire against disposed
        // signals. Remove the listeners and drop the closures on cleanup.
        let window_for_cleanup = window.clone();
        let guard = send_wrapper::SendWrapper::new((on_online, on_offline));
        on_cleanup(move || {
            let (on_online, on_offline) = guard.take();
            let _ = window_for_cleanup
                .remove_event_listener_with_callback("online", on_online.as_ref().unchecked_ref());
            let _ = window_for_cleanup.remove_event_listener_with_callback(
                "offline",
                on_offline.as_ref().unchecked_ref(),
            );
            drop(on_online);
            drop(on_offline);
        });
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
