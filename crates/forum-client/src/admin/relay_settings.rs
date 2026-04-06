//! Admin panel for relay connection settings.
//!
//! Displays the current relay URL, connection status, and controls for
//! testing, disconnecting, and reconnecting. Settings persist to localStorage.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::{ConnectionState, RelayConnection};

const RELAY_SETTINGS_KEY: &str = "nostr_bbs_relay_settings";

fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
}

fn load_saved_relay_url() -> Option<String> {
    get_local_storage()
        .and_then(|s| s.get_item(RELAY_SETTINGS_KEY).ok())
        .flatten()
}

fn save_relay_url(url: &str) {
    if let Some(storage) = get_local_storage() {
        let _ = storage.set_item(RELAY_SETTINGS_KEY, url);
    }
}

/// Admin relay settings panel. Admin-only guard at component level.
#[component]
pub fn RelaySettingsPanel() -> impl IntoView {
    let auth = use_auth();
    let _pubkey = auth.pubkey();

    let zone_access = crate::stores::zone_access::use_zone_access();
    let is_admin = Memo::new(move |_| zone_access.is_admin.get());

    view! {
        <Show
            when=move || is_admin.get()
            fallback=|| view! {
                <div class="text-center py-12">
                    <p class="text-gray-500">"Access denied."</p>
                </div>
            }
        >
            <RelaySettingsInner />
        </Show>
    }
}

#[component]
fn RelaySettingsInner() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();
    let toasts = use_toasts();

    // Relay URL input — default to saved URL or current
    let relay_url = RwSignal::new(load_saved_relay_url().unwrap_or_default());
    let testing = RwSignal::new(false);
    let test_result: RwSignal<Option<(String, bool)>> = RwSignal::new(None);

    // Stats tracking (simple counters)
    let msgs_sent = RwSignal::new(0u32);
    let msgs_received = RwSignal::new(0u32);

    let on_url_input = move |ev: leptos::ev::Event| {
        let target = ev.target().unwrap();
        let input: web_sys::HtmlInputElement = target.unchecked_into();
        relay_url.set(input.value());
    };

    // Test connection handler
    let toasts_for_test = toasts.clone();
    let on_test = move |_| {
        let url = relay_url.get_untracked().trim().to_string();
        if url.is_empty() {
            toasts_for_test.show("Enter a relay URL first", ToastVariant::Warning);
            return;
        }

        testing.set(true);
        test_result.set(None);

        // Try creating a WebSocket to test connectivity
        match web_sys::WebSocket::new(&url) {
            Ok(ws) => {
                let testing_sig = testing;
                let test_result_sig = test_result;

                let on_open = wasm_bindgen::closure::Closure::once(Box::new(move || {
                    testing_sig.set(false);
                    test_result_sig.set(Some(("Connection successful".to_string(), true)));
                })
                    as Box<dyn FnOnce()>);

                let on_error = wasm_bindgen::closure::Closure::once(Box::new(move || {
                    testing_sig.set(false);
                    test_result_sig.set(Some(("Connection failed".to_string(), false)));
                })
                    as Box<dyn FnOnce()>);

                ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
                ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
                on_open.forget();
                on_error.forget();

                // Close after test
                crate::utils::set_timeout_once(
                    move || {
                        let _ = ws.close();
                        if testing_sig.get_untracked() {
                            testing_sig.set(false);
                            test_result_sig.set(Some(("Connection timed out".to_string(), false)));
                        }
                    },
                    5000,
                );
            }
            Err(_) => {
                testing.set(false);
                test_result.set(Some(("Invalid WebSocket URL".to_string(), false)));
            }
        }
    };

    // Disconnect handler
    let relay_for_disconnect = relay.clone();
    let toasts_for_disc = toasts.clone();
    let on_disconnect = move |_| {
        relay_for_disconnect.disconnect();
        toasts_for_disc.show("Disconnected from relay", ToastVariant::Info);
    };

    // Reconnect handler
    let relay_for_reconnect = relay.clone();
    let toasts_for_reconn = toasts.clone();
    let on_reconnect = move |_| {
        relay_for_reconnect.connect();
        toasts_for_reconn.show("Reconnecting to relay...", ToastVariant::Info);
    };

    // Save URL handler
    let toasts_for_save = toasts.clone();
    let on_save = move |_| {
        let url = relay_url.get_untracked().trim().to_string();
        if url.is_empty() {
            toasts_for_save.show("URL cannot be empty", ToastVariant::Warning);
            return;
        }
        save_relay_url(&url);
        toasts_for_save.show("Relay URL saved", ToastVariant::Success);
    };

    view! {
        <div class="space-y-6">
            <h2 class="text-xl font-bold text-white flex items-center gap-2">
                {relay_icon()}
                "Relay Settings"
            </h2>

            // Connection status
            <div class="glass-card p-6 space-y-4">
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wider">"Connection Status"</h3>

                <div class="flex items-center gap-3">
                    {move || {
                        match conn_state.get() {
                            ConnectionState::Connected => view! {
                                <span class="w-3 h-3 rounded-full bg-green-400"></span>
                                <span class="text-green-300 font-medium">"Connected"</span>
                            }.into_any(),
                            ConnectionState::Connecting => view! {
                                <span class="animate-pulse w-3 h-3 rounded-full bg-yellow-400"></span>
                                <span class="text-yellow-300 font-medium">"Connecting..."</span>
                            }.into_any(),
                            ConnectionState::Reconnecting => view! {
                                <span class="animate-pulse w-3 h-3 rounded-full bg-yellow-400"></span>
                                <span class="text-yellow-300 font-medium">"Reconnecting..."</span>
                            }.into_any(),
                            ConnectionState::Error => view! {
                                <span class="w-3 h-3 rounded-full bg-red-400"></span>
                                <span class="text-red-300 font-medium">"Error"</span>
                            }.into_any(),
                            ConnectionState::Disconnected => view! {
                                <span class="w-3 h-3 rounded-full bg-gray-500"></span>
                                <span class="text-gray-400 font-medium">"Disconnected"</span>
                            }.into_any(),
                        }
                    }}
                </div>

                // Connection control buttons
                <div class="flex gap-3">
                    <button
                        on:click=on_disconnect
                        disabled=move || conn_state.get() == ConnectionState::Disconnected
                        class="text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded-lg px-4 py-2 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        "Disconnect"
                    </button>
                    <button
                        on:click=on_reconnect
                        disabled=move || conn_state.get() == ConnectionState::Connected
                        class="text-sm text-green-400 hover:text-green-300 border border-green-500/30 hover:border-green-400 rounded-lg px-4 py-2 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                        "Reconnect"
                    </button>
                </div>
            </div>

            // Relay URL configuration
            <div class="glass-card p-6 space-y-4">
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wider">"Relay URL"</h3>

                <div class="space-y-3">
                    <input
                        type="url"
                        prop:value=move || relay_url.get()
                        on:input=on_url_input
                        placeholder="wss://relay.example.com"
                        class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white font-mono text-sm placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors"
                    />

                    <div class="flex gap-3">
                        <button
                            on:click=on_test
                            disabled=move || testing.get()
                            class="text-sm text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded-lg px-4 py-2 transition-colors disabled:opacity-50 flex items-center gap-1.5"
                        >
                            {move || if testing.get() {
                                view! {
                                    <span class="animate-spin inline-block w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full"></span>
                                    "Testing..."
                                }.into_any()
                            } else {
                                view! {
                                    {test_icon()}
                                    "Test Connection"
                                }.into_any()
                            }}
                        </button>
                        <button
                            on:click=on_save
                            class="text-sm text-gray-300 hover:text-white border border-gray-600 hover:border-gray-500 rounded-lg px-4 py-2 transition-colors"
                        >
                            "Save URL"
                        </button>
                    </div>

                    // Test result
                    {move || {
                        test_result.get().map(|(msg, is_ok)| {
                            let cls = if is_ok {
                                "text-green-400 text-sm flex items-center gap-1.5"
                            } else {
                                "text-red-400 text-sm flex items-center gap-1.5"
                            };
                            let dot_cls = if is_ok {
                                "w-2 h-2 rounded-full bg-green-400"
                            } else {
                                "w-2 h-2 rounded-full bg-red-400"
                            };
                            view! {
                                <div class=cls>
                                    <span class=dot_cls></span>
                                    {msg}
                                </div>
                            }
                        })
                    }}
                </div>
            </div>

            // Relay stats (simple counters)
            <div class="glass-card p-6 space-y-4">
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wider">"Relay Statistics"</h3>

                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-gray-800/50 rounded-lg p-3">
                        <p class="text-xs text-gray-500">"Messages Sent"</p>
                        <p class="text-lg font-bold text-amber-400">{move || msgs_sent.get().to_string()}</p>
                    </div>
                    <div class="bg-gray-800/50 rounded-lg p-3">
                        <p class="text-xs text-gray-500">"Messages Received"</p>
                        <p class="text-lg font-bold text-blue-400">{move || msgs_received.get().to_string()}</p>
                    </div>
                </div>
            </div>

            // Advanced settings (placeholder)
            <div class="glass-card p-6 space-y-4 opacity-60">
                <h3 class="text-sm font-semibold text-gray-400 uppercase tracking-wider">"Advanced Filters"</h3>
                <p class="text-gray-500 text-sm">"Relay filter configuration coming soon."</p>
            </div>
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn relay_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 11a9 9 0 0118 0"/>
            <path d="M8 11a5 5 0 0110 0"/>
            <line x1="13" y1="11" x2="13" y2="14"/>
            <circle cx="13" cy="17" r="3"/>
        </svg>
    }
}

fn test_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
    }
}
