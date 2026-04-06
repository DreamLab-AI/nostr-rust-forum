//! User settings and preferences page.
//!
//! Route: `/settings`
//! Sections: Profile, Muted Users, Privacy, Appearance (future), Account.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::components::A;
use nostr_core::UnsignedEvent;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::confirm_dialog::{ConfirmDialog, ConfirmVariant};
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::preferences::{
    save_preferences, use_preferences, NotificationLevel, Theme,
};
use crate::utils::shorten_pubkey;

/// Key used to persist muted pubkeys in localStorage.
const MUTED_STORAGE_KEY: &str = "nostr_bbs_muted";

/// Key used to persist privacy toggles in localStorage.
const PRIVACY_STORAGE_KEY: &str = "nostr_bbs_privacy";

fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
}

fn load_muted_list() -> Vec<String> {
    get_local_storage()
        .and_then(|s| s.get_item(MUTED_STORAGE_KEY).ok())
        .flatten()
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default()
}

fn save_muted_list(list: &[String]) {
    if let Some(storage) = get_local_storage() {
        let json = serde_json::to_string(list).unwrap_or_default();
        let _ = storage.set_item(MUTED_STORAGE_KEY, &json);
    }
}

fn load_privacy_settings() -> (bool, bool) {
    get_local_storage()
        .and_then(|s| s.get_item(PRIVACY_STORAGE_KEY).ok())
        .flatten()
        .and_then(|json| serde_json::from_str::<(bool, bool)>(&json).ok())
        .unwrap_or((true, true))
}

fn save_privacy_settings(show_online: bool, allow_dms: bool) {
    if let Some(storage) = get_local_storage() {
        let json = serde_json::to_string(&(show_online, allow_dms)).unwrap_or_default();
        let _ = storage.set_item(PRIVACY_STORAGE_KEY, &json);
    }
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();
    let relay = expect_context::<RelayConnection>();

    // Profile fields
    let nickname = RwSignal::new(auth.nickname().get_untracked().unwrap_or_default());
    let about = RwSignal::new(String::new());
    let avatar_url = RwSignal::new(String::new());
    let birthday = RwSignal::new(String::new()); // "MM-DD" format
    let profile_saving = RwSignal::new(false);

    // Muted users
    let muted = RwSignal::new(load_muted_list());

    // Privacy toggles
    let (init_online, init_dms) = load_privacy_settings();
    let show_online = RwSignal::new(init_online);
    let allow_dms = RwSignal::new(init_dms);
    let privacy_saving = RwSignal::new(false);

    // Confirm dialog for nsec export
    let confirm_nsec_open = RwSignal::new(false);

    let pubkey_display = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .map(|pk| shorten_pubkey(&pk))
            .unwrap_or_else(|| "not logged in".to_string())
    });

    let pubkey_full = Memo::new(move |_| auth.pubkey().get().unwrap_or_default());

    // -- Fetch kind-0 metadata on mount to populate fields --
    {
        let relay = relay.clone();
        let conn_state = relay.connection_state();
        let nickname_sig = nickname;
        let about_sig = about;
        let avatar_sig = avatar_url;
        let birthday_sig = birthday;
        let auth_for_fetch = auth.clone();

        Effect::new(move |_| {
            if conn_state.get() != ConnectionState::Connected {
                return;
            }
            let pk = match auth_for_fetch.pubkey().get() {
                Some(pk) => pk,
                None => return,
            };

            let on_event: Rc<dyn Fn(nostr_core::NostrEvent)> =
                Rc::new(move |event: nostr_core::NostrEvent| {
                    if event.kind != 0 {
                        return;
                    }
                    if let Ok(obj) =
                        serde_json::from_str::<serde_json::Value>(&event.content)
                    {
                        if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
                            nickname_sig.set(name.to_string());
                        }
                        if let Some(bio) = obj.get("about").and_then(|v| v.as_str()) {
                            about_sig.set(bio.to_string());
                        }
                        if let Some(pic) = obj.get("picture").and_then(|v| v.as_str()) {
                            avatar_sig.set(pic.to_string());
                        }
                        if let Some(bday) = obj.get("birthday").and_then(|v| v.as_str()) {
                            birthday_sig.set(bday.to_string());
                        }
                    }
                });

            let sub_id = relay.subscribe(
                vec![Filter {
                    kinds: Some(vec![0]),
                    authors: Some(vec![pk]),
                    limit: Some(1),
                    ..Default::default()
                }],
                on_event,
                None,
            );

            // Auto-unsubscribe after 5 seconds
            let relay_unsub = relay.clone();
            crate::utils::set_timeout_once(
                move || {
                    relay_unsub.unsubscribe(&sub_id);
                },
                5_000,
            );
        });
    }

    // -- Profile save handler --
    let toasts_for_profile = toasts.clone();
    let on_save_profile = move |_| {
        let name = nickname.get_untracked().trim().to_string();
        if name.is_empty() {
            toasts_for_profile.show("Nickname cannot be empty", ToastVariant::Warning);
            return;
        }

        let pubkey_hex = match auth.pubkey().get_untracked() {
            Some(pk) => pk,
            None => {
                toasts_for_profile.show("Not authenticated", ToastVariant::Error);
                return;
            }
        };

        profile_saving.set(true);

        let mut metadata = serde_json::Map::new();
        metadata.insert("name".into(), serde_json::Value::String(name.clone()));
        let bio = about.get_untracked().trim().to_string();
        if !bio.is_empty() {
            metadata.insert("about".into(), serde_json::Value::String(bio));
        }
        let pic = avatar_url.get_untracked().trim().to_string();
        if !pic.is_empty() {
            metadata.insert("picture".into(), serde_json::Value::String(pic));
        }
        let bday = birthday.get_untracked().trim().to_string();
        if !bday.is_empty() {
            metadata.insert("birthday".into(), serde_json::Value::String(bday));
        }

        let content =
            serde_json::to_string(&serde_json::Value::Object(metadata)).unwrap_or_default();

        let unsigned = UnsignedEvent {
            pubkey: pubkey_hex,
            created_at: (js_sys::Date::now() / 1000.0) as u64,
            kind: 0,
            tags: vec![],
            content,
        };

        let toasts_ok = toasts_for_profile.clone();
        let toasts_pub = toasts_for_profile.clone();
        let toasts_err = toasts_for_profile.clone();
        let relay = relay.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match auth.sign_event_async(unsigned).await {
                Ok(signed) => {
                    let saving_sig = profile_saving;
                    let auth_for_ack = auth;
                    let name_for_ack = name.clone();
                    let ack = Rc::new(move |accepted: bool, message: String| {
                        saving_sig.set(false);
                        if accepted {
                            auth_for_ack.set_profile(Some(name_for_ack.clone()), None);
                            toasts_ok.show("Profile updated", ToastVariant::Success);
                        } else {
                            toasts_ok.show(
                                format!("Profile rejected: {}", message),
                                ToastVariant::Error,
                            );
                        }
                    });
                    if let Err(e) = relay.publish_with_ack(&signed, Some(ack)) {
                        profile_saving.set(false);
                        toasts_pub.show(format!("Publish failed: {}", e), ToastVariant::Error);
                    }
                }
                Err(e) => {
                    profile_saving.set(false);
                    toasts_err.show(format!("Failed to sign: {}", e), ToastVariant::Error);
                }
            }
        });
    };

    // -- Unmute handler --
    let toasts_for_unmute = toasts.clone();
    let on_unmute = move |pk: String| {
        muted.update(|list| list.retain(|p| p != &pk));
        save_muted_list(&muted.get_untracked());
        toasts_for_unmute.show("User unmuted", ToastVariant::Success);
    };

    // -- Privacy save handler --
    let toasts_for_privacy = toasts.clone();
    let on_save_privacy = move |_| {
        privacy_saving.set(true);
        save_privacy_settings(show_online.get_untracked(), allow_dms.get_untracked());
        privacy_saving.set(false);
        toasts_for_privacy.show("Privacy settings saved", ToastVariant::Success);
    };

    // -- Nsec export handler --
    let toasts_for_nsec = toasts.clone();
    let on_confirm_nsec = Callback::new(move |_: ()| {
        if let Some(privkey) = auth.get_privkey_bytes() {
            let hex_str = hex::encode(*privkey);
            // Copy to clipboard
            if let Some(window) = web_sys::window() {
                let nav = window.navigator().clipboard();
                let _ = nav.write_text(&hex_str);
                toasts_for_nsec.show("Private key copied to clipboard", ToastVariant::Warning);
            }
        } else {
            toasts_for_nsec.show("No private key available", ToastVariant::Error);
        }
    });

    // -- Logout handler --
    let on_logout = move |_| {
        auth.logout();
    };

    view! {
        <div class="max-w-2xl mx-auto p-4 sm:p-6">
            // Breadcrumb
            <div class="flex items-center gap-2 text-sm text-gray-500 mb-6">
                <A href=base_href("/") attr:class="hover:text-amber-400 transition-colors">"Home"</A>
                <span>"/"</span>
                <span class="text-gray-300">"Settings"</span>
            </div>

            <h1 class="text-3xl font-bold bg-gradient-to-r from-amber-400 to-orange-500 bg-clip-text text-transparent mb-8">
                "Settings"
            </h1>

            <div class="space-y-6">
                // -- Section 1: Profile --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {user_icon()}
                        "Profile"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div class="space-y-3">
                        <div class="space-y-1">
                            <label class="block text-sm font-medium text-gray-300">"Nickname"</label>
                            <input
                                type="text"
                                prop:value=move || nickname.get()
                                on:input=move |ev| nickname.set(event_target_value(&ev))
                                maxlength="50"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                        <div class="space-y-1">
                            <label class="block text-sm font-medium text-gray-300">"About"</label>
                            <textarea
                                prop:value=move || about.get()
                                on:input=move |ev| about.set(event_target_value(&ev))
                                rows="3"
                                maxlength="256"
                                placeholder="Tell people about yourself"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors resize-none"
                            />
                        </div>
                        <div class="space-y-1">
                            <label class="block text-sm font-medium text-gray-300">"Avatar URL"</label>
                            <input
                                type="url"
                                prop:value=move || avatar_url.get()
                                on:input=move |ev| avatar_url.set(event_target_value(&ev))
                                placeholder="https://example.com/avatar.jpg"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </div>
                        <div class="space-y-1">
                            <label class="block text-sm font-medium text-gray-300">"Birthday"</label>
                            <input
                                type="text"
                                prop:value=move || birthday.get()
                                on:input=move |ev| birthday.set(event_target_value(&ev))
                                placeholder="MM-DD (e.g. 03-15)"
                                maxlength="5"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                            <p class="text-xs text-gray-500">"Shown on the Events birthday calendar"</p>
                        </div>
                    </div>

                    <button
                        on:click=on_save_profile
                        disabled=move || profile_saving.get()
                        class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm flex items-center gap-1.5"
                    >
                        {move || if profile_saving.get() { "Saving..." } else { "Save Profile" }}
                    </button>
                </div>

                // -- Section 2: Muted Users --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {mute_icon()}
                        "Muted Users"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    {move || {
                        let list = muted.get();
                        if list.is_empty() {
                            view! {
                                <p class="text-gray-500 text-sm">"No muted users."</p>
                            }.into_any()
                        } else {
                            view! {
                                <div class="space-y-2">
                                    {list.into_iter().map(|pk| {
                                        let pk_display = shorten_pubkey(&pk);
                                        let pk_for_unmute = pk.clone();
                                        let on_unmute = on_unmute.clone();
                                        view! {
                                            <div class="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
                                                <code class="text-xs text-gray-300 font-mono">{pk_display}</code>
                                                <button
                                                    on:click=move |_| on_unmute(pk_for_unmute.clone())
                                                    class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors"
                                                >
                                                    "Unmute"
                                                </button>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }
                    }}
                </div>

                // -- Section 3: Privacy --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {privacy_icon()}
                        "Privacy"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div class="space-y-3">
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Show online status"</span>
                            <input
                                type="checkbox"
                                prop:checked=move || show_online.get()
                                on:change=move |_| show_online.update(|v| *v = !*v)
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                            />
                        </label>
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Allow DMs from non-contacts"</span>
                            <input
                                type="checkbox"
                                prop:checked=move || allow_dms.get()
                                on:change=move |_| allow_dms.update(|v| *v = !*v)
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                            />
                        </label>
                    </div>

                    <button
                        on:click=on_save_privacy
                        disabled=move || privacy_saving.get()
                        class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm flex items-center gap-1.5"
                    >
                        {move || if privacy_saving.get() { "Saving..." } else { "Save Privacy" }}
                    </button>
                </div>

                // -- Section 4: Appearance --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {palette_icon()}
                        "Appearance"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    // Theme selector
                    <div class="space-y-2">
                        <span class="text-sm font-medium text-gray-300">"Theme"</span>
                        <div class="flex gap-2" role="radiogroup" aria-label="Theme selection">
                            {[Theme::Dark, Theme::Light, Theme::System].into_iter().map(|t| {
                                let label = t.label();
                                let theme_for_class = t.clone();
                                let theme_for_aria = t.clone();
                                let theme_for_click = t.clone();
                                view! {
                                    <button
                                        class=move || {
                                            let prefs = use_preferences();
                                            if prefs.get().theme == theme_for_class {
                                                "px-4 py-2 rounded-full text-sm font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30 transition-colors"
                                            } else {
                                                "px-4 py-2 rounded-full text-sm font-medium text-gray-400 hover:text-white bg-gray-800/50 border border-gray-700 hover:border-gray-600 transition-colors"
                                            }
                                        }
                                        on:click={
                                            let t = theme_for_click.clone();
                                            move |_| {
                                                let prefs = use_preferences();
                                                prefs.update(|p| p.theme = t.clone());
                                                save_preferences(&prefs.get_untracked());
                                            }
                                        }
                                        role="radio"
                                        aria-checked=move || {
                                            let prefs = use_preferences();
                                            (prefs.get().theme == theme_for_aria).to_string()
                                        }
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    </div>

                    // Show technical details toggle
                    <label class="flex items-center justify-between cursor-pointer">
                        <div>
                            <span class="text-sm text-gray-300">"Show technical details"</span>
                            <p class="text-xs text-gray-500 mt-0.5">"Display protocol names, public keys, and relay URLs"</p>
                        </div>
                        <input
                            type="checkbox"
                            prop:checked=move || use_preferences().get().show_technical_details
                            on:change=move |_| {
                                let prefs = use_preferences();
                                prefs.update(|p| p.show_technical_details = !p.show_technical_details);
                                save_preferences(&prefs.get_untracked());
                            }
                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                        />
                    </label>

                    // Reduced motion toggle
                    <label class="flex items-center justify-between cursor-pointer">
                        <span class="text-sm text-gray-300">"Reduced motion"</span>
                        <input
                            type="checkbox"
                            prop:checked=move || use_preferences().get().reduced_motion
                            on:change=move |_| {
                                let prefs = use_preferences();
                                prefs.update(|p| p.reduced_motion = !p.reduced_motion);
                                save_preferences(&prefs.get_untracked());
                            }
                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                        />
                    </label>
                </div>

                // -- Section 4b: Notifications --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {bell_icon()}
                        "Notifications"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div class="space-y-2">
                        <span class="text-sm font-medium text-gray-300">"Notification level"</span>
                        <select
                            class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors text-sm"
                            on:change=move |ev| {
                                let val = event_target_value(&ev);
                                let level = match val.as_str() {
                                    "MentionsOnly" => NotificationLevel::MentionsOnly,
                                    "None" => NotificationLevel::None,
                                    _ => NotificationLevel::All,
                                };
                                let prefs = use_preferences();
                                prefs.update(|p| p.notification_level = level);
                                save_preferences(&prefs.get_untracked());
                            }
                            aria-label="Notification level"
                        >
                            {NotificationLevel::all_variants().iter().map(|level| {
                                let val = format!("{:?}", level);
                                let label = level.label();
                                let level_cmp = level.clone();
                                view! {
                                    <option
                                        value=val.clone()
                                        selected=move || use_preferences().get().notification_level == level_cmp
                                    >
                                        {label}
                                    </option>
                                }
                            }).collect_view()}
                        </select>
                    </div>
                </div>

                // -- Section 4c: Content --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {content_icon()}
                        "Content"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div class="space-y-3">
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Show link previews"</span>
                            <input
                                type="checkbox"
                                prop:checked=move || use_preferences().get().show_link_previews
                                on:change=move |_| {
                                    let prefs = use_preferences();
                                    prefs.update(|p| p.show_link_previews = !p.show_link_previews);
                                    save_preferences(&prefs.get_untracked());
                                }
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                            />
                        </label>
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Compact messages"</span>
                            <input
                                type="checkbox"
                                prop:checked=move || use_preferences().get().compact_messages
                                on:change=move |_| {
                                    let prefs = use_preferences();
                                    prefs.update(|p| p.compact_messages = !p.compact_messages);
                                    save_preferences(&prefs.get_untracked());
                                }
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                            />
                        </label>
                    </div>
                </div>

                // -- Section 5: Account --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {key_icon()}
                        "Account"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div class="space-y-3">
                        <div>
                            <span class="text-sm text-gray-400">"Public Key"</span>
                            <div class="bg-gray-800 rounded-lg px-3 py-2 mt-1">
                                <code class="text-xs text-amber-300 font-mono break-all">
                                    {move || pubkey_full.get()}
                                </code>
                            </div>
                        </div>
                        <div class="text-sm text-gray-400">
                            "Display: "
                            <span class="text-gray-300">{move || pubkey_display.get()}</span>
                        </div>
                    </div>

                    <div class="flex gap-3 pt-2">
                        <button
                            on:click=move |_| confirm_nsec_open.set(true)
                            class="text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded-lg px-4 py-2 transition-colors"
                        >
                            "Export Private Key"
                        </button>
                        <button
                            on:click=on_logout
                            class="text-sm text-gray-400 hover:text-white border border-gray-600 hover:border-gray-500 rounded-lg px-4 py-2 transition-colors hover:bg-gray-800"
                        >
                            "Logout"
                        </button>
                    </div>
                </div>
            </div>

            // Confirm dialog for nsec export
            <ConfirmDialog
                is_open=confirm_nsec_open
                title="Export Private Key".to_string()
                message="This will copy your raw private key to the clipboard. Anyone with this key has full control of your Nostr identity. Only proceed if you understand the risks.".to_string()
                confirm_label="Copy to Clipboard".to_string()
                on_confirm=on_confirm_nsec
                variant=ConfirmVariant::Danger
            />
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn section_icon(d: &'static str) -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d=d/>
        </svg>
    }
}
fn user_icon() -> impl IntoView {
    section_icon("M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2M16 7a4 4 0 11-8 0 4 4 0 018 0")
}
fn mute_icon() -> impl IntoView {
    section_icon("M1 1l22 22M9 9v3a3 3 0 005.12 2.12M15 9.34V4a3 3 0 00-5.94-.6M17 16.95A7 7 0 015 12v-2m14 0v2c0 .38-.03.75-.08 1.12M12 19v4M8 23h8")
}
fn privacy_icon() -> impl IntoView {
    section_icon("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z")
}
fn palette_icon() -> impl IntoView {
    section_icon("M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 011.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z")
}
fn key_icon() -> impl IntoView {
    section_icon("M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4")
}
fn bell_icon() -> impl IntoView {
    section_icon("M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0")
}
fn content_icon() -> impl IntoView {
    section_icon("M4 6h16M4 12h16M4 18h7")
}
