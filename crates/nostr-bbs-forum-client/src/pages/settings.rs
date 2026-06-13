//! User settings and preferences page.
//!
//! Route: `/settings`
//! Sections: Profile, Muted Users, Privacy, Appearance (future), Account.

use std::rc::Rc;

use leptos::prelude::*;
use leptos_router::components::A;
use nostr_bbs_core::UnsignedEvent;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::confirm_dialog::{ConfirmDialog, ConfirmVariant};
use crate::components::onboarding_modal::{
    cache_claimed_username, claimed_username_cached, open_onboarding_with_prefill,
    release_username, use_claimed_username, username_from_nip05,
};
use crate::components::toast::{use_toasts, ToastVariant};
use crate::components::user_display::use_display_name_tracked;
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::preferences::{
    save_preferences, use_preferences, Density, FontSize, NotificationLevel, Theme,
};
use crate::utils::pod_client::upload_to_pod_signer;
use crate::utils::relay_url::auth_api_base;
use crate::utils::shorten_pubkey;

/// NIP-05 host that backs claimed usernames (mirrors onboarding_modal::NIP05_HOST).
const NIP05_USERNAME_HOST: &str = "example.test";

/// Pod API base URL — same source-of-truth as `pages::pod_browser` and
/// `utils::pod_client`. Surfaces the `[pod].base_url` operator-config
/// value via the `VITE_POD_API_URL` build-time env. Used here to render
/// the per-user git clone URL (ADR-089).
const POD_API: &str = match option_env!("VITE_POD_API_URL") {
    Some(u) => u,
    None => "https://pod.example.com",
};

/// Client-side size cap for profile picture uploads (~2 MB).
const MAX_AVATAR_BYTES: f64 = 2.0 * 1024.0 * 1024.0;

/// Read a key from the `window.__ENV__` runtime-config object injected by the
/// deploy (mirrors the private reader in `utils::relay_url`). Returns `None`
/// for a missing/undefined/empty value.
fn window_env(key: &str) -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let val = js_sys::Reflect::get(&env, &key.into()).ok()?;
    let s = val.as_string()?;
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Deploy version string, from `window.__ENV__.BUILD_VERSION`. The website
/// deploy injects this; falls back to `"dev"` for local/un-injected builds
/// (issue #27).
fn build_version() -> String {
    window_env("BUILD_VERSION").unwrap_or_else(|| "dev".to_string())
}

/// Short git hash of the deployed build, from `window.__ENV__.BUILD_HASH`.
/// Falls back to `"local"` when absent (issue #27).
fn build_hash() -> String {
    window_env("BUILD_HASH").unwrap_or_else(|| "local".to_string())
}

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

    // Real name (admin-only): loaded from + saved to the auth-worker D1 via
    // NIP-98 authed routes. NEVER published to kind-0 / the relay.
    let real_name = RwSignal::new(String::new());
    let real_name_saving = RwSignal::new(false);

    // Muted users
    let muted = RwSignal::new(load_muted_list());

    // Privacy toggles
    let (init_online, init_dms) = load_privacy_settings();
    let show_online = RwSignal::new(init_online);
    let allow_dms = RwSignal::new(init_dms);
    let privacy_saving = RwSignal::new(false);

    // Devices (ADR-099, gated on window.__ENV__.DEVICE_KEYS_ENABLED).
    // When the flag is off the whole section is hidden and never fetches.
    let device_keys_on = crate::utils::devices::device_keys_enabled();
    let devices_list: RwSignal<Vec<crate::utils::devices::DeviceKey>> = RwSignal::new(Vec::new());
    let devices_loading = RwSignal::new(false);
    let devices_error: RwSignal<Option<String>> = RwSignal::new(None);
    // "Add a device" QR + link, rendered after a successful registration.
    let new_device_qr = RwSignal::new(String::new());
    let new_device_connect = RwSignal::new(String::new());
    let new_device_busy = RwSignal::new(false);

    // Load the device list once, only when the feature is enabled and authed.
    if device_keys_on {
        Effect::new(move |_| {
            if auth.pubkey().get().is_none() {
                return;
            }
            if devices_loading.get_untracked() || !devices_list.get_untracked().is_empty() {
                return;
            }
            devices_loading.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                match crate::utils::devices::list_devices(auth).await {
                    Ok(list) => devices_list.set(list),
                    Err(e) => devices_error.set(Some(e.to_string())),
                }
                devices_loading.set(false);
            });
        });
    }

    // Derive + register a new device key, then surface its /connect QR.
    let on_add_device = move |_| {
        if new_device_busy.get_untracked() {
            return;
        }
        new_device_busy.set(true);
        devices_error.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            let label = format!("Device added {}", crate::utils::devices::today_utc());
            match crate::utils::devices::register_device(auth, &label).await {
                Ok(reg) => {
                    let url = crate::utils::devices::device_connect_url(&reg.device_nsec)
                        .unwrap_or_default();
                    new_device_qr.set(crate::utils::devices::qr_svg(&url));
                    new_device_connect.set(url);
                    // Refresh the list to include the newly-registered device.
                    match crate::utils::devices::list_devices(auth).await {
                        Ok(list) => devices_list.set(list),
                        Err(e) => devices_error.set(Some(e.to_string())),
                    }
                }
                Err(e) => devices_error.set(Some(e.to_string())),
            }
            new_device_busy.set(false);
        });
    };

    // Revoke a device key and drop it from the list optimistically.
    let on_revoke_device = move |pubkey: String| {
        let pk = pubkey.clone();
        devices_error.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match crate::utils::devices::revoke_device(auth, &pk).await {
                Ok(()) => {
                    devices_list.update(|l| {
                        for d in l.iter_mut() {
                            if d.device_pubkey == pk {
                                d.revoked = 1;
                            }
                        }
                    });
                }
                Err(e) => devices_error.set(Some(e.to_string())),
            }
        });
    };

    // Confirm dialog for nsec export
    let confirm_nsec_open = RwSignal::new(false);

    // Confirm dialog for username release
    let confirm_release_open = RwSignal::new(false);
    let release_pending = RwSignal::new(false);

    // Display the currently-claimed username (if any).
    //
    // Deliberately NOT derived from `auth.nickname()` — the nickname is the
    // kind-0 display name and conflating the two made a profile nickname
    // save (e.g. "Carol QA") render as a claimed username with an invalid
    // NIP-05 (QA HIGH bug #5a). The shared ClaimedUsername signal is fed by
    // the claim flow, the localStorage claim cache, and the kind-0 `nip05`
    // field fetched below (QA HIGH bug #5b: claimed usernames now load).
    let claimed_sig = use_claimed_username();
    let claimed_username = Memo::new(move |_| claimed_sig.and_then(|c| c.0.get()));
    let claimed_nip05 = Memo::new(move |_| {
        claimed_username
            .get()
            .map(|n| format!("{}@{}", n, NIP05_USERNAME_HOST))
    });

    // Hydrate from the local claim cache on mount (covers direct /settings
    // navigation before the onboarding modal effect has run).
    if let (Some(claimed), Some(pk)) = (claimed_sig, auth.pubkey().get_untracked()) {
        if claimed.0.get_untracked().is_none() {
            if let Some(cached) = claimed_username_cached(&pk) {
                claimed.0.set(Some(cached));
            }
        }
    }

    let pubkey_display = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .map(|pk| shorten_pubkey(&pk))
            .unwrap_or_else(|| "not logged in".to_string())
    });

    let pubkey_full = Memo::new(move |_| auth.pubkey().get().unwrap_or_default());

    // Per-user pod git clone URL (ADR-089). Renders when the user has a
    // pubkey; the URL only resolves on deployments where the operator has
    // enabled git-init at pod provisioning (non-CF tier). The CF Workers
    // tier does not git-init pods — see ADR-089 for the divergence.
    let pod_clone_url = Memo::new(move |_| {
        auth.pubkey()
            .get()
            .map(|pk| format!("{}/pods/{}/", POD_API.trim_end_matches('/'), pk))
    });
    let pod_clone_command = Memo::new(move |_| {
        pod_clone_url
            .get()
            .map(|url| format!("git clone {}", url))
            .unwrap_or_default()
    });

    // -- Fetch kind-0 metadata on mount to populate fields --
    {
        let relay = relay.clone();
        let conn_state = relay.connection_state();
        let nickname_sig = nickname;
        let about_sig = about;
        let avatar_sig = avatar_url;
        let birthday_sig = birthday;
        let auth_for_fetch = auth;

        Effect::new(move |_| {
            if conn_state.get() != ConnectionState::Connected {
                return;
            }
            let pk = match auth_for_fetch.pubkey().get() {
                Some(pk) => pk,
                None => return,
            };

            let pk_for_event = pk.clone();
            let on_event: Rc<dyn Fn(nostr_bbs_core::NostrEvent)> =
                Rc::new(move |event: nostr_bbs_core::NostrEvent| {
                    if event.kind != 0 {
                        return;
                    }
                    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&event.content) {
                        // The nickname is the DISPLAY name — prefer
                        // `display_name`, falling back to `name` for events
                        // published before the username/nickname split.
                        let display = obj
                            .get("display_name")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.trim().is_empty())
                            .or_else(|| obj.get("name").and_then(|v| v.as_str()));
                        if let Some(name) = display {
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
                        // Recover an already-claimed username from the
                        // kind-0 `nip05` field (QA HIGH bug #5b).
                        if let Some(nip05) = obj.get("nip05").and_then(|v| v.as_str()) {
                            if let Some(username) = username_from_nip05(nip05) {
                                cache_claimed_username(&pk_for_event, &username);
                                if let Some(claimed) = claimed_sig {
                                    if claimed.0.get_untracked().as_deref()
                                        != Some(username.as_str())
                                    {
                                        claimed.0.set(Some(username));
                                    }
                                }
                            }
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

    // -- Load the admin-only real name (authed GET) on mount --
    {
        let real_name_sig = real_name;
        Effect::new(move |_| {
            // Re-run when authentication establishes a signer.
            if auth.pubkey().get().is_none() {
                return;
            }
            let Some(signer) = auth.get_signer() else {
                return;
            };
            wasm_bindgen_futures::spawn_local(async move {
                let url = format!("{}/api/profile/real-name", auth_api_base());
                if let Ok(body) =
                    crate::auth::nip98::fetch_with_nip98_get_signer(&url, signer.as_ref()).await
                {
                    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(rn) = resp.get("real_name").and_then(|v| v.as_str()) {
                            real_name_sig.set(rn.to_string());
                        }
                    }
                }
            });
        });
    }

    // -- Real name save handler (authed POST; empty value clears) --
    let toasts_for_real_name = toasts;
    let on_save_real_name = move |_| {
        let Some(signer) = auth.get_signer() else {
            toasts_for_real_name.show("Not authenticated", ToastVariant::Error);
            return;
        };
        real_name_saving.set(true);
        let value = real_name.get_untracked().trim().to_string();
        let body = serde_json::json!({ "real_name": value }).to_string();
        let toasts_ok = toasts_for_real_name;
        let toasts_err = toasts_for_real_name;
        wasm_bindgen_futures::spawn_local(async move {
            let url = format!("{}/api/profile/real-name", auth_api_base());
            match crate::auth::nip98::fetch_with_nip98_post_signer(&url, &body, signer.as_ref())
                .await
            {
                Ok(_) => {
                    real_name_saving.set(false);
                    if value.is_empty() {
                        toasts_ok.show("Real name cleared", ToastVariant::Success);
                    } else {
                        toasts_ok.show("Real name saved", ToastVariant::Success);
                    }
                }
                Err(e) => {
                    real_name_saving.set(false);
                    toasts_err.show(format!("Save failed: {}", e), ToastVariant::Error);
                }
            }
        });
    };

    // -- Profile save handler --
    let toasts_for_profile = toasts;
    let relay_for_save = relay.clone();
    let on_save_profile = move |_| {
        let name = nickname.get_untracked().trim().to_string();
        if name.is_empty() {
            toasts_for_profile.show("Nickname cannot be empty", ToastVariant::Warning);
            return;
        }
        publish_profile_metadata(
            auth,
            relay_for_save.clone(),
            toasts_for_profile,
            profile_saving,
            name,
            claimed_username.get_untracked(),
            about.get_untracked().trim().to_string(),
            avatar_url.get_untracked().trim().to_string(),
            birthday.get_untracked().trim().to_string(),
            "Profile updated",
        );
    };

    // -- Profile picture upload handler --
    //
    // Stores the image in the user's pod public media folder (NIP-98 authed
    // POST via `pod_client::upload_to_pod_signer`), then republishes kind-0
    // with `picture` set to the public pod URL, preserving all other fields.
    let pic_uploading = RwSignal::new(false);
    let toasts_for_pic = toasts;
    let relay_for_pic = relay.clone();
    let on_pic_file = move |ev: leptos::ev::Event| {
        let input: web_sys::HtmlInputElement = event_target(&ev);
        let Some(file) = input.files().and_then(|fl| fl.get(0)) else {
            return;
        };
        // Reset so re-selecting the same file re-fires `change`.
        input.set_value("");
        if file.size() > MAX_AVATAR_BYTES {
            toasts_for_pic.show(
                "Image too large — maximum size is 2 MB",
                ToastVariant::Warning,
            );
            return;
        }
        let Some(pk) = auth.pubkey().get_untracked() else {
            toasts_for_pic.show("Not authenticated", ToastVariant::Error);
            return;
        };
        let Some(signer) = auth.get_signer() else {
            toasts_for_pic.show("Not authenticated", ToastVariant::Error);
            return;
        };
        pic_uploading.set(true);
        let relay = relay_for_pic.clone();
        let name = nickname.get_untracked().trim().to_string();
        let claimed = claimed_username.get_untracked();
        let bio = about.get_untracked().trim().to_string();
        let bday = birthday.get_untracked().trim().to_string();
        wasm_bindgen_futures::spawn_local(async move {
            let filename = avatar_filename(&file.type_());
            let mut result =
                upload_to_pod_signer(&file, &filename, &pk, signer.as_ref(), None).await;
            // Pods are provisioned eagerly at signup, but accounts predating
            // that may not have one yet — on 404, provision once and retry.
            if matches!(&result, Err(e) if e.starts_with("HTTP 404")) {
                result = match provision_pod(auth).await {
                    Ok(()) => {
                        upload_to_pod_signer(&file, &filename, &pk, signer.as_ref(), None).await
                    }
                    Err(e) => Err(format!("pod provisioning failed: {e}")),
                };
            }
            match result {
                Ok(url) => {
                    pic_uploading.set(false);
                    avatar_url.set(url.clone());
                    publish_profile_metadata(
                        auth,
                        relay,
                        toasts_for_pic,
                        profile_saving,
                        name,
                        claimed,
                        bio,
                        url,
                        bday,
                        "Profile picture updated",
                    );
                }
                Err(e) => {
                    pic_uploading.set(false);
                    toasts_for_pic.show(format!("Upload failed: {}", e), ToastVariant::Error);
                }
            }
        });
    };

    // -- Profile picture remove handler --
    //
    // Clears `picture` from kind-0 (replaceable, so the next publish without
    // the field removes it). The pod file is deliberately left in place.
    let toasts_for_pic_remove = toasts;
    let relay_for_pic_remove = relay.clone();
    let on_remove_picture = move |_: leptos::ev::MouseEvent| {
        avatar_url.set(String::new());
        publish_profile_metadata(
            auth,
            relay_for_pic_remove.clone(),
            toasts_for_pic_remove,
            profile_saving,
            nickname.get_untracked().trim().to_string(),
            claimed_username.get_untracked(),
            about.get_untracked().trim().to_string(),
            String::new(),
            birthday.get_untracked().trim().to_string(),
            "Profile picture removed",
        );
    };

    // -- Unmute handler --
    let toasts_for_unmute = toasts;
    let on_unmute = move |pk: String| {
        muted.update(|list| list.retain(|p| p != &pk));
        save_muted_list(&muted.get_untracked());
        toasts_for_unmute.show("User unmuted", ToastVariant::Success);
    };

    // -- Privacy save handler --
    let toasts_for_privacy = toasts;
    let on_save_privacy = move |_| {
        privacy_saving.set(true);
        save_privacy_settings(show_online.get_untracked(), allow_dms.get_untracked());
        privacy_saving.set(false);
        toasts_for_privacy.show("Privacy settings saved", ToastVariant::Success);
    };

    // -- Nsec export handler --
    // NOTE: get_privkey_bytes() is the intentional and legitimate path here --
    // the user explicitly wants to see/export their raw private key. NIP-07
    // users cannot export because the extension never exposes keys.
    let toasts_for_nsec = toasts;
    let on_confirm_nsec = Callback::new(move |_: ()| {
        if auth.get().is_nip07 {
            toasts_for_nsec.show(
                "Private key export is not available with NIP-07 browser extensions. Your key is managed by the extension.",
                ToastVariant::Warning,
            );
            return;
        }
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

    // -- Username change handler (opens onboarding modal pre-filled) --
    // Pre-fill with the CLAIMED username, never the nickname — the claim
    // flow enforces the [a-z0-9_-]{3,30} format client-side.
    let on_change_username = move |_| {
        let current = claimed_username.get_untracked();
        open_onboarding_with_prefill(current);
    };

    // -- Pod git clone URL: copy-to-clipboard handler (ADR-089) --
    let toasts_for_clone = toasts;
    let on_copy_clone_cmd = move |_| {
        let cmd = pod_clone_command.get_untracked();
        if cmd.is_empty() {
            toasts_for_clone.show("No clone URL available", ToastVariant::Warning);
            return;
        }
        if let Some(window) = web_sys::window() {
            let nav = window.navigator().clipboard();
            let _ = nav.write_text(&cmd);
            toasts_for_clone.show("Clone command copied", ToastVariant::Success);
        }
    };

    // -- Username release handler (called from confirm dialog) --
    let toasts_for_release = toasts;
    let on_confirm_release = Callback::new(move |_: ()| {
        release_pending.set(true);
        let toasts_ok = toasts_for_release;
        let toasts_err = toasts_for_release;
        spawn_local_release(release_pending, toasts_ok, toasts_err);
    });

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
                // -- Section 0: Username --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {handle_icon()}
                        "Username"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    {move || {
                        match claimed_username.get() {
                            Some(name) if !name.is_empty() => {
                                let nip05 = claimed_nip05.get().unwrap_or_default();
                                view! {
                                    <div class="space-y-3">
                                        <div>
                                            <span class="text-xs text-gray-500 uppercase tracking-wide">"Current"</span>
                                            <div class="bg-gray-800 rounded-lg px-3 py-2 mt-1 flex items-center gap-2">
                                                <span class="text-amber-300 font-mono">"@" {name.clone()}</span>
                                            </div>
                                        </div>
                                        <div>
                                            <span class="text-xs text-gray-500 uppercase tracking-wide">"NIP-05"</span>
                                            <div class="bg-gray-800 rounded-lg px-3 py-2 mt-1">
                                                <code class="text-xs text-gray-300 font-mono break-all">{nip05}</code>
                                            </div>
                                        </div>
                                        <div class="flex gap-3 pt-1">
                                            <button
                                                on:click=on_change_username
                                                class="text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors"
                                            >
                                                "Change"
                                            </button>
                                            <button
                                                on:click=move |_| confirm_release_open.set(true)
                                                disabled=move || release_pending.get()
                                                class="text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded-lg px-4 py-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                            >
                                                {move || if release_pending.get() {
                                                    "Releasing..."
                                                } else {
                                                    "Release username"
                                                }}
                                            </button>
                                        </div>
                                    </div>
                                }.into_any()
                            }
                            _ => view! {
                                <div class="space-y-3">
                                    <p class="text-sm text-gray-400">
                                        "You haven\u{2019}t claimed a username yet. Choose a unique handle so others can mention and find you."
                                    </p>
                                    <button
                                        on:click=on_change_username
                                        class="text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors"
                                    >
                                        "Claim username"
                                    </button>
                                </div>
                            }.into_any(),
                        }
                    }}
                </div>

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
                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-gray-300">"Profile picture"</label>
                            {move || {
                                let pic = avatar_url.get().trim().to_string();
                                let on_remove = on_remove_picture.clone();
                                (!pic.is_empty()).then(|| view! {
                                    <div class="flex items-center gap-3">
                                        <img
                                            src=pic
                                            alt="Current profile picture"
                                            loading="lazy"
                                            class="w-16 h-16 rounded-full object-cover border border-gray-600"
                                        />
                                        <button
                                            on:click=on_remove
                                            class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors"
                                        >
                                            "Remove"
                                        </button>
                                    </div>
                                })
                            }}
                            <input
                                type="file"
                                accept="image/*"
                                on:change=on_pic_file
                                disabled=move || pic_uploading.get()
                                class="block w-full text-sm text-gray-400 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-amber-500 file:text-gray-900 hover:file:bg-amber-400 file:cursor-pointer disabled:opacity-50"
                            />
                            <p class="text-xs text-gray-500">
                                {move || if pic_uploading.get() {
                                    "Uploading to your pod\u{2026}"
                                } else {
                                    "Stored in your pod\u{2019}s public media folder and published in your profile. Max 2 MB."
                                }}
                            </p>
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
                            <p class="text-xs text-gray-500">"Or paste an external image URL, then Save Profile."</p>
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

                    // Real name (admin-only) — separate backend, separate save.
                    <div class="border-t border-gray-700/50 pt-4 mt-2 space-y-3">
                        <div class="space-y-1">
                            <label class="block text-sm font-medium text-gray-300">
                                "Real name "
                                <span class="text-xs text-gray-500">"(optional)"</span>
                            </label>
                            <input
                                type="text"
                                prop:value=move || real_name.get()
                                on:input=move |ev| real_name.set(event_target_value(&ev))
                                maxlength="200"
                                placeholder="e.g. Ada Lovelace"
                                class="w-full bg-gray-800 border border-gray-600 focus:border-amber-500 rounded-lg px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                            <p class="text-xs text-gray-500">
                                "Visible only to administrators and used to provision your access. It is never published, never shown publicly, and never written to the relay. Your handle is what everyone sees. Clear the field and save to remove it."
                            </p>
                        </div>
                        <button
                            on:click=on_save_real_name
                            disabled=move || real_name_saving.get()
                            class="bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:cursor-not-allowed text-gray-100 font-semibold px-4 py-2 rounded-lg transition-colors text-sm flex items-center gap-1.5"
                        >
                            {move || if real_name_saving.get() { "Saving..." } else { "Save Real Name" }}
                        </button>
                    </div>
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
                                        // Tracked resolver — the enclosing `move ||` closure
                                        // re-runs when kind-0 metadata fills the cache, so
                                        // muted users show nicknames as soon as available.
                                        let pk_display = use_display_name_tracked(&pk);
                                        let pk_for_unmute = pk.clone();
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

                    // Font size selector
                    <div class="space-y-2">
                        <span class="text-sm font-medium text-gray-300">"Text size"</span>
                        <div class="flex gap-2" role="radiogroup" aria-label="Text size selection">
                            {FontSize::all_variants().iter().cloned().map(|fs| {
                                let label = fs.label();
                                let fs_for_class = fs.clone();
                                let fs_for_aria = fs.clone();
                                let fs_for_click = fs.clone();
                                view! {
                                    <button
                                        class=move || {
                                            let prefs = use_preferences();
                                            if prefs.get().font_size == fs_for_class {
                                                "px-4 py-2 rounded-full text-sm font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30 transition-colors"
                                            } else {
                                                "px-4 py-2 rounded-full text-sm font-medium text-gray-400 hover:text-white bg-gray-800/50 border border-gray-700 hover:border-gray-600 transition-colors"
                                            }
                                        }
                                        on:click={
                                            let fs = fs_for_click.clone();
                                            move |_| {
                                                let prefs = use_preferences();
                                                prefs.update(|p| p.font_size = fs.clone());
                                                save_preferences(&prefs.get_untracked());
                                            }
                                        }
                                        role="radio"
                                        aria-checked=move || {
                                            let prefs = use_preferences();
                                            (prefs.get().font_size == fs_for_aria).to_string()
                                        }
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                        <p class="text-xs text-gray-500">"Scales text across the whole forum."</p>
                    </div>

                    // Density selector
                    <div class="space-y-2">
                        <span class="text-sm font-medium text-gray-300">"Density"</span>
                        <div class="flex gap-2" role="radiogroup" aria-label="Density selection">
                            {Density::all_variants().iter().cloned().map(|d| {
                                let label = d.label();
                                let d_for_class = d.clone();
                                let d_for_aria = d.clone();
                                let d_for_click = d.clone();
                                view! {
                                    <button
                                        class=move || {
                                            let prefs = use_preferences();
                                            if prefs.get().density == d_for_class {
                                                "px-4 py-2 rounded-full text-sm font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30 transition-colors"
                                            } else {
                                                "px-4 py-2 rounded-full text-sm font-medium text-gray-400 hover:text-white bg-gray-800/50 border border-gray-700 hover:border-gray-600 transition-colors"
                                            }
                                        }
                                        on:click={
                                            let d = d_for_click.clone();
                                            move |_| {
                                                let prefs = use_preferences();
                                                prefs.update(|p| p.density = d.clone());
                                                save_preferences(&prefs.get_untracked());
                                            }
                                        }
                                        role="radio"
                                        aria-checked=move || {
                                            let prefs = use_preferences();
                                            (prefs.get().density == d_for_aria).to_string()
                                        }
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                        <p class="text-xs text-gray-500">"Tightens spacing in lists and cards."</p>
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
                        <div>
                            <span class="text-sm text-gray-300">"Reduced motion"</span>
                            <p class="text-xs text-gray-500 mt-0.5">"Minimise animations and transitions, regardless of your system setting"</p>
                        </div>
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

                // -- Section 4d: Pod git repository (ADR-089) --
                <div class="glass-card p-6 space-y-4">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {git_icon()}
                        "Pod git repository"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div class="space-y-3">
                        <p class="text-sm text-gray-400">
                            "Your pod can be cloned as a git repository on deployments where the operator has enabled git-init at provisioning."
                        </p>
                        <div>
                            <span class="text-xs text-gray-500 uppercase tracking-wide">"Clone command"</span>
                            <div class="bg-gray-800 rounded-lg px-3 py-2 mt-1">
                                <code class="text-xs text-amber-300 font-mono break-all">
                                    {move || pod_clone_command.get()}
                                </code>
                            </div>
                        </div>
                        <div class="flex gap-3 pt-1">
                            <button
                                on:click=on_copy_clone_cmd
                                class="text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors"
                            >
                                "Copy"
                            </button>
                        </div>
                        <p class="text-xs text-gray-500">
                            "Available on pods with git-init enabled (see your operator's deployment). Cloudflare Workers deployments cannot auto-init git — see ADR-089."
                        </p>
                    </div>
                </div>

                // -- Section 4e: Devices (ADR-099, gated) --
                // Hidden entirely unless DEVICE_KEYS_ENABLED is set, so the
                // feature is inert by default with zero behaviour change.
                <Show when=move || device_keys_on>
                    <div class="glass-card p-6 space-y-4">
                        <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                            {device_icon()}
                            "Devices"
                        </h2>
                        <div class="border-t border-gray-700/50"></div>

                        <p class="text-sm text-gray-400">
                            "Phones and other devices that can sign in as you with a "
                            <span class="text-gray-300">"revocable device key"</span>
                            ". Revoking a device kills its access immediately without touching your main account."
                        </p>

                        <Show when=move || devices_error.get().is_some()>
                            <p class="text-sm text-red-400" data-testid="devices-error">
                                {move || devices_error.get().unwrap_or_default()}
                            </p>
                        </Show>

                        // Device list.
                        <div class="space-y-2">
                            <Show
                                when=move || !devices_list.get().is_empty()
                                fallback=move || view! {
                                    <p class="text-sm text-gray-500" data-testid="devices-empty">
                                        {move || if devices_loading.get() {
                                            "Loading devices…"
                                        } else {
                                            "No devices yet. Add one below to sign in on your phone."
                                        }}
                                    </p>
                                }
                            >
                                <For
                                    each=move || devices_list.get()
                                    key=|d| d.device_pubkey.clone()
                                    children=move |d| {
                                        let pk = d.device_pubkey.clone();
                                        let active = d.is_active();
                                        let label = d.label.clone().unwrap_or_else(|| "Unnamed device".to_string());
                                        let short = shorten_pubkey(&d.device_pubkey);
                                        let added = if d.created_at > 0 {
                                            crate::utils::format_relative_time(d.created_at)
                                        } else {
                                            String::new()
                                        };
                                        let revoke_pk = pk.clone();
                                        view! {
                                            <div class="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
                                                <div class="min-w-0">
                                                    <p class="text-sm text-white truncate">
                                                        {label}
                                                        {(!active).then(|| view! {
                                                            <span class="ml-2 text-xs text-red-400">"(revoked)"</span>
                                                        })}
                                                    </p>
                                                    <p class="text-xs text-gray-500 font-mono truncate">
                                                        {short}
                                                        {(!added.is_empty()).then(|| format!(" · {added}"))}
                                                    </p>
                                                </div>
                                                <Show when=move || active>
                                                    <button
                                                        on:click={
                                                            let on_revoke_device = on_revoke_device;
                                                            let revoke_pk = revoke_pk.clone();
                                                            move |_| on_revoke_device(revoke_pk.clone())
                                                        }
                                                        class="text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded-lg px-3 py-1 transition-colors flex-shrink-0"
                                                        data-testid="device-revoke"
                                                    >
                                                        "Revoke"
                                                    </button>
                                                </Show>
                                            </div>
                                        }
                                    }
                                />
                            </Show>
                        </div>

                        // Add-a-device action.
                        <div class="border-t border-gray-700/50 pt-3 space-y-3">
                            <button
                                on:click=on_add_device
                                prop:disabled=move || new_device_busy.get()
                                class="text-sm bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors"
                                data-testid="device-add"
                            >
                                {move || if new_device_busy.get() { "Adding…" } else { "Add a device" }}
                            </button>

                            // /connect QR for the freshly-added device (scan/print).
                            <Show when=move || !new_device_connect.get().is_empty()>
                                <div class="bg-gray-800 rounded-lg p-3 space-y-2">
                                    <p class="text-xs text-amber-300">
                                        "Scan this with your phone to sign in. It grants forum access as you — revoke it above if the phone is lost."
                                    </p>
                                    <div class="flex flex-col sm:flex-row items-center gap-3">
                                        <div
                                            class="bg-white p-2 rounded flex-shrink-0 [&_svg]:w-40 [&_svg]:h-40"
                                            inner_html=move || new_device_qr.get()
                                            data-testid="device-qr"
                                        ></div>
                                        <code class="text-[10px] text-gray-300 font-mono break-all min-w-0">
                                            {move || new_device_connect.get()}
                                        </code>
                                    </div>
                                </div>
                            </Show>
                        </div>
                    </div>
                </Show>

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
                            on:click=move |_| {
                                if auth.get().is_nip07 {
                                    // Show toast immediately for NIP-07 — no confirmation dialog needed
                                    let toasts = use_toasts();
                                    toasts.show(
                                        "Private key export is not available with NIP-07 browser extensions. Your key is managed by the extension.",
                                        ToastVariant::Warning,
                                    );
                                } else {
                                    confirm_nsec_open.set(true);
                                }
                            }
                            class=move || {
                                if auth.get().is_nip07 {
                                    "text-sm text-gray-500 border border-gray-600 rounded-lg px-4 py-2 transition-colors cursor-not-allowed opacity-60"
                                } else {
                                    "text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded-lg px-4 py-2 transition-colors"
                                }
                            }
                        >
                            {move || if auth.get().is_nip07 {
                                "Export Private Key (unavailable)"
                            } else {
                                "Export Private Key"
                            }}
                        </button>
                        <button
                            on:click=on_logout
                            class="text-sm text-gray-400 hover:text-white border border-gray-600 hover:border-gray-500 rounded-lg px-4 py-2 transition-colors hover:bg-gray-800"
                        >
                            "Logout"
                        </button>
                    </div>
                </div>

                // -- Section 6: About / Version (issue #27) --
                // BUILD_VERSION / BUILD_HASH come from window.__ENV__ injected
                // by the website deploy; fall back to dev/local so the row is
                // always meaningful, even in local Trunk serve builds.
                <div class="glass-card p-6 space-y-4" data-testid="settings-about">
                    <h2 class="text-lg font-semibold text-white flex items-center gap-2">
                        {info_icon()}
                        "About"
                    </h2>
                    <div class="border-t border-gray-700/50"></div>

                    <div>
                        <span class="text-xs text-gray-500 uppercase tracking-wide">"Build"</span>
                        <div class="bg-gray-800 rounded-lg px-3 py-2 mt-1">
                            <code class="text-xs text-amber-300 font-mono break-all" data-testid="build-version">
                                {move || format!("Build {} ({})", build_version(), build_hash())}
                            </code>
                        </div>
                        <p class="text-xs text-gray-500 mt-1">
                            "Use this to confirm whether a deployed build includes a given fix."
                        </p>
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

            // Confirm dialog for username release
            <ConfirmDialog
                is_open=confirm_release_open
                title="Release Username".to_string()
                message="This will release your username and free it for anyone else to claim. Your NIP-05 handle will stop resolving. You can claim a new username at any time.".to_string()
                confirm_label="Release".to_string()
                on_confirm=on_confirm_release
                variant=ConfirmVariant::Danger
            />
        </div>
    }
}

/// Spawn the async release-username flow and surface success/error toasts.
///
/// Extracted to a free function so that the `release_username` future is not
/// reified inside the event-handler closure (which would force `Send` bounds
/// the rest of the page does not satisfy).
fn spawn_local_release(
    pending: RwSignal<bool>,
    toasts_ok: crate::components::toast::ToastStore,
    toasts_err: crate::components::toast::ToastStore,
) {
    wasm_bindgen_futures::spawn_local(async move {
        match release_username().await {
            Ok(()) => {
                pending.set(false);
                toasts_ok.show("Username released", ToastVariant::Success);
            }
            Err(e) => {
                pending.set(false);
                toasts_err.show(format!("Release failed: {}", e), ToastVariant::Error);
            }
        }
    });
}

/// Build and publish the kind-0 profile metadata event, preserving every
/// field the Settings page manages (display name, claimed username + NIP-05,
/// about, picture, birthday).
///
/// The nickname is published as `display_name` ONLY — it is never a
/// username claim (QA HIGH bug #5a: saving "Carol QA" used to be
/// presented as a claimed handle, violating the [a-z0-9_-]{3,30}
/// rule and minting an invalid NIP-05). When a username IS claimed,
/// it keeps owning the `name` + `nip05` fields; username changes go
/// through the explicit, validated claim flow.
///
/// Shared by the Save Profile button, the picture upload flow, and the
/// picture Remove flow so kind-0 (a replaceable event) is always rebuilt
/// from the full field set and never clobbers sibling fields.
#[allow(clippy::too_many_arguments)]
fn publish_profile_metadata(
    auth: crate::auth::AuthStore,
    relay: RelayConnection,
    toasts: crate::components::toast::ToastStore,
    saving: RwSignal<bool>,
    name: String,
    claimed: Option<String>,
    bio: String,
    pic: String,
    bday: String,
    success_msg: &'static str,
) {
    let pubkey_hex = match auth.pubkey().get_untracked() {
        Some(pk) => pk,
        None => {
            toasts.show("Not authenticated", ToastVariant::Error);
            return;
        }
    };

    saving.set(true);

    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "display_name".into(),
        serde_json::Value::String(name.clone()),
    );
    match &claimed {
        Some(username) => {
            metadata.insert("name".into(), serde_json::Value::String(username.clone()));
            metadata.insert(
                "nip05".into(),
                serde_json::Value::String(format!("{}@{}", username, NIP05_USERNAME_HOST)),
            );
        }
        None => {
            // No claimed username: keep `name` mirroring the display name
            // for clients that only read `name`, but nothing here is ever
            // treated as a claimed handle.
            metadata.insert("name".into(), serde_json::Value::String(name.clone()));
        }
    }
    if !bio.is_empty() {
        metadata.insert("about".into(), serde_json::Value::String(bio));
    }
    if !pic.is_empty() {
        metadata.insert("picture".into(), serde_json::Value::String(pic.clone()));
    }
    if !bday.is_empty() {
        metadata.insert("birthday".into(), serde_json::Value::String(bday));
    }

    let content = serde_json::to_string(&serde_json::Value::Object(metadata)).unwrap_or_default();

    let unsigned = UnsignedEvent {
        pubkey: pubkey_hex,
        created_at: (js_sys::Date::now() / 1000.0) as u64,
        kind: 0,
        tags: vec![],
        content,
    };

    wasm_bindgen_futures::spawn_local(async move {
        match auth.sign_event_async(unsigned).await {
            Ok(signed) => {
                let name_for_ack = name.clone();
                let avatar_for_ack = if pic.is_empty() {
                    None
                } else {
                    Some(pic.clone())
                };
                let ack = Rc::new(move |accepted: bool, message: String| {
                    saving.set(false);
                    if accepted {
                        auth.set_profile(Some(name_for_ack.clone()), avatar_for_ack.clone());
                        toasts.show(success_msg, ToastVariant::Success);
                    } else {
                        toasts.show(
                            format!("Profile rejected: {}", message),
                            ToastVariant::Error,
                        );
                    }
                });
                if let Err(e) = relay.publish_with_ack(&signed, Some(ack)) {
                    saving.set(false);
                    toasts.show(format!("Publish failed: {}", e), ToastVariant::Error);
                }
            }
            Err(e) => {
                saving.set(false);
                toasts.show(format!("Failed to sign: {}", e), ToastVariant::Error);
            }
        }
    });
}

/// Derive a timestamped pod filename for an uploaded avatar from its MIME
/// type, e.g. `avatar-1765432100.png`. The timestamp busts client caches
/// when a user replaces their picture.
fn avatar_filename(mime: &str) -> String {
    let ext = match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/avif" => "avif",
        _ => "img",
    };
    format!("avatar-{}.{}", (js_sys::Date::now() / 1000.0) as u64, ext)
}

/// Provision the caller's Solid pod (`POST {POD_API}/.provision`, NIP-98
/// authed — the pod owner is the authed pubkey).
///
/// Pods are provisioned eagerly at signup; this mirrors
/// `pages::signup::provision_pod` for accounts that predate eager
/// provisioning. Called once when an avatar upload 404s, after which the
/// upload is retried. 201 = created, 409 = already exists; both are success.
async fn provision_pod(auth: crate::auth::AuthStore) -> Result<(), String> {
    let url = format!("{}/.provision", POD_API);
    let signer = auth.get_signer().ok_or("no signer")?;
    let token = crate::auth::nip98::create_nip98_token_with_signer(&*signer, &url, "POST", None)
        .await
        .map_err(|e| format!("nip98: {e}"))?;
    let win = web_sys::window().ok_or("no window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("{e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "bad response".to_string())?;
    match resp.status() {
        201 | 409 => Ok(()),
        s => Err(format!("HTTP {s}")),
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
fn handle_icon() -> impl IntoView {
    section_icon("M16 9a4 4 0 11-4-4M16 9v3a2 2 0 002 2M21 12a9 9 0 11-18 0 9 9 0 0118 0")
}
fn mute_icon() -> impl IntoView {
    section_icon("M1 1l22 22M9 9v3a3 3 0 005.12 2.12M15 9.34V4a3 3 0 00-5.94-.6M17 16.95A7 7 0 015 12v-2m14 0v2c0 .38-.03.75-.08 1.12M12 19v4M8 23h8")
}
fn privacy_icon() -> impl IntoView {
    section_icon("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z")
}
fn device_icon() -> impl IntoView {
    // Smartphone outline.
    section_icon("M7 2h10a2 2 0 012 2v16a2 2 0 01-2 2H7a2 2 0 01-2-2V4a2 2 0 012-2zM11 18h2")
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
fn git_icon() -> impl IntoView {
    section_icon("M6 3v12a3 3 0 003 3h6a3 3 0 003-3M6 3a3 3 0 016 0M6 3a3 3 0 00-3 3v12a3 3 0 003 3M18 9a3 3 0 100-6 3 3 0 000 6z")
}
fn info_icon() -> impl IntoView {
    // Circle-i info glyph.
    section_icon("M12 22a10 10 0 100-20 10 10 0 000 20zM12 16v-4M12 8h.01")
}
