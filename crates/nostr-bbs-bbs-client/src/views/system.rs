//! System views: Landing (`#/welcome`), Notifications (`#/notifications`),
//! Settings & Identity (`#/settings`), ADR-109 Rebind (`#/rebind`), and
//! Interactive Help (`#/help`).

use leptos::prelude::*;
use nostr_bbs_client_core::auth::{nip07, use_auth};
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::stores::custom_emoji::use_custom_emoji_store;
use nostr_bbs_client_core::stores::mute::use_mute_store;
use nostr_bbs_client_core::stores::notifications::use_notification_store;
use nostr_bbs_client_core::stores::preferences::{save_preferences, use_preferences};
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::{bake, devices};

use crate::components::{launch_sentry, qr_svg, AuthorChip, CopyKeyBtn, EmptyCard};
use crate::config::BbsConfig;
use crate::prefs::use_bbs_prefs;
use crate::pwa;
use crate::router::{use_router, Route};
use crate::theme::Theme;

/// Logged-out onboarding & welcome view (`#/welcome`).
#[component]
pub fn LandingView() -> impl IntoView {
    let cfg = expect_context::<BbsConfig>();
    let router = use_router();
    let auth = use_auth();
    let node_name = cfg.node_name.clone();
    let tagline = cfg.tagline.clone();
    let location = cfg.location.clone();

    view! {
        <div class="bbs-view bbs-landing">
            <section class="bbs-card bbs-hero-card">
                <div class="bbs-hero-kicker">{format!("NODE // {location}")}</div>
                <h1 class="bbs-hero-title">{node_name}</h1>
                <p class="bbs-hero-sub">{tagline}</p>

                <div class="bbs-hero-actions">
                    {move || if auth.is_authenticated().get() {
                        view! {
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-primary bbs-btn-lg"
                                on:click=move |_| router.go(Route::Zones)
                            >
                                "▶ ENTER FORUMS"
                            </button>
                        }.into_any()
                    } else {
                        view! {
                            <>
                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-primary bbs-btn-lg"
                                    on:click=move |_| router.go(Route::Settings)
                                >
                                    "SIGN IN"
                                </button>
                                <a href="../signup" class="bbs-btn bbs-btn-lg">
                                    "CREATE ACCOUNT"
                                </a>
                                <button
                                    type="button"
                                    class="bbs-btn bbs-btn-ghost bbs-btn-lg"
                                    on:click=move |_| router.go(Route::Zones)
                                >
                                    "BROWSE PUBLIC BOARDS"
                                </button>
                            </>
                        }.into_any()
                    }}
                </div>
            </section>

            <div class="bbs-grid">
                <article class="bbs-card">
                    <h2 class="bbs-card-title">"TERMINAL + MOBILE TUI"</h2>
                    <p class="bbs-card-desc">
                        "Full Nostr community client with encrypted zones, Kanban boards, calendar RSVPs, Colloquy knowledge base, Solid pods, and door games — tuned for keyboard and phone thumbs alike."
                    </p>
                </article>
                <article class="bbs-card">
                    <h2 class="bbs-card-title">"SHARED IDENTITY & CRYPTO"</h2>
                    <p class="bbs-card-desc">
                        "Sign in once with Passkey PRF, NIP-07 extension, or local key. Sessions, NIP-59 DMs, zone keys, and Sidestr wallets stay in lockstep with the main forum."
                    </p>
                </article>
            </div>
        </div>
    }
}

/// Notifications center (`#/notifications`).
#[component]
pub fn NotificationsView() -> impl IntoView {
    let notifs = use_notification_store();
    let router = use_router();

    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div>
                    <h1 class="bbs-view-title">"NOTIFICATIONS"</h1>
                    <p class="bbs-view-sub">
                        {move || format!("{} unread", notifs.unread_count().get())}
                    </p>
                </div>
                <div class="bbs-row-gap">
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-sm"
                        on:click=move |_| notifs.mark_all_read()
                    >
                        "MARK ALL READ"
                    </button>
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-ghost bbs-btn-sm"
                        on:click=move |_| notifs.clear_all()
                    >
                        "CLEAR"
                    </button>
                </div>
            </div>

            {move || {
                let items = notifs.items.get();
                if items.is_empty() {
                    return view! {
                        <EmptyCard
                            title="ALL CLEAR"
                            body="New replies, mentions, DMs, join approvals, and RSVPs will appear here."
                        />
                    }.into_any();
                }
                view! {
                    <div class="bbs-stack">
                        {items.into_iter().map(|n| {
                            let id = n.id.clone();
                            let link = n.link.clone();
                            let unread = !n.read;
                            let cls = if unread { "bbs-card bbs-notif-unread" } else { "bbs-card" };
                            let ts = format_ts(n.timestamp);
                            view! {
                                <div class=cls>
                                    <div class="bbs-card-head">
                                        <strong>{n.title}</strong>
                                        <span class="bbs-muted">{ts}</span>
                                    </div>
                                    <p class="bbs-card-desc">{n.body}</p>
                                    <div class="bbs-row-gap">
                                        {unread.then(|| {
                                            let id_mark = id.clone();
                                            view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-sm"
                                                    on:click=move |_| notifs.mark_read(&id_mark)
                                                >
                                                    "MARK READ"
                                                </button>
                                            }
                                        })}
                                        {link.map(|l| {
                                            let id_open = id.clone();
                                            let target_route = route_from_forum_link(&l);
                                            view! {
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-primary bbs-btn-sm"
                                                    on:click=move |_| {
                                                        notifs.mark_read(&id_open);
                                                        router.go(target_route.clone());
                                                    }
                                                >
                                                    "OPEN →"
                                                </button>
                                            }
                                        })}
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

/// Settings, Display, Identity, Custom Emoji, Mutes, Device Keys, and PWA install (`#/settings`).
#[component]
pub fn SettingsView() -> impl IntoView {
    let cfg = expect_context::<BbsConfig>();
    let auth = use_auth();
    let prefs = use_bbs_prefs();
    let app_prefs = use_preferences();
    let toasts = use_toasts();
    let custom_emoji = use_custom_emoji_store();
    let mutes = use_mute_store();
    let relay = expect_context::<RelayConnection>();

    // Auth forms
    let key_input: RwSignal<String> = RwSignal::new(String::new());
    let remember_me: RwSignal<bool> = RwSignal::new(true);
    let passkey_busy: RwSignal<bool> = RwSignal::new(false);
    let auth_err: RwSignal<Option<String>> = RwSignal::new(None);
    let generated_secret: RwSignal<Option<String>> = RwSignal::new(None);
    let gen_name: RwSignal<String> = RwSignal::new(String::new());

    // Custom emoji input
    let emoji_input: RwSignal<String> = RwSignal::new(String::new());

    // Revocable device keys (ADR-099)
    let dev_enabled = devices::device_keys_enabled();
    let dev_list: RwSignal<Vec<devices::DeviceKey>> = RwSignal::new(Vec::new());
    let dev_label: RwSignal<String> = RwSignal::new("Phone".into());
    let dev_created: RwSignal<Option<devices::RegisteredDevice>> = RwSignal::new(None);
    let dev_busy: RwSignal<bool> = RwSignal::new(false);

    // PWA baked status
    let is_baked: RwSignal<bool> = RwSignal::new(false);
    let pwa_enabled = cfg.pwa_enabled;
    let first_zone_id = cfg
        .zones
        .first()
        .map(|z| z.id.clone())
        .unwrap_or_else(|| "public".into());
    let relay_url_str = cfg.relay_url.clone();
    let pod_api_str = cfg.pod_api.clone();

    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(async move {
            is_baked.set(bake::is_baked().await);
        });
    }

    let load_devices = move || {
        if !dev_enabled || !auth.is_authenticated().get_untracked() {
            return;
        }
        dev_busy.set(true);
        wasm_bindgen_futures::spawn_local(async move {
            match devices::list_devices(auth).await {
                Ok(list) => dev_list.set(list),
                Err(e) => toasts.show(format!("Devices: {e}"), ToastVariant::Error),
            }
            dev_busy.set(false);
        });
    };

    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div>
                    <h1 class="bbs-view-title">"SETTINGS"</h1>
                    <p class="bbs-view-sub">"Display phosphor, CRT effects, identity, custom emoji, and device controls."</p>
                </div>
            </div>

            // 1. Display & Retro Theme
            <section class="bbs-card bbs-stack">
                <h2 class="bbs-section-title">"DISPLAY & PHOSPHOR"</h2>

                <div class="bbs-row-wrap">
                    {Theme::all()
                        .into_iter()
                        .map(|t| {
                            let label = t.label().to_uppercase();
                            view! {
                                <button
                                    type="button"
                                    class=move || if prefs.theme.get() == t { "bbs-pill bbs-pill-active" } else { "bbs-pill" }
                                    on:click=move |_| prefs.theme.set(t)
                                >
                                    {label}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>

                <div class="bbs-toggle-grid">
                    <button
                        type="button"
                        class=move || if prefs.crt_effects.get() { "bbs-btn bbs-btn-primary" } else { "bbs-btn" }
                        on:click=move |_| prefs.toggle_crt()
                    >
                        {move || if prefs.crt_effects.get() { "CRT SCANLINES: ON" } else { "CRT SCANLINES: OFF" }}
                    </button>

                    <button
                        type="button"
                        class=move || if prefs.text_large.get() { "bbs-btn bbs-btn-primary" } else { "bbs-btn" }
                        on:click=move |_| prefs.text_large.update(|v| *v = !*v)
                    >
                        {move || if prefs.text_large.get() { "TEXT SIZE: LARGE" } else { "TEXT SIZE: NORMAL" }}
                    </button>

                    <button
                        type="button"
                        class=move || if prefs.reduced_motion.get() { "bbs-btn bbs-btn-primary" } else { "bbs-btn" }
                        on:click=move |_| prefs.reduced_motion.update(|v| *v = !*v)
                    >
                        {move || if prefs.reduced_motion.get() { "MOTION: REDUCED" } else { "MOTION: FULL" }}
                    </button>

                    <button
                        type="button"
                        class=move || if app_prefs.with(|p| p.poker_table) { "bbs-btn bbs-btn-primary" } else { "bbs-btn" }
                        on:click=move |_| {
                            app_prefs.update(|p| p.poker_table = !p.poker_table);
                            save_preferences(&app_prefs.get_untracked());
                        }
                    >
                        {move || if app_prefs.with(|p| p.poker_table) { "POKER TABLE: ON" } else { "POKER TABLE: OFF" }}
                    </button>
                </div>
            </section>

            // 2. Account & Sign-in
            <section class="bbs-card bbs-stack">
                <h2 class="bbs-section-title">"ACCOUNT & IDENTITY"</h2>

                {move || match auth.pubkey().get() {
                    Some(pk) => {
                        let st = auth.get();
                        let npub = nostr_bbs_core::encode_npub(&pk).unwrap_or_else(|_| pk.clone());
                        let mode = if st.is_nip07 {
                            format!("NIP-07 ({})", st.extension_name.unwrap_or_else(|| "extension".into()))
                        } else if st.is_passkey {
                            "WebAuthn Passkey PRF".to_string()
                        } else {
                            "Local Key".to_string()
                        };
                        let z_bake = first_zone_id.clone();
                        view! {
                            <div class="bbs-stack">
                                <div class="bbs-kv-list">
                                    <div class="bbs-kv-row">
                                        <span class="bbs-label">"SIGNER"</span>
                                        <span>{mode}</span>
                                    </div>
                                    <div class="bbs-kv-row">
                                        <span class="bbs-label">"NPUB"</span>
                                        <code class="bbs-mono-xs bbs-truncate">{npub.clone()}</code>
                                        <CopyKeyBtn full=npub label="COPY"/>
                                    </div>
                                    <div class="bbs-kv-row">
                                        <span class="bbs-label">"HEX"</span>
                                        <code class="bbs-mono-xs bbs-truncate">{pk.clone()}</code>
                                        <CopyKeyBtn full=pk label="COPY"/>
                                    </div>
                                </div>

                                <div class="bbs-row-wrap">
                                    <a href="../" class="bbs-btn bbs-btn-sm">"OPEN MAIN FORUM ↗"</a>
                                    {pwa_enabled.then(move || {
                                        let zb = z_bake.clone();
                                        view! {
                                            <>
                                                <button
                                                    type="button"
                                                    class="bbs-btn bbs-btn-sm"
                                                    on:click=move |_| {
                                                        let zb = zb.clone();
                                                        wasm_bindgen_futures::spawn_local(async move {
                                                            let Some(sk) = auth.get_privkey_bytes() else {
                                                                toasts.show("Baking requires a local or passkey session.", ToastVariant::Error);
                                                                return;
                                                            };
                                                            match bake::bake(&sk, &zb).await {
                                                                Ok(()) => {
                                                                    is_baked.set(true);
                                                                    toasts.show("Device key baked for one-shot PWA boot.", ToastVariant::Success);
                                                                }
                                                                Err(e) => toasts.show(format!("Bake failed: {e}"), ToastVariant::Error),
                                                            }
                                                        });
                                                    }
                                                >
                                                    {move || if is_baked.get() { "RE-BAKE DEVICE KEY" } else { "BAKE FOR PWA" }}
                                                </button>
                                                {move || is_baked.get().then(|| view! {
                                                    <button
                                                        type="button"
                                                        class="bbs-btn bbs-btn-danger bbs-btn-sm"
                                                        on:click=move |_| {
                                                            wasm_bindgen_futures::spawn_local(async move {
                                                                let _ = bake::unbake().await;
                                                                is_baked.set(false);
                                                                toasts.show("Device key forgotten.", ToastVariant::Success);
                                                            });
                                                        }
                                                    >
                                                        "FORGET THIS DEVICE"
                                                    </button>
                                                })}
                                            </>
                                        }
                                    })}
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-danger bbs-btn-sm"
                                        on:click=move |_| {
                                            auth.logout();
                                            toasts.show("Signed out.", ToastVariant::Info);
                                        }
                                    >
                                        "SIGN OUT"
                                    </button>
                                </div>
                            </div>
                        }.into_any()
                    }
                    None => {
                        let has_ext = nip07::has_nip07_extension();
                        view! {
                            <div class="bbs-stack">
                                <div class="bbs-row-wrap">
                                    {has_ext.then(|| view! {
                                        <button
                                            type="button"
                                            class="bbs-btn bbs-btn-primary"
                                            on:click=move |_| {
                                                auth_err.set(None);
                                                wasm_bindgen_futures::spawn_local(async move {
                                                    if let Err(e) = auth.login_with_nip07().await {
                                                        auth_err.set(Some(e));
                                                    } else {
                                                        toasts.show("Signed in with NIP-07 extension.", ToastVariant::Success);
                                                    }
                                                });
                                            }
                                        >
                                            "SIGN IN WITH EXTENSION (NIP-07)"
                                        </button>
                                    })}
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-primary"
                                        disabled=move || passkey_busy.get()
                                        on:click=move |_| {
                                            auth_err.set(None);
                                            passkey_busy.set(true);
                                            wasm_bindgen_futures::spawn_local(async move {
                                                match auth.login_with_passkey(None).await {
                                                    Ok(()) => toasts.show("Signed in with Passkey.", ToastVariant::Success),
                                                    Err(e) => auth_err.set(Some(e)),
                                                }
                                                passkey_busy.set(false);
                                            });
                                        }
                                    >
                                        {move || if passkey_busy.get() { "WAITING FOR PASSKEY..." } else { "SIGN IN WITH PASSKEY" }}
                                    </button>
                                    <a href="../signup" class="bbs-btn">"FULL SIGNUP ↗"</a>
                                </div>

                                <div class="bbs-divider"></div>

                                <label class="bbs-field">
                                    <span class="bbs-label">"PASTE RECOVERY KEY (NSEC1... OR 64-HEX)"</span>
                                    <input
                                        type="password"
                                        class="bbs-input"
                                        placeholder="nsec1..."
                                        prop:value=move || key_input.get()
                                        on:input=move |ev| key_input.set(event_target_value(&ev))
                                    />
                                </label>
                                <div class="bbs-row-wrap">
                                    <label class="bbs-check-row">
                                        <input
                                            type="checkbox"
                                            prop:checked=move || remember_me.get()
                                            on:change=move |ev| remember_me.set(event_target_checked(&ev))
                                        />
                                        <span>"Stay signed in on this device"</span>
                                    </label>
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-primary"
                                        on:click=move |_| {
                                            auth_err.set(None);
                                            auth.set_remember_me(remember_me.get_untracked());
                                            let raw = key_input.get_untracked();
                                            match auth.login_with_local_key(&raw) {
                                                Ok(()) => {
                                                    key_input.set(String::new());
                                                    toasts.show("Signed in with key.", ToastVariant::Success);
                                                }
                                                Err(e) => auth_err.set(Some(e)),
                                            }
                                        }
                                    >
                                        "SIGN IN WITH KEY"
                                    </button>
                                </div>

                                <div class="bbs-divider"></div>

                                <div class="bbs-row-wrap">
                                    <input
                                        type="text"
                                        class="bbs-input bbs-flex-1"
                                        placeholder="Display name for throwaway key"
                                        prop:value=move || gen_name.get()
                                        on:input=move |ev| gen_name.set(event_target_value(&ev))
                                    />
                                    <button
                                        type="button"
                                        class="bbs-btn"
                                        on:click=move |_| {
                                            auth_err.set(None);
                                            let name = gen_name.get_untracked();
                                            let label = if name.trim().is_empty() { "Anon" } else { name.trim() };
                                            match auth.register_with_generated_key(label) {
                                                Ok(hex_sk) => {
                                                    let nsec = nostr_bbs_core::encode_nsec(&hex_sk).unwrap_or(hex_sk);
                                                    generated_secret.set(Some(nsec));
                                                    toasts.show("Generated new keypair — back up your nsec now!", ToastVariant::Success);
                                                }
                                                Err(e) => auth_err.set(Some(e)),
                                            }
                                        }
                                    >
                                        "GENERATE KEYPAIR"
                                    </button>
                                </div>

                                {move || auth_err.get().map(|e| view! { <div class="bbs-alert bbs-alert-err">{e}</div> })}
                            </div>
                        }.into_any()
                    }
                }}

                // One-time backup sheet for freshly generated key
                {move || generated_secret.get().map(|nsec| view! {
                    <div class="bbs-alert bbs-alert-warn bbs-stack">
                        <strong>"ONE-TIME RECOVERY KEY — SAVE NOW"</strong>
                        <p>"This secret will not be shown again once dismissed."</p>
                        <div class="bbs-row-wrap">
                            <code class="bbs-mono-xs bbs-truncate">{nsec.clone()}</code>
                            <CopyKeyBtn full=nsec.clone() label="COPY NSEC"/>
                        </div>
                        {qr_svg(&nsec).map(|svg| view! { <div class="bbs-qr-wrap" inner_html=svg></div> })}
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm"
                            on:click=move |_| generated_secret.set(None)
                        >
                            "I HAVE SAVED THIS KEY"
                        </button>
                    </div>
                })}
            </section>

            // 3. Install PWA prompt (when captured by browser)
            {#[cfg(target_arch = "wasm32")]
            {
                pwa_enabled.then(|| view! {
                    {move || pwa::installable().get().then(|| view! {
                        <section class="bbs-card bbs-row-wrap">
                            <div class="bbs-flex-1">
                                <strong>"INSTALL RETRO BBS APP"</strong>
                                <p class="bbs-muted">"Add to your home screen for one-shot mobile launch."</p>
                            </div>
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-primary"
                                on:click=move |_| {
                                    wasm_bindgen_futures::spawn_local(async move {
                                        let _ = pwa::prompt_install().await;
                                    });
                                }
                            >
                                "INSTALL APP"
                            </button>
                        </section>
                    })}
                })
            }}

            // 4. Revocable Device Keys (ADR-099)
            {move || (dev_enabled && auth.is_authenticated().get()).then(|| view! {
                <section class="bbs-card bbs-stack">
                    <div class="bbs-card-head">
                        <h2 class="bbs-section-title">"REVOCABLE DEVICE KEYS"</h2>
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm"
                            disabled=move || dev_busy.get()
                            on:click=move |_| load_devices()
                        >
                            "↻ LOAD DEVICES"
                        </button>
                    </div>
                    <div class="bbs-row-wrap">
                        <input
                            type="text"
                            class="bbs-input bbs-flex-1"
                            placeholder="Device label (e.g. My phone)"
                            prop:value=move || dev_label.get()
                            on:input=move |ev| dev_label.set(event_target_value(&ev))
                        />
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-primary"
                            disabled=move || dev_busy.get()
                            on:click=move |_| {
                                let lbl = dev_label.get_untracked();
                                dev_busy.set(true);
                                wasm_bindgen_futures::spawn_local(async move {
                                    match devices::register_device(auth, &lbl).await {
                                        Ok(reg) => {
                                            dev_created.set(Some(reg));
                                            toasts.show("Device key registered.", ToastVariant::Success);
                                        }
                                        Err(e) => toasts.show(format!("Register failed: {e}"), ToastVariant::Error),
                                    }
                                    dev_busy.set(false);
                                });
                            }
                        >
                            "+ REGISTER DEVICE"
                        </button>
                    </div>
                    {move || dev_created.get().map(|reg| view! {
                        <div class="bbs-alert bbs-stack">
                            <strong>"NEW DEVICE KEY (SCAN OR COPY ON PHONE)"</strong>
                            <div class="bbs-row-wrap">
                                <code class="bbs-mono-xs bbs-truncate">{reg.device_nsec.clone()}</code>
                                <CopyKeyBtn full=reg.device_nsec.clone() label="COPY"/>
                            </div>
                            {qr_svg(&reg.device_nsec).map(|svg| view! { <div class="bbs-qr-wrap" inner_html=svg></div> })}
                        </div>
                    })}
                    {move || {
                        let list = dev_list.get();
                        (!list.is_empty()).then(|| view! {
                            <ul class="bbs-list">
                                {list.into_iter().map(|d| {
                                    let dpk = d.device_pubkey.clone();
                                    let active = d.is_active();
                                    let lbl = d.label.unwrap_or_else(|| "Device".into());
                                    view! {
                                        <li class="bbs-list-row">
                                            <span class="bbs-flex-1">{format!("{lbl} ({}…)", &dpk[..dpk.len().min(10)])}</span>
                                            {if active {
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="bbs-btn bbs-btn-danger bbs-btn-sm"
                                                        on:click=move |_| {
                                                            let target = dpk.clone();
                                                            wasm_bindgen_futures::spawn_local(async move {
                                                                match devices::revoke_device(auth, &target).await {
                                                                    Ok(()) => {
                                                                        toasts.show("Device revoked.", ToastVariant::Success);
                                                                        dev_list.update(|l| {
                                                                            if let Some(x) = l.iter_mut().find(|x| x.device_pubkey == target) {
                                                                                x.revoked = 1;
                                                                            }
                                                                        });
                                                                    }
                                                                    Err(e) => toasts.show(format!("Revoke failed: {e}"), ToastVariant::Error),
                                                                }
                                                            });
                                                        }
                                                    >
                                                        "REVOKE"
                                                    </button>
                                                }.into_any()
                                            } else {
                                                view! { <span class="bbs-badge bbs-badge-danger">"REVOKED"</span> }.into_any()
                                            }}
                                        </li>
                                    }
                                }).collect_view()}
                            </ul>
                        })
                    }}
                </section>
            })}

            // 5. Custom Reaction Emoji
            <section class="bbs-card bbs-stack">
                <h2 class="bbs-section-title">"CUSTOM REACTION EMOJI"</h2>
                <div class="bbs-row-wrap">
                    <input
                        type="text"
                        class="bbs-input"
                        placeholder="Add emoji (e.g. 🛸)"
                        prop:value=move || emoji_input.get()
                        on:input=move |ev| emoji_input.set(event_target_value(&ev))
                    />
                    <button
                        type="button"
                        class="bbs-btn bbs-btn-primary"
                        on:click=move |_| {
                            let val = emoji_input.get_untracked();
                            if custom_emoji.add(&val) {
                                emoji_input.set(String::new());
                            }
                        }
                    >
                        "+ ADD"
                    </button>
                </div>
                <div class="bbs-row-wrap">
                    {move || custom_emoji.emojis().into_iter().map(|e| {
                        let e_rm = e.clone();
                        view! {
                            <button
                                type="button"
                                class="bbs-pill"
                                title="Click to remove"
                                on:click=move |_| custom_emoji.remove(&e_rm)
                            >
                                {format!("{e} ×")}
                            </button>
                        }
                    }).collect_view()}
                </div>
            </section>

            // 6. Muted Users
            <section class="bbs-card bbs-stack">
                <h2 class="bbs-section-title">"MUTED USERS"</h2>
                {move || {
                    let muted = mutes.muted_user_pubkeys();
                    if muted.is_empty() {
                        view! { <p class="bbs-muted">"No muted users."</p> }.into_any()
                    } else {
                        view! {
                            <ul class="bbs-list">
                                {muted.into_iter().map(|pk| {
                                    let pk_unmute = pk.clone();
                                    view! {
                                        <li class="bbs-list-row">
                                            <AuthorChip pubkey=pk/>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                on:click=move |_| { mutes.toggle_mute_user(&pk_unmute); }
                                            >
                                                "UNMUTE"
                                            </button>
                                        </li>
                                    }
                                }).collect_view()}
                            </ul>
                        }.into_any()
                    }
                }}
            </section>

            // 7. Diagnostics
            <section class="bbs-card bbs-stack">
                <h2 class="bbs-section-title">"NODE DIAGNOSTICS"</h2>
                <div class="bbs-kv-list">
                    <div class="bbs-kv-row">
                        <span class="bbs-label">"RELAY"</span>
                        <code class="bbs-mono-xs bbs-truncate">{relay_url_str}</code>
                    </div>
                    <div class="bbs-kv-row">
                        <span class="bbs-label">"STATE"</span>
                        <span>{move || format!("{:?}", relay.connection_state().get())}</span>
                    </div>
                    <div class="bbs-kv-row">
                        <span class="bbs-label">"POD API"</span>
                        <code class="bbs-mono-xs bbs-truncate">{pod_api_str}</code>
                    </div>
                </div>
            </section>
        </div>
    }
}

/// ADR-109 iOS one-shot PWA rebind view (`#/rebind`).
#[component]
pub fn RebindView() -> impl IntoView {
    let cfg = expect_context::<BbsConfig>();
    let auth = use_auth();
    let router = use_router();
    let toasts = use_toasts();

    let key_input: RwSignal<String> = RwSignal::new(String::new());
    let err_msg: RwSignal<Option<String>> = RwSignal::new(None);
    let busy: RwSignal<bool> = RwSignal::new(false);

    let zone_idx = pwa::resolve_boot_zone_index(&cfg.boot_profile, &cfg.zones);
    let zone_id = zone_idx
        .and_then(|i| cfg.zones.get(i))
        .map(|z| z.id.clone())
        .unwrap_or_else(|| "public".into());
    let zone_slug_str = zone_idx
        .and_then(|i| cfg.zones.get(i))
        .map(|z| z.slug.as_deref().unwrap_or(&z.id).to_string())
        .unwrap_or_else(|| zone_id.clone());

    let z_passkey = zone_id.clone();
    let slug_passkey = zone_slug_str.clone();
    let z_paste = zone_id.clone();
    let slug_paste = zone_slug_str.clone();

    view! {
        <div class="bbs-view">
            <section class="bbs-card bbs-stack">
                <h1 class="bbs-view-title">"ONE-TIME APP REBIND"</h1>
                <p class="bbs-view-sub">
                    "Installed home-screen apps on iOS start with an isolated storage partition. Authenticate once here to bake your key into this app for one-shot launch."
                </p>

                <button
                    type="button"
                    class="bbs-btn bbs-btn-primary"
                    disabled=move || busy.get()
                    on:click=move |_| {
                        let zb = z_passkey.clone();
                        let sl = slug_passkey.clone();
                        err_msg.set(None);
                        busy.set(true);
                        wasm_bindgen_futures::spawn_local(async move {
                            match auth.login_with_passkey(None).await {
                                Ok(()) => {
                                    if let Some(sk) = auth.get_privkey_bytes() {
                                        let _ = bake::bake(&sk, &zb).await;
                                    }
                                    toasts.show("Rebind complete!", ToastVariant::Success);
                                    router.enter_pwa(sl);
                                }
                                Err(e) => err_msg.set(Some(e)),
                            }
                            busy.set(false);
                        });
                    }
                >
                    "REBIND WITH PASSKEY"
                </button>

                <div class="bbs-divider"></div>

                <label class="bbs-field">
                    <span class="bbs-label">"OR PASTE RECOVERY KEY (NSEC1... / 64-HEX)"</span>
                    <input
                        type="password"
                        class="bbs-input"
                        placeholder="nsec1..."
                        prop:value=move || key_input.get()
                        on:input=move |ev| key_input.set(event_target_value(&ev))
                    />
                </label>

                <button
                    type="button"
                    class="bbs-btn bbs-btn-primary"
                    disabled=move || busy.get()
                    on:click=move |_| {
                        let zb = z_paste.clone();
                        let sl = slug_paste.clone();
                        let raw = key_input.get_untracked();
                        err_msg.set(None);
                        busy.set(true);
                        wasm_bindgen_futures::spawn_local(async move {
                            match auth.login_with_local_key(&raw) {
                                Ok(()) => {
                                    if let Some(sk) = auth.get_privkey_bytes() {
                                        let _ = bake::bake(&sk, &zb).await;
                                    }
                                    key_input.set(String::new());
                                    toasts.show("Rebind complete!", ToastVariant::Success);
                                    router.enter_pwa(sl);
                                }
                                Err(e) => err_msg.set(Some(e)),
                            }
                            busy.set(false);
                        });
                    }
                >
                    "REBIND & BAKE KEY"
                </button>

                {move || err_msg.get().map(|e| view! { <div class="bbs-alert bbs-alert-err">{e}</div> })}
            </section>
        </div>
    }
}

/// Interactive Help, Slash Commands, and Keybindings reference (`#/help`).
#[component]
pub fn HelpView() -> impl IntoView {
    view! {
        <div class="bbs-view">
            <div class="bbs-view-head">
                <div>
                    <h1 class="bbs-view-title">"HELP & COMMANDS"</h1>
                    <p class="bbs-view-sub">"Keyboard shortcuts, slash commands, and terminal features."</p>
                </div>
                <button
                    type="button"
                    class="bbs-btn bbs-btn-primary bbs-btn-sm"
                    on:click=move |_| launch_sentry()
                >
                    "▶ UA 571-C SENTRY"
                </button>
            </div>

            <div class="bbs-grid">
                <section class="bbs-card bbs-stack">
                    <h2 class="bbs-section-title">"KEYBOARD SHORTCUTS"</h2>
                    <div class="bbs-kv-list">
                        <div class="bbs-kv-row"><code>"/"</code><span>"Focus slash command bar"</span></div>
                        <div class="bbs-kv-row"><code>"Ctrl/Cmd + K"</code><span>"Open global & sealed search"</span></div>
                        <div class="bbs-kv-row"><code>"g z"</code><span>"Go to Zones"</span></div>
                        <div class="bbs-kv-row"><code>"g l"</code><span>"Go to Live Feed"</span></div>
                        <div class="bbs-kv-row"><code>"g m"</code><span>"Go to Direct Messages"</span></div>
                        <div class="bbs-kv-row"><code>"g a"</code><span>"Go to Agent Governance"</span></div>
                        <div class="bbs-kv-row"><code>"g g"</code><span>"Go to Door Games"</span></div>
                        <div class="bbs-kv-row"><code>"g w"</code><span>"Go to Sidestr Wallet"</span></div>
                        <div class="bbs-kv-row"><code>"g p"</code><span>"Go to Solid Pod"</span></div>
                        <div class="bbs-kv-row"><code>"?"</code><span>"Open this Help screen"</span></div>
                        <div class="bbs-kv-row"><code>"Esc"</code><span>"Close drawer / search / command bar"</span></div>
                    </div>
                </section>

                <section class="bbs-card bbs-stack">
                    <h2 class="bbs-section-title">"SLASH COMMANDS"</h2>
                    <div class="bbs-kv-list">
                        <div class="bbs-kv-row"><code>"/zones"</code><span>"List all community zones"</span></div>
                        <div class="bbs-kv-row"><code>"/live"</code><span>"Cross-board live post feed"</span></div>
                        <div class="bbs-kv-row"><code>"/dm"</code><span>"Encrypted direct messages"</span></div>
                        <div class="bbs-kv-row"><code>"/agents"</code><span>"Governance inbox & panels"</span></div>
                        <div class="bbs-kv-row"><code>"/games"</code><span>"Door Games hub"</span></div>
                        <div class="bbs-kv-row"><code>"/poker"</code><span>"Practice Hold'em poker table"</span></div>
                        <div class="bbs-kv-row"><code>"/wallet"</code><span>"Sidestr multi-chain wallet"</span></div>
                        <div class="bbs-kv-row"><code>"/pod"</code><span>"Authenticated Solid Pod & Git"</span></div>
                        <div class="bbs-kv-row"><code>"/members"</code><span>"Member directory & badges"</span></div>
                        <div class="bbs-kv-row"><code>"/bookmarks"</code><span>"Saved posts"</span></div>
                        <div class="bbs-kv-row"><code>"/theme"</code><span>"Cycle phosphor palette"</span></div>
                        <div class="bbs-kv-row"><code>"/crt"</code><span>"Toggle CRT scanline overlay"</span></div>
                        <div class="bbs-kv-row"><code>"/sentry"</code><span>"Launch UA 571-C Sentry Gun"</span></div>
                    </div>
                </section>
            </div>
        </div>
    }
}

fn route_from_forum_link(link: &str) -> Route {
    let trimmed = link.trim_start_matches('/');
    if let Some(pk) = trimmed.strip_prefix("dm/") {
        return Route::DmChat {
            pubkey: pk.to_string(),
        };
    }
    if let Some(rest) = trimmed.strip_prefix("channels/") {
        let mut parts = rest.split('/');
        if let Some(ch) = parts.next() {
            return Route::Board {
                zone: "public".into(),
                channel_id: ch.to_string(),
            };
        }
    }
    if trimmed.starts_with("governance") {
        return Route::Agents;
    }
    Route::LiveFeed
}

fn format_ts(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    #[cfg(target_arch = "wasm32")]
    {
        let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((secs as f64) * 1000.0));
        format!("{:02}:{:02}", d.get_hours(), d.get_minutes())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        format!("{secs}s")
    }
}
