//! Member Directory & Rich Profile View (did:nostr, WebID, NIP-58 badges,
//! mute/DM actions, and in-BBS non-clobbering kind-0 profile editing).

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::RelayConnection;
use nostr_bbs_client_core::stores::badges::{badge_def, use_badges};
use nostr_bbs_client_core::stores::mute::use_mute_store;
use nostr_bbs_client_core::stores::profile_cache::try_use_profile_cache;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::shorten_pubkey;
use nostr_bbs_core::event::UnsignedEvent;

use crate::components::{CopyKeyBtn, EmptyCard};
use crate::config::BbsConfig;
use crate::identity::Identity;
use crate::router::{use_router, Route};

/// Member roster (`#/members`).
#[component]
pub fn MembersView() -> impl IntoView {
    let router = use_router();
    let filter = RwSignal::new(String::new());

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"● Members"</h1>
                    <p class="tui-page-sub">"Community directory — did:nostr identities & Solid WebIDs."</p>
                </div>
            </div>

            <input
                class="bbs-input"
                type="search"
                placeholder="Filter members by name, NIP-05, or pubkey…"
                prop:value=move || filter.get()
                on:input=move |ev| filter.set(event_target_value(&ev))
            />

            {move || {
                let Some(pc) = try_use_profile_cache() else {
                    return view! { <EmptyCard title="Loading directory…" body="Waiting for profile cache." /> }.into_any();
                };
                let q = filter.get().trim().to_ascii_lowercase();
                let mut list: Vec<_> = pc
                    .entries
                    .get()
                    .into_iter()
                    .filter(|(pk, e)| {
                        if q.is_empty() {
                            return true;
                        }
                        e.best_label()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(&q)
                            || pk.to_ascii_lowercase().contains(&q)
                    })
                    .collect();
                list.sort_by(|a, b| {
                    a.1.best_label()
                        .unwrap_or_else(|| a.0.clone())
                        .to_lowercase()
                        .cmp(&b.1.best_label().unwrap_or_else(|| b.0.clone()).to_lowercase())
                });

                if list.is_empty() {
                    return view! {
                        <EmptyCard
                            title="No members matched"
                            body="Profiles (kind-0) populate as you browse boards or when the relay streams metadata."
                        />
                    }.into_any();
                }

                view! {
                    <div class="tui-grid">
                        {list.into_iter().take(120).map(|(pk, entry)| {
                            let label = entry.best_label().unwrap_or_else(|| shorten_pubkey(&pk));
                            let about = entry.about.clone().unwrap_or_default();
                            let pk_go = pk.clone();
                            view! {
                                <div
                                    class="tui-card tui-card-interactive tui-stack"
                                    role="button"
                                    tabindex="0"
                                    on:click=move |_| router.go(Route::Profile { pubkey: pk_go.clone() })
                                >
                                    <div class="tui-row-between">
                                        <strong>"● " {label}</strong>
                                        <span class="tui-muted" style="font-size:0.78rem">{shorten_pubkey(&pk)}</span>
                                    </div>
                                    {(!about.is_empty()).then(|| view! {
                                        <p class="tui-muted" style="font-size:0.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                                            {about}
                                        </p>
                                    })}
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

/// Single member profile (`#/profile/<pubkey>`), with edit mode when viewing yourself.
#[component]
pub fn ProfileView(pubkey: String) -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let badges = use_badges();
    let mute = use_mute_store();
    let toasts = use_toasts();
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("BbsConfig");
    let pod_api = cfg.with_value(|c| c.pod_api.clone());

    let pk_badge = pubkey.clone();
    Effect::new(move |_| {
        badges.fetch_for_pubkey(&pk_badge);
    });

    let editing = RwSignal::new(false);
    let edit_name = RwSignal::new(String::new());
    let edit_about = RwSignal::new(String::new());
    let saving = RwSignal::new(false);

    let pk_view = pubkey.clone();
    let pk_save = pubkey.clone();

    let save_profile = move |_| {
        let Some(signer) = auth.get_signer() else {
            return;
        };
        let dn = edit_name.get_untracked().trim().to_string();
        let ab = edit_about.get_untracked().trim().to_string();
        // Non-clobbering kind-0 merge: preserve existing fields from ProfileCache
        let existing = try_use_profile_cache().and_then(|pc| pc.lookup(&pk_save));
        let mut obj = serde_json::Map::new();
        if let Some(ex) = existing {
            if let Some(n) = ex.name {
                obj.insert("name".into(), serde_json::Value::String(n));
            }
            if let Some(pic) = ex.picture {
                obj.insert("picture".into(), serde_json::Value::String(pic));
            }
            if let Some(n05) = ex.nip05 {
                obj.insert("nip05".into(), serde_json::Value::String(n05));
            }
        }
        if !dn.is_empty() {
            obj.insert("display_name".into(), serde_json::Value::String(dn.clone()));
            obj.entry("name")
                .or_insert_with(|| serde_json::Value::String(dn.clone()));
        }
        obj.insert("about".into(), serde_json::Value::String(ab.clone()));
        let content = serde_json::Value::Object(obj).to_string();

        let unsigned = UnsignedEvent {
            pubkey: signer.public_key().to_string(),
            created_at: (js_sys::Date::now() / 1000.0) as u64,
            kind: 0,
            tags: vec![],
            content: content.clone(),
        };
        saving.set(true);
        let relay = relay.clone();
        let pk_up = pk_save.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match signer.sign_event(unsigned).await {
                Ok(signed) => {
                    let ts = signed.created_at;
                    relay.publish(&signed);
                    if let Some(pc) = try_use_profile_cache() {
                        pc.upsert_from_kind0(&pk_up, &content, ts);
                    }
                    editing.set(false);
                    toasts.show("Profile updated (kind-0)", ToastVariant::Success);
                }
                Err(e) => toasts.show(format!("Profile sign failed: {e}"), ToastVariant::Error),
            }
            saving.set(false);
        });
    };

    view! {
        <div class="tui-container">
            <div class="tui-crumb">
                <button type="button" class="bbs-btn bbs-btn-ghost bbs-btn-sm" on:click=move |_| router.go(Route::Members)>
                    "← Members"
                </button>
                <span>"/"</span>
                <strong>"Profile"</strong>
            </div>

            {move || {
                let entry = try_use_profile_cache().and_then(|pc| pc.lookup_reactive(&pk_view));
                let name = entry
                    .as_ref()
                    .and_then(|e| e.best_label())
                    .unwrap_or_else(|| shorten_pubkey(&pk_view));
                let about = entry.as_ref().and_then(|e| e.about.clone()).unwrap_or_default();
                let nip05 = entry.as_ref().and_then(|e| e.nip05.clone());
                let is_me = auth.pubkey().get().as_deref() == Some(pk_view.as_str());
                let id = Identity::derive(&pk_view, &pod_api);
                let is_muted = mute.is_user_muted(&pk_view);
                let pk_dm = pk_view.clone();
                let pk_mute = pk_view.clone();
                let name_edit_init = name.clone();
                let about_edit_init = about.clone();
                let save_click = Callback::new(save_profile.clone());

                view! {
                    <div class="tui-card tui-card-accent tui-stack">
                        <div class="tui-row-between">
                            <div>
                                <h1 class="tui-page-title">{name}</h1>
                                {nip05.map(|h| view! { <div class="tui-muted">{h}</div> })}
                            </div>
                            <div class="tui-actions">
                                {(!is_me).then(|| view! {
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-primary bbs-btn-sm"
                                        on:click=move |_| router.go(Route::DmChat { pubkey: pk_dm.clone() })
                                    >"✉ Message"</button>
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-sm"
                                        on:click=move |_| {
                                            let now_muted = mute.toggle_mute_user(&pk_mute);
                                            toasts.show(
                                                if now_muted { "Member muted" } else { "Member unmuted" },
                                                ToastVariant::Info,
                                            );
                                        }
                                    >{if is_muted { "Unmute" } else { "Mute" }}</button>
                                })}
                                {is_me.then(|| view! {
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-sm"
                                        on:click=move |_| {
                                            edit_name.set(name_edit_init.clone());
                                            edit_about.set(about_edit_init.clone());
                                            editing.update(|v| *v = !*v);
                                        }
                                    >{move || if editing.get() { "Cancel Edit" } else { "Edit Profile" }}</button>
                                })}
                            </div>
                        </div>

                        {(!about.is_empty()).then(|| view! { <p style="margin:0">{about}</p> })}

                        <div class="bbs-id-block tui-stack" style="border-top:1px dashed var(--border);padding-top:0.5rem">
                            <div class="tui-row-between">
                                <span class="tui-muted">"pubkey: " {shorten_pubkey(&pk_view)}</span>
                                <CopyKeyBtn full=pk_view.clone() label="copy hex" />
                            </div>
                            {id.map(|i| view! {
                                <div class="tui-row-between">
                                    <span class="tui-muted">"did: " {i.did.clone()}</span>
                                    <CopyKeyBtn full=i.did label="copy DID" />
                                </div>
                                <div class="tui-row-between">
                                    <span class="tui-muted">"webid: " {i.webid.clone()}</span>
                                    <CopyKeyBtn full=i.webid label="copy WebID" />
                                </div>
                            })}
                        </div>
                    </div>

                    // In-BBS profile editor
                    <Show when=move || editing.get() fallback=|| ()>
                        <div class="tui-card tui-stack">
                            <strong>"Edit Profile (kind-0)"</strong>
                            <div>
                                <label class="bbs-label">"Display Name"</label>
                                <input
                                    class="bbs-input"
                                    type="text"
                                    prop:value=move || edit_name.get()
                                    on:input=move |ev| edit_name.set(event_target_value(&ev))
                                />
                            </div>
                            <div>
                                <label class="bbs-label">"About / Bio"</label>
                                <textarea
                                    class="bbs-textarea"
                                    prop:value=move || edit_about.get()
                                    on:input=move |ev| edit_about.set(event_target_value(&ev))
                                ></textarea>
                            </div>
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-primary"
                                disabled=move || saving.get()
                                on:click=move |ev| save_click.run(ev)
                            >{move || if saving.get() { "Saving…" } else { "Publish Profile ▶" }}</button>
                        </div>
                    </Show>

                    // NIP-58 Earned Badges
                    <div class="tui-card tui-stack">
                        <strong>"NIP-58 Badges"</strong>
                        {move || {
                            let earned = badges.badge_ids().get();
                            if earned.is_empty() {
                                return view! { <p class="tui-muted">"No badges awarded yet."</p> }.into_any();
                            }
                            view! {
                                <div class="tui-row">
                                    {earned.into_iter().map(|bid| {
                                        let label = badge_def(&bid)
                                            .map(|d| d.name.to_string())
                                            .unwrap_or(bid);
                                        view! { <span class="bbs-badge bbs-badge-accent">"★ " {label}</span> }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }}
                    </div>
                }
            }}
        </div>
    }
}
