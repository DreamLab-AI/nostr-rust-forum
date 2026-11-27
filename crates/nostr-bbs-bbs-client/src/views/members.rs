//! Member Directory & Rich Profile View (did:nostr, WebID, NIP-58 badges,
//! mute/DM actions, and in-BBS non-clobbering kind-0 profile editing).

use std::cell::Cell;
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::relay::{Filter, RelayConnection};
use nostr_bbs_client_core::stores::badges::{badge_def, use_badges};
use nostr_bbs_client_core::stores::mute::use_mute_store;
use nostr_bbs_client_core::stores::profile_cache::try_use_profile_cache;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::{set_timeout_once, shorten_pubkey};
use nostr_bbs_core::event::UnsignedEvent;
use serde_json::{Map, Value};

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
    // The member's current kind-0, which a save starts from (see
    // `merge_profile_edit`). Captured here: the publish task has no owner.
    let base = RwSignal::new(ProfileBase::Idle);
    // Bumped by each load, so a superseded load's answer or timeout (the
    // editor closed and reopened meanwhile) cannot overwrite a newer one.
    let load_generation = StoredValue::new(0u32);
    let profile_cache = try_use_profile_cache();

    let pk_view = pubkey.clone();
    let pk_save = pubkey.clone();

    // Fetch the newest kind-0 of `pubkey` from the relay and pre-fill the
    // form from it. The profile cache cannot serve: it keeps only the fields
    // it displays, and a kind-0 is replaced whole.
    let load_base = {
        let relay = relay.clone();
        let pubkey = pubkey.clone();
        move || {
            load_generation.update_value(|g| *g = g.wrapping_add(1));
            let generation = load_generation.get_value();
            let current = move || load_generation.try_get_value() == Some(generation);
            base.set(ProfileBase::Loading);
            let newest = Rc::new(Cell::new(None::<u64>));
            let on_event = {
                let newest = newest.clone();
                let author = pubkey.clone();
                Rc::new(move |ev: nostr_bbs_core::NostrEvent| {
                    if !current()
                        || ev.kind != 0
                        || ev.pubkey != author
                        || newest.get().is_some_and(|ts| ts >= ev.created_at)
                    {
                        return;
                    }
                    newest.set(Some(ev.created_at));
                    let next = match parse_kind0(&ev.content) {
                        Some(obj) => {
                            let (name, about) = form_values(&obj);
                            let _ = edit_name.try_set(name);
                            let _ = edit_about.try_set(about);
                            ProfileBase::Loaded(obj)
                        }
                        None => ProfileBase::Unreadable(
                            "your current profile on the relay is not valid JSON".into(),
                        ),
                    };
                    let _ = base.try_set(next);
                })
            };
            let settle = move |outcome: ProfileBase| {
                if !current() {
                    return;
                }
                base.try_update(|b| {
                    if *b == ProfileBase::Loading {
                        *b = outcome;
                    }
                });
            };
            let on_answer = Rc::new(move |_authenticated: bool| {
                // End of stored events with no kind-0: the member has none yet.
                settle(ProfileBase::NotFound);
            });
            let on_closed = Rc::new(move |reason: String| {
                settle(ProfileBase::Unreadable(format!(
                    "the relay refused: {reason}"
                )));
            });
            let sub_id = relay.subscribe_with_receipt_or_closed(
                vec![Filter {
                    kinds: Some(vec![0]),
                    authors: Some(vec![pubkey.clone()]),
                    limit: Some(1),
                    ..Default::default()
                }],
                on_event,
                on_answer,
                on_closed,
            );
            let relay = relay.clone();
            set_timeout_once(
                move || {
                    relay.unsubscribe(&sub_id);
                    settle(ProfileBase::Unreadable("the relay did not answer".into()));
                },
                PROFILE_LOAD_TIMEOUT_MS,
            );
        }
    };
    let load_base = StoredValue::new_local(load_base);

    let save_profile = move |_| {
        let Some(signer) = auth.get_signer() else {
            return;
        };
        if signer.public_key() != pk_save {
            toasts.show("You can only edit your own profile", ToastVariant::Error);
            return;
        }
        let existing = match base.get_untracked() {
            ProfileBase::Loaded(obj) => Some(obj),
            ProfileBase::NotFound => None,
            ProfileBase::Idle | ProfileBase::Loading => {
                toasts.show(
                    "Still reading your current profile; try again in a moment",
                    ToastVariant::Warning,
                );
                return;
            }
            ProfileBase::Unreadable(why) => {
                toasts.show(
                    format!(
                        "Not saved: {why}, so fields set elsewhere (picture, NIP-05, \
                         lightning address…) would be lost. Retry loading first."
                    ),
                    ToastVariant::Error,
                );
                return;
            }
        };
        let merged = merge_profile_edit(
            existing,
            &edit_name.get_untracked(),
            &edit_about.get_untracked(),
        );
        let content = Value::Object(merged.clone()).to_string();

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
                    if let Some(pc) = profile_cache {
                        pc.upsert_from_kind0(&pk_up, &content, ts);
                    }
                    let _ = base.try_set(ProfileBase::Loaded(merged));
                    let _ = editing.try_set(false);
                    toasts.show("Profile updated (kind-0)", ToastVariant::Success);
                }
                Err(e) => toasts.show(format!("Profile sign failed: {e}"), ToastVariant::Error),
            }
            let _ = saving.try_set(false);
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
                let entry = profile_cache.and_then(|pc| pc.lookup_reactive(&pk_view));
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
                                            let opening = !editing.get_untracked();
                                            editing.set(opening);
                                            // Every opening re-reads the current
                                            // kind-0: it may have changed elsewhere.
                                            if opening {
                                                load_base.with_value(|load| load());
                                            }
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
                            {move || match base.get() {
                                ProfileBase::Idle | ProfileBase::Loading => view! {
                                    <p class="tui-muted">"Reading your current profile from the relay…"</p>
                                }.into_any(),
                                ProfileBase::Unreadable(why) => view! {
                                    <p class="bbs-badge bbs-badge-warn" role="alert">
                                        {format!("Cannot edit: {why}. Saving now could erase fields set elsewhere.")}
                                    </p>
                                    <button
                                        type="button"
                                        class="bbs-btn bbs-btn-sm"
                                        on:click=move |_| load_base.with_value(|load| load())
                                    >"Retry loading"</button>
                                }.into_any(),
                                ProfileBase::Loaded(_) | ProfileBase::NotFound => view! {
                                    <p class="tui-muted" style="font-size:0.8rem">
                                        "Only the display name and bio change; every other profile field is kept."
                                    </p>
                                }.into_any(),
                            }}
                            <div>
                                <label class="bbs-label" for="bbs-profile-display-name">"Display Name"</label>
                                <input
                                    id="bbs-profile-display-name"
                                    class="bbs-input"
                                    type="text"
                                    disabled=move || !base.get().may_save()
                                    prop:value=move || edit_name.get()
                                    on:input=move |ev| edit_name.set(event_target_value(&ev))
                                />
                            </div>
                            <div>
                                <label class="bbs-label" for="bbs-profile-about">"About / Bio"</label>
                                <textarea
                                    id="bbs-profile-about"
                                    class="bbs-textarea"
                                    disabled=move || !base.get().may_save()
                                    prop:value=move || edit_about.get()
                                    on:input=move |ev| edit_about.set(event_target_value(&ev))
                                ></textarea>
                            </div>
                            <button
                                type="button"
                                class="bbs-btn bbs-btn-primary"
                                disabled=move || saving.get() || !base.get().may_save()
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

/// How long the profile editor waits for the relay's answer about the
/// member's current kind-0 before refusing to save.
const PROFILE_LOAD_TIMEOUT_MS: i32 = 8_000;

/// What a profile save starts from.
#[derive(Clone, Debug, PartialEq)]
enum ProfileBase {
    /// The editor has not asked yet.
    Idle,
    /// Waiting for the relay.
    Loading,
    /// The member's newest kind-0 content.
    Loaded(Map<String, Value>),
    /// The relay answered with no kind-0: the member has none yet.
    NotFound,
    /// The current kind-0 could not be read (timeout, refusal, bad JSON).
    /// Saving would replace it blind, so it is refused.
    Unreadable(String),
}

impl ProfileBase {
    /// Whether a save may proceed: only from a known starting point.
    fn may_save(&self) -> bool {
        matches!(self, ProfileBase::Loaded(_) | ProfileBase::NotFound)
    }
}

/// The JSON object of a kind-0's content, or `None` when it is not one.
fn parse_kind0(content: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str(content) {
        Ok(Value::Object(obj)) => Some(obj),
        _ => None,
    }
}

/// The form's starting values: the kind-0's own `display_name` and `about`
/// (never a derived label, which saving would then write as a name).
fn form_values(obj: &Map<String, Value>) -> (String, String) {
    let field = |k: &str| {
        obj.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (field("display_name"), field("about"))
}

/// The kind-0 content a save publishes: the member's current content
/// (`existing`, `None` when they have none) with only the two fields the form
/// edits changed. A kind-0 is replaced whole, so every other field (`name`,
/// `picture`, `banner`, `nip05`, `lud16`, `website`, fields other clients
/// set) is carried over untouched. An empty value removes its field, which is
/// how clearing it works.
fn merge_profile_edit(
    existing: Option<Map<String, Value>>,
    display_name: &str,
    about: &str,
) -> Map<String, Value> {
    let mut obj = existing.unwrap_or_default();
    for (key, value) in [("display_name", display_name), ("about", about)] {
        let value = value.trim();
        if value.is_empty() {
            obj.remove(key);
        } else {
            obj.insert(key.into(), Value::String(value.to_string()));
        }
    }
    obj
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(json: &str) -> Map<String, Value> {
        parse_kind0(json).expect("object")
    }

    #[test]
    fn a_save_changes_only_the_edited_fields() {
        let existing = obj(
            r#"{"name":"alice","display_name":"Alice","about":"old","picture":"https://p/a.png",
                "banner":"https://p/b.png","nip05":"alice@example.com","lud16":"alice@ln.example",
                "website":"https://alice.example","bot":false,"custom":{"k":1}}"#,
        );
        let out = merge_profile_edit(Some(existing.clone()), "  Alice B ", "new bio");
        assert_eq!(out["display_name"], "Alice B");
        assert_eq!(out["about"], "new bio");
        for key in [
            "name", "picture", "banner", "nip05", "lud16", "website", "bot", "custom",
        ] {
            assert_eq!(out.get(key), existing.get(key), "{key} is kept");
        }
        assert_eq!(out.len(), existing.len());
    }

    #[test]
    fn clearing_a_field_removes_it_and_nothing_else() {
        let existing =
            obj(r#"{"name":"alice","display_name":"Alice","about":"bio","lud16":"a@b"}"#);
        let out = merge_profile_edit(Some(existing), "Alice", "  ");
        assert!(!out.contains_key("about"));
        assert_eq!(out["name"], "alice");
        assert_eq!(out["lud16"], "a@b");
    }

    #[test]
    fn no_existing_profile_writes_just_the_form() {
        let out = merge_profile_edit(None, "New", "");
        assert_eq!(Value::Object(out).to_string(), r#"{"display_name":"New"}"#);
    }

    #[test]
    fn the_form_starts_from_the_profiles_own_fields() {
        assert_eq!(
            form_values(&obj(r#"{"name":"alice","about":"hi"}"#)),
            (String::new(), "hi".to_string()),
            "a name alone is not offered as the display name"
        );
        assert_eq!(
            form_values(&obj(r#"{"display_name":"Alice","about":7}"#)),
            ("Alice".to_string(), String::new())
        );
    }

    #[test]
    fn only_a_known_starting_point_may_be_saved_over() {
        assert!(parse_kind0("not json").is_none());
        assert!(parse_kind0("[1]").is_none());
        assert!(ProfileBase::Loaded(Map::new()).may_save());
        assert!(ProfileBase::NotFound.may_save());
        assert!(!ProfileBase::Idle.may_save());
        assert!(!ProfileBase::Loading.may_save());
        assert!(!ProfileBase::Unreadable("x".into()).may_save());
    }
}
