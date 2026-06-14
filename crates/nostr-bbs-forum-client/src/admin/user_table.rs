//! Whitelist user table component for the admin panel.
//!
//! Displays whitelisted users in a table with truncated pubkeys, cohort badges,
//! trust level indicators, and suspend/silence/notes management.

use leptos::prelude::*;
use send_wrapper::SendWrapper;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;

use super::WhitelistUser;
use crate::auth::nip98::fetch_with_nip98_post_signer;
use crate::auth::use_auth;
use crate::components::modal::Modal;
use crate::components::user_display::{try_display_name_tracked, use_display_name_memo};
use crate::utils::shorten_pubkey;

/// Cohort options for the inline editor, derived from the live `ZONE_CONFIG`
/// (`window.__ENV__.ZONE_CONFIG`) rather than a hardcoded list (Task #7,
/// coordinator finding #3 — the prior `home/members/private` set never matched
/// the real `friends/family/business/agent` zone cohorts).
///
/// Returns `(cohort_id, label)` pairs: the union of every zone's
/// `required_cohorts` plus `write_cohorts`, de-duplicated, preserving the order
/// zones are declared so the editor is stable. Each cohort is labelled by the
/// zone it gates (falling back to a humanised cohort id).
fn available_cohorts() -> Vec<(String, String)> {
    use std::collections::BTreeSet;
    let zones = crate::stores::zones::load_zones();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<(String, String)> = Vec::new();
    for zone in &zones {
        let mut cohorts: Vec<String> = zone.required_cohorts.clone();
        if let Some(write) = &zone.write_cohorts {
            cohorts.extend(write.iter().cloned());
        }
        for c in cohorts {
            if c.is_empty() {
                continue;
            }
            if seen.insert(c.clone()) {
                out.push((c.clone(), zone.label()));
            }
        }
    }
    out
}

/// Callback type for cohort updates: (pubkey, new_cohorts).
type UpdateCallback = Rc<dyn Fn(String, Vec<String>)>;

/// Callback type for admin toggle: (pubkey, is_admin).
type AdminToggleCallback = Rc<dyn Fn(String, bool)>;

/// Callback type for user deletion: (pubkey, also_delete_events).
type DeleteCallback = Rc<dyn Fn(String, bool)>;

/// Whitelist user table. Shows username, cohorts, and an edit button for each user.
/// Calls `on_update_cohorts` when cohorts are changed for a user.
/// Calls `on_toggle_admin` when admin status is toggled for a user.
#[component]
pub fn UserTable(
    users: Signal<Vec<WhitelistUser>>,
    #[prop(into)] on_update_cohorts: UpdateCohortsCb,
    #[prop(into)] on_toggle_admin: AdminToggleCb,
    #[prop(into)] on_delete_user: DeleteCb,
) -> impl IntoView {
    let editing_pubkey = RwSignal::new(Option::<String>::None);
    let editing_cohorts = RwSignal::new(Vec::<String>::new());
    let callback = on_update_cohorts.0;
    let admin_callback = on_toggle_admin.0;
    let delete_callback = on_delete_user.0;

    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            // Table header
            <div class="grid grid-cols-12 gap-2 px-4 py-3 bg-gray-750 border-b border-gray-700 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                <div class="col-span-3">"User"</div>
                <div class="col-span-3">"Cohorts"</div>
                <div class="col-span-3">"Status"</div>
                <div class="col-span-3 text-right">"Actions"</div>
            </div>

            // User rows
            <div class="divide-y divide-gray-700">
                {move || {
                    let user_list = users.get();
                    if user_list.is_empty() {
                        view! {
                            <div class="px-4 py-8 text-center text-gray-500">
                                "No whitelisted users found."
                            </div>
                        }.into_any()
                    } else {
                        let cb = callback.clone();
                        let acb = admin_callback.clone();
                        let dcb = delete_callback.clone();
                        user_list.into_iter().map(move |user| {
                            let cb_for_row = cb.clone();
                            let acb_for_row = acb.clone();
                            let dcb_for_row = dcb.clone();
                            view! {
                                <UserRow
                                    user=user
                                    editing_pubkey=editing_pubkey
                                    editing_cohorts=editing_cohorts
                                    on_save=UpdateCohortsCb(cb_for_row)
                                    on_toggle_admin=AdminToggleCb(acb_for_row)
                                    on_delete_user=DeleteCb(dcb_for_row)
                                />
                            }
                        }).collect_view().into_any()
                    }
                }}
            </div>
        </div>
    }
}

/// A wrapper to make the callback Send+Sync for Leptos context.
/// SAFETY: WASM is single-threaded, so Send+Sync is safe. We use
/// SendWrapper internally to satisfy Leptos bounds.
#[derive(Clone)]
pub struct UpdateCohortsCb(SendWrapper<UpdateCallback>);

impl UpdateCohortsCb {
    pub fn new(f: impl Fn(String, Vec<String>) + 'static) -> Self {
        Self(SendWrapper::new(Rc::new(f)))
    }
}

#[cfg(target_arch = "wasm32")]
unsafe impl Send for UpdateCohortsCb {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for UpdateCohortsCb {}

impl<F: Fn(String, Vec<String>) + 'static> From<F> for UpdateCohortsCb {
    fn from(f: F) -> Self {
        Self::new(f)
    }
}

/// A wrapper to make the admin toggle callback Send+Sync for Leptos context.
#[derive(Clone)]
pub struct AdminToggleCb(SendWrapper<AdminToggleCallback>);

impl AdminToggleCb {
    pub fn new(f: impl Fn(String, bool) + 'static) -> Self {
        Self(SendWrapper::new(Rc::new(f)))
    }
}

#[cfg(target_arch = "wasm32")]
unsafe impl Send for AdminToggleCb {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for AdminToggleCb {}

impl<F: Fn(String, bool) + 'static> From<F> for AdminToggleCb {
    fn from(f: F) -> Self {
        Self::new(f)
    }
}

/// A wrapper to make the delete callback Send+Sync for Leptos context.
/// Carries `(pubkey, also_delete_events)`.
#[derive(Clone)]
pub struct DeleteCb(SendWrapper<DeleteCallback>);

impl DeleteCb {
    pub fn new(f: impl Fn(String, bool) + 'static) -> Self {
        Self(SendWrapper::new(Rc::new(f)))
    }
}

#[cfg(target_arch = "wasm32")]
unsafe impl Send for DeleteCb {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for DeleteCb {}

impl<F: Fn(String, bool) + 'static> From<F> for DeleteCb {
    fn from(f: F) -> Self {
        Self::new(f)
    }
}

// -- Suspend/Silence types ----------------------------------------------------

/// Duration options for user suspension.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SuspendDuration {
    OneDay,
    OneWeek,
    OneMonth,
    Permanent,
}

impl SuspendDuration {
    fn label(&self) -> &'static str {
        match self {
            Self::OneDay => "1 Day",
            Self::OneWeek => "1 Week",
            Self::OneMonth => "1 Month",
            Self::Permanent => "Permanent",
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::OneDay => "1d",
            Self::OneWeek => "1w",
            Self::OneMonth => "1m",
            Self::Permanent => "permanent",
        }
    }

    const ALL: &'static [SuspendDuration] =
        &[Self::OneDay, Self::OneWeek, Self::OneMonth, Self::Permanent];
}

// -- Suspend modal ------------------------------------------------------------

#[component]
fn SuspendModal(
    pubkey: String,
    on_close: impl Fn() + 'static + Clone + Send + Sync,
) -> impl IntoView {
    let auth = use_auth();
    let duration = RwSignal::new(SuspendDuration::OneDay);
    let reason = RwSignal::new(String::new());
    let is_submitting = RwSignal::new(false);
    let error_msg = RwSignal::new(Option::<String>::None);

    let pk = pubkey.clone();
    let on_close_submit = on_close.clone();
    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if let Some(signer) = auth.get_signer() {
            is_submitting.set(true);
            error_msg.set(None);
            let body = serde_json::json!({
                "pubkey": pk,
                "duration": duration.get_untracked().as_str(),
                "reason": reason.get_untracked(),
            });
            let body_json = serde_json::to_string(&body).unwrap_or_default();
            let close_fn = on_close_submit.clone();
            spawn_local(async move {
                let url = format!(
                    "{}/api/admin/suspend",
                    crate::utils::relay_url::relay_api_base()
                );
                match fetch_with_nip98_post_signer(&url, &body_json, &*signer).await {
                    Ok(_) => {
                        is_submitting.set(false);
                        close_fn();
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Failed: {}", e)));
                        is_submitting.set(false);
                    }
                }
            });
        }
    };

    // Resolved nickname (reactive) plus the truncated hex key as the exact
    // technical identifier the admin is acting on.
    let display_name = use_display_name_memo(pubkey.clone());
    let pk_display = truncate_pubkey(&pubkey);

    // Local visibility for the shared Modal shell; every close path forwards to
    // the caller's `on_close`.
    let is_open = RwSignal::new(true);
    let on_modal_close = {
        let close = on_close.clone();
        Callback::new(move |()| close())
    };

    view! {
        <Modal is_open=is_open title="Suspend User".to_string() on_close=on_modal_close>
            <div>
                <p class="text-sm text-gray-400 mb-4">
                    {move || display_name.get()}
                    " "
                    <span class="font-mono text-xs text-gray-500">{pk_display}</span>
                </p>

                {move || error_msg.get().map(|msg| view! {
                    <div class="mb-3 bg-red-900/50 border border-red-700 rounded-lg px-3 py-2 text-red-200 text-sm">{msg}</div>
                })}

                <form on:submit=on_submit class="space-y-4">
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300">"Duration"</label>
                        <div class="grid grid-cols-2 gap-2">
                            {SuspendDuration::ALL.iter().map(|&d| {
                                let is_selected = move || duration.get() == d;
                                let cls = move || if is_selected() {
                                    "text-sm rounded-lg px-3 py-2 border-2 border-amber-500 bg-amber-500/10 text-amber-300 cursor-pointer transition-colors"
                                } else {
                                    "text-sm rounded-lg px-3 py-2 border border-gray-600 bg-gray-900 text-gray-400 hover:border-gray-500 cursor-pointer transition-colors"
                                };
                                view! {
                                    <button type="button" class=cls on:click=move |_| duration.set(d)>
                                        {d.label()}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    </div>

                    <div class="space-y-1">
                        <label class="block text-sm font-medium text-gray-300">"Reason"</label>
                        <textarea
                            prop:value=move || reason.get()
                            on:input=move |ev| reason.set(event_target_value(&ev))
                            placeholder="Reason for suspension (visible to other admins)"
                            rows="3"
                            class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors resize-none"
                        />
                    </div>

                    <div class="flex justify-end gap-3 pt-2">
                        <button type="button" on:click={
                            let close = on_close.clone();
                            move |_| close()
                        } class="text-sm text-gray-400 hover:text-gray-200 px-4 py-2 transition-colors">
                            "Cancel"
                        </button>
                        <button
                            type="submit"
                            disabled=move || is_submitting.get()
                            class="bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white font-medium px-4 py-2 rounded-lg transition-colors text-sm"
                        >
                            {move || if is_submitting.get() { "Suspending..." } else { "Suspend" }}
                        </button>
                    </div>
                </form>
            </div>
        </Modal>
    }
}

// -- Notes modal --------------------------------------------------------------

#[component]
fn NotesModal(
    pubkey: String,
    on_close: impl Fn() + 'static + Clone + Send + Sync,
) -> impl IntoView {
    let auth = use_auth();
    let notes = RwSignal::new(String::new());
    let is_loading = RwSignal::new(true);
    let is_saving = RwSignal::new(false);

    // Load existing notes
    let pk_for_load = pubkey.clone();
    Effect::new(move |_| {
        if let Some(signer) = auth.get_signer() {
            let pk = pk_for_load.clone();
            spawn_local(async move {
                let url = format!(
                    "{}/api/admin/notes/{}",
                    crate::utils::relay_url::relay_api_base(),
                    pk
                );
                if let Ok(body) =
                    crate::auth::nip98::fetch_with_nip98_get_signer(&url, &*signer).await
                {
                    if let Ok(resp) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(n) = resp.get("notes").and_then(|v| v.as_str()) {
                            notes.set(n.to_string());
                        }
                    }
                }
                is_loading.set(false);
            });
        } else {
            is_loading.set(false);
        }
    });

    let pk_for_save = pubkey.clone();
    let on_close_save = on_close.clone();
    let on_save = move |_| {
        if let Some(signer) = auth.get_signer() {
            is_saving.set(true);
            let body = serde_json::json!({
                "pubkey": pk_for_save,
                "notes": notes.get_untracked(),
            });
            let body_json = serde_json::to_string(&body).unwrap_or_default();
            let close_fn = on_close_save.clone();
            spawn_local(async move {
                let url = format!(
                    "{}/api/admin/notes",
                    crate::utils::relay_url::relay_api_base()
                );
                let _ = fetch_with_nip98_post_signer(&url, &body_json, &*signer).await;
                is_saving.set(false);
                close_fn();
            });
        }
    };

    // Resolved nickname (reactive) plus the truncated hex key as the exact
    // technical identifier the admin is acting on.
    let display_name = use_display_name_memo(pubkey.clone());
    let pk_display = truncate_pubkey(&pubkey);

    // Local visibility for the shared Modal shell; every close path forwards to
    // the caller's `on_close`.
    let is_open = RwSignal::new(true);
    let on_modal_close = {
        let close = on_close.clone();
        Callback::new(move |()| close())
    };

    view! {
        <Modal is_open=is_open title="Admin Notes".to_string() on_close=on_modal_close>
            <div>
                <p class="text-sm text-gray-400 mb-4">
                    {move || display_name.get()}
                    " "
                    <span class="font-mono text-xs text-gray-500">{pk_display}</span>
                </p>

                <Show
                    when=move || !is_loading.get()
                    fallback=|| view! {
                        <div class="h-24 bg-gray-700 rounded-lg animate-pulse"></div>
                    }
                >
                    <textarea
                        prop:value=move || notes.get()
                        on:input=move |ev| notes.set(event_target_value(&ev))
                        placeholder="Private admin notes about this user..."
                        rows="5"
                        class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors resize-none"
                    />
                </Show>

                <div class="flex justify-end gap-3 pt-4">
                    <button on:click={
                        let close = on_close.clone();
                        move |_| close()
                    } class="text-sm text-gray-400 hover:text-gray-200 px-4 py-2 transition-colors">
                        "Cancel"
                    </button>
                    <button
                        on:click=on_save
                        disabled=move || is_saving.get()
                        class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm"
                    >
                        {move || if is_saving.get() { "Saving..." } else { "Save Notes" }}
                    </button>
                </div>
            </div>
        </Modal>
    }
}

// -- Delete-user modal --------------------------------------------------------

/// Confirmation modal for deleting a user, with an opt-in checkbox to also
/// purge the user's posted messages. Invokes `on_confirm(also_delete_events)`.
#[component]
fn DeleteUserModal(
    pubkey: String,
    display_label: String,
    on_close: impl Fn() + 'static + Clone + Send + Sync,
    on_confirm: impl Fn(bool) + 'static + Clone + Send + Sync,
) -> impl IntoView {
    let also_delete_events = RwSignal::new(false);
    let pk_display = truncate_pubkey(&pubkey);

    let confirm = {
        let on_confirm = on_confirm.clone();
        let on_close = on_close.clone();
        move |_| {
            on_confirm.clone()(also_delete_events.get_untracked());
            on_close.clone()();
        }
    };

    // Local visibility for the shared Modal shell; backdrop / Esc / header X all
    // forward to the caller's `on_close` (equivalent to Cancel — non-destructive).
    let is_open = RwSignal::new(true);
    let on_modal_close = {
        let close = on_close.clone();
        Callback::new(move |()| close())
    };

    view! {
        <Modal is_open=is_open title="Delete User".to_string() on_close=on_modal_close>
            <div>
                <p class="text-sm text-gray-400 mb-4">
                    {display_label}
                    " "
                    <span class="font-mono text-xs text-gray-500">{pk_display}</span>
                </p>

                <div class="bg-red-900/40 border border-red-700/60 rounded-lg px-3 py-2 text-red-200 text-sm mb-4">
                    "This removes the user from the whitelist, revoking all relay access. "
                    "Their auth-side handle and provisioning name are also removed. This cannot be undone."
                </div>

                <label class="flex items-start gap-2 cursor-pointer text-sm mb-5">
                    <input
                        type="checkbox"
                        prop:checked=move || also_delete_events.get()
                        on:change=move |ev| also_delete_events.set(event_target_checked(&ev))
                        class="mt-0.5 rounded border-gray-600 bg-gray-900 text-red-500 focus:ring-red-500"
                    />
                    <span class="text-gray-300">
                        "Also delete this user's posted messages"
                        <span class="block text-xs text-gray-500">
                            "Purges every event this pubkey authored from the relay. Other users' messages are unaffected."
                        </span>
                    </span>
                </label>

                <div class="flex justify-end gap-3">
                    <button type="button" on:click={
                        let close = on_close.clone();
                        move |_| close()
                    } class="text-sm text-gray-400 hover:text-gray-200 px-4 py-2 transition-colors">
                        "Cancel"
                    </button>
                    <button
                        type="button"
                        on:click=confirm
                        class="bg-red-600 hover:bg-red-500 text-white font-medium px-4 py-2 rounded-lg transition-colors text-sm"
                    >
                        "Delete User"
                    </button>
                </div>
            </div>
        </Modal>
    }
}

/// A single row in the user table with inline edit capability,
/// suspend/silence buttons, and admin notes.
#[component]
fn UserRow(
    user: WhitelistUser,
    editing_pubkey: RwSignal<Option<String>>,
    editing_cohorts: RwSignal<Vec<String>>,
    on_save: UpdateCohortsCb,
    on_toggle_admin: AdminToggleCb,
    on_delete_user: DeleteCb,
) -> impl IntoView {
    let pk = user.pubkey.clone();
    let pk_display = truncate_pubkey(&pk);
    let cohorts = user.cohorts.clone();
    let is_admin_user = user.is_admin;
    // Admin-only real name (enriched from the auth-worker). Rendered on this
    // admin surface only so admins can provision the right person.
    let real_name = user.real_name.clone();
    // Public claimed handle (auth-worker). Task #7: the fallback display name
    // for users whose kind-0 profile has no name (most live "hex" rows). The
    // profile cache (kind-0) is still tried first; the handle covers the gap so
    // the admin table no longer falls back to a raw 64-hex pubkey.
    let handle_fallback = user.handle.clone();
    // The relay's /api/whitelist/list already joins the latest kind-0 and
    // returns its display_name/name as `displayName`. We use it as a source
    // before the auth handle (it is zero-extra-fetch and already loaded).
    let relay_display_name = user.display_name.clone();
    // Reactively resolve display name, in precedence order:
    //   kind-0 profile cache -> relay-joined kind-0 name -> auth handle ->
    //   shortened hex. The cache read subscribes so the name fills in live when
    //   kind-0 metadata arrives. The auth handle is the key Task #7 fix: most
    //   live "hex" rows have a blank kind-0 name but a claimed handle.
    let display_name = {
        let pk = pk.clone();
        let handle = handle_fallback.clone();
        let relay_name = relay_display_name.clone();
        Memo::new(move |_| {
            if let Some(name) = try_display_name_tracked(&pk) {
                return name;
            }
            if let Some(n) = relay_name.as_ref() {
                let t = n.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
            if let Some(h) = handle.as_ref() {
                let t = h.trim();
                if !t.is_empty() {
                    return format!("@{t}");
                }
            }
            shorten_pubkey(&pk)
        })
    };

    let pk_for_edit = pk.clone();
    let cohorts_for_edit = cohorts.clone();
    let pk_for_check = pk.clone();
    let pk_for_check2 = pk.clone();
    let pk_for_save = pk.clone();
    let pk_for_admin = pk.clone();
    let pk_for_suspend = pk.clone();
    let pk_for_notes = pk.clone();
    let pk_for_silence = pk.clone();
    let pk_for_delete = pk.clone();

    let is_editing = move || editing_pubkey.get().as_deref() == Some(&*pk_for_check);
    let is_editing2 = move || editing_pubkey.get().as_deref() == Some(&*pk_for_check2);

    // Modal states
    let show_suspend_modal = RwSignal::new(false);
    let show_notes_modal = RwSignal::new(false);
    let show_delete_modal = RwSignal::new(false);
    let is_silenced = RwSignal::new(false);

    // Delete callback (pubkey, also_delete_events).
    let delete_cb = on_delete_user.0;
    let pk_delete = pk_for_delete.clone();
    let on_delete_confirm = move |also_delete_events: bool| {
        delete_cb(pk_delete.clone(), also_delete_events);
    };

    let on_edit_click = move |_| {
        editing_pubkey.set(Some(pk_for_edit.clone()));
        editing_cohorts.set(cohorts_for_edit.clone());
    };

    let save_cb = on_save.0;
    let pk_save = pk_for_save.clone();
    let on_save_click = move |_| {
        let updated = editing_cohorts.get_untracked();
        save_cb(pk_save.clone(), updated);
        editing_pubkey.set(None);
    };

    let on_cancel_click = move |_| {
        editing_pubkey.set(None);
    };

    let admin_cb = on_toggle_admin.0;
    let on_admin_toggle = move |_| {
        admin_cb(pk_for_admin.clone(), !is_admin_user);
    };

    // Silence toggle
    let on_silence_toggle = move |_| {
        let auth = use_auth();
        if let Some(signer) = auth.get_signer() {
            let new_state = !is_silenced.get_untracked();
            let body = serde_json::json!({
                "pubkey": pk_for_silence,
                "silenced": new_state,
            });
            let body_json = serde_json::to_string(&body).unwrap_or_default();
            spawn_local(async move {
                let url = format!(
                    "{}/api/admin/silence",
                    crate::utils::relay_url::relay_api_base()
                );
                if fetch_with_nip98_post_signer(&url, &body_json, &*signer)
                    .await
                    .is_ok()
                {
                    is_silenced.set(new_state);
                }
            });
        }
    };

    let cohorts_for_display = cohorts.clone();

    view! {
        <div class="grid grid-cols-12 gap-2 px-4 py-3 items-center text-sm hover:bg-gray-750 hover:border-l-2 hover:border-l-amber-500/50 border-l-2 border-l-transparent transition-all">
            // User column -- reactive display name + admin-only real name + truncated pubkey
            <div class="col-span-3">
                <div class="flex flex-col gap-0.5">
                    <span class="text-white font-medium text-sm">{display_name}</span>
                    {real_name.map(|rn| view! {
                        <span class="text-xs text-gray-400" title="Real name (admin-only)">
                            {rn}
                        </span>
                    })}
                    <span
                        class="font-mono text-gray-500 bg-gray-900 rounded px-2 py-0.5 text-xs w-fit"
                        title=pk.clone()
                    >
                        {pk_display}
                    </span>
                </div>
            </div>

            // Cohorts column
            <div class="col-span-3">
                <Show
                    when=is_editing
                    fallback={
                        let cohorts_disp = cohorts_for_display.clone();
                        move || {
                            view! {
                                <div class="flex flex-wrap gap-1">
                                    {is_admin_user.then(|| view! {
                                        <span class="inline-block text-xs rounded px-1.5 py-0.5 bg-red-500/20 text-red-300 border border-red-500/30">
                                            "Admin"
                                        </span>
                                    })}
                                    {cohorts_disp.iter().map(|c| {
                                        let badge_class = cohort_badge_class(c);
                                        let label = c.clone();
                                        view! {
                                            <span class=badge_class>
                                                {label}
                                            </span>
                                        }
                                    }).collect_view()}
                                </div>
                            }
                        }
                    }
                >
                    <CohortEditor editing_cohorts=editing_cohorts />
                </Show>
            </div>

            // Status column -- trust level, silenced indicator
            <div class="col-span-3">
                <div class="flex flex-wrap gap-1 items-center">
                    // Trust level badge (default TL0 since we don't have trust_level on WhitelistUser yet)
                    <span class="inline-block text-xs rounded px-1.5 py-0.5 bg-gray-500/20 text-gray-300 border border-gray-500/30">
                        "TL0"
                    </span>
                    {move || is_silenced.get().then(|| view! {
                        <span class="inline-block text-xs rounded px-1.5 py-0.5 bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">
                            "Silenced"
                        </span>
                    })}
                </div>
            </div>

            // Actions column
            <div class="col-span-3 flex justify-end gap-1 flex-wrap">
                <Show
                    when=is_editing2
                    fallback=move || view! {
                        <button
                            on:click=on_admin_toggle.clone()
                            class=if is_admin_user {
                                "text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors"
                            } else {
                                "text-xs text-emerald-400 hover:text-emerald-300 border border-emerald-500/30 hover:border-emerald-400 rounded px-2 py-1 transition-colors"
                            }
                        >
                            {if is_admin_user { "Revoke Admin" } else { "Make Admin" }}
                        </button>
                        <button
                            on:click=on_edit_click.clone()
                            class="text-xs text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-2 py-1 transition-colors flex items-center gap-1"
                        >
                            {pencil_icon()}
                            "Edit"
                        </button>
                        <button
                            on:click=move |_| show_suspend_modal.set(true)
                            class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors"
                        >
                            "Suspend"
                        </button>
                        <button
                            on:click=on_silence_toggle.clone()
                            class=move || if is_silenced.get() {
                                "text-xs text-yellow-400 hover:text-yellow-300 border border-yellow-500/30 hover:border-yellow-400 rounded px-2 py-1 transition-colors"
                            } else {
                                "text-xs text-gray-400 hover:text-gray-300 border border-gray-600 hover:border-gray-500 rounded px-2 py-1 transition-colors"
                            }
                        >
                            {move || if is_silenced.get() { "Unsilence" } else { "Silence" }}
                        </button>
                        <button
                            on:click=move |_| show_notes_modal.set(true)
                            class="text-xs text-blue-400 hover:text-blue-300 border border-blue-500/30 hover:border-blue-400 rounded px-2 py-1 transition-colors flex items-center gap-1"
                        >
                            {notes_icon()}
                        </button>
                        <button
                            on:click=move |_| show_delete_modal.set(true)
                            title="Delete user"
                            class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors flex items-center gap-1"
                        >
                            {trash_icon()}
                        </button>
                    }
                >
                    <button
                        on:click=on_save_click.clone()
                        class="text-xs text-green-400 hover:text-green-300 border border-green-500/30 hover:border-green-400 rounded px-2 py-1 transition-colors flex items-center gap-1"
                    >
                        {check_icon()}
                        "Save"
                    </button>
                    <button
                        on:click=on_cancel_click
                        class="text-xs text-gray-400 hover:text-gray-300 border border-gray-600 hover:border-gray-500 rounded px-2 py-1 transition-colors flex items-center gap-1"
                    >
                        {x_icon()}
                        "Cancel"
                    </button>
                </Show>
            </div>
        </div>

        // Modals (rendered outside the grid row for correct z-index)
        {move || show_suspend_modal.get().then(|| {
            let pk = pk_for_suspend.clone();
            view! {
                <SuspendModal
                    pubkey=pk
                    on_close=move || show_suspend_modal.set(false)
                />
            }
        })}
        {move || show_notes_modal.get().then(|| {
            let pk = pk_for_notes.clone();
            view! {
                <NotesModal
                    pubkey=pk
                    on_close=move || show_notes_modal.set(false)
                />
            }
        })}
        {move || show_delete_modal.get().then(|| {
            let pk = pk_for_delete.clone();
            let label = display_name.get();
            let confirm = on_delete_confirm.clone();
            view! {
                <DeleteUserModal
                    pubkey=pk
                    display_label=label
                    on_close=move || show_delete_modal.set(false)
                    on_confirm=confirm
                />
            }
        })}
    }
}

/// Inline cohort editor with a checkbox per cohort. The cohort set is derived
/// from the live `ZONE_CONFIG` via [`available_cohorts`] (Task #7) so it always
/// matches the operator's real zones rather than a hardcoded list.
#[component]
fn CohortEditor(editing_cohorts: RwSignal<Vec<String>>) -> impl IntoView {
    let cohorts = available_cohorts();
    view! {
        <div class="flex flex-wrap gap-2">
            {cohorts.into_iter().map(|(cohort_id, zone_label)| {
                let cohort_for_check = cohort_id.clone();
                let cohort_for_toggle = cohort_id.clone();
                let label = capitalize(&cohort_id);

                let is_checked = move || {
                    editing_cohorts.get().contains(&cohort_for_check)
                };

                let on_toggle = move |_| {
                    editing_cohorts.update(|list| {
                        if list.contains(&cohort_for_toggle) {
                            list.retain(|c| c != &cohort_for_toggle);
                        } else {
                            list.push(cohort_for_toggle.clone());
                        }
                    });
                };

                view! {
                    <label class="flex items-center gap-1 cursor-pointer text-xs" title=zone_label>
                        <input
                            type="checkbox"
                            prop:checked=is_checked
                            on:change=on_toggle
                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                        />
                        <span class="text-gray-300">{label}</span>
                    </label>
                }
            }).collect_view()}
        </div>
    }
}

/// Capitalise a cohort id for display (`"friends"` -> `"Friends"`).
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Truncate a hex pubkey to show first 8 and last 4 characters.
fn truncate_pubkey(pk: &str) -> String {
    if pk.len() <= 16 {
        return pk.to_string();
    }
    format!("{}...{}", &pk[..8], &pk[pk.len() - 4..])
}

/// Read a checkbox's `checked` state from a DOM `change` event.
fn event_target_checked(ev: &leptos::ev::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.checked())
        .unwrap_or(false)
}

/// Return a Tailwind CSS class string for a cohort badge based on the cohort
/// name. Covers the real DreamLab zone cohorts (friends/family/business/agent)
/// plus the legacy fallback names; any unrecognised cohort renders with the
/// neutral grey badge so config-driven cohorts always have a sensible style.
fn cohort_badge_class(cohort: &str) -> &'static str {
    match cohort {
        // Real DreamLab zone cohorts.
        "friends" => "inline-block text-xs rounded px-1.5 py-0.5 bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:shadow-[0_0_6px_rgba(245,158,11,0.3)] transition-shadow",
        "family" => "inline-block text-xs rounded px-1.5 py-0.5 bg-pink-500/20 text-pink-300 border border-pink-500/30 hover:shadow-[0_0_6px_rgba(236,72,153,0.3)] transition-shadow",
        "business" => "inline-block text-xs rounded px-1.5 py-0.5 bg-blue-500/20 text-blue-300 border border-blue-500/30 hover:shadow-[0_0_6px_rgba(59,130,246,0.3)] transition-shadow",
        "agent" => "inline-block text-xs rounded px-1.5 py-0.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:shadow-[0_0_6px_rgba(16,185,129,0.3)] transition-shadow",
        // Legacy fallback cohorts (pre-zone-redesign deployments).
        "home" => "inline-block text-xs rounded px-1.5 py-0.5 bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:shadow-[0_0_6px_rgba(245,158,11,0.3)] transition-shadow",
        "members" => "inline-block text-xs rounded px-1.5 py-0.5 bg-pink-500/20 text-pink-300 border border-pink-500/30 hover:shadow-[0_0_6px_rgba(236,72,153,0.3)] transition-shadow",
        "private" => "inline-block text-xs rounded px-1.5 py-0.5 bg-purple-500/20 text-purple-300 border border-purple-500/30 hover:shadow-[0_0_6px_rgba(168,85,247,0.3)] transition-shadow",
        _ => "inline-block text-xs rounded px-1.5 py-0.5 bg-gray-500/20 text-gray-300 border border-gray-500/30 hover:shadow-[0_0_6px_rgba(107,114,128,0.3)] transition-shadow",
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn pencil_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17 3a2.828 2.828 0 114 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>
        </svg>
    }
}

fn check_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
        </svg>
    }
}

fn x_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
    }
}

fn notes_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="16" y1="13" x2="8" y2="13"/>
            <line x1="16" y1="17" x2="8" y2="17"/>
        </svg>
    }
}

fn trash_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
            <line x1="10" y1="11" x2="10" y2="17"/>
            <line x1="14" y1="11" x2="14" y2="17"/>
        </svg>
    }
}
