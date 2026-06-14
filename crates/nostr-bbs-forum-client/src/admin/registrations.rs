//! Admin panel for approving pending user registrations.
//!
//! Lists users who have a username reservation on the auth-worker but are not
//! yet on the relay whitelist (the "pending" set), with per-row and bulk
//! Approve / Reject actions. This is the surface that makes a joined-but-not-
//! approved user (e.g. one who signed up but whose kind-0 auto-whitelist never
//! landed) visible to the admin — without it such users are invisible because
//! the Users tab only lists the relay whitelist.
//!
//! Data flow: the shared [`AdminStore`](super::AdminStore) owns both the
//! registrations list (auth-worker) and the whitelist (relay); the pending set
//! is `registrations − whitelist`, derived live so an approval immediately
//! removes the row and decrements the Overview "Pending" stat.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use super::use_admin;
use crate::auth::use_auth;
use crate::components::user_display::use_display_name_memo;

/// Default cohort granted on approval. Derived from the live `ZONE_CONFIG`
/// (first declared zone cohort) rather than a hardcoded value, so an approved
/// user lands in a cohort the operator's zones actually recognise. Falls back
/// to `"friends"` if no zone declares a cohort.
fn default_approval_cohort() -> String {
    let zones = crate::stores::zones::load_zones();
    for zone in &zones {
        if let Some(c) = zone.required_cohorts.iter().find(|c| !c.is_empty()) {
            return c.clone();
        }
        if let Some(write) = &zone.write_cohorts {
            if let Some(c) = write.iter().find(|c| !c.is_empty()) {
                return c.clone();
            }
        }
    }
    "friends".to_string()
}

/// Pending registrations review panel. Reads from the shared admin store and
/// refetches registrations on mount so the list is fresh when the tab opens.
#[component]
pub fn RegistrationsPanel() -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();

    let registrations = admin.state.registrations;
    let users = admin.state.users;
    let is_loading = admin.state.is_loading;
    let action_msg: RwSignal<Option<(String, bool)>> = RwSignal::new(None);
    let loaded = RwSignal::new(false);

    // Selection set for bulk actions, keyed by pubkey.
    let selected: RwSignal<Vec<String>> = RwSignal::new(Vec::new());

    // Refetch registrations when the tab mounts. The whitelist is loaded by the
    // admin page init effect; the pending set is derived from both.
    {
        let admin_for_load = admin.clone();
        Effect::new(move |_| {
            if let Some(signer) = auth.get_signer() {
                let admin_clone = admin_for_load.clone();
                spawn_local(async move {
                    let _ = admin_clone.fetch_registrations_signer(&*signer).await;
                    loaded.set(true);
                });
            }
        });
    }

    // Derived pending set: registrations whose pubkey is not on the whitelist.
    let pending = Signal::derive(move || {
        let wl: std::collections::HashSet<String> =
            users.get().into_iter().map(|u| u.pubkey).collect();
        let mut list: Vec<super::Registration> = registrations
            .get()
            .into_iter()
            .filter(|r| !wl.contains(&r.pubkey))
            .collect();
        list.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        list
    });

    let pending_count = Memo::new(move |_| pending.get().len());

    let all_selected = Memo::new(move |_| {
        let list = pending.get();
        !list.is_empty() && list.iter().all(|u| selected.get().contains(&u.pubkey))
    });

    let on_toggle_all = move |_| {
        let target = !all_selected.get_untracked();
        if target {
            selected.set(
                pending
                    .get_untracked()
                    .iter()
                    .map(|u| u.pubkey.clone())
                    .collect(),
            );
        } else {
            selected.set(Vec::new());
        }
    };

    // Approve one user: add to the relay whitelist with the default cohort.
    // `add_to_whitelist_signer` refetches the whitelist on success, which
    // recomputes the pending count, so the row drops out automatically.
    //
    // Wrapped in `Rc` so it can be cloned cheaply into each table row and the
    // bulk handler — the reactive list closure re-runs, so it cannot move the
    // callback out (it must clone it), which `Rc<dyn Fn>` makes a `Fn` closure.
    let approve_user = StoredValue::new_local({
        let admin_for_approve = admin.clone();
        std::rc::Rc::new(move |pubkey: String| {
            let Some(signer) = auth.get_signer() else {
                action_msg.set(Some(("No signing key — log in first".to_string(), false)));
                return;
            };
            let admin_clone = admin_for_approve.clone();
            let cohort = default_approval_cohort();
            let short = format!("{}…", &pubkey[..8.min(pubkey.len())]);
            spawn_local(async move {
                match admin_clone
                    .add_to_whitelist_signer(&pubkey, &[cohort], &*signer)
                    .await
                {
                    Ok(_) => action_msg.set(Some((format!("Approved {short}"), true))),
                    Err(e) => action_msg.set(Some((format!("Approve failed: {e}"), false))),
                }
                selected.update(|s| s.retain(|p| p != &pubkey));
            });
        }) as std::rc::Rc<dyn Fn(String)>
    });

    // Reject: drop locally from the registrations list (the reservation stays
    // on the auth-worker but is hidden from review until the next refetch).
    let reject_user = StoredValue::new_local({
        let admin_for_reject = admin.clone();
        std::rc::Rc::new(move |pubkey: String| {
            registrations.update(|list| list.retain(|r| r.pubkey != pubkey));
            admin_for_reject.recompute_pending();
            selected.update(|s| s.retain(|p| p != &pubkey));
            let short = format!("{}…", &pubkey[..8.min(pubkey.len())]);
            action_msg.set(Some((format!("Dismissed {short}"), true)));
        }) as std::rc::Rc<dyn Fn(String)>
    });

    let on_bulk_approve = move |_| {
        let to_approve = selected.get_untracked();
        let f = approve_user.get_value();
        for pk in to_approve {
            f(pk);
        }
    };

    let on_bulk_reject = move |_| {
        let to_reject = selected.get_untracked();
        let f = reject_user.get_value();
        for pk in to_reject {
            f(pk);
        }
    };

    let admin_for_refresh = admin.clone();
    let on_refresh = move |_| {
        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_refresh.clone();
            spawn_local(async move {
                let _ = admin_clone.fetch_registrations_signer(&*signer).await;
            });
        }
    };

    view! {
        <div class="space-y-4">
            <div class="flex items-center justify-between">
                <h2 class="text-xl font-bold text-white flex items-center gap-2">
                    {user_clock_icon()}
                    "Pending Registrations"
                    <Show when=move || { pending_count.get() > 0 }>
                        <span class="bg-red-500/20 text-red-400 text-xs font-bold px-2 py-0.5 rounded-full border border-red-500/30">
                            {move || pending_count.get().to_string()}
                        </span>
                    </Show>
                </h2>
                <button on:click=on_refresh disabled=move || is_loading.get()
                    class="text-sm text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-3 py-1 transition-colors disabled:opacity-50">
                    {move || if is_loading.get() { "Refreshing…" } else { "Refresh" }}
                </button>
            </div>

            <p class="text-sm text-gray-400">
                "Users who signed up but are not yet on the whitelist. Approving adds them to the relay whitelist (cohort: "
                <span class="font-mono text-amber-300">{default_approval_cohort()}</span>
                "), granting access. Adjust their cohorts afterwards in the Users tab."
            </p>

            // Action message
            {move || action_msg.get().map(|(msg, is_ok)| {
                let cls = if is_ok {
                    "mb-3 bg-green-900/50 border border-green-700 rounded-lg px-4 py-2 text-green-200 text-sm flex items-center justify-between"
                } else {
                    "mb-3 bg-red-900/50 border border-red-700 rounded-lg px-4 py-2 text-red-200 text-sm flex items-center justify-between"
                };
                view! {
                    <div class=cls>
                        <span>{msg}</span>
                        <button on:click=move |_| action_msg.set(None)
                            class="text-xs opacity-60 hover:opacity-100 ml-4">"dismiss"</button>
                    </div>
                }
            })}

            // Bulk actions
            <Show when=move || { pending_count.get() > 0 }>
                <div class="flex items-center gap-3 bg-gray-800/50 rounded-lg px-4 py-2">
                    <label class="flex items-center gap-2 cursor-pointer text-sm text-gray-300">
                        <input type="checkbox"
                            prop:checked=move || all_selected.get()
                            on:change=on_toggle_all
                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500" />
                        "Select all"
                    </label>
                    <div class="flex-1"></div>
                    <button on:click=on_bulk_approve disabled=move || is_loading.get()
                        class="text-xs text-green-400 hover:text-green-300 border border-green-500/30 hover:border-green-400 rounded px-3 py-1 transition-colors disabled:opacity-50">
                        "Approve Selected"
                    </button>
                    <button on:click=on_bulk_reject disabled=move || is_loading.get()
                        class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-3 py-1 transition-colors disabled:opacity-50">
                        "Dismiss Selected"
                    </button>
                </div>
            </Show>

            // List
            <Show
                when=move || loaded.get()
                fallback=|| view! {
                    <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center animate-pulse">
                        <p class="text-gray-500">"Loading registrations…"</p>
                    </div>
                }
            >
                {move || {
                    let list = pending.get();
                    if list.is_empty() {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
                                <div class="w-14 h-14 rounded-full bg-gray-700/50 flex items-center justify-center mx-auto mb-4">
                                    {empty_inbox_icon()}
                                </div>
                                <h3 class="text-white font-semibold mb-1">"No pending registrations"</h3>
                                <p class="text-gray-500 text-sm">"All caught up. New sign-ups awaiting approval appear here."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                                <div class="grid grid-cols-12 gap-2 px-4 py-3 bg-gray-750 border-b border-gray-700 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                    <div class="col-span-1"></div>
                                    <div class="col-span-3">"Handle"</div>
                                    <div class="col-span-3">"Real Name"</div>
                                    <div class="col-span-3">"Pubkey"</div>
                                    <div class="col-span-2 text-right">"Actions"</div>
                                </div>
                                <div class="divide-y divide-gray-700/50">
                                    {list.into_iter().map(|reg| {
                                        let pk = reg.pubkey.clone();
                                        let pk_short = use_display_name_memo(pk.clone());
                                        let handle = reg.handle.clone()
                                            .map(|h| format!("@{h}"))
                                            .unwrap_or_else(|| "—".to_string());
                                        let real = reg.real_name.clone().unwrap_or_else(|| "—".to_string());
                                        let real_is_set = reg.real_name.is_some();
                                        let pk_in_selected = pk.clone();
                                        let pk_toggle = pk.clone();
                                        let pk_approve = pk.clone();
                                        let pk_reject = pk.clone();
                                        let is_sel = move || selected.get().contains(&pk_in_selected);
                                        view! {
                                            <div class="grid grid-cols-12 gap-2 px-4 py-3 items-center text-sm hover:bg-gray-750 transition-colors">
                                                <div class="col-span-1">
                                                    <input type="checkbox"
                                                        prop:checked=is_sel
                                                        on:change=move |_| {
                                                            let pk = pk_toggle.clone();
                                                            selected.update(|s| {
                                                                if s.contains(&pk) { s.retain(|p| p != &pk); }
                                                                else { s.push(pk); }
                                                            });
                                                        }
                                                        class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500" />
                                                </div>
                                                <div class="col-span-3 text-amber-300 font-mono text-xs truncate" title=handle.clone()>
                                                    {handle.clone()}
                                                </div>
                                                <div
                                                    class=if real_is_set { "col-span-3 text-gray-200 text-xs truncate" } else { "col-span-3 text-gray-600 text-xs truncate italic" }
                                                    title=real.clone()
                                                >
                                                    {real.clone()}
                                                </div>
                                                <div class="col-span-3">
                                                    <span class="font-mono text-gray-400 bg-gray-900 rounded px-2 py-0.5 text-xs" title=pk.clone()>
                                                        {move || pk_short.get()}
                                                    </span>
                                                </div>
                                                <div class="col-span-2 flex justify-end gap-1">
                                                    <button on:click=move |_| approve_user.get_value()(pk_approve.clone())
                                                        class="text-xs text-green-400 hover:text-green-300 border border-green-500/30 hover:border-green-400 rounded px-2 py-1 transition-colors">
                                                        "Approve"
                                                    </button>
                                                    <button on:click=move |_| reject_user.get_value()(pk_reject.clone())
                                                        class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors">
                                                        "Dismiss"
                                                    </button>
                                                </div>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_any()
                    }
                }}
            </Show>
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn user_clock_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
            <circle cx="8.5" cy="7" r="4"/>
            <circle cx="19" cy="17" r="3"/>
            <path d="M19 15.5v1.5l1 .5"/>
        </svg>
    }
}

fn empty_inbox_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/>
            <path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/>
        </svg>
    }
}
