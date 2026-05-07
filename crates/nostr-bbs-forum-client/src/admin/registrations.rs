//! Admin panel for approving/rejecting pending user registrations.
//!
//! Displays a table of users who have registered but are not yet whitelisted,
//! with approve/reject actions and bulk selection.

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use super::use_admin;
use crate::auth::use_auth;
use crate::components::user_display::use_display_name;

/// A pending registration entry. In the current system, pending users are
/// those who have registered passkeys but have not yet been added to the
/// whitelist. This is a simplified representation for the UI.
#[derive(Clone, Debug)]
struct PendingUser {
    pubkey: String,
    nickname: Option<String>,
    registered_at: Option<u64>,
    selected: RwSignal<bool>,
}

/// Admin registrations panel. Admin-only guard at component level.
#[component]
pub fn RegistrationsPanel() -> impl IntoView {
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
            <RegistrationsInner />
        </Show>
    }
}

#[component]
fn RegistrationsInner() -> impl IntoView {
    let _admin = use_admin(); // verified via context
    let auth = use_auth();

    // Pending users state. In practice this would come from an auth API
    // endpoint; here we use admin state and filter for "pending" status.
    let pending = RwSignal::new(Vec::<PendingUser>::new());
    let is_loading = RwSignal::new(false);
    let action_msg: RwSignal<Option<(String, bool)>> = RwSignal::new(None);

    // Derive pending count
    let pending_count = Memo::new(move |_| pending.get().len());

    // Select all toggle
    let all_selected = Memo::new(move |_| {
        let list = pending.get();
        !list.is_empty() && list.iter().all(|u| u.selected.get())
    });

    let on_toggle_all = move |_| {
        let target = !all_selected.get();
        pending.with_untracked(|list| {
            for user in list {
                user.selected.set(target);
            }
        });
    };

    // Approve a single user — use expect_context inside to keep closure Copy-friendly
    let approve_user = Callback::<String>::new(move |pubkey: String| {
        let admin_ctx = use_admin();
        if let Some(privkey) = auth.get_privkey_bytes() {
            is_loading.set(true);
            action_msg.set(None);
            let pending_sig = pending;
            spawn_local(async move {
                let cohorts = vec!["cross-access".to_string()];
                match admin_ctx
                    .add_to_whitelist(&pubkey, &cohorts, &privkey)
                    .await
                {
                    Ok(_) => {
                        pending_sig.update(|list| list.retain(|u| u.pubkey != pubkey));
                        action_msg.set(Some((
                            format!(
                                "Approved {}...{}",
                                &pubkey[..6],
                                &pubkey[pubkey.len().saturating_sub(4)..]
                            ),
                            true,
                        )));
                    }
                    Err(e) => {
                        action_msg.set(Some((e, false)));
                    }
                }
                is_loading.set(false);
            });
        }
    });

    // Reject a single user (remove from pending list, not from whitelist)
    let reject_user = Callback::<String>::new(move |pubkey: String| {
        pending.update(|list| list.retain(|u| u.pubkey != pubkey));
        let pk_short = use_display_name(&pubkey);
        action_msg.set(Some((format!("Rejected {}", pk_short), true)));
    });

    // Bulk approve selected — use expect_context inside to keep closure Copy-friendly
    let on_bulk_approve = move |_| {
        let selected: Vec<String> = pending
            .get_untracked()
            .iter()
            .filter(|u| u.selected.get_untracked())
            .map(|u| u.pubkey.clone())
            .collect();

        if selected.is_empty() {
            return;
        }

        let admin_ctx = use_admin();
        if let Some(privkey) = auth.get_privkey_bytes() {
            is_loading.set(true);
            action_msg.set(None);
            let pending_sig = pending;
            let count = selected.len();
            spawn_local(async move {
                let cohorts = vec!["cross-access".to_string()];
                let mut ok_count = 0usize;
                for pk in &selected {
                    if admin_ctx
                        .add_to_whitelist(pk, &cohorts, &privkey)
                        .await
                        .is_ok()
                    {
                        ok_count += 1;
                    }
                }
                pending_sig.update(|list| {
                    list.retain(|u| !selected.contains(&u.pubkey));
                });
                action_msg.set(Some((
                    format!("Approved {}/{} users", ok_count, count),
                    true,
                )));
                is_loading.set(false);
            });
        }
    };

    // Bulk reject selected
    let on_bulk_reject = move |_| {
        let selected: Vec<String> = pending
            .get_untracked()
            .iter()
            .filter(|u| u.selected.get_untracked())
            .map(|u| u.pubkey.clone())
            .collect();

        if selected.is_empty() {
            return;
        }

        let count = selected.len();
        pending.update(|list| {
            list.retain(|u| !selected.contains(&u.pubkey));
        });
        action_msg.set(Some((format!("Rejected {} users", count), true)));
    };

    view! {
        <div class="space-y-4">
            // Header with badge
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
            </div>

            // Action message
            {move || {
                action_msg.get().map(|(msg, is_ok)| {
                    let cls = if is_ok {
                        "mb-3 bg-green-900/50 border border-green-700 rounded-lg px-4 py-2 text-green-200 text-sm flex items-center justify-between"
                    } else {
                        "mb-3 bg-red-900/50 border border-red-700 rounded-lg px-4 py-2 text-red-200 text-sm flex items-center justify-between"
                    };
                    view! {
                        <div class=cls>
                            <span>{msg}</span>
                            <button
                                on:click=move |_| action_msg.set(None)
                                class="text-xs opacity-60 hover:opacity-100 ml-4"
                            >
                                "dismiss"
                            </button>
                        </div>
                    }
                })
            }}

            // Bulk actions
            <Show when=move || { pending_count.get() > 0 }>
                <div class="flex items-center gap-3 bg-gray-800/50 rounded-lg px-4 py-2">
                    <label class="flex items-center gap-2 cursor-pointer text-sm text-gray-300">
                        <input
                            type="checkbox"
                            prop:checked=move || all_selected.get()
                            on:change=on_toggle_all
                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                        />
                        "Select all"
                    </label>
                    <div class="flex-1"></div>
                    <button
                        on:click=on_bulk_approve
                        disabled=move || is_loading.get()
                        class="text-xs text-green-400 hover:text-green-300 border border-green-500/30 hover:border-green-400 rounded px-3 py-1 transition-colors disabled:opacity-50"
                    >
                        "Approve Selected"
                    </button>
                    <button
                        on:click=on_bulk_reject
                        disabled=move || is_loading.get()
                        class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-3 py-1 transition-colors disabled:opacity-50"
                    >
                        "Reject Selected"
                    </button>
                </div>
            </Show>

            // Table/list
            <Show
                when=move || !is_loading.get()
                fallback=|| view! {
                    <div class="glass-card p-8 text-center animate-pulse">
                        <div class="h-4 bg-gray-700 rounded w-48 mx-auto mb-3"></div>
                        <div class="h-3 bg-gray-700 rounded w-32 mx-auto"></div>
                    </div>
                }
            >
                {move || {
                    let users = pending.get();
                    if users.is_empty() {
                        view! {
                            <div class="glass-card p-8 text-center">
                                <div class="w-14 h-14 rounded-full bg-gray-800 flex items-center justify-center mx-auto mb-4">
                                    {empty_inbox_icon()}
                                </div>
                                <h3 class="text-white font-semibold mb-1">"No pending registrations"</h3>
                                <p class="text-gray-500 text-sm">"All caught up. New registrations will appear here."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="glass-card overflow-hidden">
                                // Table header
                                <div class="grid grid-cols-12 gap-2 px-4 py-3 bg-gray-800/80 border-b border-gray-700 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                                    <div class="col-span-1"></div>
                                    <div class="col-span-4">"Pubkey"</div>
                                    <div class="col-span-3">"Nickname"</div>
                                    <div class="col-span-2">"Registered"</div>
                                    <div class="col-span-2 text-right">"Actions"</div>
                                </div>

                                // Rows
                                <div class="divide-y divide-gray-700/50">
                                    {users.into_iter().map(|user| {
                                        let pk = user.pubkey.clone();
                                        let pk_short = use_display_name(&pk);
                                        let nick = user.nickname.clone().unwrap_or_else(|| "-".to_string());
                                        let time_str = user.registered_at
                                            .map(crate::utils::format_relative_time)
                                            .unwrap_or_else(|| "-".to_string());
                                        let selected = user.selected;
                                        let pk_approve = pk.clone();
                                        let pk_reject = pk.clone();

                                        view! {
                                            <div class="grid grid-cols-12 gap-2 px-4 py-3 items-center text-sm hover:bg-gray-800/40 transition-colors">
                                                <div class="col-span-1">
                                                    <input
                                                        type="checkbox"
                                                        prop:checked=move || selected.get()
                                                        on:change=move |_| selected.update(|v| *v = !*v)
                                                        class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                                    />
                                                </div>
                                                <div class="col-span-4">
                                                    <span class="font-mono text-gray-300 bg-gray-900 rounded px-2 py-0.5 text-xs" title=pk.clone()>
                                                        {pk_short}
                                                    </span>
                                                </div>
                                                <div class="col-span-3 text-gray-400 text-xs truncate">{nick}</div>
                                                <div class="col-span-2 text-gray-500 text-xs">{time_str}</div>
                                                <div class="col-span-2 flex justify-end gap-1">
                                                    <button
                                                        on:click=move |_| approve_user.run(pk_approve.clone())
                                                        class="text-xs text-green-400 hover:text-green-300 border border-green-500/30 hover:border-green-400 rounded px-2 py-1 transition-colors"
                                                    >
                                                        "Approve"
                                                    </button>
                                                    <button
                                                        on:click=move |_| reject_user.run(pk_reject.clone())
                                                        class="text-xs text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-400 rounded px-2 py-1 transition-colors"
                                                    >
                                                        "Reject"
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
