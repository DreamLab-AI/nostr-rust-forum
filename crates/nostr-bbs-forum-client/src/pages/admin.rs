//! Admin panel page -- auth-gated and admin-only.
//!
//! Provides a tabbed interface for Overview, Channels, and Users management.
//! Route: `/admin`

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::admin::agents_roster::AgentsRoster;
use crate::admin::audit_log::AuditLogTab;
use crate::admin::calendar::AdminCalendar;
use crate::admin::channel_form::{ChannelForm, ChannelFormData};
use crate::admin::overview::{ConnectionStatusBar, OverviewTab};
use crate::admin::registrations::RegistrationsPanel;
use crate::admin::reports::ReportsTab;
use crate::admin::section_requests::SectionRequests;
use crate::admin::settings::SettingsTab;
use crate::admin::user_table::{AdminToggleCb, DeleteCb};
use crate::admin::user_table::{UpdateCohortsCb, UserTable};
use crate::admin::{provide_admin, use_admin, AdminTab};
use crate::auth::use_auth;
use crate::components::admin_checklist::AdminChecklist;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::relay::{ConnectionState, RelayConnection};
use crate::stores::zone_access::use_zone_access;

/// Admin panel page component. Checks auth + admin status before rendering.
#[component]
pub fn AdminPage() -> impl IntoView {
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let is_ready = auth.is_ready();
    let zone_access = use_zone_access();
    // StoredValue is Copy — safe to capture in multiple Effect closures
    let navigate = StoredValue::new(use_navigate());

    let is_admin = Memo::new(move |_| zone_access.is_admin.get());

    // Redirect non-authenticated users (SPA navigation — preserves WASM state)
    Effect::new(move |_| {
        if is_ready.get() && !is_authed.get() {
            navigate.with_value(|nav| nav("/login", NavigateOptions::default()));
        }
    });

    // Redirect non-admin users. Surface a toast BEFORE the navigate so the
    // user understands why they were bounced — silent redirects make /admin
    // appear broken to anyone without the role (Bug #4).
    //
    // The admin flag (`ZoneAccess::is_admin`) is fetched asynchronously from the
    // relay whitelist after login (`ZoneAccess::loaded`). On a cold full-page
    // load of `/admin` — a direct link or a refresh — the flag is briefly false
    // before that fetch resolves; bouncing on it kicked genuine admins out to
    // the forums and made `/admin` reachable only via in-app nav. Gate the
    // bounce (and the access fallback below) on `loaded`, mirroring
    // `AdminGatedGovernance`, so the page waits for the flag instead of racing it.
    let toasts = use_toasts();
    let access_loaded = zone_access.loaded;
    Effect::new(move |_| {
        if is_ready.get() && is_authed.get() && access_loaded.get() && !is_admin.get() {
            toasts.show("Admin access required.", ToastVariant::Warning);
            navigate.with_value(|nav| nav("/forums", NavigateOptions::default()));
        }
    });

    view! {
        <Show
            when=move || is_ready.get()
            fallback=|| view! {
                <div class="flex items-center justify-center min-h-[60vh]">
                    <div class="animate-pulse text-gray-400">"Loading..."</div>
                </div>
            }
        >
            <Show
                // While the whitelist access fetch is still in flight, keep
                // rendering (the inner Show shows a spinner) instead of flashing
                // "Access Denied" or bouncing — only show denial once `loaded`
                // resolves and the user is genuinely not an admin.
                when=move || is_authed.get() && (!access_loaded.get() || is_admin.get())
                fallback=|| view! {
                    <div class="flex items-center justify-center min-h-[60vh]">
                        <div class="text-center">
                            <h2 class="text-2xl font-bold text-red-400 mb-2">"Access Denied"</h2>
                            <p class="text-gray-400">"You do not have admin privileges."</p>
                        </div>
                    </div>
                }
            >
                <Show
                    when=move || is_admin.get()
                    fallback=|| view! {
                        <div class="flex items-center justify-center min-h-[60vh]">
                            <div class="animate-pulse text-gray-400">"Loading..."</div>
                        </div>
                    }
                >
                    <AdminPanelInner />
                </Show>
            </Show>
        </Show>
    }
}

/// Inner admin panel rendered only for authenticated admins.
#[component]
fn AdminPanelInner() -> impl IntoView {
    provide_admin();

    let admin = use_admin();
    // Deep-link support: `/admin?tab=channels` opens the panel straight on a
    // named tab. The empty-zone "Create a section" CTA (see `pages/category.rs`)
    // relies on this — sections are created via the Channels tab's "Create
    // Channel" form, NOT the "Sections" tab (which is join-request approvals).
    // Resolve once on mount, before first render.
    if let Some(tab) = initial_tab_from_query() {
        admin.state.active_tab.set(tab);
    }
    let auth = use_auth();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    // Fetch initial data when relay is connected
    let admin_for_init = admin.clone();
    let auth_for_init = auth;
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }

        admin_for_init.fetch_stats();

        if let Some(signer) = auth_for_init.get_signer() {
            let admin_clone = admin_for_init.clone();
            spawn_local(async move {
                // Whitelist first, then registrations: the pending count is
                // registrations − whitelist, so we want the whitelist loaded
                // before recomputing. Both end with `recompute_pending`, so the
                // Overview "Pending" stat is populated on first load (fixing the
                // frozen-0 count) regardless of which finishes last.
                let _ = admin_clone.fetch_whitelist_signer(&*signer).await;
                let _ = admin_clone.fetch_registrations_signer(&*signer).await;
            });
        }
    });

    // Refresh registrations whenever the admin returns to a tab that surfaces
    // the pending count (Overview stat, Pending list). Keeps the count and the
    // review list fresh without a manual refresh after approvals elsewhere.
    let admin_for_focus = admin.clone();
    let auth_for_focus = auth;
    let active_tab_for_focus = admin.state.active_tab;
    Effect::new(move |_| {
        let tab = active_tab_for_focus.get();
        if matches!(tab, AdminTab::Overview | AdminTab::Pending) {
            if let Some(signer) = auth_for_focus.get_signer() {
                let admin_clone = admin_for_focus.clone();
                spawn_local(async move {
                    let _ = admin_clone.fetch_registrations_signer(&*signer).await;
                });
            }
        }
    });

    let active_tab = admin.state.active_tab;
    let error = admin.state.error;
    let success = admin.state.success;

    let admin_for_dismiss_err = admin.clone();
    let admin_for_dismiss_success = admin.clone();

    // Auto-dismiss toasts after 5 seconds
    Effect::new(move |_| {
        if error.get().is_some() {
            let admin_clone = admin_for_dismiss_err.clone();
            auto_dismiss(move || admin_clone.clear_error());
        }
    });
    Effect::new(move |_| {
        if success.get().is_some() {
            let admin_clone = admin_for_dismiss_success.clone();
            auto_dismiss(move || admin_clone.clear_success());
        }
    });

    let admin_for_err_btn = admin.clone();
    let admin_for_suc_btn = admin.clone();

    // Onboarding checklist signals
    let channels_for_check = admin.state.channels;
    let users_for_check = admin.state.users;
    let has_channels = Signal::derive(move || !channels_for_check.get().is_empty());
    let has_members = Signal::derive(move || users_for_check.get().len() > 1);
    // Zones are configured if any user has cohorts beyond the default empty list
    let users_for_zone = admin.state.users;
    let has_zones =
        Signal::derive(move || users_for_zone.get().iter().any(|u| !u.cohorts.is_empty()));

    view! {
        <div class="max-w-6xl mx-auto p-4 sm:p-6">
            <div class="mb-6">
                <h1 class="text-3xl font-bold text-white flex items-center gap-2">
                    {admin_shield_icon()}
                    "Admin Panel"
                </h1>
                <p class="text-gray-400 mt-1">
                    "Manage whitelist, channels, and view forum statistics."
                </p>
            </div>

            <AdminChecklist has_channels=has_channels has_members=has_members has_zones=has_zones />

            <ConnectionStatusBar />

            // Error toast
            {move || {
                error.get().map(|msg| {
                    let admin_err = admin_for_err_btn.clone();
                    view! {
                        <div class="mb-4 bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 flex items-center justify-between animate-slide-in-down">
                            <span class="text-red-200 text-sm">{msg}</span>
                            <button
                                on:click=move |_| admin_err.clear_error()
                                class="text-red-300 hover:text-red-100 text-xs ml-4"
                            >
                                "Dismiss"
                            </button>
                        </div>
                    }
                })
            }}
            // Success toast
            {move || {
                success.get().map(|msg| {
                    let admin_suc = admin_for_suc_btn.clone();
                    view! {
                        <div class="mb-4 bg-green-900/50 border border-green-700 rounded-lg px-4 py-3 flex items-center justify-between animate-slide-in-down">
                            <span class="text-green-200 text-sm">{msg}</span>
                            <button
                                on:click=move |_| admin_suc.clear_success()
                                class="text-green-300 hover:text-green-100 text-xs ml-4"
                            >
                                "Dismiss"
                            </button>
                        </div>
                    }
                })
            }}

            // Tab navigation
            <div class="flex gap-6 border-b border-gray-700 mb-6">
                <TabButton tab=AdminTab::Overview active=active_tab label="Overview" />
                <TabButton tab=AdminTab::Channels active=active_tab label="Channels" />
                <TabButton tab=AdminTab::Users active=active_tab label="Users" />
                <PendingTabButton active=active_tab pending=admin.state.stats />
                <TabButton tab=AdminTab::Sections active=active_tab label="Sections" />
                <TabButton tab=AdminTab::Agents active=active_tab label="Agents" />
                <TabButton tab=AdminTab::Calendar active=active_tab label="Calendar" />
                <TabButton tab=AdminTab::Settings active=active_tab label="Settings" />
                <TabButton tab=AdminTab::Reports active=active_tab label="Reports" />
                <TabButton tab=AdminTab::AuditLog active=active_tab label="Audit Log" />
                <TabButton tab=AdminTab::NativePods active=active_tab label="Native Pods" />
            </div>

            // Tab content
            {move || {
                match active_tab.get() {
                    AdminTab::Overview => view! { <OverviewTab /> }.into_any(),
                    AdminTab::Channels => view! { <ChannelsTab /> }.into_any(),
                    AdminTab::Users => view! { <UsersTab /> }.into_any(),
                    AdminTab::Pending => view! { <RegistrationsPanel /> }.into_any(),
                    AdminTab::Sections => view! { <SectionRequests /> }.into_any(),
                    AdminTab::Agents => view! { <AgentsRoster /> }.into_any(),
                    AdminTab::Calendar => view! { <AdminCalendar /> }.into_any(),
                    AdminTab::Settings => view! { <SettingsTab /> }.into_any(),
                    AdminTab::Reports => view! { <ReportsTab /> }.into_any(),
                    AdminTab::AuditLog => view! { <AuditLogTab /> }.into_any(),
                    AdminTab::NativePods => view! { <NativePodsTab /> }.into_any(),
                }
            }}

            // Danger zone
            <DangerZone />
        </div>
    }
}

/// Resolve an initial [`AdminTab`] from the `?tab=` query parameter, if present
/// and recognised. Tolerant of a missing `?`, extra parameters, and unknown
/// slugs (returns `None`, leaving the default Overview tab). Slugs are plain
/// ASCII so no percent-decoding is required.
fn initial_tab_from_query() -> Option<AdminTab> {
    let search = web_sys::window()?.location().search().ok()?;
    let query = search.strip_prefix('?').unwrap_or(search.as_str());
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key != "tab" {
            return None;
        }
        match value {
            "overview" => Some(AdminTab::Overview),
            "channels" => Some(AdminTab::Channels),
            "users" => Some(AdminTab::Users),
            "pending" => Some(AdminTab::Pending),
            "sections" => Some(AdminTab::Sections),
            "agents" => Some(AdminTab::Agents),
            "calendar" => Some(AdminTab::Calendar),
            "settings" => Some(AdminTab::Settings),
            "reports" => Some(AdminTab::Reports),
            "audit" | "auditlog" => Some(AdminTab::AuditLog),
            "pods" | "nativepods" => Some(AdminTab::NativePods),
            _ => None,
        }
    })
}

// -- Tab button ---------------------------------------------------------------

#[component]
fn TabButton(tab: AdminTab, active: RwSignal<AdminTab>, label: &'static str) -> impl IntoView {
    let is_active = move || active.get() == tab;

    let class = move || {
        if is_active() {
            "py-2 px-1 text-sm font-medium transition-colors text-amber-400 border-b-2 border-amber-400 -mb-px"
        } else {
            "py-2 px-1 text-sm font-medium transition-colors text-gray-400 hover:text-gray-200 border-b-2 border-transparent -mb-px"
        }
    };

    view! {
        <button on:click=move |_| active.set(tab) class=class>
            {label}
        </button>
    }
}

/// Tab button for the Pending registrations tab, carrying a live count badge
/// sourced from the same `pending_approvals` stat shown on the Overview card —
/// so the icon and the number always agree and refresh together.
#[component]
fn PendingTabButton(
    active: RwSignal<AdminTab>,
    pending: RwSignal<crate::admin::AdminStats>,
) -> impl IntoView {
    let tab = AdminTab::Pending;
    let is_active = move || active.get() == tab;
    let class = move || {
        if is_active() {
            "py-2 px-1 text-sm font-medium transition-colors text-amber-400 border-b-2 border-amber-400 -mb-px flex items-center gap-1.5"
        } else {
            "py-2 px-1 text-sm font-medium transition-colors text-gray-400 hover:text-gray-200 border-b-2 border-transparent -mb-px flex items-center gap-1.5"
        }
    };
    let count = move || pending.get().pending_approvals;

    view! {
        <button on:click=move |_| active.set(tab) class=class>
            "Pending"
            <Show when=move || { count() > 0 }>
                <span class="bg-red-500/20 text-red-400 text-xs font-bold px-1.5 py-0.5 rounded-full border border-red-500/30 leading-none">
                    {move || count().to_string()}
                </span>
            </Show>
        </button>
    }
}

// -- Channels tab -------------------------------------------------------------

#[component]
fn ChannelsTab() -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let channels = admin.state.channels;

    // Resolved here, in component scope: context is NOT reachable from inside
    // the spawn_local below (no reactive owner), so the store method takes the
    // connection as a parameter instead of calling expect_context itself.
    let relay_for_create = expect_context::<RelayConnection>();
    let admin_for_create = admin.clone();
    let on_create_channel = move |data: ChannelFormData| {
        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_create.clone();
            let relay = relay_for_create.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = admin_clone
                    .create_channel_with_zone_signer(
                        &data.name,
                        &data.description,
                        &data.section,
                        &data.picture,
                        data.zone,
                        data.cohort.as_deref(),
                        &*signer,
                        relay,
                    )
                    .await
                {
                    admin_clone.state.error.set(Some(e));
                }
            });
        } else {
            admin_for_create
                .state
                .error
                .set(Some("No signer available".into()));
        }
    };

    view! {
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="lg:col-span-1">
                <ChannelForm on_submit=on_create_channel />
            </div>
            <div class="lg:col-span-2">
                <h3 class="text-lg font-semibold text-white mb-3">"Existing Channels"</h3>
                {move || {
                    let chan_list = channels.get();
                    if chan_list.is_empty() {
                        view! {
                            <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center">
                                <p class="text-gray-500">"No channels found. Create one to get started."</p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-2">
                                {chan_list.into_iter().map(|ch| {
                                    let section = if ch.section.is_empty() { "none".to_string() } else { ch.section.clone() };
                                    let section_dot_class = section_color_dot(&section);
                                    let id_short = format!("ID: {}...{}", &ch.id[..8], &ch.id[ch.id.len().saturating_sub(4)..]);
                                    view! {
                                        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 hover:border-gray-600 transition-colors">
                                            <h4 class="font-semibold text-white truncate">{ch.name.clone()}</h4>
                                            {(!ch.description.is_empty()).then(|| view! {
                                                <p class="text-sm text-gray-400 mt-0.5 truncate">{ch.description.clone()}</p>
                                            })}
                                            <div class="flex items-center gap-2 mt-2">
                                                <span class="flex items-center gap-1.5 text-xs text-gray-500 border border-gray-600 rounded px-1.5 py-0.5">
                                                    <span class=section_dot_class></span>
                                                    {section}
                                                </span>
                                                <span class="text-xs text-gray-600">{id_short}</span>
                                            </div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

// -- Users tab ----------------------------------------------------------------

#[component]
fn UsersTab() -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let users = admin.state.users;
    let is_loading = admin.state.is_loading;

    // Config-driven cohorts (Task #7): the selectable cohort set comes from the
    // live ZONE_CONFIG, not a hardcoded list. `cohort_options()` returns
    // (cohort_id, zone_label) pairs; the default selection is the first cohort.
    let cohort_options: Vec<(String, String)> = cohort_options();
    let default_cohort = cohort_options
        .first()
        .map(|(id, _)| id.clone())
        .unwrap_or_default();

    let new_pubkey = RwSignal::new(String::new());
    let new_cohorts = RwSignal::new(if default_cohort.is_empty() {
        Vec::new()
    } else {
        vec![default_cohort.clone()]
    });
    let add_error = RwSignal::new(Option::<String>::None);

    // Alias inheritance (Task #7): link the newly-joining pubkey to a prior
    // identity so it inherits cohorts and displays under the prior handle.
    let link_prior = RwSignal::new(false);
    let prior_pubkey = RwSignal::new(String::new());

    let on_pubkey_input = move |ev: leptos::ev::Event| {
        new_pubkey.set(event_target_value(&ev));
        add_error.set(None);
    };

    let admin_for_add = admin.clone();
    let default_cohort_for_reset = default_cohort.clone();
    let on_add_user = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let pk = new_pubkey.get_untracked();
        let pk_trimmed = pk.trim();

        if pk_trimmed.len() != 64 || !pk_trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            add_error.set(Some("Pubkey must be 64 hex characters".into()));
            return;
        }
        let cohorts = new_cohorts.get_untracked();
        if cohorts.is_empty() {
            add_error.set(Some("Select at least one cohort".into()));
            return;
        }

        // When linking to a prior identity, validate the prior pubkey now.
        let prior = if link_prior.get_untracked() {
            let p = prior_pubkey.get_untracked();
            let p = p.trim().to_string();
            if p.len() != 64 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
                add_error.set(Some("Prior pubkey must be 64 hex characters".into()));
                return;
            }
            if p == pk_trimmed {
                add_error.set(Some("Prior pubkey must differ from the new pubkey".into()));
                return;
            }
            Some(p)
        } else {
            None
        };

        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_add.clone();
            let pk_owned = pk_trimmed.to_string();
            let reset_cohort = default_cohort_for_reset.clone();
            spawn_local(async move {
                if (admin_clone
                    .add_to_whitelist_signer(&pk_owned, &cohorts, &*signer)
                    .await)
                    .is_ok()
                {
                    // Optional alias link — inherits cohorts + display attribution.
                    if let Some(old_pk) = prior {
                        let _ = admin_clone
                            .set_alias_signer(
                                &old_pk,
                                &pk_owned,
                                true,
                                Some("linked at onboarding"),
                                &*signer,
                            )
                            .await;
                    }
                    new_pubkey.set(String::new());
                    new_cohorts.set(if reset_cohort.is_empty() {
                        Vec::new()
                    } else {
                        vec![reset_cohort.clone()]
                    });
                    link_prior.set(false);
                    prior_pubkey.set(String::new());
                }
            });
        } else {
            add_error.set(Some("No signing key available — log in first".into()));
        }
    };

    let admin_for_update = admin.clone();
    let on_update_cohorts = move |pubkey: String, cohorts: Vec<String>| {
        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_update.clone();
            spawn_local(async move {
                let _ = admin_clone
                    .update_cohorts_signer(&pubkey, &cohorts, &*signer)
                    .await;
            });
        }
    };

    let admin_for_admin_toggle = admin.clone();
    let on_toggle_admin = move |pubkey: String, new_admin_status: bool| {
        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_admin_toggle.clone();
            spawn_local(async move {
                let _ = admin_clone
                    .set_admin_signer(&pubkey, new_admin_status, &*signer)
                    .await;
            });
        }
    };

    let admin_for_delete = admin.clone();
    let on_delete_user = move |pubkey: String, also_delete_events: bool| {
        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_delete.clone();
            spawn_local(async move {
                let _ = admin_clone
                    .delete_user_signer(&pubkey, also_delete_events, &*signer)
                    .await;
            });
        }
    };

    let admin_for_refresh = admin.clone();
    let on_refresh = move |_| {
        if let Some(signer) = auth.get_signer() {
            let admin_clone = admin_for_refresh.clone();
            spawn_local(async move {
                let _ = admin_clone.fetch_whitelist_signer(&*signer).await;
            });
        }
    };

    let users_signal = Signal::derive(move || users.get());

    view! {
        <div class="space-y-6">
            // Add user form
            <div class="bg-gray-800 border border-gray-700 rounded-lg p-6">
                <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    {user_plus_icon()}
                    "Add User to Whitelist"
                </h3>
                <form on:submit=on_add_user class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="space-y-1 md:col-span-2">
                            <label for="add-pubkey" class="block text-sm font-medium text-gray-300">"Public Key (hex)"</label>
                            <input
                                id="add-pubkey"
                                type="text"
                                prop:value=move || new_pubkey.get()
                                on:input=on_pubkey_input
                                placeholder="64-character hex public key"
                                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white font-mono text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                            {move || add_error.get().map(|msg| view! { <p class="text-red-400 text-sm">{msg}</p> })}
                        </div>
                    </div>
                    <div class="space-y-1">
                        <label class="block text-sm font-medium text-gray-300">"Cohorts"</label>
                        <div class="flex flex-wrap gap-3">
                            {cohort_options.clone().into_iter().map(|(cohort_id, zone_label)| {
                                let cc = cohort_id.clone();
                                let ct = cohort_id.clone();
                                let label = capitalize_str(&cohort_id);
                                let is_checked = move || new_cohorts.get().contains(&cc);
                                let on_toggle = move |_| {
                                    new_cohorts.update(|list| {
                                        if list.contains(&ct) { list.retain(|c| c != &ct); } else { list.push(ct.clone()); }
                                    });
                                };
                                view! {
                                    <label class="flex items-center gap-1.5 cursor-pointer" title=zone_label>
                                        <input type="checkbox" prop:checked=is_checked on:change=on_toggle
                                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500" />
                                        <span class="text-sm text-gray-300">{label}</span>
                                    </label>
                                }
                            }).collect_view()}
                        </div>
                    </div>

                    // Alias inheritance (Task #7): link this newly-joining pubkey to a
                    // prior identity. Nostr events can't be re-signed, so this records
                    // an alias — the new key inherits the prior key's cohorts and posts
                    // display under the prior handle.
                    <div class="space-y-2 border-t border-gray-700 pt-4">
                        <label class="flex items-start gap-2 cursor-pointer">
                            <input type="checkbox"
                                prop:checked=move || link_prior.get()
                                on:change=move |ev| link_prior.set(checkbox_checked(&ev))
                                class="mt-0.5 rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500" />
                            <span class="text-sm text-gray-300">
                                "Link to a prior identity (inherit cohorts + display attribution)"
                                <span class="block text-xs text-gray-500">
                                    "For a returning member who generated a new key. Their old posts stay signed by the old key but render under the prior handle."
                                </span>
                            </span>
                        </label>
                        <Show when=move || link_prior.get()>
                            <input
                                type="text"
                                prop:value=move || prior_pubkey.get()
                                on:input=move |ev| prior_pubkey.set(event_target_value(&ev))
                                placeholder="Prior public key (64-char hex)"
                                class="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-white font-mono text-sm placeholder-gray-500 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 transition-colors"
                            />
                        </Show>
                    </div>

                    <button type="submit" disabled=move || is_loading.get()
                        class="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-600 disabled:cursor-not-allowed text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors flex items-center gap-1.5">
                        {move || if is_loading.get() { "Adding..." } else { "Add User" }}
                    </button>
                </form>
            </div>

            // User table
            <div>
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-semibold text-white">"Whitelisted Users"</h3>
                    <button on:click=on_refresh disabled=move || is_loading.get()
                        class="text-sm text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-3 py-1 transition-colors disabled:opacity-50">
                        {move || if is_loading.get() { "Refreshing..." } else { "Refresh" }}
                    </button>
                </div>
                <Show
                    when=move || !is_loading.get()
                    fallback=|| view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 text-center animate-pulse">
                            <p class="text-gray-500">"Loading whitelist..."</p>
                        </div>
                    }
                >
                    <UserTable
                        users=users_signal
                        on_update_cohorts=UpdateCohortsCb::new(on_update_cohorts.clone())
                        on_toggle_admin=AdminToggleCb::new(on_toggle_admin.clone())
                        on_delete_user=DeleteCb::new(on_delete_user.clone())
                    />
                </Show>
            </div>
        </div>
    }
}

// -- Native Pods tab ----------------------------------------------------------

#[component]
fn NativePodsTab() -> impl IntoView {
    let provision_pubkey = RwSignal::new(String::new());
    let provision_status = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);
    let auth = use_auth();

    let on_provision = move |_| {
        let pk = provision_pubkey.get_untracked();
        if pk.len() != 64 {
            provision_status.set(Some("Invalid pubkey (need 64 hex chars)".into()));
            return;
        }
        if busy.get_untracked() {
            return;
        }
        let Some(signer) = auth.get_signer() else {
            provision_status.set(Some("No signer available — log in first".into()));
            return;
        };
        busy.set(true);
        provision_status.set(None);
        let pk_owned = pk.clone();
        spawn_local(async move {
            let url = format!(
                "{}/api/native-pod/provision",
                crate::utils::relay_url::auth_api_base()
            );
            let body = serde_json::json!({ "pubkey": pk_owned }).to_string();
            let result =
                crate::auth::nip98::fetch_with_nip98_post_signer(&url, &body, &*signer).await;
            match result {
                Ok(_) => {
                    provision_status.set(Some(format!("\u{2713} Pod provisioned for {pk_owned}")));
                    provision_pubkey.set(String::new());
                }
                Err(e) => provision_status.set(Some(format!("Error: {e}"))),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <div>
                <h3 class="text-sm font-semibold text-gray-300 mb-3">"Provision Native Pod"</h3>
                <p class="text-xs text-gray-500 mb-4">
                    "Provisions a pod on the agentbox native server for a user pubkey. "
                    "The user will see a second pod with full git support in their pod browser."
                </p>
                <div class="flex gap-2">
                    <input
                        type="text"
                        placeholder="User pubkey (64 hex chars)"
                        class="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono placeholder-gray-600 focus:outline-none focus:border-green-500/50"
                        on:input=move |ev| provision_pubkey.set(event_target_value(&ev))
                        prop:value=provision_pubkey
                    />
                    <button
                        on:click=on_provision
                        disabled=move || busy.get() || provision_pubkey.get().len() != 64
                        class="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:opacity-40 text-white text-sm font-medium rounded transition-colors"
                    >
                        {move || if busy.get() { "Provisioning\u{2026}" } else { "Provision" }}
                    </button>
                </div>
                {move || provision_status.get().map(|msg| view! {
                    <p class="mt-2 text-xs text-gray-400">{msg}</p>
                })}
            </div>
        </div>
    }
}

// -- Danger zone --------------------------------------------------------------

#[component]
fn DangerZone() -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let confirm = RwSignal::new(false);
    let is_loading = admin.state.is_loading;

    let on_initial_click = move |_| {
        confirm.set(true);
    };

    let admin_stored = StoredValue::new(admin.clone());

    let on_cancel = move |_| {
        confirm.set(false);
    };

    view! {
        <div class="mt-12 border border-red-800/50 rounded-lg p-6">
            <h3 class="text-lg font-semibold text-red-400 mb-2">"Danger Zone"</h3>
            <p class="text-gray-400 text-sm mb-4">
                "Reset the database to start fresh. This deletes all events and whitelist entries. The first user to register after reset becomes admin."
            </p>
            <div class="flex items-center gap-3">
                <Show when=move || !confirm.get()>
                    <button
                        on:click=on_initial_click
                        disabled=move || is_loading.get()
                        class="bg-red-600 hover:bg-red-500 disabled:bg-gray-700 text-white font-medium px-4 py-2 rounded-lg transition-colors text-sm"
                    >
                        "Reset Database"
                    </button>
                </Show>
                <Show when=move || confirm.get()>
                    <span class="text-red-300 text-sm">"Are you sure? This cannot be undone."</span>
                    <button
                        on:click=move |_| {
                            admin_stored.with_value(|admin| {
                                if let Some(signer) = auth.get_signer() {
                                    let admin_clone = admin.clone();
                                    spawn_local(async move {
                                        let _ = admin_clone.reset_db_signer(&*signer).await;
                                    });
                                }
                            });
                            confirm.set(false);
                        }
                        disabled=move || is_loading.get()
                        class="bg-red-600 hover:bg-red-500 disabled:bg-gray-700 text-white font-medium px-4 py-2 rounded-lg transition-colors text-sm"
                    >
                        "Yes, Reset Everything"
                    </button>
                    <button
                        on:click=on_cancel
                        class="text-gray-400 hover:text-gray-200 text-sm"
                    >
                        "Cancel"
                    </button>
                </Show>
            </div>
        </div>
    }
}

// -- Helpers ------------------------------------------------------------------

fn capitalize_str(s: &str) -> String {
    crate::utils::capitalize(s)
}

/// Config-driven cohort options for the add-user form (Task #7). Derived from
/// the live `ZONE_CONFIG` (`stores::zones`): the de-duplicated union of every
/// zone's `required_cohorts` and `write_cohorts`, paired with the zone's label.
/// Replaces the prior hardcoded `general/music/events/tech/moderator/vip` set
/// that never matched the real `friends/family/business/agent` cohorts.
fn cohort_options() -> Vec<(String, String)> {
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

/// Read a checkbox's `checked` state from a DOM `change` event.
fn checkbox_checked(ev: &leptos::ev::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.checked())
        .unwrap_or(false)
}

/// Set a 5-second timer that calls the given closure.
fn auto_dismiss(f: impl Fn() + 'static) {
    let cb = wasm_bindgen::closure::Closure::once(Box::new(f) as Box<dyn FnOnce()>);
    if let Some(w) = web_sys::window() {
        let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.as_ref().unchecked_ref(),
            5000,
        );
    }
    cb.forget();
}

/// Return a Tailwind class for a small colored dot representing the section.
fn section_color_dot(section: &str) -> &'static str {
    match section {
        "general" => "w-2 h-2 rounded-full bg-gray-400 inline-block",
        "announcements" => "w-2 h-2 rounded-full bg-amber-400 inline-block",
        "introductions" => "w-2 h-2 rounded-full bg-cyan-400 inline-block",
        "music" => "w-2 h-2 rounded-full bg-pink-400 inline-block",
        "events" => "w-2 h-2 rounded-full bg-green-400 inline-block",
        "tech" => "w-2 h-2 rounded-full bg-blue-400 inline-block",
        "random" => "w-2 h-2 rounded-full bg-purple-400 inline-block",
        "support" => "w-2 h-2 rounded-full bg-red-400 inline-block",
        _ => "w-2 h-2 rounded-full bg-gray-500 inline-block",
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn admin_shield_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-7 h-7 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
        </svg>
    }
}

fn user_plus_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
            <circle cx="8.5" cy="7" r="4"/>
            <line x1="20" y1="8" x2="20" y2="14"/>
            <line x1="23" y1="11" x2="17" y2="11"/>
        </svg>
    }
}
