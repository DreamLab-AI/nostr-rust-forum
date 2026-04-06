//! Admin panel page -- auth-gated and admin-only.
//!
//! Provides a tabbed interface for Overview, Channels, and Users management.
//! Route: `/admin`

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::admin::audit_log::AuditLogTab;
use crate::admin::calendar::AdminCalendar;
use crate::admin::channel_form::{ChannelForm, ChannelFormData};
use crate::admin::overview::{ConnectionStatusBar, OverviewTab};
use crate::admin::reports::ReportsTab;
use crate::admin::section_requests::SectionRequests;
use crate::admin::settings::SettingsTab;
use crate::admin::user_table::{UpdateCohortsCb, UserTable};
use crate::admin::{provide_admin, use_admin, AdminTab};
use crate::admin::user_table::AdminToggleCb;
use crate::auth::use_auth;
use crate::components::admin_checklist::AdminChecklist;
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

    // Redirect non-admin users
    Effect::new(move |_| {
        if is_ready.get() && is_authed.get() && !is_admin.get() {
            navigate.with_value(|nav| nav("/chat", NavigateOptions::default()));
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
                when=move || is_authed.get() && is_admin.get()
                fallback=|| view! {
                    <div class="flex items-center justify-center min-h-[60vh]">
                        <div class="text-center">
                            <h2 class="text-2xl font-bold text-red-400 mb-2">"Access Denied"</h2>
                            <p class="text-gray-400">"You do not have admin privileges."</p>
                        </div>
                    </div>
                }
            >
                <AdminPanelInner />
            </Show>
        </Show>
    }
}

/// Inner admin panel rendered only for authenticated admins.
#[component]
fn AdminPanelInner() -> impl IntoView {
    provide_admin();

    let admin = use_admin();
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

        if let Some(privkey) = auth_for_init.get_privkey_bytes() {
            let admin_clone = admin_for_init.clone();
            spawn_local(async move {
                let _ = admin_clone.fetch_whitelist(&privkey).await;
            });
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
    let has_zones = Signal::derive(move || {
        users_for_zone.get().iter().any(|u| !u.cohorts.is_empty())
    });

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
                <TabButton tab=AdminTab::Sections active=active_tab label="Sections" />
                <TabButton tab=AdminTab::Calendar active=active_tab label="Calendar" />
                <TabButton tab=AdminTab::Settings active=active_tab label="Settings" />
                <TabButton tab=AdminTab::Reports active=active_tab label="Reports" />
                <TabButton tab=AdminTab::AuditLog active=active_tab label="Audit Log" />
            </div>

            // Tab content
            {move || {
                match active_tab.get() {
                    AdminTab::Overview => view! { <OverviewTab /> }.into_any(),
                    AdminTab::Channels => view! { <ChannelsTab /> }.into_any(),
                    AdminTab::Users => view! { <UsersTab /> }.into_any(),
                    AdminTab::Sections => view! { <SectionRequests /> }.into_any(),
                    AdminTab::Calendar => view! { <AdminCalendar /> }.into_any(),
                    AdminTab::Settings => view! { <SettingsTab /> }.into_any(),
                    AdminTab::Reports => view! { <ReportsTab /> }.into_any(),
                    AdminTab::AuditLog => view! { <AuditLogTab /> }.into_any(),
                }
            }}

            // Danger zone
            <DangerZone />
        </div>
    }
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

// -- Channels tab -------------------------------------------------------------

#[component]
fn ChannelsTab() -> impl IntoView {
    let admin = use_admin();
    let auth = use_auth();
    let channels = admin.state.channels;

    let admin_for_create = admin.clone();
    let on_create_channel = move |data: ChannelFormData| {
        if let Some(privkey) = auth.get_privkey_bytes() {
            if let Err(e) = admin_for_create.create_channel_with_zone(
                &data.name,
                &data.description,
                &data.section,
                &data.picture,
                data.zone,
                data.cohort.as_deref(),
                &privkey,
            ) {
                admin_for_create.state.error.set(Some(e));
            }
        } else {
            admin_for_create
                .state
                .error
                .set(Some("No private key available".into()));
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

    let new_pubkey = RwSignal::new(String::new());
    let new_cohorts = RwSignal::new(vec!["general".to_string()]);
    let add_error = RwSignal::new(Option::<String>::None);

    let on_pubkey_input = move |ev: leptos::ev::Event| {
        new_pubkey.set(event_target_value(&ev));
        add_error.set(None);
    };

    let admin_for_add = admin.clone();
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
        if let Some(privkey) = auth.get_privkey_bytes() {
            let admin_clone = admin_for_add.clone();
            let pk_owned = pk_trimmed.to_string();
            spawn_local(async move {
                if (admin_clone
                    .add_to_whitelist(&pk_owned, &cohorts, &privkey)
                    .await)
                    .is_ok()
                {
                    new_pubkey.set(String::new());
                    new_cohorts.set(vec!["general".to_string()]);
                }
            });
        } else {
            add_error.set(Some("No private key available".into()));
        }
    };

    let admin_for_update = admin.clone();
    let on_update_cohorts = move |pubkey: String, cohorts: Vec<String>| {
        if let Some(privkey) = auth.get_privkey_bytes() {
            let admin_clone = admin_for_update.clone();
            spawn_local(async move {
                let _ = admin_clone
                    .update_cohorts(&pubkey, &cohorts, &privkey)
                    .await;
            });
        }
    };

    let admin_for_admin_toggle = admin.clone();
    let on_toggle_admin = move |pubkey: String, new_admin_status: bool| {
        if let Some(privkey) = auth.get_privkey_bytes() {
            let admin_clone = admin_for_admin_toggle.clone();
            spawn_local(async move {
                let _ = admin_clone
                    .set_admin(&pubkey, new_admin_status, &privkey)
                    .await;
            });
        }
    };

    let admin_for_refresh = admin.clone();
    let on_refresh = move |_| {
        if let Some(privkey) = auth.get_privkey_bytes() {
            let admin_clone = admin_for_refresh.clone();
            spawn_local(async move {
                let _ = admin_clone.fetch_whitelist(&privkey).await;
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
                            {["general", "music", "events", "tech", "moderator", "vip"].iter().map(|cohort| {
                                let cs = cohort.to_string();
                                let cc = cs.clone();
                                let ct = cs.clone();
                                let label = capitalize_str(cohort);
                                let is_checked = move || new_cohorts.get().contains(&cc);
                                let on_toggle = move |_| {
                                    new_cohorts.update(|list| {
                                        if list.contains(&ct) { list.retain(|c| c != &ct); } else { list.push(ct.clone()); }
                                    });
                                };
                                view! {
                                    <label class="flex items-center gap-1.5 cursor-pointer">
                                        <input type="checkbox" prop:checked=is_checked on:change=on_toggle
                                            class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500" />
                                        <span class="text-sm text-gray-300">{label}</span>
                                    </label>
                                }
                            }).collect_view()}
                        </div>
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
                    <UserTable users=users_signal on_update_cohorts=UpdateCohortsCb::new(on_update_cohorts.clone()) on_toggle_admin=AdminToggleCb::new(on_toggle_admin.clone()) />
                </Show>
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
                                if let Some(privkey) = auth.get_privkey_bytes() {
                                    let admin_clone = admin.clone();
                                    spawn_local(async move {
                                        let _ = admin_clone.reset_db(&privkey).await;
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
