//! Overview tab and shared display components for the admin panel.
//!
//! Contains stat cards, connection status bar, and the overview tab.

use leptos::prelude::*;

use super::use_admin;
use crate::auth::use_auth;
use crate::relay::{ConnectionState, RelayConnection};

// -- Connection status bar ----------------------------------------------------

/// Displays the current relay connection state with a colored indicator.
#[component]
pub fn ConnectionStatusBar() -> impl IntoView {
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    view! {
        {move || {
            match conn_state.get() {
                ConnectionState::Connected => view! {
                    <div class="mb-4 bg-green-900/30 border border-green-700/50 rounded-lg px-4 py-2 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-green-400"></span>
                        <span class="text-green-300 text-sm">"Relay connected"</span>
                    </div>
                }.into_any(),
                ConnectionState::Connecting | ConnectionState::Reconnecting => view! {
                    <div class="mb-4 bg-yellow-900/30 border border-yellow-700/50 rounded-lg px-4 py-2 flex items-center gap-2">
                        <span class="animate-pulse w-2 h-2 rounded-full bg-yellow-400"></span>
                        <span class="text-yellow-300 text-sm">"Connecting to relay..."</span>
                    </div>
                }.into_any(),
                ConnectionState::Error => view! {
                    <div class="mb-4 bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-2 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-red-400"></span>
                        <span class="text-red-300 text-sm">"Relay connection error"</span>
                    </div>
                }.into_any(),
                ConnectionState::Disconnected => view! {
                    <div class="mb-4 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-gray-500"></span>
                        <span class="text-gray-400 text-sm">"Relay disconnected"</span>
                    </div>
                }.into_any(),
            }
        }}
    }
}

// -- Overview tab -------------------------------------------------------------

/// The overview tab displaying aggregate stats and admin info.
#[component]
pub fn OverviewTab() -> impl IntoView {
    let admin = use_admin();
    let stats = admin.state.stats;
    let is_loading = admin.state.is_loading;

    view! {
        <Show
            when=move || !is_loading.get()
            fallback=|| view! {
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCardSkeleton />
                    <StatCardSkeleton />
                    <StatCardSkeleton />
                    <StatCardSkeleton />
                </div>
            }
        >
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                    label="Total Users"
                    value=Signal::derive(move || stats.get().total_users.to_string())
                    icon="users"
                    color="amber"
                />
                <StatCard
                    label="Channels"
                    value=Signal::derive(move || stats.get().total_channels.to_string())
                    icon="hash"
                    color="blue"
                />
                <StatCard
                    label="Messages"
                    value=Signal::derive(move || stats.get().total_messages.to_string())
                    icon="messages"
                    color="green"
                />
                <StatCard
                    label="Pending"
                    value=Signal::derive(move || stats.get().pending_approvals.to_string())
                    icon="alert"
                    color="orange"
                />
            </div>
        </Show>

        // Admin pubkey info (shows the current user's pubkey)
        {move || {
            let auth = use_auth();
            auth.pubkey().get().map(|pk| {
                view! {
                    <div class="mt-6 bg-gray-800 border border-gray-700 rounded-lg p-4">
                        <h3 class="text-sm font-medium text-gray-400 mb-2 flex items-center gap-1.5">
                            {key_icon()}
                            "Your Admin Public Key"
                        </h3>
                        <div class="bg-gray-900 rounded-lg px-3 py-2 flex items-center justify-between gap-2">
                            <code class="text-xs text-amber-300 font-mono break-all">{pk}</code>
                        </div>
                    </div>
                }
            })
        }}
    }
}

// -- Stat card ----------------------------------------------------------------

#[component]
fn StatCard(
    label: &'static str,
    value: Signal<String>,
    icon: &'static str,
    color: &'static str,
) -> impl IntoView {
    let (bg, text, icon_bg) = match color {
        "amber" => (
            "bg-amber-500/10 border-amber-500/20",
            "text-amber-400",
            "bg-amber-500/20",
        ),
        "blue" => (
            "bg-blue-500/10 border-blue-500/20",
            "text-blue-400",
            "bg-blue-500/20",
        ),
        "green" => (
            "bg-green-500/10 border-green-500/20",
            "text-green-400",
            "bg-green-500/20",
        ),
        "orange" => (
            "bg-orange-500/10 border-orange-500/20",
            "text-orange-400",
            "bg-orange-500/20",
        ),
        _ => (
            "bg-gray-500/10 border-gray-500/20",
            "text-gray-400",
            "bg-gray-500/20",
        ),
    };

    let card_class = format!(
        "border rounded-lg p-4 {bg} hover:-translate-y-0.5 hover:shadow-lg transition-all duration-200"
    );
    let icon_class =
        format!("w-12 h-12 rounded-lg {icon_bg} {text} flex items-center justify-center");
    let value_class = format!("text-2xl font-bold {text}");

    view! {
        <div class=card_class>
            <div class="flex items-start justify-between">
                <div>
                    <p class="text-sm text-gray-400 mb-1">{label}</p>
                    <p class=value_class>{move || value.get()}</p>
                </div>
                <div class=icon_class>
                    {stat_icon_svg(icon)}
                </div>
            </div>
        </div>
    }
}

#[component]
fn StatCardSkeleton() -> impl IntoView {
    view! {
        <div class="border border-gray-700 rounded-lg p-4 bg-gray-800 animate-pulse">
            <div class="flex items-start justify-between">
                <div class="space-y-2">
                    <div class="h-3 bg-gray-700 rounded w-16"></div>
                    <div class="h-7 bg-gray-700 rounded w-12"></div>
                </div>
                <div class="w-12 h-12 rounded-lg bg-gray-700"></div>
            </div>
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn stat_icon_svg(icon: &str) -> impl IntoView {
    match icon {
        "users" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 00-3-3.87"/>
                <path d="M16 3.13a4 4 0 010 7.75"/>
            </svg>
        }.into_any(),
        "hash" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="4" y1="9" x2="20" y2="9"/>
                <line x1="4" y1="15" x2="20" y2="15"/>
                <line x1="10" y1="3" x2="8" y2="21"/>
                <line x1="16" y1="3" x2="14" y2="21"/>
            </svg>
        }.into_any(),
        "messages" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
            </svg>
        }.into_any(),
        "alert" => view! {
            <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        }.into_any(),
        _ => view! {
            <span class="text-lg font-bold">"?"</span>
        }.into_any(),
    }
}

fn key_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
        </svg>
    }
}
