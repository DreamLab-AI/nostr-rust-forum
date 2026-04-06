//! Admin statistics dashboard component.
//!
//! Displays aggregate stats (users, channels, messages, DMs) and a recent
//! activity feed. Admin-only — guarded by `AdminStore::is_admin()`.

use leptos::prelude::*;
use nostr_core::NostrEvent;
use std::rc::Rc;

use super::use_admin;
use crate::auth::use_auth;
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::components::user_display::use_display_name;
use crate::utils::{format_relative_time, search_client};

/// A single recent activity entry.
#[derive(Clone, Debug)]
struct ActivityEntry {
    kind: u64,
    pubkey: String,
    created_at: u64,
    content_preview: String,
}

impl ActivityEntry {
    fn from_event(event: &NostrEvent) -> Self {
        let preview = if event.content.len() > 80 {
            format!("{}...", &event.content[..77])
        } else {
            event.content.clone()
        };
        Self {
            kind: event.kind,
            pubkey: event.pubkey.clone(),
            created_at: event.created_at,
            content_preview: preview,
        }
    }
}

fn kind_icon_label(kind: u64) -> (&'static str, &'static str) {
    match kind {
        0 => ("Profile", "text-blue-400"),
        1 => ("Note", "text-gray-400"),
        4 => ("DM", "text-purple-400"),
        7 => ("Reaction", "text-pink-400"),
        40 => ("Channel", "text-green-400"),
        42 => ("Message", "text-amber-400"),
        1059 => ("GiftWrap", "text-purple-400"),
        _ => ("Event", "text-gray-500"),
    }
}

/// Admin stats dashboard. Only renders for admin users.
#[component]
pub fn StatsPanel() -> impl IntoView {
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
            <StatsDashboardInner />
        </Show>
    }
}

#[component]
fn StatsDashboardInner() -> impl IntoView {
    let admin = use_admin();
    let relay = expect_context::<RelayConnection>();
    let conn_state = relay.connection_state();

    let stats = admin.state.stats;
    let is_loading = admin.state.is_loading;

    let dm_count = RwSignal::new(0u32);
    let activity = RwSignal::new(Vec::<ActivityEntry>::new());
    let feed_sub_id: RwSignal<Option<String>> = RwSignal::new(None);

    let relay_for_sub = relay.clone();
    let relay_for_cleanup = relay;

    // Subscribe to recent events for the activity feed + DM count
    Effect::new(move |_| {
        let state = conn_state.get();
        if state != ConnectionState::Connected {
            return;
        }
        if feed_sub_id.get_untracked().is_some() {
            return;
        }

        // Subscribe to various kinds for the feed
        let filter = Filter {
            kinds: Some(vec![0, 1, 7, 40, 42, 1059]),
            limit: Some(50),
            ..Default::default()
        };

        let dm_count_sig = dm_count;
        let activity_sig = activity;
        let on_event = Rc::new(move |event: NostrEvent| {
            if event.kind == 1059 || event.kind == 4 {
                dm_count_sig.update(|c| *c += 1);
            }

            let entry = ActivityEntry::from_event(&event);
            activity_sig.update(|list| {
                list.push(entry);
                list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                list.truncate(10);
            });
        });

        let id = relay_for_sub.subscribe(vec![filter], on_event, None);
        feed_sub_id.set(Some(id));
    });

    on_cleanup(move || {
        if let Some(id) = feed_sub_id.get_untracked() {
            relay_for_cleanup.unsubscribe(&id);
        }
    });

    // Refresh handler
    let admin_for_refresh = admin.clone();
    let on_refresh = move |_| {
        admin_for_refresh.fetch_stats();
    };

    view! {
        <div class="space-y-6">
            // Header
            <div class="flex items-center justify-between">
                <h2 class="text-xl font-bold text-white flex items-center gap-2">
                    {chart_icon()}
                    "Statistics"
                </h2>
                <button
                    on:click=on_refresh
                    disabled=move || is_loading.get()
                    class="text-sm text-amber-400 hover:text-amber-300 border border-amber-500/30 hover:border-amber-400 rounded px-3 py-1 transition-colors disabled:opacity-50"
                >
                    {move || if is_loading.get() { "Loading..." } else { "Refresh" }}
                </button>
            </div>

            // Stats cards grid
            <Show
                when=move || !is_loading.get()
                fallback=|| view! {
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                        <CardSkeleton /><CardSkeleton /><CardSkeleton /><CardSkeleton />
                    </div>
                }
            >
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatsCard
                        label="Total Users"
                        value=Signal::derive(move || stats.get().total_users.to_string())
                        color="amber"
                    />
                    <StatsCard
                        label="Active Channels"
                        value=Signal::derive(move || stats.get().total_channels.to_string())
                        color="blue"
                    />
                    <StatsCard
                        label="Messages"
                        value=Signal::derive(move || stats.get().total_messages.to_string())
                        color="green"
                    />
                    <StatsCard
                        label="DMs Seen"
                        value=Signal::derive(move || dm_count.get().to_string())
                        color="purple"
                    />
                </div>
            </Show>

            // Search index status
            <SearchIndexPanel />

            // Recent activity feed
            <div class="glass-card p-6">
                <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    {activity_icon()}
                    "Recent Activity"
                </h3>

                {move || {
                    let entries = activity.get();
                    if entries.is_empty() {
                        view! {
                            <p class="text-gray-500 text-sm">"No recent activity yet. Events will appear as they arrive."</p>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-2">
                                {entries.into_iter().map(|entry| {
                                    let (label, color_cls) = kind_icon_label(entry.kind);
                                    let pk_short = use_display_name(&entry.pubkey);
                                    let time_str = format_relative_time(entry.created_at);
                                    let preview = entry.content_preview.clone();
                                    let has_content = !preview.is_empty();

                                    view! {
                                        <div class="flex items-start gap-3 bg-gray-800/50 rounded-lg px-3 py-2 hover:bg-gray-800 transition-colors">
                                            <span class=format!("text-xs font-medium px-1.5 py-0.5 rounded border border-gray-700 {}", color_cls)>
                                                {label}
                                            </span>
                                            <div class="flex-1 min-w-0">
                                                <div class="flex items-center gap-2 text-xs">
                                                    <span class="text-gray-300 font-mono">{pk_short}</span>
                                                    <span class="text-gray-600">{time_str}</span>
                                                </div>
                                                {has_content.then(|| view! {
                                                    <p class="text-gray-500 text-xs truncate mt-0.5">{preview}</p>
                                                })}
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

// -- Sub-components -----------------------------------------------------------

#[component]
fn StatsCard(label: &'static str, value: Signal<String>, color: &'static str) -> impl IntoView {
    let (bg, text) = match color {
        "amber" => ("bg-amber-500/10 border-amber-500/20", "text-amber-400"),
        "blue" => ("bg-blue-500/10 border-blue-500/20", "text-blue-400"),
        "green" => ("bg-green-500/10 border-green-500/20", "text-green-400"),
        "purple" => ("bg-purple-500/10 border-purple-500/20", "text-purple-400"),
        _ => ("bg-gray-500/10 border-gray-500/20", "text-gray-400"),
    };

    let card_class = format!(
        "border rounded-lg p-4 {} hover:-translate-y-0.5 hover:shadow-lg transition-all duration-200",
        bg
    );
    let value_class = format!("text-3xl font-bold {}", text);

    // Decorative gradient bar
    let bar_class = format!(
        "h-1 rounded-full mt-3 bg-gradient-to-r from-transparent via-current to-transparent opacity-20 {}",
        text
    );

    view! {
        <div class=card_class>
            <p class="text-sm text-gray-400 mb-1">{label}</p>
            <p class=value_class>{move || value.get()}</p>
            <div class=bar_class></div>
        </div>
    }
}

#[component]
fn CardSkeleton() -> impl IntoView {
    view! {
        <div class="border border-gray-700 rounded-lg p-4 bg-gray-800 animate-pulse">
            <div class="h-3 bg-gray-700 rounded w-16 mb-2"></div>
            <div class="h-8 bg-gray-700 rounded w-12"></div>
            <div class="h-1 bg-gray-700 rounded mt-3"></div>
        </div>
    }
}

// -- Search index panel -------------------------------------------------------

#[component]
fn SearchIndexPanel() -> impl IntoView {
    let search_stats: RwSignal<Option<search_client::SearchStats>> = RwSignal::new(None);
    let search_error: RwSignal<Option<String>> = RwSignal::new(None);
    let search_loading = RwSignal::new(true);

    // Fetch search status on mount
    wasm_bindgen_futures::spawn_local(async move {
        match search_client::get_search_status().await {
            Ok(stats) => {
                search_stats.set(Some(stats));
                search_loading.set(false);
            }
            Err(e) => {
                search_error.set(Some(e));
                search_loading.set(false);
            }
        }
    });

    view! {
        <div class="glass-card p-6">
            <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                {search_icon()}
                "Search Index"
            </h3>

            {move || {
                if search_loading.get() {
                    view! {
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            <CardSkeleton /><CardSkeleton /><CardSkeleton />
                        </div>
                    }.into_any()
                } else if let Some(err) = search_error.get() {
                    view! {
                        <div class="flex items-center gap-2 text-yellow-400 text-sm">
                            <span class="w-2 h-2 rounded-full bg-yellow-500"></span>
                            {format!("Search API offline: {}", err)}
                        </div>
                    }.into_any()
                } else if let Some(stats) = search_stats.get() {
                    view! {
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            <div class="border border-amber-500/20 bg-amber-500/10 rounded-lg p-4">
                                <p class="text-sm text-gray-400 mb-1">"Vectors"</p>
                                <p class="text-3xl font-bold text-amber-400">{stats.total_vectors.to_string()}</p>
                            </div>
                            <div class="border border-blue-500/20 bg-blue-500/10 rounded-lg p-4">
                                <p class="text-sm text-gray-400 mb-1">"Engine"</p>
                                <p class="text-xl font-bold text-blue-400">{stats.engine.clone()}</p>
                            </div>
                            <div class="border border-green-500/20 bg-green-500/10 rounded-lg p-4">
                                <p class="text-sm text-gray-400 mb-1">"Dimensions"</p>
                                <p class="text-3xl font-bold text-green-400">{stats.dimensions.to_string()}</p>
                                <div class="flex items-center gap-1 mt-1">
                                    <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                    <span class="text-xs text-green-600">"Healthy"</span>
                                </div>
                            </div>
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <p class="text-gray-500 text-sm">"No data available."</p>
                    }.into_any()
                }
            }}
        </div>
    }
}

// -- SVG icon helpers ---------------------------------------------------------

fn chart_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="20" x2="18" y2="10"/>
            <line x1="12" y1="20" x2="12" y2="4"/>
            <line x1="6" y1="20" x2="6" y2="14"/>
        </svg>
    }
}

fn activity_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
    }
}

fn search_icon() -> impl IntoView {
    view! {
        <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
    }
}
