//! Channel list page -- reads from shared ChannelStore (no per-page subscription).

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_query_map;

use crate::app::base_href;
use crate::components::activity_graph::{ActivityGraph, ActivityPoint};
use crate::components::board_stats::BoardStats;
use crate::components::channel_card::{ChannelCard, ChannelInfo};
use crate::components::mark_all_read::MarkAllRead;
use crate::components::todays_activity::TodaysActivity;
use crate::components::top_posters::{TopPosters, PosterData};
use crate::stores::channels::use_channel_store;
use crate::stores::mute::use_mute_store;
use crate::stores::read_position::use_read_positions;
use crate::stores::zone_access::use_zone_access;

/// Zone-based filter pill definitions.
/// Each entry: (label, zone_id). Empty zone_id = "All".
const SECTION_FILTERS: &[(&str, &str)] = &[
    ("All", ""),
    ("Home", "home"),
    ("Nostr BBS", "members"),
    ("Private", "private"),
];

/// Maps zone IDs to their child section IDs.
const ZONE_SECTIONS: &[(&str, &[&str])] = &[
    ("home", &["public-lobby"]),
    ("members", &["members-training", "members-projects", "members-bookings", "ai-general", "ai-claude-flow", "ai-visionflow"]),
    ("private", &["private-welcome", "private-events", "private-booking"]),
];

/// Resolve a channel's section tag to its parent zone ID.
fn section_to_zone_id(section: &str) -> Option<&'static str> {
    for &(zone_id, sections) in ZONE_SECTIONS {
        if sections.contains(&section) {
            return Some(zone_id);
        }
    }
    None
}

/// Check whether the user can see a channel based on its section's zone access.
fn can_see_channel(
    section: &str,
    home: bool,
    members: bool,
    private: bool,
) -> bool {
    match section_to_zone_id(section) {
        Some("home") => home,
        Some("members") => members,
        Some("private") => private,
        Some(_) => false,
        None => true, // Unknown section → show it
    }
}

/// Channel list page. Reads from shared ChannelStore and supports zone filtering.
#[component]
pub fn ChatPage() -> impl IntoView {
    let store = use_channel_store();
    let conn_state = expect_context::<crate::relay::RelayConnection>().connection_state();
    let zone_access = use_zone_access();
    // Extract Copy signals for use in multiple closures
    let za_home = zone_access.home;
    let za_members = zone_access.members;
    let za_private = zone_access.private_zone;

    let query = use_query_map();
    let section_filter = move || query.read().get("section").unwrap_or_default();

    let mute_store = use_mute_store();
    let read_store = use_read_positions();

    // -- Dashboard derived signals from ChannelStore --
    let total_messages = Signal::derive(move || {
        store.message_counts.get().values().sum::<u32>()
    });
    let total_users = Signal::derive(move || {
        // Approximate: count unique authors from channel_messages
        let all = store.channel_messages.get();
        let mut unique = std::collections::HashSet::new();
        for events in all.values() {
            for ev in events {
                unique.insert(ev.pubkey.clone());
            }
        }
        unique.len() as u32
    });
    let total_channels = Signal::derive(move || store.channels.get().len() as u32);
    let online_count = Signal::derive(move || {
        // Estimate: channels with activity in last 5 minutes
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let active = store.last_active.get();
        active.values().filter(|&&ts| now.saturating_sub(ts) < 300).count() as u32
    });
    let today_messages = Signal::derive(move || {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let day_start = now - (now % 86400);
        let all = store.channel_messages.get();
        let mut count = 0u32;
        for events in all.values() {
            count += events.iter().filter(|e| e.created_at >= day_start).count() as u32;
        }
        count
    });
    let today_active_channels = Signal::derive(move || {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let day_start = now - (now % 86400);
        let active = store.last_active.get();
        active.values().filter(|&&ts| ts >= day_start).count() as u32
    });
    let new_users_today = Signal::derive(move || 0u32); // No join timestamp available
    let top_posters_data = Signal::derive(move || {
        let all = store.channel_messages.get();
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for events in all.values() {
            for ev in events {
                *counts.entry(ev.pubkey.clone()).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(10);
        sorted.into_iter().map(|(pk, count)| PosterData {
            pubkey: pk.clone(),
            name: crate::components::user_display::use_display_name(&pk),
            message_count: count,
            avatar_url: None,
        }).collect::<Vec<_>>()
    });
    let activity_data = Signal::derive(move || {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        let mut hourly = [0u32; 24];
        let all = store.channel_messages.get();
        for events in all.values() {
            for ev in events {
                if now.saturating_sub(ev.created_at) < 86400 {
                    let date = js_sys::Date::new_0();
                    date.set_time((ev.created_at as f64) * 1000.0);
                    let hour = date.get_hours() as usize;
                    if hour < 24 { hourly[hour] += 1; }
                }
            }
        }
        (0..24).map(|h| ActivityPoint { hour: h as u32, count: hourly[h] }).collect::<Vec<_>>()
    });

    // Mark all channels as read callback
    let channels_for_mark = store.channels;
    let on_mark_all_read = Callback::new(move |_: ()| {
        let chans = channels_for_mark.get_untracked();
        let now = (js_sys::Date::now() / 1000.0) as u64;
        for ch in &chans {
            read_store.mark_read(&ch.id, "", now);
        }
    });

    // Filtered and sorted channel list (unmuted, zone-gated)
    let filtered_channels = move || {
        let section = section_filter();
        let chans = store.channels.get();
        let counts = store.message_counts.get();
        let active = store.last_active.get();
        let home = za_home.get();
        let members = za_members.get();
        let private_zone = za_private.get();

        let mut result: Vec<ChannelInfo> = chans
            .iter()
            // Zone access gate: only show channels the user can see
            .filter(|c| can_see_channel(&c.section, home, members, private_zone))
            .filter(|c| {
                if section.is_empty() {
                    return true;
                }
                // Match against zone ID or direct section
                c.section == section || section_to_zone_id(&c.section) == Some(section.as_str())
            })
            .filter(|c| !mute_store.is_channel_muted(&c.id))
            .map(|c| ChannelInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                description: c.description.clone(),
                section: c.section.clone(),
                picture: c.picture.clone(),
                message_count: counts.get(&c.id).copied().unwrap_or(0),
                last_active: active.get(&c.id).copied().unwrap_or(0),
            })
            .collect();

        result.sort_by(|a, b| b.last_active.cmp(&a.last_active));
        result
    };

    // Muted channels (shown collapsed at bottom, also zone-gated)
    let muted_channels = move || {
        let section = section_filter();
        let chans = store.channels.get();
        let counts = store.message_counts.get();
        let active = store.last_active.get();
        let home = za_home.get();
        let members = za_members.get();
        let private_zone = za_private.get();

        let mut result: Vec<ChannelInfo> = chans
            .iter()
            .filter(|c| can_see_channel(&c.section, home, members, private_zone))
            .filter(|c| {
                if section.is_empty() {
                    return true;
                }
                c.section == section || section_to_zone_id(&c.section) == Some(section.as_str())
            })
            .filter(|c| mute_store.is_channel_muted(&c.id))
            .map(|c| ChannelInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                description: c.description.clone(),
                section: c.section.clone(),
                picture: c.picture.clone(),
                message_count: counts.get(&c.id).copied().unwrap_or(0),
                last_active: active.get(&c.id).copied().unwrap_or(0),
            })
            .collect();

        result.sort_by(|a, b| b.last_active.cmp(&a.last_active));
        result
    };

    let page_title = move || {
        let section = section_filter();
        if section.is_empty() {
            "Channels".to_string()
        } else {
            match section.as_str() {
                "home" => "Home".to_string(),
                "members" => "Nostr BBS".to_string(),
                "private" => "Private".to_string(),
                _ => "Channels".to_string(),
            }
        }
    };

    let channel_count = move || filtered_channels().len();
    let loading = store.loading;

    view! {
        <div class="max-w-4xl mx-auto p-4 sm:p-6">
            <div class="mb-6">
                <div class="flex items-center gap-3 mb-1">
                    <h1 class="text-3xl font-bold text-white">{page_title}</h1>
                    {move || {
                        let count = channel_count();
                        if !loading.get() && count > 0 {
                            Some(view! {
                                <span class="text-xs font-medium text-gray-400 bg-gray-800 border border-gray-700 rounded-full px-2.5 py-0.5">
                                    {count}
                                </span>
                            })
                        } else {
                            None
                        }
                    }}
                </div>
                <p class="text-gray-400">"Join conversations in public channels"</p>
            </div>

            // Community dashboard — activity pill + stats
            <Show when=move || !loading.get()>
                <div class="space-y-3 mb-4">
                    <TodaysActivity
                        message_count=today_messages
                        new_users=new_users_today
                        active_channels=today_active_channels
                    />
                    <BoardStats
                        total_messages=total_messages
                        total_users=total_users
                        total_channels=total_channels
                        online_count=online_count
                    />
                </div>
            </Show>

            // Mark all read button
            <div class="flex justify-end mb-2">
                <MarkAllRead on_click=on_mark_all_read />
            </div>

            // Section filter pills (only show zones the user can access)
            <div class="flex gap-2 overflow-x-auto pb-2 mb-4 scrollbar-none" style="-webkit-overflow-scrolling: touch">
                {move || {
                    let current = section_filter();
                    SECTION_FILTERS.iter().filter(|&&(_, zone_id)| {
                        zone_id.is_empty() || match zone_id {
                            "home" => za_home.get(),
                            "members" => za_members.get(),
                            "private" => za_private.get(),
                            _ => false,
                        }
                    }).map(|&(label, value)| {
                        let is_active = if value.is_empty() {
                            current.is_empty()
                        } else {
                            current == value
                        };
                        let href = if value.is_empty() {
                            base_href("/chat")
                        } else {
                            base_href(&format!("/chat?section={}", value))
                        };
                        let class = if is_active {
                            "inline-block px-3 py-1.5 rounded-full text-sm font-semibold bg-amber-500 text-gray-900 whitespace-nowrap transition-colors"
                        } else {
                            "inline-block px-3 py-1.5 rounded-full text-sm bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-700 hover:text-gray-200 whitespace-nowrap transition-colors"
                        };
                        view! {
                            <A href=href attr:class=class>
                                {label}
                            </A>
                        }
                    }).collect_view()
                }}
            </div>

            // Connection banner
            {move || {
                let state = conn_state.get();
                match state {
                    crate::relay::ConnectionState::Reconnecting => Some(view! {
                        <div class="bg-yellow-900/50 border border-yellow-700 rounded-lg px-4 py-3 mb-4 flex items-center gap-2">
                            <span class="animate-pulse w-2 h-2 rounded-full bg-yellow-400"></span>
                            <span class="text-yellow-200 text-sm">"Reconnecting to relay..."</span>
                        </div>
                    }.into_any()),
                    crate::relay::ConnectionState::Error => Some(view! {
                        <div class="bg-red-900/50 border border-red-700 rounded-lg px-4 py-3 mb-4">
                            <span class="text-red-200 text-sm">"Connection error. Retrying..."</span>
                        </div>
                    }.into_any()),
                    crate::relay::ConnectionState::Disconnected => Some(view! {
                        <div class="bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 mb-4">
                            <span class="text-gray-300 text-sm">"Disconnected from relay."</span>
                        </div>
                    }.into_any()),
                    _ => None,
                }
            }}

            // Content
            {move || {
                if loading.get() {
                    view! {
                        <div class="space-y-3">
                            <ChannelSkeleton/>
                            <ChannelSkeleton/>
                            <ChannelSkeleton/>
                            <ChannelSkeleton/>
                            <ChannelSkeleton/>
                        </div>
                    }.into_any()
                } else {
                    let chans = filtered_channels();
                    if chans.is_empty() {
                        view! {
                            <div class="bg-gray-800/50 border border-gray-700 rounded-xl p-12 text-center">
                                <div class="flex justify-center mb-5">
                                    <div class="w-16 h-16 rounded-full bg-gray-700/50 flex items-center justify-center">
                                        <svg class="w-8 h-8 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z"/>
                                        </svg>
                                    </div>
                                </div>
                                <h3 class="text-lg font-semibold text-white mb-2">
                                    {move || {
                                        let section = section_filter();
                                        if section.is_empty() {
                                            "No channels yet".to_string()
                                        } else {
                                            format!("No channels in {}", section)
                                        }
                                    }}
                                </h3>
                                <p class="text-gray-400 mb-6 max-w-sm mx-auto">
                                    "Channels are where conversations happen. New channels will appear here as they are created."
                                </p>
                                {move || {
                                    let section = section_filter();
                                    if !section.is_empty() {
                                        Some(view! {
                                            <A href=base_href("/chat") attr:class="inline-flex items-center gap-2 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-5 py-2.5 rounded-lg transition-colors">
                                                <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
                                                    <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/>
                                                </svg>
                                                "View All Channels"
                                            </A>
                                        })
                                    } else {
                                        None
                                    }
                                }}
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-3">
                                {chans.into_iter().map(|ch| {
                                    view! { <ChannelCard channel=ch/> }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }
                }
            }}

            // Muted channels section
            {move || {
                let muted = muted_channels();
                if muted.is_empty() {
                    None
                } else {
                    Some(view! {
                        <div class="mt-6">
                            <div class="flex items-center gap-2 mb-2">
                                <span class="text-xs font-medium text-gray-500 uppercase tracking-wider">"Muted"</span>
                                <span class="text-xs text-gray-600 bg-gray-800 rounded-full px-2 py-0.5">
                                    {muted.len()}
                                </span>
                            </div>
                            <div class="space-y-2 opacity-50">
                                {muted.into_iter().map(|ch| {
                                    let cid = ch.id.clone();
                                    view! {
                                        <div class="relative">
                                            <ChannelCard channel=ch/>
                                            <button
                                                class="absolute top-2 right-2 text-xs text-gray-500 hover:text-amber-400 bg-gray-800/90 rounded px-2 py-1 transition-colors z-10"
                                                on:click=move |e| {
                                                    e.prevent_default();
                                                    e.stop_propagation();
                                                    mute_store.toggle_mute_channel(&cid);
                                                }
                                            >
                                                "Unmute"
                                            </button>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    })
                }
            }}

            // Community insights — top posters + activity graph
            <Show when=move || !loading.get()>
                <div class="mt-8 space-y-4">
                    <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider">"Community Insights"</h2>
                    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <TopPosters posters=top_posters_data />
                        <ActivityGraph data=activity_data />
                    </div>
                </div>
            </Show>
        </div>
    }
}

/// Skeleton loader for a channel card.
#[component]
fn ChannelSkeleton() -> impl IntoView {
    view! {
        <div class="bg-gray-800 border border-gray-700 rounded-lg p-4">
            <div class="flex gap-4">
                <div class="w-12 h-12 rounded-lg skeleton"></div>
                <div class="flex-1 space-y-2">
                    <div class="h-4 skeleton rounded w-1/3"></div>
                    <div class="h-3 skeleton rounded w-2/3"></div>
                    <div class="h-3 skeleton rounded w-1/4 mt-3"></div>
                </div>
            </div>
        </div>
    }
}
