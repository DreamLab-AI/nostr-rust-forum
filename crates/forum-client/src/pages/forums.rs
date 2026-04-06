//! Forum index page -- displays all zones and their categories with hero cards.
//!
//! Subscribes to kind 40 (channel creation) events from the relay,
//! groups them by zone/category from the `section` tag, and renders
//! each zone with its categories as visually rich hero cards.

use leptos::prelude::*;
use std::collections::HashMap;

use leptos_router::components::A;

use crate::app::base_href;
use crate::auth::use_auth;
use crate::components::breadcrumb::{Breadcrumb, BreadcrumbItem};
use crate::components::category_card::CategoryCard;
use crate::components::empty_state::EmptyState;
use crate::stores::channels::use_channel_store;
use crate::stores::zone_access::use_zone_access;

// -- Zone definitions ---------------------------------------------------------

struct Zone {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    icon: &'static str,
    accent: &'static str,
    /// Sections belonging to this zone (section IDs from the YAML config).
    /// Channels tagged with these section IDs will appear under this zone.
    sections: &'static [&'static str],
}

/// Production zone definitions — 3 zones with boolean access flags.
const ZONES: &[Zone] = &[
    Zone {
        id: "home",
        name: "Home",
        description: "Welcome! General discussion, introductions, and community chat",
        icon: "sparkle",
        accent: "amber",
        sections: &["public-lobby"],
    },
    Zone {
        id: "members",
        name: "Nostr BBS",
        description: "Business training, collaboration, and AI agent workspace",
        icon: "sparkle",
        accent: "pink",
        sections: &[
            "members-training", "members-projects", "members-bookings",
            "ai-general", "ai-claude-flow", "ai-visionflow",
        ],
    },
    Zone {
        id: "private",
        name: "Private",
        description: "For friends and visitors staying with us",
        icon: "moon",
        accent: "purple",
        sections: &["private-welcome", "private-events", "private-booking"],
    },
];

/// Resolve a section tag to its parent zone ID.
fn section_to_zone(section: &str) -> Option<&'static str> {
    for zone in ZONES {
        if zone.sections.contains(&section) {
            return Some(zone.id);
        }
    }
    None
}

// -- Welcome card helpers -----------------------------------------------------

fn is_welcome_dismissed() -> bool {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item("bbs_welcome_dismissed").ok())
        .flatten()
        .is_some()
}

fn dismiss_welcome() {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.set_item("bbs_welcome_dismissed", "true");
    }
}

/// Main forum index page showing all zones and their categories.
/// Only shows zones the user has access to — inaccessible zones are hidden.
/// Reads from the shared ChannelStore — no per-page relay subscription.
#[component]
pub fn ForumsPage() -> impl IntoView {
    let store = use_channel_store();
    let loading = store.loading;
    let auth = use_auth();
    let is_authed = auth.is_authenticated();
    let welcome_name = auth.nickname();
    let show_welcome = RwSignal::new(!is_welcome_dismissed());
    let zone_access = use_zone_access();
    // Extract Copy signals so closures can capture them by value
    let za_home = zone_access.home;
    let za_members = zone_access.members;
    let za_private = zone_access.private_zone;
    let za_loaded = zone_access.loaded;

    // Derive zone_id -> { section_id -> channel_count } from the shared store
    let zone_categories = Memo::new(move |_| {
        let chans = store.channels.get();
        let mut map = HashMap::<String, HashMap<String, u32>>::new();
        for ch in &chans {
            if ch.section.is_empty() {
                continue;
            }
            if let Some(zone_id) = section_to_zone(&ch.section) {
                let cats = map.entry(zone_id.to_string()).or_default();
                *cats.entry(ch.section.clone()).or_insert(0) += 1;
            }
        }
        map
    });

    view! {
        // Onboarding modal — shown once to new users on first login
        <crate::components::onboarding_modal::OnboardingModal />

        <div class="max-w-6xl mx-auto p-4 sm:p-6">
            // Hero header
            <div class="relative mb-10 py-10 rounded-2xl overflow-hidden mesh-bg aurora-shimmer">
                <div class="ambient-orb ambient-orb-1" aria-hidden="true"></div>
                <div class="ambient-orb ambient-orb-2" aria-hidden="true"></div>
                <div class="relative z-10 text-center">
                    <h1 class="text-4xl sm:text-5xl font-bold candy-gradient mb-3">
                        "Forums"
                    </h1>
                    <p class="text-gray-400 text-lg max-w-xl mx-auto">
                        "Explore zones, dive into categories, and join the conversation"
                    </p>
                </div>
            </div>

            <Breadcrumb items=vec![
                BreadcrumbItem::link("Home", "/"),
                BreadcrumbItem::current("Forums"),
            ] />

            // Welcome card — shown once to new users
            <Show when=move || is_authed.get() && show_welcome.get()>
                <div class="relative mb-6 p-6 rounded-2xl bg-gradient-to-br from-amber-500/10 via-orange-500/5 to-transparent border border-amber-500/20 backdrop-blur-sm overflow-hidden">
                    <div class="absolute -top-10 -right-10 w-40 h-40 rounded-full bg-amber-500/5 blur-3xl" aria-hidden="true"></div>
                    <button
                        class="absolute top-3 right-3 text-gray-500 hover:text-white p-1 rounded-lg hover:bg-gray-700/50 transition-colors"
                        on:click=move |_| {
                            dismiss_welcome();
                            show_welcome.set(false);
                        }
                        aria-label="Dismiss welcome message"
                    >
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18" stroke-linecap="round"/>
                            <line x1="6" y1="6" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                    </button>
                    <div class="relative z-10">
                        <h2 class="text-xl font-bold text-white mb-2">
                            {move || {
                                let name = welcome_name.get().unwrap_or_default();
                                if name.is_empty() {
                                    "Welcome to Nostr BBS!".to_string()
                                } else {
                                    format!("Welcome, {}!", name)
                                }
                            }}
                        </h2>
                        <p class="text-gray-300 text-sm mb-3">
                            "This is your community hub. Forums are organized into zones \u{2014} "
                            "each zone has categories and topics for different discussions."
                        </p>
                        <p class="text-gray-400 text-xs">
                            "Start by exploring the "
                            <span class="text-amber-400 font-medium">"Home"</span>
                            " zone below."
                        </p>
                    </div>
                </div>
            </Show>

            // Loading state
            <Show when=move || loading.get()>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                    <ZoneSkeleton/>
                    <ZoneSkeleton/>
                    <ZoneSkeleton/>
                </div>
            </Show>

            // Zone sections — only show zones the user can access
            <Show when=move || !loading.get()>
                {move || {
                    let zc = zone_categories.get();
                    let visible_zones: Vec<_> = ZONES.iter().filter(|zone| {
                        match zone.id {
                            "home" => za_home.get(),
                            "members" => za_members.get(),
                            "private" => za_private.get(),
                            _ => false,
                        }
                    }).collect();

                    if visible_zones.is_empty() {
                        // Authenticated but zone access not yet fetched — show loading
                        if is_authed.get() && !za_loaded.get() {
                            return view! {
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                                    <ZoneSkeleton/>
                                    <ZoneSkeleton/>
                                    <ZoneSkeleton/>
                                </div>
                            }.into_any();
                        }

                        // Authenticated but no zone access — pending approval
                        if is_authed.get() {
                            let clock_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                                <svg class="w-7 h-7 text-amber-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <circle cx="12" cy="12" r="10"/>
                                    <polyline points="12 6 12 12 16 14"/>
                                </svg>
                            }.into_any());
                            return view! {
                                <EmptyState
                                    icon=clock_icon
                                    title="Awaiting zone access".to_string()
                                    description="Your account is set up. An admin will grant you zone access shortly.".to_string()
                                />
                            }.into_any();
                        }

                        // Not authenticated — sign in prompt
                        let lock_icon: Box<dyn FnOnce() -> leptos::prelude::AnyView + Send> = Box::new(|| view! {
                            <svg class="w-7 h-7 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                                <circle cx="8.5" cy="7" r="4"/>
                                <line x1="20" y1="8" x2="20" y2="14"/>
                                <line x1="23" y1="11" x2="17" y2="11"/>
                            </svg>
                        }.into_any());
                        return view! {
                            <EmptyState
                                icon=lock_icon
                                title="Sign in to get started".to_string()
                                description="Create an account or log in to access the Nostr BBS community forums.".to_string()
                            />
                        }.into_any();
                    }

                    visible_zones.into_iter().map(|zone| {
                        let cats = zc.get(zone.id).cloned().unwrap_or_default();
                        let zone_id = zone.id;
                        let zone_name = zone.name;
                        let zone_desc = zone.description;
                        let accent = zone.accent;
                        let icon = zone.icon;
                        let has_cats = !cats.is_empty();

                        let gradient = zone_gradient(accent);
                        let border = zone_border(accent);
                        let hero_img = zone_default_image(zone_id);
                        let has_hero = !hero_img.is_empty();

                        view! {
                            <section class="mb-10">
                                // Zone hero card with gradient
                                <div class=format!(
                                    "relative mb-4 py-6 px-6 rounded-2xl overflow-hidden bg-gradient-to-br {} border {} backdrop-blur-sm",
                                    gradient, border
                                )>
                                    {has_hero.then(|| view! {
                                        <img
                                            src=hero_img
                                            alt=""
                                            class="absolute inset-0 w-full h-full object-cover opacity-15 pointer-events-none"
                                            loading="lazy"
                                        />
                                        <div class="absolute inset-0 bg-gray-900/50 pointer-events-none"></div>
                                    })}
                                    <div class="absolute -top-10 -right-10 w-40 h-40 rounded-full bg-white/5 blur-3xl" aria-hidden="true"></div>
                                    <div class="absolute -bottom-8 -left-8 w-32 h-32 rounded-full bg-white/3 blur-2xl" aria-hidden="true"></div>

                                    <div class="relative z-10 flex items-start gap-4">
                                        <ZoneIcon icon=icon accent=accent/>
                                        <div class="flex-1 min-w-0">
                                            <h2 class="text-xl sm:text-2xl font-bold text-white mb-1">{zone_name}</h2>
                                            <p class="text-gray-300 text-sm">{zone_desc}</p>
                                        </div>
                                    </div>
                                </div>

                                {if has_cats {
                                    let cards: Vec<_> = cats.iter().map(|(section_id, topic_count)| {
                                        let display_name = humanize_section_id(section_id);
                                        let sid = section_id.clone();
                                        let count = *topic_count;
                                        view! {
                                            <CategoryCard
                                                name=display_name
                                                description=section_description(section_id).to_string()
                                                section_id=sid
                                                icon=icon
                                                section_count=count
                                                accent_color=accent
                                                zone_id=zone_id
                                            />
                                        }
                                    }).collect();
                                    view! {
                                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            {cards.into_iter().collect_view()}
                                        </div>
                                    }.into_any()
                                } else {
                                    // No topics yet — show a direct link to enter the zone
                                    let zone_href = base_href(&format!("/forums/{}", zone_id));
                                    view! {
                                        <A href=zone_href attr:class="block glass-card-interactive p-4 text-center no-underline text-inherit">
                                            <p class="text-gray-400 text-sm mb-2">"No topics yet"</p>
                                            <span class="text-amber-400 font-medium text-sm hover:text-amber-300 transition-colors">
                                                "Enter & start a conversation →"
                                            </span>
                                        </A>
                                    }.into_any()
                                }}
                            </section>
                        }
                    }).collect_view().into_any()
                }}
            </Show>
        </div>
    }
}

/// Map zone IDs to default hero images from the main marketing site.
fn zone_default_image(zone_id: &str) -> &'static str {
    match zone_id {
        "home" => "/images/heroes/members-hero.webp",
        "members" => "/images/heroes/ai-commander-week.webp",
        "private" => "/images/heroes/corporate-immersive.webp",
        _ => "",
    }
}

/// Gradient class for zone hero cards.
fn zone_gradient(accent: &str) -> &'static str {
    match accent {
        "amber" => "from-amber-500/20 via-orange-500/10 to-yellow-500/5",
        "purple" => "from-purple-500/20 via-indigo-500/10 to-violet-500/5",
        "pink" => "from-pink-500/20 via-rose-500/10 to-fuchsia-500/5",
        _ => "from-gray-500/20 via-gray-500/10 to-gray-500/5",
    }
}

/// Border class for zone hero cards.
fn zone_border(accent: &str) -> &'static str {
    match accent {
        "amber" => "border-amber-500/20",
        "purple" => "border-purple-500/20",
        "pink" => "border-pink-500/20",
        _ => "border-gray-500/20",
    }
}

/// Inline SVG icon per zone type.
#[component]
fn ZoneIcon(icon: &'static str, accent: &'static str) -> impl IntoView {
    let bg_class = match accent {
        "amber" => "w-10 h-10 rounded-lg flex items-center justify-center bg-amber-500/10",
        "purple" => "w-10 h-10 rounded-lg flex items-center justify-center bg-purple-500/10",
        "pink" => "w-10 h-10 rounded-lg flex items-center justify-center bg-pink-500/10",
        _ => "w-10 h-10 rounded-lg flex items-center justify-center bg-gray-500/10",
    };

    let icon_color = match accent {
        "amber" => "text-amber-400",
        "purple" => "text-purple-400",
        "pink" => "text-pink-400",
        _ => "text-gray-400",
    };

    let svg = match icon {
        // Moon icon for Private
        "moon" => view! {
            <svg class=format!("w-5 h-5 {}", icon_color) viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        // Sparkle icon for Nostr BBS / Home
        "sparkle" => view! {
            <svg class=format!("w-5 h-5 {}", icon_color) viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 2l2.4 7.2L22 12l-7.6 2.8L12 22l-2.4-7.2L2 12l7.6-2.8L12 2z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        }.into_any(),
        _ => view! { <span class=format!("{}", icon_color)>"?"</span> }.into_any(),
    };

    view! {
        <div class=bg_class>
            {svg}
        </div>
    }
}

/// Convert a section ID like "private-welcome" to "Welcome".
fn humanize_section_id(id: &str) -> String {
    let suffix = id
        .find('-')
        .map(|i| &id[i + 1..])
        .unwrap_or(id);
    suffix
        .split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Human-friendly descriptions for known section IDs.
fn section_description(id: &str) -> &'static str {
    match id {
        "private-welcome" => "Welcome info for guests",
        "private-events" => "Upcoming events and activities",
        "private-booking" => "Room availability and reservations",
        "public-lobby" => "General discussion and introductions",
        "members-training" => "Training courses and materials",
        "members-projects" => "Active projects and collaboration",
        "members-bookings" => "Session and room bookings",
        "ai-general" => "General AI discussion",
        "ai-claude-flow" => "Claude Flow agent coordination",
        "ai-visionflow" => "VisionFlow AI agents",
        _ => "Browse topics in this section",
    }
}

#[component]
fn ZoneSkeleton() -> impl IntoView {
    view! {
        <div class="glass-card p-6">
            <div class="flex gap-3 mb-4">
                <div class="w-10 h-10 rounded-lg skeleton"></div>
                <div class="flex-1 space-y-2">
                    <div class="h-5 skeleton rounded w-1/3"></div>
                    <div class="h-3 skeleton rounded w-2/3"></div>
                </div>
            </div>
            <div class="h-24 skeleton rounded-lg"></div>
        </div>
    }
}
