//! Forum index page -- displays all zones and their categories with hero cards.
//!
//! Subscribes to kind 40 (channel creation) events from the relay,
//! groups them by zone/category from the `section` tag, and renders
//! each zone with its categories as visually rich hero cards.

use leptos::prelude::AnyView;
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
use crate::stores::zones::{load_zones, Zone, ZoneVisibility};

// -- Zone -> section routing --------------------------------------------------

/// Resolve a channel's `section` tag to the id of the owning config zone.
///
/// Channels carry a free-form `section` tag (e.g. `"family-events"`). With
/// config-driven zones the relationship is by prefix/exact match against the
/// live zone ids: a section belongs to the zone whose id it equals or is
/// prefixed by (`"<zone>-..."`). Falls back to the first zone so channels never
/// silently disappear from the index.
fn section_to_zone(section: &str, zones: &[Zone]) -> Option<String> {
    let sec = section.to_lowercase();
    // Exact id match.
    if let Some(z) = zones.iter().find(|z| z.id.to_lowercase() == sec) {
        return Some(z.id.clone());
    }
    // Prefix match: "<zone-id>-suffix".
    if let Some(z) = zones
        .iter()
        .find(|z| sec.starts_with(&format!("{}-", z.id.to_lowercase())))
    {
        return Some(z.id.clone());
    }
    // Catch-all: first zone so unrouted channels remain visible.
    zones.first().map(|z| z.id.clone())
}

/// Deterministic accent colour per zone, derived from the zone id so themed
/// gradients/badges stay stable across renders without hardcoding zone names.
fn zone_accent(zone_id: &str) -> &'static str {
    const ACCENTS: &[&str] = &["amber", "pink", "purple", "sky", "emerald", "blue"];
    let idx = zone_id
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_add(b as u32)) as usize;
    ACCENTS[idx % ACCENTS.len()]
}

// -- Welcome card helpers -----------------------------------------------------

fn is_welcome_dismissed() -> bool {
    web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item("nostrbbs_welcome_dismissed").ok())
        .flatten()
        .is_some()
}

fn dismiss_welcome() {
    if let Some(storage) = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
    {
        let _ = storage.set_item("nostrbbs_welcome_dismissed", "true");
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
    let za_loaded = zone_access.loaded;
    let za_cohorts = zone_access.cohorts;
    let za_admin = zone_access.is_admin;

    // Config-driven zone list, sourced once from `window.__ENV__.ZONE_CONFIG`
    // (falls back to the legacy 3-zone list). Stored in a StoredValue so the
    // render closures can clone it cheaply without re-parsing.
    let zones = StoredValue::new(load_zones());

    // Derive zone_id -> { section_id -> post_count } from the shared store.
    // Reads both `channels` (for section routing) and `channel_messages`
    // (for live post counts) so the Memo re-runs whenever either changes.
    let zone_categories = Memo::new(move |_| {
        let chans = store.channels.get();
        let msgs = store.channel_messages.get();
        let zs = zones.get_value();
        let mut map = HashMap::<String, HashMap<String, u32>>::new();
        for ch in &chans {
            let section = if ch.section.is_empty() {
                zs.first().map(|z| z.id.clone()).unwrap_or_default()
            } else {
                ch.section.clone()
            };
            if let Some(zone_id) = section_to_zone(&section, &zs) {
                let cats = map.entry(zone_id).or_default();
                let post_count = msgs.get(&ch.id).map(|v| v.len() as u32).unwrap_or(0);
                // Ensure the section entry exists even if post_count == 0 so
                // the category card still renders (section is known to exist).
                let entry = cats.entry(section).or_insert(0);
                *entry += post_count;
            }
        }
        map
    });

    view! {
        // Onboarding modal mounted globally in app.rs Layout — see N3e.

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
                                    "Welcome!".to_string()
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

            // Zone sections — config-driven section tiles, each headed by its
            // banner. Member/public zones render normally; locked zones the user
            // can't enter render as greyed locked tiles; hidden zones the user
            // can't enter are omitted entirely. The relay is the real boundary.
            <Show when=move || !loading.get()>
                {move || {
                    let zc = zone_categories.get();
                    let all_zones = zones.get_value();
                    let cohorts = za_cohorts.get();
                    let is_admin = za_admin.get();
                    let authed = is_authed.get();

                    // Per-zone classification:
                    //   member  -> normal openable tile
                    //   locked  -> greyed, non-openable tile (visibility=locked)
                    //   omitted -> not rendered (visibility=hidden, non-member)
                    let mut rendered: Vec<AnyView> = Vec::new();
                    for zone in &all_zones {
                        let is_member = is_admin || zone.is_member(&cohorts);
                        match (zone.visibility, is_member) {
                            // Public zone, or any zone the user is a member of:
                            // normal tile.
                            (ZoneVisibility::Public, _) | (_, true) => {
                                let cats = zc.get(&zone.id).cloned().unwrap_or_default();
                                rendered.push(zone_tile(zone, cats));
                            }
                            // Locked zone, non-member: greyed locked tile.
                            (ZoneVisibility::Locked, false) => {
                                rendered.push(locked_tile(zone));
                            }
                            // Hidden zone, non-member: omit entirely.
                            (ZoneVisibility::Hidden, false) => {}
                        }
                    }

                    if rendered.is_empty() {
                        // Authenticated but zone access not yet fetched — show loading
                        if authed && !za_loaded.get() {
                            return view! {
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                                    <ZoneSkeleton/>
                                    <ZoneSkeleton/>
                                    <ZoneSkeleton/>
                                </div>
                            }.into_any();
                        }

                        // Authenticated but no accessible zones — pending approval
                        if authed {
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
                                description="Create an account or log in to access the community forums.".to_string()
                            />
                        }.into_any();
                    }

                    rendered.into_iter().collect_view().into_any()
                }}
            </Show>
        </div>
    }
}

// -- Tile builders ------------------------------------------------------------

/// Render a normal, openable section tile for a member/public zone.
///
/// The tile is headed by the zone's `banner_image_url` (responsive, lazy,
/// `alt = display_name`) and lists the zone's category cards below. When the
/// zone has no topics yet it shows an "enter" link instead.
fn zone_tile(zone: &Zone, cats: HashMap<String, u32>) -> AnyView {
    let zone_id = zone.id.clone();
    let label = zone.label();
    let label_alt = label.clone();
    let accent = zone_accent(&zone.id);
    let gradient = zone_gradient(accent);
    let border = zone_border(accent);
    let banner = zone.banner_image_url.clone().unwrap_or_default();
    let has_banner = !banner.is_empty();
    let has_cats = !cats.is_empty();

    let cards_view = if has_cats {
        let mut entries: Vec<(String, u32)> = cats.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let cards: Vec<_> = entries
            .into_iter()
            .map(|(section_id, post_count)| {
                let display_name = humanize_section_id(&section_id);
                view! {
                    <CategoryCard
                        name=display_name
                        description=section_description(&section_id).to_string()
                        section_id=section_id
                        icon="sparkle"
                        post_count=post_count
                        accent_color=accent
                        zone_id=zone_id.clone()
                    />
                }
            })
            .collect();
        view! {
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                {cards.into_iter().collect_view()}
            </div>
        }
        .into_any()
    } else {
        let zone_href = base_href(&format!("/forums/{}", zone_id));
        view! {
            <A href=zone_href attr:class="block glass-card-interactive p-4 text-center no-underline text-inherit">
                <p class="text-gray-400 text-sm mb-2">"No topics yet"</p>
                <span class="text-amber-400 font-medium text-sm hover:text-amber-300 transition-colors">
                    "Enter & start a conversation →"
                </span>
            </A>
        }
        .into_any()
    };

    view! {
        <section class="mb-10">
            // Banner-headed zone card.
            <div class=format!(
                "relative mb-4 rounded-2xl overflow-hidden bg-gradient-to-br {} border {} backdrop-blur-sm",
                gradient, border
            )>
                {has_banner.then(|| view! {
                    <img
                        src=banner.clone()
                        alt=label_alt
                        class="w-full h-40 sm:h-48 object-cover"
                        loading="lazy"
                    />
                    <div class="absolute inset-0 bg-gradient-to-t from-gray-900/90 via-gray-900/40 to-transparent pointer-events-none"></div>
                })}
                <div class=move || if has_banner {
                    "absolute bottom-0 left-0 right-0 z-10 p-5"
                } else {
                    "relative z-10 p-6"
                }>
                    <h2 class="text-xl sm:text-2xl font-bold text-white">{label}</h2>
                </div>
            </div>

            {cards_view}
        </section>
    }
    .into_any()
}

/// Render a greyed, non-openable locked tile for a `visibility = locked` zone
/// the user is not a member of. Shows the banner (desaturated), the name, and a
/// lock affordance. There is no entry route — the relay would refuse anyway.
fn locked_tile(zone: &Zone) -> AnyView {
    let label = zone.label();
    let label_aria = format!("{} (locked)", label);
    let label_alt = label.clone();
    let banner = zone.banner_image_url.clone().unwrap_or_default();
    let has_banner = !banner.is_empty();

    view! {
        <section class="mb-10" aria-label=label_aria>
            <div class="relative rounded-2xl overflow-hidden border border-gray-700/60 bg-gray-800/40 cursor-not-allowed select-none">
                {has_banner.then(|| view! {
                    <img
                        src=banner.clone()
                        alt=label_alt
                        class="w-full h-40 sm:h-48 object-cover grayscale opacity-30"
                        loading="lazy"
                    />
                })}
                <div class="absolute inset-0 bg-gray-900/70 pointer-events-none"></div>
                <div class="absolute inset-0 z-10 flex flex-col items-center justify-center text-center p-5 gap-2">
                    <div class="w-11 h-11 rounded-full bg-gray-700/70 flex items-center justify-center">
                        <svg class="w-5 h-5 text-gray-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                            <path d="M7 11V7a5 5 0 0110 0v4"/>
                        </svg>
                    </div>
                    <h2 class="text-lg sm:text-xl font-bold text-gray-200">{label}</h2>
                    <span class="text-xs text-gray-400 uppercase tracking-wide">"Locked"</span>
                </div>
                // Reserve height when there is no banner so the tile still has body.
                {(!has_banner).then(|| view! { <div class="h-40 sm:h-48"></div> })}
            </div>
        </section>
    }
    .into_any()
}

/// Gradient class for zone hero cards.
fn zone_gradient(accent: &str) -> &'static str {
    match accent {
        "amber" => "from-amber-500/20 via-orange-500/10 to-yellow-500/5",
        "purple" => "from-purple-500/20 via-indigo-500/10 to-violet-500/5",
        "pink" => "from-pink-500/20 via-rose-500/10 to-fuchsia-500/5",
        "sky" => "from-sky-500/20 via-blue-500/10 to-cyan-500/5",
        "emerald" => "from-emerald-500/20 via-teal-500/10 to-green-500/5",
        "blue" => "from-blue-500/20 via-indigo-500/10 to-sky-500/5",
        _ => "from-gray-500/20 via-gray-500/10 to-gray-500/5",
    }
}

/// Border class for zone hero cards.
fn zone_border(accent: &str) -> &'static str {
    match accent {
        "amber" => "border-amber-500/20",
        "purple" => "border-purple-500/20",
        "pink" => "border-pink-500/20",
        "sky" => "border-sky-500/20",
        "emerald" => "border-emerald-500/20",
        "blue" => "border-blue-500/20",
        _ => "border-gray-500/20",
    }
}

/// Convert a section ID like "private-welcome" to "Welcome".
fn humanize_section_id(id: &str) -> String {
    let suffix = id.find('-').map(|i| &id[i + 1..]).unwrap_or(id);
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
        "home-lobby" => "General discussion and introductions",
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
